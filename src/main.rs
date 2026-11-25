use p2p_tunnel_lib::{cli, config, supervisor, tui};

use std::time::Duration;

use clap::Parser;
use crossterm::tty::IsTty;
use tracing::info;

use p2p_tunnel_lib::tui::{TuiEvent, TuiHandle};

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    // Decide up front whether to run the TUI: explicit --tui forces it on, --no-tui
    // forces it off, otherwise auto-enable only when stdout is a real terminal.
    let use_tui = if cli.no_tui {
        false
    } else if cli.tui {
        true
    } else {
        std::io::stdout().is_tty()
    };

    // TUI setup: build the event channel plus the shared state (exchange mode
    // + aborted flag) that both the pipeline and the render loop touch, then
    // spawn the render loop on its own thread (it owns the terminal, which is
    // blocking I/O). When the TUI is off, the handle is a no-op and we just
    // run the plain log path.
    let handle = if use_tui {
        let (handle, rx, mode, aborted) = tui::channel();
        std::thread::Builder::new()
            .name("tui".into())
            .spawn(move || {
                let _ = tui::run_render_loop(rx, mode, aborted);
            })
            .expect("spawn TUI render thread");
        handle
    } else {
        TuiHandle::disabled()
    };

    // Logging: RUST_LOG wins if set, then --verbose, then info. When the TUI is
    // on we switch tracing to `off` so the stderr formatter never interleaves
    // with the alternate screen — the TUI is the single source of truth and
    // already surfaces every meaningful stage as an event.
    let log_level = if use_tui {
        "off"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .init();

    let result = run(cli, handle.clone()).await;

    if let Err(e) = result {
        // Surface the error. When the TUI is running, it paints the error red in
        // the events panel and turns the header red — so we suppress the raw
        // stderr block (it would interleave with the alternate screen) but still
        // exit non-zero. When the TUI is off, print the usual `error:` + hint.
        let chain = format!("{e:#}");
        handle.emit(TuiEvent::Error(chain.clone()));
        if use_tui {
            // Give the render loop a beat to paint the error before we exit.
            std::thread::sleep(Duration::from_secs(3));
        } else {
            eprintln!();
            eprintln!("error: {chain}");
            if let Some(hint) = hint_for(&e) {
                eprintln!("{hint}");
            }
        }
        std::process::exit(1);
    }

    if use_tui {
        // The run ended cleanly (user abort is the only non-error exit):
        // tell the render loop to close the tunnel panel and restore the
        // terminal, then give it a beat to paint. (A q/Esc/Ctrl-C in the
        // prompt editor does not set the quit flag, so without this the
        // render loop — and the alternate screen — would linger.)
        handle.emit(TuiEvent::Done("tunnel closed — goodbye".into()));
        std::thread::sleep(Duration::from_millis(400));
    }
}

async fn run(cli: cli::Cli, ui: TuiHandle) -> anyhow::Result<()> {
    let cfg = config::Config::load(&cli.config)?;

    ui.emit(TuiEvent::Log(
        tui::LogLevel::Info,
        format!("loaded config: {}", cli.config.display()),
    ));

    info!(
        config_path = %cli.config.display(),
        stun_servers = ?cfg.stun_servers,
        punch_interval_ms = cfg.punch_interval_ms,
        punch_timeout_secs = cfg.punch_timeout_secs,
        keep_alive_interval_secs = cfg.keep_alive_interval_secs,
        local_tcp_listen_port = ?cfg.local_tcp_listen_port,
        remote_target_addr = ?cfg.remote_target_addr,
        telegram = cfg.telegram.is_some(),
        role = ?cfg.role,
        "loaded config"
    );

    // v2: the supervisor resolves role/setting/channel (interactive setup),
    // then loops until the user aborts or a structural error occurs.
    supervisor::run(&cfg, &cli, &ui).await
}

/// A short, actionable hint for the common failure modes.
fn hint_for(err: &anyhow::Error) -> Option<String> {
    let chain = format!("{err:#}");
    if chain.contains("STUN discovery failed") {
        Some(
            "hint: check internet connectivity and that outbound UDP is not blocked. \
             If you are behind CGNAT, STUN may report a carrier address you cannot \
             receive on — this MVP cannot traverse that (see plan: TURN fallback)."
                .into(),
        )
    } else if chain.contains("hole punching timed out") {
        Some(
            "hint: double-check the peer's address (it goes stale when the peer's NAT \
             binding expires or they restart). One side may also be behind a symmetric \
             NAT, which simultaneous UDP punching cannot open — this MVP has no TURN fallback."
                .into(),
        )
    } else if chain.contains("QUIC handshake") {
        Some(
            "hint: the UDP hole was open but the QUIC/TLS handshake did not complete. A \
             middlebox may be interfering, or the peer's process exited. Retry on both sides."
                .into(),
        )
    } else if chain.contains("is required for the")
        || chain.contains("remote_target_addr")
        || chain.contains("local_tcp_listen_port")
    {
        Some(
            "hint: add the missing option to your config.toml (see the sample config comments)."
                .into(),
        )
    } else {
        None
    }
}
