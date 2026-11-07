use p2p_tunnel_lib::{cli, config, punch, quic, role, stun, telegram, tui, tui_state, tunnel};

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use crossterm::tty::IsTty;
use tracing::{Instrument, info};

use p2p_tunnel_lib::tui::{TuiEvent, TuiHandle};
use p2p_tunnel_lib::tui_state::{Phase, PhaseStatus};

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
    // on we drop tracing to warnings so the pretty UI isn't double-printed by
    // the stderr formatter (the TUI already surfaces progress as events).
    // When the TUI is on we switch tracing to `off` so the stderr formatter
    // never interleaves with the alternate screen — the TUI is the single
    // source of truth and already surfaces every meaningful stage as an event.
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

    if let Err(e) = run(cli, handle.clone()).await {
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
        // Let the render loop paint the final "CLOSED" state before exiting.
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
        "loaded config"
    );

    // THE socket: bound once, reused for STUN → hole punching → QUIC.
    // (0.0.0.0:0 keeps the MVP on IPv4, which is what home NATs typically hand out.)
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    // Address exchange: Telegram bot-to-bot (if --telegram) or the manual
    // prompt. Telegram is a *second channel*, not a replacement — on any
    // failure (bad token, bot-to-bot disabled, timeout) we fall back to the
    // prompt so the tunnel can still be established manually.
    //
    // Address exchange: Telegram bot-to-bot (if --telegram) or the manual
    // prompt. Telegram is a *second channel*, not a replacement — on any
    // failure (bad token, bot-to-bot disabled, timeout) we fall back to the
    // prompt so the tunnel can still be established manually.
    //
    // In Telegram mode the exchange runs in two ordered steps, gated by the
    // bots: (1) a `PTUN READY` handshake proves the peer's process is up and
    // listening *before* either side spends time on STUN; (2) only after
    // that handshake do both sides discover their public addresses and
    // announce them to each other. The manual path skips (1) — the human on
    // the other end is the liveness signal — so STUN comes first there.
    let (public_addr, peer_addr) = if cli.telegram && cfg.telegram.is_some() {
        resolve_addrs_telegram(&cfg, &socket, &ui).await?
    } else {
        resolve_addrs_manual(&cfg, &socket, &ui).await?
    };
    info!(%peer_addr, "peer address resolved");
    ui.emit(TuiEvent::PeerAddr(peer_addr.to_string()));
    ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Done));

    ui.emit(TuiEvent::Phase(Phase::Punch, PhaseStatus::Active));
    punch::punch(&socket, peer_addr, &cfg)
        .instrument(tracing::info_span!("punch"))
        .await?;
    ui.emit(TuiEvent::Phase(Phase::Punch, PhaseStatus::Done));

    ui.emit(TuiEvent::Phase(Phase::Role, PhaseStatus::Active));
    let role = role::determine_role(public_addr, peer_addr);
    info!(role = role.as_str(), "role determined");
    ui.emit(TuiEvent::Role(role.as_str().to_string()));
    ui.emit(TuiEvent::Phase(Phase::Role, PhaseStatus::Done));

    // QUIC keep-alive: a PING every `keep_alive` keeps the tunnel alive while
    // idle — NAT port mappings expire on silent connections and would drop a
    // healthy tunnel. `0` in the config disables it.
    let keep_alive = (cfg.keep_alive_interval_secs > 0)
        .then(|| Duration::from_secs(cfg.keep_alive_interval_secs));
    info!(?keep_alive, "QUIC keep-alive configured");

    // ── Phase 6: fresh self-signed certificate for the QUIC handshake ──
    ui.emit(TuiEvent::Phase(Phase::Quic, PhaseStatus::Active));
    let (cert_chain, key) = quic::generate_self_signed_cert()?;
    let fingerprint = quic::fingerprint(&cert_chain[0]);
    ui.emit(TuiEvent::Fingerprint(fingerprint));

    // ── Phase 7: QUIC endpoint on the punched socket ──
    // The socket has done its STUN + punch job; hand it to quinn, which
    // takes ownership and runs its own I/O driver on it.
    let std_socket = socket
        .into_std()
        .context("converting the punched UDP socket for quinn")?;
    let server_config = match role {
        role::Role::Server => Some(quic::build_server_config(cert_chain, key, keep_alive)?),
        role::Role::Client => None,
    };
    let mut endpoint = quic::create_endpoint(std_socket, server_config)?;
    if matches!(role, role::Role::Client) {
        endpoint.set_default_client_config(quic::build_client_config(keep_alive)?);
    }

    // ── Phase 10: run the tunnel according to the negotiated role ──
    match role {
        role::Role::Server => {
            let target = cfg
                .remote_target_addr
                .as_deref()
                .context(
                    "config: `remote_target_addr` is required for the server role \n                     (the private ip:port to forward tunneled TCP to)",
                )?;
            let target: SocketAddr = target.parse().with_context(|| {
                format!("config: `remote_target_addr` = {target:?} is not a valid ip:port")
            })?;
            ui.emit(TuiEvent::Target(target.to_string()));
            ui.emit(TuiEvent::Phase(Phase::Quic, PhaseStatus::Done));
            info!("waiting for the peer's QUIC connection…");
            let conn = quic::accept(&endpoint)
                .instrument(tracing::info_span!("quic_handshake"))
                .await?;
            ui.emit(TuiEvent::Phase(Phase::Tunnel, PhaseStatus::Active));
            ui.emit(TuiEvent::Ready);
            tunnel::run_server_side(conn, target)
                .instrument(tracing::info_span!("tunnel", role = "server"))
                .await?;
        }
        role::Role::Client => {
            let port = cfg
                .local_tcp_listen_port
                .context(
                    "config: `local_tcp_listen_port` is required for the client role \n                     (the local TCP port to expose through the tunnel)",
                )?;
            ui.emit(TuiEvent::LocalPort(port));
            info!("initiating QUIC connection to peer…");
            let conn = quic::connect(&endpoint, peer_addr)
                .instrument(tracing::info_span!("quic_handshake"))
                .await?;
            ui.emit(TuiEvent::Phase(Phase::Quic, PhaseStatus::Done));
            ui.emit(TuiEvent::Phase(Phase::Tunnel, PhaseStatus::Active));
            ui.emit(TuiEvent::Ready);
            tunnel::run_client_side(conn, port)
                .instrument(tracing::info_span!("tunnel", role = "client"))
                .await?;
        }
    }
    if ui.aborted() {
        // The user pressed q/Esc/Ctrl-C while the tunnel was running; the
        // render loop has already torn the UI down, so just stop cleanly.
        info!("tunnel aborted by the user");
        return Ok(());
    }
    info!("tunnel closed; goodbye");
    ui.emit(TuiEvent::Phase(Phase::Tunnel, PhaseStatus::Done));
    ui.emit(TuiEvent::Done("tunnel closed; goodbye".into()));
    Ok(())
}

/// Read one line of user input through the active transport.
///
/// TUI on: `ui.ask_line` hands the prompt to the render loop, which shows an
/// inline editor (the TUI keeps drawing while the user types) and reports
/// the outcome — a submitted line, a `t` mode-toggle, an abort, or EOF.
/// TUI off: plain `read_line` on stdin (line, or EOF).
fn read_line(ui: &TuiHandle, prompt: &str) -> std::io::Result<tui::PromptOutcome> {
    ui.ask_line(prompt)
}

/// The Telegram path: (1) the `PTUN READY` handshake proves the peer is up
/// *before* STUN, (2) STUN discovers our address, (3) we announce it and
/// wait for the peer's. On any Telegram failure we fall back to the manual
/// prompt (STUN is then run first, as in [`resolve_addrs_manual`]).
async fn resolve_addrs_telegram(
    cfg: &config::Config,
    socket: &tokio::net::UdpSocket,
    ui: &TuiHandle,
) -> anyhow::Result<(SocketAddr, SocketAddr)> {
    let tg_cfg = cfg.telegram.as_ref().expect("checked by the caller");
    ui.emit(TuiEvent::TelegramChannel(true));
    ui.set_exchange_mode(tui_state::ExchangeMode::Telegram);
    ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Active));

    let mut tg = match telegram::Telegram::init(tg_cfg).await {
        Ok(t) => {
            ui.emit(TuiEvent::Log(
                tui::LogLevel::Info,
                "exchanging readiness with the peer bot over Telegram…".into(),
            ));
            t
        }
        Err(e) => {
            let msg = format!(
                "Telegram signaling unavailable ({e:#}) — falling back to the manual address prompt."
            );
            eprintln!("{msg}");
            ui.emit(TuiEvent::TelegramChannel(false));
            ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
            ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
            return resolve_addrs_manual(cfg, socket, ui).await;
        }
    };

    // (1) Readiness handshake — the peer bot must confirm it is up before
    // either side spends time on STUN.
    if let Err(e) = tg.handshake(tg_cfg, || ui.aborted()).await {
        let msg = format!(
            "Timed out / failed waiting for the peer bot's readiness confirmation ({e:#}) — switching to the manual address prompt."
        );
        eprintln!("{msg}");
        ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
        ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
        return resolve_addrs_manual(cfg, socket, ui).await;
    }
    ui.emit(TuiEvent::Log(
        tui::LogLevel::Info,
        "peer bot confirmed it is up — discovering our address".into(),
    ));

    // (2) STUN — safe now: the peer is up and will be announcing soon.
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Active));
    let public_addr = stun::discover_public_addr(socket, &cfg.stun_servers)
        .instrument(tracing::info_span!("stun"))
        .await?;
    info!(%public_addr, "discovered public address");
    ui.emit(TuiEvent::OwnAddr(public_addr.to_string()));
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Done));

    // (3) Announce our address, wait for the peer's.
    if let Err(e) = tg.send_own_addr(public_addr).await {
        let msg = format!(
            "Telegram signaling failed ({e:#}) — falling back to the manual address prompt."
        );
        eprintln!("{msg}");
        ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
        ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
        // STUN already ran; only the address is needed from the manual path.
        let peer_addr = manual_peer_addr(cfg, Some(public_addr), ui).await?;
        return Ok((public_addr, peer_addr));
    }

    match tg.wait_peer_addr(tg_cfg, || ui.aborted()).await {
        Ok(addr) => Ok((public_addr, addr)),
        Err(telegram::TelegramError::Aborted) => Err(anyhow::anyhow!("aborted by the user")),
        Err(e) => {
            let msg = format!(
                "Timed out / failed waiting for the peer bot's address ({e}) — switching to the manual address prompt."
            );
            eprintln!("{msg}");
            ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
            ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
            let peer_addr = manual_peer_addr(cfg, Some(public_addr), ui).await?;
            Ok((public_addr, peer_addr))
        }
    }
}

/// The manual path: STUN first (the human on the other end is the liveness
/// signal — no bot handshake needed), then the address prompt.
async fn resolve_addrs_manual(
    cfg: &config::Config,
    socket: &tokio::net::UdpSocket,
    ui: &TuiHandle,
) -> anyhow::Result<(SocketAddr, SocketAddr)> {
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Active));
    let public_addr = stun::discover_public_addr(socket, &cfg.stun_servers)
        .instrument(tracing::info_span!("stun"))
        .await?;
    info!(%public_addr, "discovered public address");
    ui.emit(TuiEvent::OwnAddr(public_addr.to_string()));
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Done));

    // Display own public address and ask for the peer's. In TUI mode the
    // address is shown in the connection panel, so the plain-text prompt is
    // only printed in the non-TUI path.
    let tui_active = !ui.is_disabled();
    if !tui_active {
        println!();
        println!("Your public address is: {public_addr}");
        println!("Give it to the other party, then enter their public address below.");
    }
    ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Active));
    let peer_addr = manual_peer_addr(cfg, Some(public_addr), ui).await?;
    Ok((public_addr, peer_addr))
}

/// Resolve the peer's public address, following the *current* exchange mode.
///
/// The mode is shared with the TUI: the `t` key toggles it at any time (when
/// Telegram is available), so this function loops — waiting on Telegram in
/// Telegram mode, showing the manual prompt in manual mode — until one of
/// them yields an address. A Telegram failure or a toggle falls through to
/// the manual prompt so a bot misconfiguration never blocks a working
/// tunnel. Aborts (q/Esc/Ctrl-C) stop the run.
///
/// `own_addr` is `Some` when STUN already ran (the common case — the caller
/// announces it over Telegram, or just shows it at the prompt) and `None` on
/// the Telegram-first path where the `PTUN READY` handshake must complete
/// before STUN; that variant is only entered from [`resolve_addrs_telegram`]
/// *after* the handshake, so it always has the address by the time an
/// announcement is needed.
async fn manual_peer_addr(
    cfg: &config::Config,
    own_addr: Option<SocketAddr>,
    ui: &TuiHandle,
) -> anyhow::Result<SocketAddr> {
    let mut tg: Option<telegram::Telegram> = None;
    let mut read = || read_line(ui, "Enter peer's public address (ip:port): ");

    loop {
        if ui.aborted() {
            return Err(anyhow::anyhow!("aborted by the user"));
        }
        let mode = ui.exchange_mode();

        if mode == tui_state::ExchangeMode::Telegram {
            // Lazily initialize the signaling client (getMe) on first entry.
            if tg.is_none() {
                let Some(tg_cfg) = &cfg.telegram else {
                    // No `[telegram]` table: degrade to the manual prompt.
                    ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
                    continue;
                };
                match telegram::Telegram::init(tg_cfg).await {
                    Ok(t) => {
                        ui.emit(TuiEvent::Log(
                            tui::LogLevel::Info,
                            "waiting for the peer bot's address over Telegram…".into(),
                        ));
                        tg = Some(t);
                    }
                    Err(e) => {
                        let msg = format!(
                            "Telegram signaling unavailable ({e:#}) — falling back to the manual address prompt."
                        );
                        eprintln!("{msg}");
                        ui.emit(TuiEvent::TelegramChannel(false));
                        ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                        ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
                        continue;
                    }
                }
            }
            let Some(tg) = tg.as_mut() else { continue };
            let Some(tg_cfg) = &cfg.telegram else {
                continue;
            };

            // We are only here after the READY handshake (or in a manual→
            // Telegram toggle where the peer is trivially up), so an address
            // must be available to announce.
            let Some(own_addr) = own_addr else {
                // Should not happen: the handshake variant is not reachable
                // from here. Degrade to the prompt rather than panic.
                ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
                continue;
            };

            if let Err(e) = tg.send_own_addr(own_addr).await {
                let msg = format!(
                    "Telegram signaling failed ({e:#}) — falling back to the manual address prompt."
                );
                eprintln!("{msg}");
                ui.emit(TuiEvent::TelegramChannel(false));
                ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
                continue;
            }

            match tg.wait_peer_addr(tg_cfg, || ui.aborted()).await {
                Ok(addr) => return Ok(addr),
                Err(telegram::TelegramError::Aborted) => {
                    return Err(anyhow::anyhow!("aborted by the user"));
                }
                Err(e) => {
                    let msg = format!(
                        "Timed out / failed waiting for the peer bot's address ({e}) — switching to the manual address prompt (press t to try Telegram again)."
                    );
                    eprintln!("{msg}");
                    ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                    ui.set_exchange_mode(tui_state::ExchangeMode::Manual);
                    continue;
                }
            }
        }

        // Manual mode.
        match cli::prompt_peer_addr(&mut read) {
            Ok(addr) => return Ok(addr),
            Err(cli::PromptBail::ModeToggled) => {
                // The user pressed `t` mid-prompt: loop back and wait on
                // Telegram (the render loop already flipped the shared flag).
                continue;
            }
            Err(cli::PromptBail::Aborted) => {
                return Err(anyhow::anyhow!("aborted by the user"));
            }
            Err(cli::PromptBail::Eof) => {
                return Err(anyhow::anyhow!(
                    "stdin closed before a peer address was entered"
                ));
            }
        }
    }
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
    } else if chain.contains("is required for the") {
        Some(
            "hint: add the missing option to your config.toml (see the sample config comments)."
                .into(),
        )
    } else {
        None
    }
}
