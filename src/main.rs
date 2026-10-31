use p2p_tunnel_lib::{cli, config, punch, quic, role, stun, telegram, tunnel};

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tracing::{Instrument, info};

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    // Logging: RUST_LOG wins if set, then --verbose, then info.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| (if cli.verbose { "debug" } else { "info" }).into()),
        )
        .init();

    if let Err(e) = run(cli).await {
        eprintln!();
        eprintln!("error: {e:#}");
        if let Some(hint) = hint_for(&e) {
            eprintln!("{hint}");
        }
        std::process::exit(1);
    }
}

async fn run(cli: cli::Cli) -> anyhow::Result<()> {
    let cfg = config::Config::load(&cli.config)?;

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
    let public_addr = stun::discover_public_addr(&socket, &cfg.stun_servers)
        .instrument(tracing::info_span!("stun"))
        .await?;
    info!(%public_addr, "discovered public address");

    // Display own public address and ask for the peer's.
    println!();
    println!("Your public address is: {public_addr}");
    println!("Give it to the other party, then enter their public address below.");
    // Address exchange: Telegram bot-to-bot (if --telegram) or the manual
    // prompt. Telegram is a *second channel*, not a replacement — on any
    // failure (bad token, bot-to-bot disabled, timeout) we fall back to the
    // prompt so the tunnel can still be established manually.
    let peer_addr = negotiate_peer_addr(&cli, &cfg, public_addr).await?;
    info!(%peer_addr, "peer address resolved");

    punch::punch(&socket, peer_addr, &cfg)
        .instrument(tracing::info_span!("punch"))
        .await?;

    let role = role::determine_role(public_addr, peer_addr);
    info!(role = role.as_str(), "role determined");

    // QUIC keep-alive: a PING every `keep_alive` keeps the tunnel alive while
    // idle — NAT port mappings expire on silent connections and would drop a
    // healthy tunnel. `0` in the config disables it.
    let keep_alive = (cfg.keep_alive_interval_secs > 0)
        .then(|| Duration::from_secs(cfg.keep_alive_interval_secs));
    info!(?keep_alive, "QUIC keep-alive configured");

    // ── Phase 6: fresh self-signed certificate for the QUIC handshake ──
    let (cert_chain, key) = quic::generate_self_signed_cert()?;

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
            info!("waiting for the peer's QUIC connection…");
            let conn = quic::accept(&endpoint)
                .instrument(tracing::info_span!("quic_handshake"))
                .await?;
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
            info!("initiating QUIC connection to peer…");
            let conn = quic::connect(&endpoint, peer_addr)
                .instrument(tracing::info_span!("quic_handshake"))
                .await?;
            tunnel::run_client_side(conn, port)
                .instrument(tracing::info_span!("tunnel", role = "client"))
                .await?;
        }
    }
    info!("tunnel closed; goodbye");
    Ok(())
}

/// Resolve the peer's public address.
///
/// With `--telegram` and a configured `[telegram]` table, exchange addresses
/// over the bot-to-bot DM channel; on any failure fall back to the manual
/// prompt so a bot misconfiguration never blocks a working tunnel.
async fn negotiate_peer_addr(
    cli: &cli::Cli,
    cfg: &config::Config,
    own_addr: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    if !cli.telegram {
        return cli::prompt_peer_addr();
    }
    let tg_cfg = match &cfg.telegram {
        Some(c) => c,
        None => {
            eprintln!(
                "--telegram was given but no `[telegram]` table exists in {} — \
                 falling back to the manual address prompt.",
                cli.config.display()
            );
            return cli::prompt_peer_addr();
        }
    };
    let tg = match telegram::Telegram::new(tg_cfg) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "Telegram signaling unavailable ({e:#}) — falling back to the manual address prompt."
            );
            return cli::prompt_peer_addr();
        }
    };

    if let Err(e) = tg.send_own_addr(own_addr).await {
        eprintln!("Could not send our address to the peer bot: {e:#}");
        eprintln!("Falling back to the manual address prompt.");
        return cli::prompt_peer_addr();
    }

    match tg.await_peer_addr(tg_cfg).await {
        Ok(addr) => Ok(addr),
        Err(telegram::TelegramError::Timeout { .. }) => {
            eprintln!(
                "Timed out waiting for the peer bot's address — falling back to the manual address prompt."
            );
            cli::prompt_peer_addr()
        }
        Err(e) => {
            eprintln!("Telegram signaling failed: {e:#}");
            eprintln!("Falling back to the manual address prompt.");
            cli::prompt_peer_addr()
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
