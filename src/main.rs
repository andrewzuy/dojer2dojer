mod cli;
mod config;
mod punch;
mod quic;
mod role;
mod stun;
mod tunnel;

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use tracing::{info, Instrument};

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
    let peer_addr = cli::prompt_peer_addr()?;
    info!(%peer_addr, "peer address entered");

    punch::punch(&socket, peer_addr, &cfg)
        .instrument(tracing::info_span!("punch"))
        .await?;

    let role = role::determine_role(public_addr, peer_addr);
    info!(role = role.as_str(), "role determined");

    // ── Phase 6: fresh self-signed certificate for the QUIC handshake ──
    let (cert_chain, key) = quic::generate_self_signed_cert()?;

    // ── Phase 7: QUIC endpoint on the punched socket ──
    // The socket has done its STUN + punch job; hand it to quinn, which
    // takes ownership and runs its own I/O driver on it.
    let std_socket = socket
        .into_std()
        .context("converting the punched UDP socket for quinn")?;
    let server_config = match role {
        role::Role::Server => Some(quic::build_server_config(cert_chain, key)?),
        role::Role::Client => None,
    };
    let mut endpoint = quic::create_endpoint(std_socket, server_config)?;
    if matches!(role, role::Role::Client) {
        endpoint.set_default_client_config(quic::build_client_config()?);
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
            let target: SocketAddr = target
                .parse()
                .with_context(|| {
                    format!(
                        "config: `remote_target_addr` = {target:?} is not a valid ip:port"
                    )
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
