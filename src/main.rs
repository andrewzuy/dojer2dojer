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
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = cli::Cli::parse();
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
    let public_addr = stun::discover_public_addr(&socket, &cfg.stun_servers).await?;
    info!(%public_addr, "discovered public address");

    // Display own public address and ask for the peer's.
    println!();
    println!("Your public address is: {public_addr}");
    println!("Give it to the other party, then enter their public address below.");
    let peer_addr = cli::prompt_peer_addr()?;
    info!(%peer_addr, "peer address entered");

    punch::punch(&socket, peer_addr, &cfg).await?;

    let role = role::determine_role(public_addr, peer_addr);
    info!(role = role.as_str(), "role determined");

    // ── Phase 6: fresh self-signed certificate for the QUIC handshake ──
    let (cert_chain, key) = quic::generate_self_signed_cert()?;

    // ── Phase 7: QUIC endpoint on the punched socket ──
    // The socket has done its STUN + punch job; hand it to quinn, which
    // takes ownership and runs its own I/O driver on it.
    let std_socket = socket.into_std()?;
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
            let conn = quic::accept(&endpoint).await?;
            tunnel::run_server_side(conn, target).await?;
        }
        role::Role::Client => {
            let port = cfg
                .local_tcp_listen_port
                .context(
                    "config: `local_tcp_listen_port` is required for the client role \n                     (the local TCP port to expose through the tunnel)",
                )?;
            info!("initiating QUIC connection to peer…");
            let conn = quic::connect(&endpoint, peer_addr).await?;
            tunnel::run_client_side(conn, port).await?;
        }
    }
    info!("tunnel closed; goodbye");
    Ok(())
}
