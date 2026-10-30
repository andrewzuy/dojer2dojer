//! UDP hole punching.
//!
//! We send a small UDP packet (with a random session nonce) to the peer's
//! public address every `punch_interval_ms`, while concurrently waiting on the
//! same socket for a packet FROM the peer. The first packet from the peer
//! means our NAT binding is (or will be) open: "hole punched".
//!
//! Both sides run the exact same code simultaneously; when both NATs have seen
//! outbound traffic to each other, the inbound packets flow through.

use anyhow::Context;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::config::Config;

/// Punch a hole toward `peer_addr`, resolving when a packet from the peer
/// arrives (or erroring on timeout).
///
/// Uses the same `socket` we'll later run QUIC on — the outbound punch
/// packets establish the NAT binding that lets QUIC's Initial packets in.
pub async fn punch(socket: &UdpSocket, peer_addr: SocketAddr, cfg: &Config) -> anyhow::Result<()> {
    let nonce: [u8; 8] = rand::random();
    let interval = Duration::from_millis(cfg.punch_interval_ms.max(10));
    let timeout = Duration::from_secs(cfg.punch_timeout_secs);

    info!(
        %peer_addr,
        interval_ms = interval.as_millis(),
        timeout_secs = timeout.as_secs(),
        nonce_hex = %hex(&nonce),
        "starting hole punching"
    );

    let start = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buf = [0u8; 1024];
    let mut sent = 0u64;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                // First tick completes immediately → first punch goes out at once.
                socket
                    .send_to(&nonce, peer_addr)
                    .await
                    .context("sending punch packet")?;
                sent += 1;
                debug!(peer = %peer_addr, sent, "sent punch packet");
            }
            res = socket.recv_from(&mut buf) => {
                // On Windows, ICMP "port/host unreachable" replies to our
                // outbound punch packets surface as *recv errors* (Linux
                // drops them silently). Expected while the peer's NAT is
                // still closed — log and keep punching until timeout.
                let (n, from) = match res {
                    Ok(ok) => ok,
                    Err(e) => {
                        debug!(error = %e, "recv error during punch (likely ICMP unreachable); continuing");
                        continue;
                    }
                };
                if from == peer_addr {
                    info!(
                        from = %from,
                        bytes = n,
                        sent,
                        elapsed_ms = start.elapsed().as_millis(),
                        "hole punched: packet received from peer"
                    );
                    return Ok(());
                }
                debug!(from = %from, "ignoring packet from non-peer address while punching");
            }
            _ = tokio::time::sleep_until(start + timeout) => {
                anyhow::bail!(
                    "hole punching timed out after {}s: no packet from {peer_addr} \
                     (sent {sent} punch packets)",
                    timeout.as_secs()
                );
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(interval_ms: u64, timeout_secs: u64) -> Config {
        Config {
            stun_servers: vec!["stun.l.google.com:19302".into()],
            punch_interval_ms: interval_ms,
            punch_timeout_secs: timeout_secs,
            keep_alive_interval_secs: 5,
            local_tcp_listen_port: None,
            remote_target_addr: None,
        }
    }

    #[tokio::test]
    async fn punch_succeeds_when_peer_sends() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr: SocketAddr = peer.local_addr().unwrap();
        let my_addr = socket.local_addr().unwrap();

        // Fake peer: waits a bit (so our punch packets are "in flight"), then
        // sends us a packet — as a real peer would once its NAT lets us in.
        let peer_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            peer.send_to(b"hello from peer", my_addr).await.unwrap();
        });

        punch(&socket, peer_addr, &test_cfg(50, 5))
            .await
            .expect("punch should succeed once peer replies");
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn punch_ignores_other_senders() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr: SocketAddr = peer.local_addr().unwrap();
        let my_addr = socket.local_addr().unwrap();

        let stranger_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            stranger.send_to(b"not you", my_addr).await.unwrap();
        });
        let peer_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            peer.send_to(b"the real one", my_addr).await.unwrap();
        });

        // Should ignore the stranger's packet and succeed on the peer's.
        punch(&socket, peer_addr, &test_cfg(50, 5))
            .await
            .expect("punch should succeed on the real peer's packet");
        stranger_task.await.unwrap();
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn punch_times_out_without_peer() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 127.0.0.1:9 (discard) never answers.
        let peer_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let res = punch(&socket, peer_addr, &test_cfg(50, 1)).await;
        let err = res.expect_err("punch should time out");
        assert!(err.to_string().contains("timed out"), "got: {err}");
    }
}
