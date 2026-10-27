//! TCP↔QUIC stream bridge.
//!
//! Client side (Phase 8): a local TCP listener whose accepted connections
//! are each bridged to a fresh bidirectional QUIC stream, so
//! `ssh -p <port> user@127.0.0.1` reaches the other machine's target
//! through the tunnel.
//! Server side (Phase 9): incoming QUIC streams → TCP connections to the
//! configured private target.

use std::net::SocketAddr;

use anyhow::Context;
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Client side of the tunnel: expose a local TCP port through the QUIC
/// connection.
///
/// Binds `127.0.0.1:<listen_port>` (loopback only — the tunnel port is not
/// exposed to the LAN) and gives every accepted TCP connection its own
/// bidirectional QUIC stream, so concurrent connections (e.g. several `ssh`
/// sessions) are independent. Runs until the QUIC connection closes, then
/// returns.
pub async fn run_client_side(conn: Connection, listen_port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], listen_port)))
        .await
        .with_context(|| {
            format!(
                "bind local TCP listener on 127.0.0.1:{listen_port} (is the port already in use?)"
            )
        })?;
    tracing::info!(
        port = listen_port,
        "tunnel client listening — connect to 127.0.0.1:{listen_port} (e.g. ssh -p {listen_port} user@127.0.0.1)"
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = accepted.context("accept local TCP connection")?;
                tracing::info!(%peer, "new local connection; opening QUIC stream");
                let conn = conn.clone();
                tokio::spawn(async move {
                    match bridge_stream(conn, tcp).await {
                        Ok((up, down)) => {
                            tracing::info!(
                                %peer, bytes_up = up, bytes_down = down,
                                "tunneled connection closed"
                            );
                        }
                        Err(e) => tracing::warn!(%peer, error = ?e, "tunneled connection failed"),
                    }
                });
            }
            err = conn.closed() => {
                tracing::info!(?err, "QUIC connection closed; stopping local TCP listener");
                break;
            }
        }
    }
    Ok(())
}

/// Bridge one local TCP connection to one fresh bidirectional QUIC stream
/// (client side: we open the stream).
///
/// Resolves with `(bytes_tcp_to_quic, bytes_quic_to_tcp)` once both
/// directions are finished, or with an error if either direction fails.
async fn bridge_stream(conn: Connection, tcp: TcpStream) -> anyhow::Result<(u64, u64)> {
    let (send, recv) = conn
        .open_bi()
        .await
        .context("open bidirectional QUIC stream")?;
    bridge_quic_tcp(send, recv, tcp).await
}

/// Server side of the tunnel: forward every incoming QUIC stream to a TCP
/// connection to `target_addr` (e.g. the private `ip:port` of an SSH server
/// the client wants to reach).
///
/// Each stream gets its own task, so multiple concurrent tunnels (several
/// `ssh` sessions, say) run independently. Runs until the QUIC connection
/// closes, then returns.
pub async fn run_server_side(conn: Connection, target_addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!(
        %target_addr,
        "tunnel server ready — forwarding incoming QUIC streams to {target_addr}"
    );
    loop {
        tokio::select! {
            res = conn.accept_bi() => {
                match res {
                    Ok((mut send, recv)) => {
                        tokio::spawn(async move {
                            let tcp = match TcpStream::connect(target_addr).await {
                                Ok(tcp) => tcp,
                                Err(e) => {
                                    tracing::warn!(
                                        %target_addr, error = ?e,
                                        "cannot reach target; closing stream"
                                    );
                                    // FIN so the client sees EOF instead of a hang.
                                    let _ = send.finish();
                                    return;
                                }
                            };
                            tracing::info!(%target_addr, "target connection established");
                            match bridge_quic_tcp(send, recv, tcp).await {
                                Ok((up, down)) => tracing::info!(
                                    %target_addr, bytes_up = up, bytes_down = down,
                                    "tunneled connection closed"
                                ),
                                Err(e) => tracing::warn!(
                                    %target_addr, error = ?e,
                                    "tunneled connection failed"
                                ),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::info!(?e, "QUIC stream acceptance ended; stopping tunnel server");
                        break;
                    }
                }
            }
            err = conn.closed() => {
                tracing::info!(?err, "QUIC connection closed; stopping tunnel server");
                break;
            }
        }
    }
    Ok(())
}

/// Bridge an already-received bidirectional QUIC stream to a TCP connection
/// (server side: the stream arrived, we did not open it).
async fn bridge_quic_tcp(
    send: SendStream,
    recv: RecvStream,
    tcp: TcpStream,
) -> anyhow::Result<(u64, u64)> {
    let (tcp_read, tcp_write) = tcp.into_split();
    // Direction A (up): local TCP → QUIC. Direction B (down): QUIC → local TCP.
    bridge_halves(tcp_read, send, recv, tcp_write).await
}

/// Copy bytes in both directions between two stream pairs, propagating
/// half-closes.
///
/// Direction A: `read_a` → `write_a`. Direction B: `read_b` → `write_b`.
/// Each direction runs in its own task: `tokio::io::copy` until EOF, then
/// `shutdown()` of the write side so the peer sees EOF. The future resolves
/// only when BOTH directions are done.
///
/// Half-close semantics: EOF on one side does not kill the other direction.
/// E.g. when the local app closes its write side (EOF on A), the QUIC send
/// stream is finished (remote target sees EOF) while QUIC→TCP keeps flowing
/// until the remote closes its side.
///
/// If a direction *errors* (not just EOF), the other one keeps running until
/// it completes too; in practice both copies share the same QUIC connection,
/// so a dead connection fails both directions within the QUIC idle timeout.
///
/// Generic on purpose: this is exactly the copy pattern used for
/// `ReadHalf<TcpStream>` → `quinn::SendStream` and `quinn::RecvStream` →
/// `WriteHalf<TcpStream>`, but it is unit-testable with in-memory duplex
/// streams (per project decision, no loopback QUIC server+client tests).
async fn bridge_halves<R1, W1, R2, W2>(
    mut read_a: R1,
    mut write_a: W1,
    mut read_b: R2,
    mut write_b: W2,
) -> anyhow::Result<(u64, u64)>
where
    R1: AsyncRead + Unpin + Send + 'static,
    W1: AsyncWrite + Unpin + Send + 'static,
    R2: AsyncRead + Unpin + Send + 'static,
    W2: AsyncWrite + Unpin + Send + 'static,
{
    let dir_a = tokio::spawn(async move {
        let bytes = tokio::io::copy(&mut read_a, &mut write_a).await?;
        write_a.shutdown().await?;
        Ok::<u64, std::io::Error>(bytes)
    });
    let dir_b = tokio::spawn(async move {
        let bytes = tokio::io::copy(&mut read_b, &mut write_b).await?;
        write_b.shutdown().await?;
        Ok::<u64, std::io::Error>(bytes)
    });

    let (dir_a, dir_b) = tokio::join!(dir_a, dir_b);
    let bytes_a = dir_a.context("direction A task panicked")?;
    let bytes_b = dir_b.context("direction B task panicked")?;
    let bytes_a = bytes_a.context("copy read_a → write_a")?;
    let bytes_b = bytes_b.context("copy read_b → write_b")?;
    Ok((bytes_a, bytes_b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

    /// One end of an in-memory pipe plus the split bridge-side halves.
    /// Stands in for either the local TCP connection or the QUIC stream.
    fn pipe() -> (
        DuplexStream,
        (
            ReadHalf<DuplexStream>,
            WriteHalf<DuplexStream>,
        ),
    ) {
        let (end, other) = tokio::io::duplex(65_536);
        (end, tokio::io::split(other))
    }

    /// Bytes flow in both directions simultaneously; closing both write
    /// sides ends the bridge with exact byte counts.
    #[tokio::test]
    async fn bridge_halves_moves_bytes_both_ways() {
        let (end_a, (a_read, a_write)) = pipe();
        let (end_b, (b_read, b_write)) = pipe();

        // Direction A: a → b. Direction B: b → a.
        let bridge = tokio::spawn(bridge_halves(a_read, b_write, b_read, a_write));

        let mut end_a = end_a;
        let mut end_b = end_b;
        end_a.write_all(b"hello ").await.unwrap(); // 6 bytes, A → B
        end_b.write_all(b"world").await.unwrap(); // 5 bytes, B → A

        // Deterministic: wait for both messages to actually arrive.
        let mut got_on_b = vec![0u8; 6];
        end_b.read_exact(&mut got_on_b).await.unwrap();
        assert_eq!(&got_on_b, b"hello ");
        let mut got_on_a = vec![0u8; 5];
        end_a.read_exact(&mut got_on_a).await.unwrap();
        assert_eq!(&got_on_a, b"world");

        // Close both write sides → both copies see EOF → bridge resolves.
        end_a.shutdown().await.unwrap();
        end_b.shutdown().await.unwrap();

        let (up, down) = bridge.await.unwrap().unwrap();
        assert_eq!((up, down), (6, 5));
    }

    /// When B closes its write side, the bridge shuts down A's write side
    /// (A's reader sees EOF) while A → B keeps flowing until A closes too.
    #[tokio::test]
    async fn bridge_halves_propagates_half_close() {
        let (end_a, (a_read, a_write)) = pipe();
        let (end_b, (b_read, b_write)) = pipe();

        let bridge = tokio::spawn(bridge_halves(a_read, b_write, b_read, a_write));

        let mut end_a = end_a;
        let mut end_b = end_b;

        // B sends, then half-closes its write side.
        end_b.write_all(b"bye").await.unwrap();
        end_b.shutdown().await.unwrap();

        // A must see "bye" followed by EOF (bridge shut A's write side).
        let mut got = Vec::new();
        end_a.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bye");

        // A → B direction is still open and still flows.
        end_a.write_all(b"still here").await.unwrap();
        let mut tail = vec![0u8; 10];
        end_b.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"still here");

        // A half-closes → both directions done → bridge resolves.
        end_a.shutdown().await.unwrap();
        let (up, down) = bridge.await.unwrap().unwrap();
        assert_eq!((up, down), (10, 3));
    }
}
