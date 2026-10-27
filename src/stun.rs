//! Manual STUN client (RFC 5389).
//!
//! We implement just enough STUN to send a Binding Request and read back the
//! XOR-MAPPED-ADDRESS. No libraries: raw UDP bytes, because we need full
//! control of the socket (it is reused for hole punching and QUIC later).

use anyhow::Context;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

const DEFAULT_STUN_PORT: u16 = 19302;

pub const STUN_MAGIC_COOKIE: u32 = 0x21_12_A4_42;

const MSG_BINDING_REQUEST: u16 = 0x0001;
const MSG_BINDING_RESPONSE: u16 = 0x0101;
const MSG_BINDING_ERROR: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ROUNDS: usize = 2;
const MAX_RESP_LEN: usize = 512;

/// Errors from the STUN discovery process.
#[derive(Debug, Error)]
pub enum StunError {
    #[error("STUN server {server} rejected request: {reason}")]
    Rejected { server: String, reason: String },
    #[error("malformed STUN response from {server}: {reason}")]
    Malformed { server: String, reason: String },
    #[error("I/O error talking to STUN server {server}: {source}")]
    Io {
        server: String,
        #[source]
        source: std::io::Error,
    },
}

/// Encode a minimal STUN Binding Request (20 bytes, no attributes).
pub fn encode_binding_request(transaction_id: &[u8; 12]) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[0..2].copy_from_slice(&MSG_BINDING_REQUEST.to_be_bytes());
    msg[2..4].copy_from_slice(&0u16.to_be_bytes()); // message length: no attributes
    msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(transaction_id);
    msg
}

/// Parse a STUN Binding Response and return the mapped (public) address.
///
/// Validates message type, magic cookie, transaction ID, then extracts
/// XOR-MAPPED-ADDRESS (falling back to plain MAPPED-ADDRESS).
pub fn parse_binding_response(
    data: &[u8],
    expected_txn: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    let unknown = "<unknown>";
    if data.len() < 20 {
        return Err(StunError::Malformed {
            server: unknown.into(),
            reason: format!("short packet ({} bytes)", data.len()),
        });
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type == MSG_BINDING_ERROR {
        return Err(StunError::Rejected {
            server: unknown.into(),
            reason: "STUN Binding Error Response received".into(),
        });
    }
    if msg_type != MSG_BINDING_RESPONSE {
        return Err(StunError::Malformed {
            server: unknown.into(),
            reason: format!("unexpected message type 0x{msg_type:04x}"),
        });
    }
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err(StunError::Malformed {
            server: unknown.into(),
            reason: format!(
                "truncated: header says {msg_len} attr bytes, got {}",
                data.len() - 20
            ),
        });
    }
    if u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != STUN_MAGIC_COOKIE {
        return Err(StunError::Malformed {
            server: unknown.into(),
            reason: "bad magic cookie (not a STUN Binding Response?)".into(),
        });
    }
    if &data[8..20] != expected_txn {
        return Err(StunError::Malformed {
            server: unknown.into(),
            reason: "transaction ID mismatch".into(),
        });
    }

    // Walk attributes: type(2) + length(2) + value(length), padded to 4 bytes.
    let attrs = &data[20..20 + msg_len];
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > attrs.len() {
            break;
        }
        let value = &attrs[offset..offset + attr_len];
        offset += attr_len + attr_len % 4; // value + padding
        if attr_len < 8 {
            continue;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return xor_mapped_address(value, expected_txn).ok_or_else(|| StunError::Malformed {
                server: unknown.into(),
                reason: "bad XOR-MAPPED-ADDRESS value".into(),
            });
        }
        if attr_type == ATTR_MAPPED_ADDRESS {
            return mapped_address(value).ok_or_else(|| StunError::Malformed {
                server: unknown.into(),
                reason: "bad MAPPED-ADDRESS value".into(),
            });
        }
    }
    Err(StunError::Malformed {
        server: unknown.into(),
        reason: "no mapped-address attribute found".into(),
    })
}

fn mapped_address(value: &[u8]) -> Option<SocketAddr> {
    // reserved(1) family(1) port(2) address(4|16)
    match value[1] {
        0x01 => Some(SocketAddr::new(
            std::net::Ipv4Addr::from(u32::from_be_bytes(value[4..8].try_into().ok()?)).into(),
            u16::from_be_bytes([value[2], value[3]]),
        )),
        0x02 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Some(SocketAddr::new(
                std::net::Ipv6Addr::from(octets).into(),
                u16::from_be_bytes([value[2], value[3]]),
            ))
        }
        _ => None,
    }
}

fn xor_mapped_address(value: &[u8], txn: &[u8; 12]) -> Option<SocketAddr> {
    // reserved(1) family(1) xor-port(2) xor-address(4|16)
    // Port is XORed with the high 16 bits of the magic cookie; the address is
    // XORed with the 32-bit cookie (v4) or the 16-byte key cookie||txn (v6).
    match value[1] {
        0x01 => Some(SocketAddr::new(
            std::net::Ipv4Addr::from(
                u32::from_be_bytes(value[4..8].try_into().ok()?) ^ STUN_MAGIC_COOKIE,
            )
            .into(),
            u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16,
        )),
        0x02 => {
            let key: [u8; 16] = {
                let mut k = [0u8; 16];
                k[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                k[4..16].copy_from_slice(txn);
                k
            };
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            for i in 0..16 {
                octets[i] ^= key[i];
            }
            Some(SocketAddr::new(
                std::net::Ipv6Addr::from(octets).into(),
                u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16,
            ))
        }
        _ => None,
    }
}

/// Discover this host's public IP:port.
///
/// Sends a Binding Request from `socket` to each server in `servers` (in order,
/// up to `MAX_ROUNDS` rounds) until one answers. The caller keeps ownership of
/// `socket` — it is the same socket used later for punching and QUIC.
pub async fn discover_public_addr(
    socket: &UdpSocket,
    servers: &[String],
) -> anyhow::Result<SocketAddr> {
    let txn: [u8; 12] = rand::random();
    let req = encode_binding_request(&txn);
    let mut last_err: Option<String> = None;

    for round in 0..MAX_ROUNDS {
        for server in servers {
            let addrs = match resolve_server(server).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    warn!(server, error = %e, "cannot resolve STUN server");
                    last_err = Some(e.to_string());
                    continue;
                }
            };
            for server_addr in addrs {
                debug!(%server_addr, round, "sending STUN binding request");
                match tokio::time::timeout(
                    PER_ATTEMPT_TIMEOUT,
                    send_and_wait(socket, server_addr, &req, &txn),
                )
                .await
                {
                    Ok(Ok(public_addr)) => {
                        debug!(%server_addr, "STUN response received");
                        return Ok(public_addr);
                    }
                    Ok(Err(e)) => {
                        warn!(%server_addr, error = %e, "STUN server failed");
                        last_err = Some(e.to_string());
                    }
                    Err(_) => {
                        warn!(%server_addr, timeout_secs = PER_ATTEMPT_TIMEOUT.as_secs(), "STUN server timed out");
                        last_err = Some(format!(
                            "{server_addr}: timed out after {}s",
                            PER_ATTEMPT_TIMEOUT.as_secs()
                        ));
                    }
                }
            }
        }
    }

    let last = last_err.unwrap_or_else(|| "no STUN servers configured".into());
    Err(anyhow::anyhow!(
        "STUN discovery failed: {last} (tried servers: {servers:?})"
    ))
}

/// Resolve a `"host:port"` (or bare `"host"`, defaulting to port 19302) STUN
/// server to concrete socket addresses. Numeric literals work too.
async fn resolve_server(server: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let (host, port) = match server.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse()
                .with_context(|| format!("bad port in STUN server {server:?}"))?,
        ),
        None => (server, DEFAULT_STUN_PORT),
    };
    if host.is_empty() {
        anyhow::bail!("empty host in STUN server {server:?}");
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving STUN server {host}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("no addresses for STUN server {host}");
    }
    Ok(addrs)
}

async fn send_and_wait(
    socket: &UdpSocket,
    server: SocketAddr,
    req: &[u8; 20],
    txn: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    socket
        .send_to(req, server)
        .await
        .map_err(|source| StunError::Io {
            server: server.to_string(),
            source,
        })?;

    let mut buf = [0u8; MAX_RESP_LEN];
    loop {
        let (n, from) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|source| StunError::Io {
                server: server.to_string(),
                source,
            })?;
        // Ignore anything that isn't a reply from the server we queried
        // (this socket later carries punch/peer traffic too).
        if from != server {
            debug!(%from, "ignoring non-STUN traffic on discovery socket");
            continue;
        }
        return parse_binding_response(&buf[..n], txn).map_err(|e| match e {
            StunError::Malformed { reason, .. } => StunError::Malformed {
                server: server.to_string(),
                reason,
            },
            StunError::Rejected { reason, .. } => StunError::Rejected {
                server: server.to_string(),
                reason,
            },
            other => other,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_response(txn: &[u8; 12], attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut resp = encode_binding_request(txn).to_vec();
        resp[0..2].copy_from_slice(&MSG_BINDING_RESPONSE.to_be_bytes());
        resp[2..4].copy_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        resp.extend_from_slice(&attr_type.to_be_bytes());
        resp.extend_from_slice(&(value.len() as u16).to_be_bytes());
        resp.extend_from_slice(value);
        resp
    }

    fn xor_mapped_value_v4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v[1] = 0x01; // family IPv4
        v[2..4]
            .copy_from_slice(&(((port as u32) ^ (STUN_MAGIC_COOKIE >> 16)) as u16).to_be_bytes());
        v[4..8].copy_from_slice(&(u32::from(ip) ^ STUN_MAGIC_COOKIE).to_be_bytes());
        v
    }

    #[test]
    fn encodes_binding_request() {
        let txn = [7u8; 12];
        let req = encode_binding_request(&txn);
        assert_eq!(&req[0..2], &0x0001u16.to_be_bytes());
        assert_eq!(&req[2..4], &0u16.to_be_bytes());
        assert_eq!(&req[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..20], &txn);
        assert_eq!(req.len(), 20);
    }

    #[test]
    fn parses_xor_mapped_response_v4() {
        let txn = [3u8; 12];
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let resp = make_response(
            &txn,
            ATTR_XOR_MAPPED_ADDRESS,
            &xor_mapped_value_v4(ip, 12345),
        );
        assert_eq!(
            parse_binding_response(&resp, &txn).unwrap(),
            SocketAddr::new(ip.into(), 12345)
        );
    }

    #[test]
    fn parses_plain_mapped_response_v4() {
        let txn = [3u8; 12];
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let mut value = vec![0u8; 8];
        value[1] = 0x01;
        value[2..4].copy_from_slice(&1234u16.to_be_bytes());
        value[4..8].copy_from_slice(&u32::from(ip).to_be_bytes());
        let resp = make_response(&txn, ATTR_MAPPED_ADDRESS, &value);
        assert_eq!(
            parse_binding_response(&resp, &txn).unwrap(),
            SocketAddr::new(ip.into(), 1234)
        );
    }

    #[test]
    fn skips_unknown_attrs_and_finds_mapped_later() {
        let txn = [3u8; 12];
        let ip = Ipv4Addr::new(10, 1, 2, 3);
        // Two attributes: an unknown one, then the mapped address.
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&0x8022u16.to_be_bytes()); // some vendor attr
        attrs.extend_from_slice(&2u16.to_be_bytes());
        attrs.extend_from_slice(&[0xAA, 0xBB]);
        attrs.extend_from_slice(&[0u8; 2]); // RFC 5389: pad attr to 4-byte boundary
        let value = xor_mapped_value_v4(ip, 99);
        attrs.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&value);
        let mut resp = encode_binding_request(&txn).to_vec();
        resp[0..2].copy_from_slice(&MSG_BINDING_RESPONSE.to_be_bytes());
        resp[2..4].copy_from_slice(&(attrs.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attrs);
        assert_eq!(
            parse_binding_response(&resp, &txn).unwrap(),
            SocketAddr::new(ip.into(), 99)
        );
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let txn = [3u8; 12];
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let resp = make_response(&txn, ATTR_XOR_MAPPED_ADDRESS, &xor_mapped_value_v4(ip, 1));
        let err = parse_binding_response(&resp, &[4u8; 12]).unwrap_err();
        assert!(matches!(err, StunError::Malformed { .. }));
    }

    #[test]
    fn rejects_non_stun_packet() {
        let txn = [3u8; 12];
        let err = parse_binding_response(&[0u8; 8], &txn).unwrap_err();
        assert!(matches!(err, StunError::Malformed { .. }));
    }

    #[test]
    fn rejects_error_response() {
        let txn = [3u8; 12];
        let mut resp = encode_binding_request(&txn).to_vec();
        resp[0..2].copy_from_slice(&MSG_BINDING_ERROR.to_be_bytes());
        let err = parse_binding_response(&resp, &txn).unwrap_err();
        assert!(matches!(err, StunError::Rejected { .. }));
    }
}
