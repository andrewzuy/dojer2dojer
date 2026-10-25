//! Deterministic role negotiation.
//!
//! Both peers independently run the same pure function over their public
//! addresses; it always yields the same (opposite) result on each side, so
//! exactly one side becomes the QUIC server and the other the client — no
//! handshake needed.

use std::net::{IpAddr, SocketAddr};

/// Which side of the QUIC connection we play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We host the QUIC endpoint; the peer connects to us.
    Server,
    /// We initiate the QUIC connection to the peer.
    Client,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Server => "server",
            Role::Client => "client",
        }
    }
}

/// Total order over IPs that works across address families:
/// all IPv4 addresses sort before all IPv6, numerically within a family.
fn ip_key(ip: IpAddr) -> (u8, [u8; 16]) {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[12..16].copy_from_slice(&v4.octets());
            (4, b)
        }
        IpAddr::V6(v6) => (6, v6.octets()),
    }
}

/// Decide our role from our public address and the peer's public address.
///
/// Lower address → server (hosts the QUIC endpoint); higher → client.
/// If the IPs are equal (local testing on one machine), fall back to the port.
pub fn determine_role(own: SocketAddr, peer: SocketAddr) -> Role {
    let own_key = ip_key(own.ip());
    let peer_key = ip_key(peer.ip());
    if own_key == peer_key {
        // Same IP — only possible in local tests; use the port. A perfect tie
        // (same ip:port) cannot happen between two real peers.
        return if own.port() <= peer.port() { Role::Server } else { Role::Client };
    }
    if own_key < peer_key {
        Role::Server
    } else {
        Role::Client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_lower_is_server() {
        let low = "1.2.3.4:1000".parse::<SocketAddr>().unwrap();
        let high = "5.6.7.8:2000".parse::<SocketAddr>().unwrap();
        assert_eq!(determine_role(low, high), Role::Server);
        assert_eq!(determine_role(high, low), Role::Client);
    }

    #[test]
    fn roles_are_always_opposite() {
        let addrs: Vec<SocketAddr> = [
            "10.0.0.1:1",
            "10.0.0.2:2",
            "172.16.5.9:10000",
            "8.8.8.8:53",
            "[2001:db8::1]:443",
            "[2001:db8::2]:443",
            "192.168.1.5:22",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        for a in &addrs {
            for b in &addrs {
                if a == b {
                    continue;
                }
                let ra = determine_role(*a, *b);
                let rb = determine_role(*b, *a);
                assert!(
                    (ra == Role::Server && rb == Role::Client)
                        || (ra == Role::Client && rb == Role::Server),
                    "asymmetric roles for {a} vs {b}"
                );
            }
        }
    }

    #[test]
    fn v4_always_beats_v6() {
        let v4 = "1.2.3.4:1".parse::<SocketAddr>().unwrap();
        let v6 = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:1".parse::<SocketAddr>().unwrap();
        assert_eq!(determine_role(v4, v6), Role::Server);
        assert_eq!(determine_role(v6, v4), Role::Client);
    }

    #[test]
    fn v6_orders_numerically() {
        let low = "[2001:db8::1]:1".parse::<SocketAddr>().unwrap();
        let high = "[2001:db8::2]:1".parse::<SocketAddr>().unwrap();
        assert_eq!(determine_role(low, high), Role::Server);
        assert_eq!(determine_role(high, low), Role::Client);
    }

    #[test]
    fn same_ip_falls_back_to_port() {
        let a = "127.0.0.1:1000".parse::<SocketAddr>().unwrap();
        let b = "127.0.0.1:2000".parse::<SocketAddr>().unwrap();
        assert_eq!(determine_role(a, b), Role::Server);
        assert_eq!(determine_role(b, a), Role::Client);
    }
}
