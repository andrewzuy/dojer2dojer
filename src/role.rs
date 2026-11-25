//! Deterministic role negotiation.
//!
//! Both peers independently run the same pure function over their public
//! addresses; it always yields the same (opposite) result on each side, so
//! exactly one side becomes the QUIC server and the other the client — no
//! handshake needed.

use std::fmt;
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

    /// The role the peer must run. The two sides must be opposite — a
    /// tunnel needs exactly one server and one client.
    pub fn opposite(self) -> Role {
        match self {
            Role::Server => Role::Client,
            Role::Client => Role::Server,
        }
    }

    /// Parse a role from its wire/setup form: `client`/`server`
    /// (case-insensitive, surrounding whitespace tolerated). Used for
    /// `PTUN ROLE` lines and setup input.
    pub fn parse(s: &str) -> Option<Role> {
        match s.trim().to_ascii_lowercase().as_str() {
            "client" => Some(Role::Client),
            "server" => Some(Role::Server),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Both sides selected the same role — no tunnel can be formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleConflict {
    pub ours: Role,
    pub theirs: Role,
}

impl fmt::Display for RoleConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A conflict can only be constructed when both sides match, so `ours`
        // names the shared (wrong) selection on both ends.
        write!(
            f,
            "role misconfiguration: both sides selected '{}' — the two sides \
             must be one client and one server",
            self.ours
        )
    }
}

/// Cross-check the user-selected roles of the two sides.
///
/// Opposite roles are compatible (a tunnel can be formed); identical roles
/// are a misconfiguration and must be reported to the operator, who
/// re-selects at the setup screen. The legacy IP-order derivation is *not*
/// applied here — an explicit selection always wins.
pub fn check_compatible(ours: Role, theirs: Role) -> Result<(), RoleConflict> {
    if ours == theirs {
        Err(RoleConflict { ours, theirs })
    } else {
        Ok(())
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
        return if own.port() <= peer.port() {
            Role::Server
        } else {
            Role::Client
        };
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

    // ---- conflict detection (v2) --------------------------------------------

    #[test]
    fn conflict_matrix() {
        // Same role on both sides → conflict.
        for r in [Role::Client, Role::Server] {
            let err = check_compatible(r, r).unwrap_err();
            assert_eq!(err, RoleConflict { ours: r, theirs: r });
            assert!(
                err.to_string().contains("role misconfiguration"),
                "message must carry the hint-able prefix, got: {err}"
            );
        }
        // Opposite roles → OK (in either order).
        assert!(check_compatible(Role::Client, Role::Server).is_ok());
        assert!(check_compatible(Role::Server, Role::Client).is_ok());
    }

    #[test]
    fn role_parse_and_display() {
        assert_eq!(Role::parse("client"), Some(Role::Client));
        assert_eq!(Role::parse("SERVER"), Some(Role::Server));
        assert_eq!(Role::parse("  client  "), Some(Role::Client));
        assert_eq!(Role::parse("banana"), None);
        assert_eq!(Role::parse(""), None);
        assert_eq!(Role::Client.to_string(), "client");
        assert_eq!(Role::Server.to_string(), "server");
    }

    #[test]
    fn opposite_is_symmetric() {
        assert_eq!(Role::Client.opposite(), Role::Server);
        assert_eq!(Role::Server.opposite(), Role::Client);
        assert_eq!(Role::Client.opposite().opposite(), Role::Client);
    }

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
        let v6 = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:1"
            .parse::<SocketAddr>()
            .unwrap();
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
