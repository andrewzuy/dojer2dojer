"""Role model (v2, PLAN §5.2) + the legacy IP-order rule from the Rust oracle.

v2 (D1): the role is *selected* by the user at startup (S1 setup) and
cross-checked against the peer's declared role during the Telegram
handshake (:func:`check_compatible`). The legacy IP-order rule (Rust
``src/role.rs::determine_role``) is kept for the legacy fallback (D4: a
Rust peer sends no ``PTUN ROLE`` line → adopt the IP-derived role) and
its five oracle tests are ported unchanged in ``tests/test_role.py``.
"""

from __future__ import annotations

import enum
import ipaddress


class Role(enum.Enum):
    """Which side of the QUIC connection this process plays."""

    #: We initiate the QUIC connection to the peer.
    CLIENT = "client"
    #: We host the QUIC endpoint; the peer connects to us.
    SERVER = "server"

    @property
    def opposite(self) -> "Role":
        """The role the peer must play."""
        return Role.CLIENT if self is Role.SERVER else Role.SERVER

    def as_str(self) -> str:
        """``"client"`` / ``"server"`` (Rust ``Role::as_str`` parity)."""
        return self.value

    @classmethod
    def from_str(cls, s: str) -> "Role":
        """Parse ``"client"``/``"server"`` (case-insensitive).

        Raises :class:`ValueError` for anything else.
        """
        try:
            return cls(s.strip().lower())
        except ValueError:
            raise ValueError(f"unknown role '{s}' (expected 'client' or 'server')") from None


class RoleConflict(Exception):
    """Both sides declared the same role (the T1 cross-check failed).

    The message contains the ``"role misconfiguration"`` substring the
    hint matcher keys on (PLAN §4); the supervisor sends the app back to
    the S1 setup screen after showing it.
    """


def check_compatible(ours: Role, theirs: Role) -> None:
    """Cross-check our declared role against the peer's declared role (D1).

    The peer's role must be the OPPOSITE of ours. Raises
    :class:`RoleConflict` — e.g. ``role misconfiguration: both sides
    selected 'server'`` — when both sides selected the same role.
    """
    if ours is not theirs:
        return
    raise RoleConflict(
        f"role misconfiguration: both sides selected '{ours.as_str()}'"
    )


def _ip_key(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[int, bytes]:
    """Total order over IPs that works across address families: all IPv4
    addresses sort before all IPv6, numerically within a family.

    Port of the Rust ``ip_key``: a ``(family, 16-byte)`` key with the
    IPv4 octets placed in the last four bytes.
    """
    if isinstance(ip, ipaddress.IPv4Address):
        return 4, ip.packed.rjust(16, b"\x00")
    return 6, ip.packed


def role_from_ip_order(own: tuple[str, int], peer: tuple[str, int]) -> Role:
    """Decide our role from our public address and the peer's (legacy rule).

    Kept from Rust for the D4 legacy fallback and its oracle tests. Both
    peers independently run the same pure function over their public
    addresses; it always yields the same (opposite) result on each side,
    so exactly one side becomes the QUIC server and the other the client.

    Lower address → server (hosts the QUIC endpoint); higher → client.
    If the IPs are equal (local testing on one machine), fall back to the
    port (a perfect tie — same ip:port — cannot happen between two real
    peers and resolves to server).
    """
    own_key = _ip_key(ipaddress.ip_address(own[0]))
    peer_key = _ip_key(ipaddress.ip_address(peer[0]))
    if own_key == peer_key:
        # Same IP — only possible in local tests; use the port.
        return Role.SERVER if own[1] <= peer[1] else Role.CLIENT
    return Role.SERVER if own_key < peer_key else Role.CLIENT
