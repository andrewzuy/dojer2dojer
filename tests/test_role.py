"""Tests for :mod:`p2p_tunnel.role`.

The first five tests are ported **unchanged** from the Rust oracle
(``src/role.rs`` tests, PLAN §4: "its 5 oracle tests"); the rest cover the
v2 role model (``Role`` enum, ``check_compatible`` / ``RoleConflict``,
D1/D4).
"""

from __future__ import annotations

import unittest

from p2p_tunnel.role import (
    Role,
    RoleConflict,
    check_compatible,
    role_from_ip_order,
)


class LegacyIpOrderTests(unittest.TestCase):
    """Ported from the Rust ``src/role.rs`` tests (oracle parity)."""

    def test_v4_lower_is_server(self):
        low = ("1.2.3.4", 1000)
        high = ("5.6.7.8", 2000)
        self.assertEqual(role_from_ip_order(low, high), Role.SERVER)
        self.assertEqual(role_from_ip_order(high, low), Role.CLIENT)

    def test_roles_are_always_opposite(self):
        addrs = [
            ("10.0.0.1", 1),
            ("10.0.0.2", 2),
            ("172.16.5.9", 10000),
            ("8.8.8.8", 53),
            ("2001:db8::1", 443),
            ("2001:db8::2", 443),
            ("192.168.1.5", 22),
        ]
        for a in addrs:
            for b in addrs:
                if a == b:
                    continue
                ra = role_from_ip_order(a, b)
                rb = role_from_ip_order(b, a)
                self.assertIn(
                    (ra, rb),
                    [(Role.SERVER, Role.CLIENT), (Role.CLIENT, Role.SERVER)],
                    msg=f"asymmetric roles for {a} vs {b}",
                )

    def test_v4_always_beats_v6(self):
        v4 = ("1.2.3.4", 1)
        v6 = ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1)
        self.assertEqual(role_from_ip_order(v4, v6), Role.SERVER)
        self.assertEqual(role_from_ip_order(v6, v4), Role.CLIENT)

    def test_v6_orders_numerically(self):
        low = ("2001:db8::1", 1)
        high = ("2001:db8::2", 1)
        self.assertEqual(role_from_ip_order(low, high), Role.SERVER)
        self.assertEqual(role_from_ip_order(high, low), Role.CLIENT)

    def test_same_ip_falls_back_to_port(self):
        a = ("127.0.0.1", 1000)
        b = ("127.0.0.1", 2000)
        self.assertEqual(role_from_ip_order(a, b), Role.SERVER)
        self.assertEqual(role_from_ip_order(b, a), Role.CLIENT)

    def test_same_ip_same_port_resolves_to_server(self):
        # A perfect tie cannot happen between two real peers (Rust comment);
        # the Rust oracle resolves it to server via ``<=``.
        a = ("127.0.0.1", 1000)
        self.assertEqual(role_from_ip_order(a, a), Role.SERVER)


class RoleEnumTests(unittest.TestCase):
    def test_as_str(self):
        self.assertEqual(Role.CLIENT.as_str(), "client")
        self.assertEqual(Role.SERVER.as_str(), "server")

    def test_opposite(self):
        self.assertEqual(Role.CLIENT.opposite, Role.SERVER)
        self.assertEqual(Role.SERVER.opposite, Role.CLIENT)

    def test_from_str_roundtrip(self):
        for role in Role:
            self.assertIs(Role.from_str(role.as_str()), role)

    def test_from_str_case_insensitive_and_trimmed(self):
        self.assertIs(Role.from_str("  Client "), Role.CLIENT)
        self.assertIs(Role.from_str("SERVER"), Role.SERVER)

    def test_from_str_rejects_unknown(self):
        for bad in ("", "boss", "clients", "serves", "admin"):
            with self.assertRaises(ValueError, msg=f"should reject {bad!r}"):
                Role.from_str(bad)


class CheckCompatibleTests(unittest.TestCase):
    def test_opposite_roles_pass(self):
        # Both directions must pass.
        check_compatible(Role.CLIENT, Role.SERVER)
        check_compatible(Role.SERVER, Role.CLIENT)

    def test_conflict_server_server(self):
        with self.assertRaises(RoleConflict) as ctx:
            check_compatible(Role.SERVER, Role.SERVER)
        self.assertEqual(
            str(ctx.exception),
            "role misconfiguration: both sides selected 'server'",
        )

    def test_conflict_client_client(self):
        with self.assertRaises(RoleConflict) as ctx:
            check_compatible(Role.CLIENT, Role.CLIENT)
        self.assertEqual(
            str(ctx.exception),
            "role misconfiguration: both sides selected 'client'",
        )

    def test_conflict_message_contains_hint_substring(self):
        # The hint matcher keys on "role misconfiguration" (PLAN §4).
        for ours, theirs in ((Role.CLIENT, Role.CLIENT), (Role.SERVER, Role.SERVER)):
            with self.assertRaises(RoleConflict) as ctx:
                check_compatible(ours, theirs)
            self.assertIn("role misconfiguration", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
