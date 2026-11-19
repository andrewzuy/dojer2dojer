"""Tests for :mod:`p2p_tunnel.config` (ported from the Rust ``config.rs`` tests)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p2p_tunnel.config import (
    DEFAULT_KEEP_ALIVE_INTERVAL_SECS,
    DEFAULT_PUNCH_INTERVAL_MS,
    DEFAULT_PUNCH_TIMEOUT_SECS,
    DEFAULT_TELEGRAM_TIMEOUT_SECS,
    Config,
    ConfigError,
    validate_for_role,
)
from p2p_tunnel.role import Role


def write_temp_toml(text: str) -> Path:
    fd, name = tempfile.mkstemp(suffix=".toml", prefix="p2p-tunnel-test-")
    with open(name, "w", encoding="utf-8") as f:
        f.write(text)
    return Path(name)


class ConfigLoadTests(unittest.TestCase):
    def setUp(self):
        self._paths: list[Path] = []

    def tearDown(self):
        for p in self._paths:
            try:
                p.unlink()
            except OSError:
                pass

    def write(self, text: str) -> Path:
        p = write_temp_toml(text)
        self._paths.append(p)
        return p

    def test_loads_full_config(self):
        path = self.write(
            """\
stun_servers = ["stun.l.google.com:19302"]
local_tcp_listen_port = 12345
remote_target_addr = "127.0.0.1:8080"
"""
        )
        cfg = Config.load(path)
        self.assertEqual(cfg.stun_servers, ["stun.l.google.com:19302"])
        self.assertEqual(cfg.punch_interval_ms, 500)  # default
        self.assertEqual(cfg.punch_timeout_secs, 30)  # default
        self.assertEqual(cfg.keep_alive_interval_secs, 5)  # default
        self.assertEqual(cfg.local_tcp_listen_port, 12345)
        self.assertEqual(cfg.remote_target_addr, "127.0.0.1:8080")
        self.assertIsNone(cfg.telegram)  # absent table -> None

    def test_loads_telegram_section(self):
        path = self.write(
            """\
stun_servers = ["stun.l.google.com:19302"]

[telegram]
token = "123456:ABC-DEF"
peer_bot_id = 987654321
"""
        )
        cfg = Config.load(path)
        tg = cfg.telegram
        self.assertIsNotNone(tg, "[telegram] table present")
        self.assertEqual(tg.token, "123456:ABC-DEF")
        self.assertEqual(tg.peer_bot_id, 987654321)
        self.assertEqual(tg.timeout_secs, 120)  # default
        self.assertIsNone(tg.secret)

    def test_telegram_timeout_override(self):
        path = self.write(
            """\
stun_servers = ["stun.l.google.com:19302"]

[telegram]
token = "t"
peer_bot_id = 1
timeout_secs = 5
"""
        )
        cfg = Config.load(path)
        self.assertEqual(cfg.telegram.timeout_secs, 5)

    def test_telegram_secret_loaded(self):
        path = self.write(
            """\
stun_servers = ["stun.l.google.com:19302"]

[telegram]
token = "t"
peer_bot_id = 1
secret = "s3cr3t"
"""
        )
        cfg = Config.load(path)
        self.assertEqual(cfg.telegram.secret, "s3cr3t")

    def test_explicit_overrides_win(self):
        path = self.write(
            """\
stun_servers = ["a:1", "b:2"]
punch_interval_ms = 250
punch_timeout_secs = 5
keep_alive_interval_secs = 0
"""
        )
        cfg = Config.load(path)
        self.assertEqual(cfg.stun_servers, ["a:1", "b:2"])
        self.assertEqual(cfg.punch_interval_ms, 250)
        self.assertEqual(cfg.punch_timeout_secs, 5)
        self.assertEqual(cfg.keep_alive_interval_secs, 0)  # explicit override
        self.assertIsNone(cfg.local_tcp_listen_port)
        self.assertIsNone(cfg.remote_target_addr)

    def test_missing_stun_servers_errors(self):
        path = self.write(
            """\
punch_interval_ms = 100
"""
        )
        with self.assertRaises(ConfigError) as ctx:
            Config.load(path)
        self.assertIn("stun_servers", str(ctx.exception))

    def test_empty_stun_servers_errors(self):
        path = self.write('stun_servers = []')
        with self.assertRaises(ConfigError) as ctx:
            Config.load(path)
        self.assertIn("stun_servers", str(ctx.exception))

    def test_malformed_toml_errors(self):
        path = self.write("stun_servers = [")
        with self.assertRaises(ConfigError) as ctx:
            Config.load(path)
        self.assertIn("parsing config file", str(ctx.exception))

    def test_nonexistent_file_errors(self):
        with self.assertRaises(ConfigError) as ctx:
            Config.load("/nonexistent/p2p-tunnel/config.toml")
        self.assertIn("reading config file", str(ctx.exception))

    def test_bad_port_type_errors(self):
        path = self.write(
            """\
stun_servers = ["a:1"]
local_tcp_listen_port = "not-a-port"
"""
        )
        with self.assertRaises(ConfigError) as ctx:
            Config.load(path)
        self.assertIn("local_tcp_listen_port", str(ctx.exception))

    def test_unknown_keys_ignored(self):
        path = self.write(
            """\
stun_servers = ["a:1"]
some_future_key = 42
"""
        )
        cfg = Config.load(path)
        self.assertEqual(cfg.stun_servers, ["a:1"])

    def test_defaults_match_constants(self):
        # Guard: the plan's parity contract pins these numbers.
        self.assertEqual(DEFAULT_PUNCH_INTERVAL_MS, 500)
        self.assertEqual(DEFAULT_PUNCH_TIMEOUT_SECS, 30)
        self.assertEqual(DEFAULT_KEEP_ALIVE_INTERVAL_SECS, 5)
        self.assertEqual(DEFAULT_TELEGRAM_TIMEOUT_SECS, 120)


class ValidateForRoleTests(unittest.TestCase):
    """Role-aware validation (v2, D5) — runs after the role is known."""

    def cfg(self, **kw) -> Config:
        base = dict(stun_servers=["stun.l.google.com:19302"])
        base.update(kw)
        return Config(**base)

    def test_client_with_port_passes(self):
        validate_for_role(self.cfg(local_tcp_listen_port=1234), Role.CLIENT)

    def test_client_without_port_raises(self):
        with self.assertRaises(ConfigError) as ctx:
            validate_for_role(self.cfg(), Role.CLIENT)
        msg = str(ctx.exception)
        self.assertIn("local_tcp_listen_port", msg)
        self.assertIn("is required for the client role", msg)

    def test_server_with_addr_passes(self):
        validate_for_role(self.cfg(remote_target_addr="1.2.3.4:5"), Role.SERVER)

    def test_server_without_addr_raises(self):
        with self.assertRaises(ConfigError) as ctx:
            validate_for_role(self.cfg(), Role.SERVER)
        msg = str(ctx.exception)
        self.assertIn("remote_target_addr", msg)
        self.assertIn("is required for the server role", msg)

    def test_client_ignores_server_key_and_vice_versa(self):
        # Only the role's own key is required; the other key is irrelevant.
        validate_for_role(self.cfg(local_tcp_listen_port=1), Role.CLIENT)
        validate_for_role(self.cfg(remote_target_addr="9.9.9.9:1"), Role.SERVER)
        # Cross-set keys do not satisfy the requirement.
        with self.assertRaises(ConfigError):
            validate_for_role(self.cfg(remote_target_addr="9.9.9.9:1"), Role.CLIENT)
        with self.assertRaises(ConfigError):
            validate_for_role(self.cfg(local_tcp_listen_port=1), Role.SERVER)

    def test_error_messages_match_hint_substring(self):
        # The hint matcher keys on "is required for the" (PLAN §4).
        for cfg, role in (
            (self.cfg(), Role.CLIENT),
            (self.cfg(), Role.SERVER),
        ):
            with self.assertRaises(ConfigError) as ctx:
                validate_for_role(cfg, role)
            self.assertIn("is required for the", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
