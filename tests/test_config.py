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
)


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


if __name__ == "__main__":
    unittest.main()
