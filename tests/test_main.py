"""Phase 10 — pipeline wiring tests.

Covers the pure/testable surface of ``p2p_tunnel.main``:

* the error presentation (``error_chain`` / ``format_error`` — Rust
  ``{:#}`` parity, including the full-chain ``hint_for`` matching);
* ``hint_for`` (all branches, the v2 additions, the attempts knob);
* ``negotiate_role`` (S1+T1) with an injected stub channel: the happy
  paths, the D4 legacy-fallback paths, the role-conflict re-entry
  (interactive) and hard error (non-interactive), and the D2 manual
  fallbacks;
* ``run_attempt``'s T2 failure path (STUN unreachable on loopback);
* ``main``'s S0 error mapping (exit codes, the ``error:`` block);
* the two-bot relay mock itself, driven by two *real*
  ``TelegramChannel`` clients (the Phase 8 machinery against the Phase 10
  relay).

The full two-process loopback flow (both exchange modes, the role
conflict re-entry over the wire) is verified manually in PROGRESS.md
(Phase 10 done-when) and automated in Phase 14.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from p2p_tunnel import main as main_mod
from p2p_tunnel.cli import (
    Eof,
    Aborted,
    ExchangeMode,
    PromptOutcome,
    Setup,
)
from p2p_tunnel.config import Config, ConfigError, TelegramConfig
from p2p_tunnel.main import (
    Handshake,
    error_chain,
    format_error,
    hint_for,
    negotiate_role,
    run_attempt,
    setup_logging,
    _env_log_level,
    _bail,
)
from p2p_tunnel.role import Role, RoleConflict
from p2p_tunnel.stun import StunError
from p2p_tunnel.telegram import TelegramChannel, TelegramError, TelegramTimeoutError

from tests.telegram.mock_two_bot_api import TwoBotApi


def _read_from(*lines: str):
    """A ``read`` callable feeding fixed lines, then EOF (the prompt
    contracts turn that into an :class:`Eof` bail)."""
    it = iter(lines)

    def read() -> PromptOutcome:
        try:
            return PromptOutcome.from_line(next(it))
        except StopIteration:
            return PromptOutcome.eof_outcome()

    return read


def _client_cfg(**over) -> Config:
    base = dict(stun_servers=["127.0.0.1:3478"], local_tcp_listen_port=15001)
    base.update(over)
    return Config(**base)


def _server_cfg(**over) -> Config:
    base = dict(stun_servers=["127.0.0.1:3478"], remote_target_addr="127.0.0.1:14012")
    base.update(over)
    return Config(**base)


class _StubChannel:
    """A stand-in for :class:`TelegramChannel` (same public surface the
    pipeline uses), scripted per test."""

    def __init__(self, cfg: TelegramConfig) -> None:
        self.cfg = cfg
        self.started = False
        self.closed = False
        self.sent: list[tuple] = []
        self.start_exc: Exception | None = None
        self.ready_exc: Exception | None = None
        self.role_line: str | None = None
        self.addr: tuple[str, int] = ("127.0.0.1", 1)
        self.addr_exc: Exception | None = None

    async def start(self) -> None:
        if self.start_exc is not None:
            raise self.start_exc
        self.started = True

    def close(self) -> None:
        self.closed = True

    async def send_ready(self, secret: str) -> None:
        self.sent.append(("ready", secret))

    async def send_role(self, role: str) -> None:
        self.sent.append(("role", role))

    async def send_addr(self, addr: tuple[str, int]) -> None:
        self.sent.append(("addr", addr))

    async def wait_ready(self, secret: str | None = None, timeout: float = 60.0):
        if self.ready_exc is not None:
            raise self.ready_exc

    async def wait_role(self, grace: float = 2.0) -> str | None:
        return self.role_line

    async def wait_addr(self, timeout: float | None = None) -> tuple[str, int]:
        if self.addr_exc is not None:
            raise self.addr_exc
        return self.addr


# ---------------------------------------------------------------------------
# Error presentation
# ---------------------------------------------------------------------------


class FormatErrorTests(unittest.TestCase):
    def test_single(self) -> None:
        self.assertEqual(format_error(ValueError("boom")), "boom")

    def test_chain_matches_rust_alt_form(self) -> None:
        try:
            try:
                raise ValueError("inner")
            except ValueError as inner:
                raise RuntimeError("outer") from inner
        except RuntimeError as e:
            err = e
        self.assertEqual(
            format_error(err), "outer\nCaused by:\n    inner"
        )

    def test_chain_from_none_is_single(self) -> None:
        try:
            with contextlib.suppress(ZeroDivisionError):
                1 / 0
            raise RuntimeError("explicit") from None
        except RuntimeError as e:
            self.assertEqual(format_error(e), "explicit")

    def test_cycle_guard(self) -> None:
        a = RuntimeError("a")
        b = RuntimeError("b")
        a.__cause__ = b
        b.__cause__ = a
        self.assertEqual([type(x) for x in error_chain(a)], [RuntimeError, RuntimeError])


class HintForTests(unittest.TestCase):
    def test_stun_failure(self) -> None:
        hint = hint_for(StunError("STUN discovery failed: no response"))
        assert hint is not None
        self.assertIn("CGNAT", hint)
        self.assertIn("outbound UDP", hint)

    def test_punch_timeout(self) -> None:
        hint = hint_for(RuntimeError("hole punching timed out after 30s"))
        assert hint is not None
        self.assertIn("goes stale", hint)
        self.assertIn("symmetric NAT", hint)

    def test_quic_first_attempt(self) -> None:
        hint = hint_for(RuntimeError("QUIC handshake timed out"))
        assert hint is not None
        self.assertIn("middlebox", hint)
        self.assertNotIn("opposite roles", hint)

    def test_quic_repeated_gains_role_advice(self) -> None:
        hint = hint_for(RuntimeError("QUIC handshake timed out"), attempts=2)
        assert hint is not None
        # the exact PLAN §4 phrase
        self.assertIn("make sure both sides selected opposite roles", hint)

    def test_config_role_requirement(self) -> None:
        hint = hint_for(ConfigError("config: `local_tcp_listen_port` is required for the client role"))
        assert hint is not None
        self.assertIn("config.toml", hint)

    def test_role_conflict(self) -> None:
        hint = hint_for(RoleConflict("role misconfiguration: both sides selected 'client'"))
        assert hint is not None
        self.assertIn("one client and one server", hint)

    def test_matches_full_chain_not_just_outmost(self) -> None:
        try:
            try:
                raise StunError("STUN discovery failed: no response")
            except StunError as inner:
                raise RuntimeError("address exchange failed") from inner
        except RuntimeError as e:
            hint = hint_for(e)
        assert hint is not None
        self.assertIn("CGNAT", hint)

    def test_unrelated_error(self) -> None:
        self.assertIsNone(hint_for(ValueError("something else entirely")))


# ---------------------------------------------------------------------------
# S1 + T1 (negotiate_role)
# ---------------------------------------------------------------------------


class NegotiateRoleTests(unittest.IsolatedAsyncioTestCase):
    TG = TelegramConfig(token="1001", peer_bot_id=1002, secret="s3cr3t")

    def _cfg(self, telegram: TelegramConfig | None) -> Config:
        return _client_cfg(telegram=telegram)

    async def test_manual_mode_returns_selection(self) -> None:
        stubs: list[_StubChannel] = []
        hs = await negotiate_role(
            self._cfg(None),
            ExchangeMode.MANUAL,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: stubs.append(_StubChannel(tc)) or None,
        )
        self.assertEqual(hs.final_role, Role.CLIENT)
        self.assertIsNone(hs.channel)
        self.assertFalse(hs.telegram_usable)
        self.assertEqual(stubs, [])  # no channel is even built

    async def test_telegram_opposite_roles(self) -> None:
        stub = _StubChannel(self.TG)
        stub.role_line = "server"  # we are client
        hs = await negotiate_role(
            self._cfg(self.TG),
            ExchangeMode.TELEGRAM,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: stub,
        )
        self.assertEqual(hs.final_role, Role.CLIENT)
        self.assertTrue(hs.telegram_usable)
        self.assertIs(hs.channel, stub)
        self.assertTrue(stub.started)
        self.assertFalse(stub.closed)
        self.assertIn(("ready", "s3cr3t"), stub.sent)
        self.assertIn(("role", "client"), stub.sent)

    async def test_telegram_no_role_line_is_legacy_fallback(self) -> None:
        stub = _StubChannel(self.TG)
        stub.role_line = None  # legacy v1 peer
        hs = await negotiate_role(
            self._cfg(self.TG),
            ExchangeMode.TELEGRAM,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: stub,
        )
        self.assertIsNone(hs.final_role)  # derive from the IP order after T3
        self.assertTrue(hs.telegram_usable)

    async def test_telegram_invalid_role_line_is_ignored(self) -> None:
        stub = _StubChannel(self.TG)
        stub.role_line = "banana"
        hs = await negotiate_role(
            self._cfg(self.TG),
            ExchangeMode.TELEGRAM,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: stub,
        )
        self.assertIsNone(hs.final_role)
        self.assertTrue(hs.telegram_usable)

    async def test_conflict_noninteractive_raises(self) -> None:
        stub = _StubChannel(self.TG)
        stub.role_line = "client"  # both sides client
        with self.assertRaises(RoleConflict):
            await negotiate_role(
                self._cfg(self.TG),
                ExchangeMode.TELEGRAM,
                read=_read_from(),
                interactive=False,
                channel_factory=lambda tc: stub,
            )

    async def test_conflict_interactive_reenters_s1(self) -> None:
        # First S1: client (prefilled port); conflict; re-enter S1: server
        # (prefilled target). Both settings must be prefilled.
        cfg = _client_cfg(telegram=self.TG, remote_target_addr="127.0.0.1:14012")
        stub = _StubChannel(self.TG)
        stub.role_line = "client"
        hs = await negotiate_role(
            cfg,
            ExchangeMode.TELEGRAM,
            read=_read_from("c", "", "s", ""),
            interactive=True,
            channel_factory=lambda tc: stub,
        )
        self.assertEqual(hs.final_role, Role.SERVER)
        self.assertEqual(hs.setup.role, Role.SERVER)
        self.assertEqual(hs.setup.target, ("127.0.0.1", 14012))
        # re-handshaked: READY/ROLE went out twice, the second as server
        self.assertEqual(stub.sent.count(("ready", "s3cr3t")), 2)
        self.assertIn(("role", "client"), stub.sent)
        self.assertIn(("role", "server"), stub.sent)

    async def test_ready_timeout_falls_back_to_manual(self) -> None:
        stub = _StubChannel(self.TG)
        stub.ready_exc = TelegramTimeoutError(1002, "READY", 60)
        hs = await negotiate_role(
            self._cfg(self.TG),
            ExchangeMode.TELEGRAM,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: stub,
        )
        self.assertEqual(hs.final_role, Role.CLIENT)
        self.assertFalse(hs.telegram_usable)
        self.assertIs(hs.channel, stub)
        self.assertFalse(stub.closed)  # the channel is healthy — reuse it next attempt

    async def test_start_failure_falls_back_and_closes(self) -> None:
        stub = _StubChannel(self.TG)
        stub.start_exc = TelegramError("getMe: connection refused")
        hs = await negotiate_role(
            self._cfg(self.TG),
            ExchangeMode.TELEGRAM,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: stub,
        )
        self.assertEqual(hs.final_role, Role.CLIENT)
        self.assertFalse(hs.telegram_usable)
        self.assertTrue(stub.closed)

    async def test_telegram_mode_without_table_falls_back(self) -> None:
        hs = await negotiate_role(
            self._cfg(None),  # no [telegram] table
            ExchangeMode.TELEGRAM,
            read=_read_from(),
            interactive=False,
            channel_factory=lambda tc: _StubChannel(tc),
        )
        self.assertEqual(hs.final_role, Role.CLIENT)
        self.assertFalse(hs.telegram_usable)
        self.assertIsNone(hs.channel)


# ---------------------------------------------------------------------------
# run_attempt: the T2 failure path (real loopback, no listener → fast ECONNREFUSED)
# ---------------------------------------------------------------------------


class RunAttemptFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_stun_failure_propagates_and_cleans_up(self) -> None:
        cfg = _server_cfg(stun_servers=["127.0.0.1:1"])  # nothing listens on :1
        with self.assertRaises(StunError):
            await run_attempt(
                cfg,
                ExchangeMode.MANUAL,
                read=_read_from(),
                interactive=False,
            )


# ---------------------------------------------------------------------------
# main(): S0 + exit codes
# ---------------------------------------------------------------------------


class MainExitCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        # isolate logging: the global root handlers would otherwise keep
        # writing to the first test's captured stream
        root = logging.getLogger()
        self._old_handlers = root.handlers[:]
        self._old_level = root.level
        root.handlers = []
        root.setLevel(logging.INFO)
        self.addCleanup(self._restore_logging)

    def _restore_logging(self) -> None:
        root = logging.getLogger()
        root.handlers = self._old_handlers
        root.setLevel(self._old_level)

    def _run_main(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code = main_mod.main(list(argv))
        return code, buf.getvalue()

    def test_missing_config_exits_1_with_error_block(self) -> None:
        code, err = self._run_main("--config", "/nonexistent/nope.toml")
        self.assertEqual(code, 1)
        self.assertIn("error:", err)
        self.assertIn("config", err)

    def test_telegram_flag_without_table_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "cfg.toml"
            cfg.write_text('stun_servers = ["127.0.0.1:3478"]\n')
            code, err = self._run_main("--config", str(cfg), "--telegram")
        self.assertEqual(code, 1)
        self.assertIn("error:", err)
        self.assertIn("[telegram]", err)
        self.assertIn("--telegram", err)

    def test_version_exits_0(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                main_mod.main(["-V"])
        self.assertEqual(cm.exception.code, 0)


# ---------------------------------------------------------------------------
# bail mapping + logging env
# ---------------------------------------------------------------------------


class MiscTests(unittest.TestCase):
    def test_bail_eof_message(self) -> None:
        self.assertEqual(str(_bail(Eof())), "stdin closed before a peer address was entered")

    def test_bail_aborted_message(self) -> None:
        self.assertEqual(str(_bail(Aborted())), "aborted by the user")

    def test_env_log_level_unset(self) -> None:
        env = {k: v for k, v in os.environ.items() if k not in ("P2P_TUNNEL_LOG", "RUST_LOG")}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(_env_log_level())

    def test_env_log_level_p2p_wins(self) -> None:
        with mock.patch.dict(
            os.environ, {"P2P_TUNNEL_LOG": "debug", "RUST_LOG": "error"}
        ):
            self.assertEqual(_env_log_level(), logging.DEBUG)

    def test_env_log_level_rust_log_token(self) -> None:
        with mock.patch.dict(os.environ, {"RUST_LOG": "p2p_tunnel=trace"}):
            self.assertEqual(_env_log_level(), logging.DEBUG)  # trace → DEBUG

    def test_env_log_level_last_token_wins(self) -> None:
        with mock.patch.dict(os.environ, {"RUST_LOG": "info,foo=warn"}):
            self.assertEqual(_env_log_level(), logging.WARNING)

    def test_env_log_level_no_token(self) -> None:
        with mock.patch.dict(os.environ, {"RUST_LOG": "p2p_tunnel"}):
            self.assertIsNone(_env_log_level())


# ---------------------------------------------------------------------------
# The two-bot relay, driven by two REAL TelegramChannel clients
# ---------------------------------------------------------------------------


class TwoBotRelayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.api = TwoBotApi().start()
        patcher = mock.patch.dict(os.environ, {"PTUN_TELEGRAM_API_BASE": self.api.api_base()})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.api.stop)

    def _channel(self, token: str, peer_id: int) -> TelegramChannel:
        return TelegramChannel(TelegramConfig(token=token, peer_bot_id=peer_id, secret="s3cr3t"))

    async def test_addr_round_trip(self) -> None:
        a, b = self._channel("1001", 1002), self._channel("1002", 1001)
        await a.start()
        await b.start()
        try:
            await a.send_addr(("1.2.3.4", 5678))
            self.assertEqual(await asyncio.wait_for(b.wait_addr(timeout=10), 12), ("1.2.3.4", 5678))
        finally:
            a.close()
            b.close()

    async def test_ready_and_role_round_trip(self) -> None:
        # All lines are committed BEFORE any wait: each channel's pending
        # long-poll then batches them in one fetch. (Interleaving sends and
        # waits can hit the real Bot API's commit-vs-offset race, which
        # PLAN v2 tolerates by design — ROLE is optional, READY falls back.)
        a, b = self._channel("1001", 1002), self._channel("1002", 1001)
        await a.start()
        await b.start()
        try:
            await a.send_ready("s3cr3t")
            await a.send_role("client")
            await b.send_ready("s3cr3t")
            await b.send_role("server")
            await asyncio.sleep(0.5)  # let the in-flight long-polls batch the lines
            ready = await asyncio.wait_for(b.wait_ready(timeout=10), 12)
            self.assertEqual(ready.secret, "s3cr3t")
            self.assertEqual(await asyncio.wait_for(b.wait_role(grace=5), 7), "client")
            ready_a = await asyncio.wait_for(a.wait_ready(timeout=10), 12)
            self.assertEqual(ready_a.secret, "s3cr3t")
            self.assertEqual(await asyncio.wait_for(a.wait_role(grace=5), 7), "server")
        finally:
            a.close()
            b.close()

    async def test_consumed_line_is_not_redelivered(self) -> None:
        a, b = self._channel("1001", 1002), self._channel("1002", 1001)
        await a.start()
        await b.start()
        try:
            await a.send_addr(("1.1.1.1", 1111))
            self.assertEqual(await asyncio.wait_for(b.wait_addr(timeout=10), 12), ("1.1.1.1", 1111))
            with self.assertRaises(TelegramTimeoutError):
                await asyncio.wait_for(b.wait_addr(timeout=1), 12)
        finally:
            a.close()
            b.close()

    async def test_both_sides_full_handshake(self) -> None:
        """Both channels run the whole PTUN v1.1 dance against each other —
        the shape of the Phase 10 T1+T3 Telegram path."""
        a, b = self._channel("1001", 1002), self._channel("1002", 1001)
        await a.start()
        await b.start()
        try:
            await a.send_ready("s3cr3t")
            await a.send_role("client")
            await b.send_ready("s3cr3t")
            await b.send_role("server")
            await asyncio.sleep(0.5)  # let the in-flight long-polls batch the lines
            await a.wait_ready()
            await b.wait_ready()
            self.assertEqual(await a.wait_role(grace=5), "server")
            self.assertEqual(await b.wait_role(grace=5), "client")
            await a.send_addr(("203.0.113.5", 40000))
            await b.send_addr(("203.0.113.6", 40001))
            self.assertEqual(await a.wait_addr(timeout=10), ("203.0.113.6", 40001))
            self.assertEqual(await b.wait_addr(timeout=10), ("203.0.113.5", 40000))
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main()
