"""Phase 8 tests — Telegram bot-to-bot signaling (PTUN protocol v1.1).

Three layers:

1. **Ported Rust classify suite** — the 18 unit tests from
   ``src/telegram.rs`` (Rust ``main`` @ f2dc2a4) translated one-for-one
   onto :meth:`p2p_tunnel.telegram.TelegramChannel.classify`, plus the
   new v1.1 ``PTUN ROLE`` line (classify + build).
2. **Async channel tests** against an in-process, programmable Bot API
   mock: waiter semantics (buffered-line claim, first-fresh-match-wins,
   legacy role fallback, duplicate handling), offset freshness across a
   simulated "attempt 2" (the Phase 8 done-when), and getMe/send error
   paths.
3. **End-to-end against the unmodified** ``tests/telegram/mock_bot_api.py``
   (spawned as a subprocess, pointed at via ``PTUN_TELEGRAM_API_BASE``)
   — the port of Rust's ``tests/telegram_exchange.rs``.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from p2p_tunnel.cli import PeerAddrError, parse_peer_addr
from p2p_tunnel.config import TelegramConfig
from p2p_tunnel.telegram import (
    PAYLOAD_PREFIX,
    READY_PREFIX,
    ROLE_PREFIX,
    TelegramChannel,
    TelegramError,
    TelegramTimeoutError,
    build_addr_line,
    build_ready_line,
    build_role_line,
    format_addr,
    parse_update,
)

OWN_ID = 1001  # the mock's own bot id (getMe)
PEER_ID = 9001  # [telegram].peer_bot_id
SECRET = "my-secret"


def make_channel(secret: str | None = SECRET, timeout_secs: int = 5) -> TelegramChannel:
    """A channel wired for tests: token set, own id pre-identified (no
    ``getMe`` needed for the pure classify tests)."""
    cfg = TelegramConfig(
        token="test:token",
        peer_bot_id=PEER_ID,
        timeout_secs=timeout_secs,
        secret=secret,
    )
    ch = TelegramChannel(cfg)
    ch.own_bot_id = OWN_ID
    return ch


def upd(update_id: int, from_id: int, is_bot: bool, text: str, date: int = 0):
    """One getUpdates entry, the shape the real API returns."""
    return parse_update(
        {
            "update_id": update_id,
            "message": {
                "message_id": update_id,
                "from": {"id": from_id, "is_bot": is_bot, "first_name": "X"},
                "date": date,
                "text": text,
            },
        }
    )


def now() -> int:
    return int(time.time())


# ===========================================================================
# 1a. Ported Rust classify suite — v1 address line (tests 1–11 in
#     src/telegram.rs).
# ===========================================================================


class TestPortedV1Classify(unittest.TestCase):
    def setUp(self):
        self.tg = make_channel()

    def test_payload_is_well_formed(self):
        self.assertEqual(build_addr_line(("1.2.3.4", 1234)), "PTUN v1 1.2.3.4:1234")

    def test_payload_round_trips_through_parser(self):
        own = ("2001:db8::7", 4433)
        line = build_addr_line(own)
        self.assertTrue(line.startswith("PTUN v1 "))
        host, port = parse_peer_addr(line[len("PTUN v1 "):])
        self.assertEqual((host, port), own)

    def test_rejects_garbage_payload(self):
        for bad in ("not an address at all", "1.2.3.4", "", "1.2.3.4:99999", "[::1]"):
            with self.assertRaises(PeerAddrError, msg=bad):
                parse_peer_addr(bad)

    def test_parses_get_updates_result(self):
        raw = [
            {
                "update_id": 1234,
                "message": {
                    "message_id": 1,
                    "from": {"id": PEER_ID, "is_bot": True, "first_name": "Peer"},
                    "date": 1_700_000_000,
                    "text": "PTUN v1 1.2.3.4:5",
                },
            }
        ]
        updates = [parse_update(u) for u in raw]
        self.assertEqual(len(updates), 1)
        u = updates[0]
        self.assertEqual(u.update_id, 1234)
        self.assertIsNotNone(u.message)
        m = u.message
        self.assertEqual(m.from_id, PEER_ID)
        self.assertTrue(m.is_bot)
        self.assertEqual(m.text, "PTUN v1 1.2.3.4:5")
        self.assertEqual(m.date, 1_700_000_000)
        # Lenient like serde(default): absent fields default, no crash.
        empty = parse_update({})
        self.assertEqual(empty.update_id, 0)
        self.assertIsNone(empty.message)
        no_from = parse_update(
            {"update_id": 7, "message": {"text": "PTUN v1 1.2.3.4:5", "date": 1}}
        )
        self.assertEqual(no_from.update_id, 7)
        self.assertIsNotNone(no_from.message)
        self.assertIsNone(no_from.message.from_id)

    def test_classify_accepts_peer_payload(self):
        m = upd(1, PEER_ID, True, build_addr_line(("203.0.113.7", 48000)))
        l = self.tg.classify(m)
        self.assertIsNotNone(l)
        self.assertEqual(l.kind, "addr")
        self.assertEqual(l.addr, ("203.0.113.7", 48000))

    def test_classify_ignores_own_echo(self):
        m = upd(1, OWN_ID, True, build_addr_line(("198.51.100.9", 4433)))
        self.assertIsNone(self.tg.classify(m))

    def test_classify_ignores_unexpected_sender(self):
        m = upd(1, 555, True, build_addr_line(("203.0.113.7", 48000)))
        self.assertIsNone(self.tg.classify(m))

    def test_classify_ignores_non_bot_and_garbage(self):
        cases = [
            upd(1, PEER_ID, False, build_addr_line(("203.0.113.7", 48000))),
            upd(2, PEER_ID, True, "hello, are you there?"),
            upd(3, PEER_ID, True, "PTUN v1"),
            upd(4, PEER_ID, True, "PTUN v1 not-an-address"),
            upd(5, PEER_ID, True, ""),
            parse_update({"update_id": 6}),  # no message at all
        ]
        for c in cases:
            self.assertIsNone(self.tg.classify(c), f"case: {c!r}")

    def test_classify_accepts_fresh_peer_payload(self):
        m = upd(1, PEER_ID, True, build_addr_line(("203.0.113.7", 48000)), date=now())
        l = self.tg.classify(m)
        self.assertIsNotNone(l)
        self.assertEqual(l.addr, ("203.0.113.7", 48000))

    def test_classify_rejects_stale_peer_payload(self):
        m = upd(1, PEER_ID, True, build_addr_line(("203.0.113.7", 48000)), date=now() - 3600)
        self.assertIsNone(self.tg.classify(m))

    def test_classify_accepts_payload_without_date(self):
        m = upd(1, PEER_ID, True, build_addr_line(("203.0.113.7", 48000)), date=0)
        l = self.tg.classify(m)
        self.assertIsNotNone(l)
        self.assertEqual(l.addr, ("203.0.113.7", 48000))


# ===========================================================================
# 1b. Ported Rust classify suite — READY line (tests 12–18 in
#     src/telegram.rs).
# ===========================================================================


class TestPortedReadyClassify(unittest.TestCase):
    def setUp(self):
        self.tg = make_channel(secret=SECRET)

    def test_ready_line_is_well_formed(self):
        self.assertEqual(build_ready_line(SECRET), f"{READY_PREFIX}{SECRET}")

    def test_classify_ready_accepts_peer_line(self):
        m = upd(1, PEER_ID, True, f"PTUN READY {SECRET}")
        l = self.tg.classify(m, ready_secret=SECRET)
        self.assertIsNotNone(l)
        self.assertEqual(l.kind, "ready")
        self.assertEqual(l.secret, SECRET)

    def test_classify_ready_ignores_own_echo(self):
        m = upd(1, OWN_ID, True, f"PTUN READY {SECRET}")
        self.assertIsNone(self.tg.classify(m, ready_secret=SECRET))

    def test_classify_ready_ignores_unexpected_sender_and_non_bot(self):
        self.assertIsNone(
            self.tg.classify(upd(1, 555, True, f"PTUN READY {SECRET}"), ready_secret=SECRET)
        )
        self.assertIsNone(
            self.tg.classify(upd(1, PEER_ID, False, f"PTUN READY {SECRET}"), ready_secret=SECRET)
        )

    def test_classify_ready_rejects_mismatched_or_missing_secret(self):
        # Mismatched secret → warn + ignore.
        self.assertIsNone(
            self.tg.classify(upd(1, PEER_ID, True, "PTUN READY wrong-secret"), ready_secret=SECRET)
        )
        # Empty secret → warn + ignore.
        self.assertIsNone(self.tg.classify(upd(1, PEER_ID, True, "PTUN READY "), ready_secret=SECRET))
        # A v1 address line is not a ready line.
        l = self.tg.classify(upd(1, PEER_ID, True, "PTUN v1 1.2.3.4:5"), ready_secret=SECRET)
        self.assertTrue(l is None or l.kind != "ready")
        # Garbage is not a ready line.
        self.assertIsNone(self.tg.classify(upd(1, PEER_ID, True, "hello"), ready_secret=SECRET))

    def test_classify_ready_rejects_stale_line(self):
        m = upd(1, PEER_ID, True, f"PTUN READY {SECRET}", date=now() - 3600)
        self.assertIsNone(self.tg.classify(m, ready_secret=SECRET))

    def test_classify_ready_accepts_fresh_line(self):
        m = upd(1, PEER_ID, True, f"PTUN READY {SECRET}", date=now())
        l = self.tg.classify(m, ready_secret=SECRET)
        self.assertIsNotNone(l)
        self.assertEqual(l.secret, SECRET)


# ===========================================================================
# 1c. New v1.1: the PTUN ROLE line (classify + build).
# ===========================================================================


class TestRoleLine(unittest.TestCase):
    def setUp(self):
        self.tg = make_channel(secret=SECRET)

    def test_role_line_is_well_formed(self):
        self.assertEqual(build_role_line("server"), "PTUN ROLE server")
        self.assertEqual(build_role_line("client"), "PTUN ROLE client")

    def test_build_role_line_rejects_unknown(self):
        for bad in ("banana", "", "CLIENT", "serv"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                build_role_line(bad)

    def test_classify_role_accepts_client_and_server(self):
        for role in ("client", "server"):
            m = upd(1, PEER_ID, True, f"PTUN ROLE {role}", date=now())
            l = self.tg.classify(m)
            self.assertIsNotNone(l, role)
            self.assertEqual(l.kind, "role")
            self.assertEqual(l.role, role)

    def test_classify_role_rejects_garbage(self):
        for bad in ("PTUN ROLE banana", "PTUN ROLE ", "PTUN ROLE client-server"):
            self.assertIsNone(self.tg.classify(upd(1, PEER_ID, True, bad)), bad)

    def test_classify_role_ignores_own_echo(self):
        self.assertIsNone(self.tg.classify(upd(1, OWN_ID, True, "PTUN ROLE server")))

    def test_classify_role_ignores_unexpected_sender(self):
        self.assertIsNone(self.tg.classify(upd(1, 555, True, "PTUN ROLE server")))

    def test_classify_role_rejects_stale_line(self):
        m = upd(1, PEER_ID, True, "PTUN ROLE server", date=now() - 3600)
        self.assertIsNone(self.tg.classify(m))

    def test_classify_role_accepts_line_without_date(self):
        m = upd(1, PEER_ID, True, "PTUN ROLE client", date=0)
        l = self.tg.classify(m)
        self.assertIsNotNone(l)
        self.assertEqual(l.role, "client")


# ===========================================================================
# 2. In-process programmable Bot API mock + async channel tests.
# ===========================================================================


class _MockBotApi:
    """A tiny in-process Bot API mock.

    Like the real API, ``getUpdates`` replays every queued update with
    ``update_id > offset`` (the client's offset cursor is the source of
    truth for consumption). Updates can be enqueued at any moment —
    that is how the tests simulate the peer bot's replies.
    """

    def __init__(self) -> None:
        self._updates: list[dict] = []
        self.sent: list[tuple[int, str]] = []  # (chat_id, text) in send order
        self.fail_send = False
        self._next_id = 1
        self._httpd: ThreadingHTTPServer | None = None
        self.port = 0

    def enqueue(self, text: str, from_id: int = PEER_ID, is_bot: bool = True, date: int | None = None) -> int:
        uid = self._next_id
        self._next_id += 1
        self._updates.append(
            {
                "update_id": uid,
                "message": {
                    "message_id": uid,
                    "from": {"id": from_id, "is_bot": is_bot, "first_name": "B"},
                    "date": now() if date is None else date,
                    "text": text,
                },
            }
        )
        return uid

    def start(self) -> None:
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 (http.server API)
                length = int(self.headers.get("Content-Length", 0))
                fields = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode("utf-8")))
                method = self.path.rsplit("/", 1)[-1]
                if method == "getMe":
                    resp = {
                        "ok": True,
                        "result": {"id": OWN_ID, "is_bot": True, "first_name": "OwnBot"},
                    }
                elif method == "sendMessage":
                    if mock.fail_send:
                        resp = {"ok": False, "description": "Forbidden: bot can't send to other bots"}
                    else:
                        mock.sent.append((int(fields["chat_id"]), fields["text"]))
                        resp = {
                            "ok": True,
                            "result": {"message_id": len(mock.sent), "date": now()},
                        }
                elif method == "getUpdates":
                    # Real Bot API semantics: "Updates with a numeric
                    # identifier greater than or equal to offset are
                    # returned." (The committed mock's `> offset`
                    # coincides with this because its client always
                    # starts at offset 0 with seeded ids >= 100.)
                    offset = int(fields.get("offset", "0"))
                    resp = {
                        "ok": True,
                        "result": [u for u in mock._updates if u["update_id"] >= offset],
                    }
                else:
                    resp = {"ok": False, "description": f"unknown method {method}"}
                data = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):  # silence request logging
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


@contextmanager
def api_base_env(port: int):
    """Point PTUN_TELEGRAM_API_BASE at a local mock for the `with` block
    (process-global, like the Rust test: save + restore)."""
    old = os.environ.get("PTUN_TELEGRAM_API_BASE")
    os.environ["PTUN_TELEGRAM_API_BASE"] = f"http://127.0.0.1:{port}"
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("PTUN_TELEGRAM_API_BASE", None)
        else:
            os.environ["PTUN_TELEGRAM_API_BASE"] = old


class _ChannelCase(unittest.IsolatedAsyncioTestCase):
    """Base: in-process mock + channel with the API base pointed at it."""

    async def asyncSetUp(self):
        self.mock = _MockBotApi()
        self.mock.start()
        self._env = api_base_env(self.mock.port)
        self._env.__enter__()
        self.channels: list[TelegramChannel] = []

    def new_channel(self, secret: str | None = SECRET) -> TelegramChannel:
        ch = make_channel(secret=secret)
        self.channels.append(ch)
        return ch

    async def asyncTearDown(self):
        for ch in self.channels:
            ch.close()
        self._env.__exit__(None, None, None)
        self.mock.close()

    async def _wait_for(self, cond, timeout: float = 3.0) -> None:
        """Poll until ``cond()`` is true (for background-loop bookkeeping)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cond():
                return
            await asyncio.sleep(0.02)
        raise AssertionError(f"condition not met within {timeout}s")


class TestChannelWaiters(_ChannelCase):
    async def test_start_gets_own_id(self):
        ch = self.new_channel()
        await ch.start()
        self.assertTrue(ch.started)
        self.assertEqual(ch.own_bot_id, OWN_ID)

    async def test_send_addr_records_message(self):
        ch = self.new_channel()
        await ch.start()
        await ch.send_addr(("198.51.100.9", 4433))
        self.assertEqual(self.mock.sent, [(PEER_ID, "PTUN v1 198.51.100.9:4433")])

    async def test_send_ready_and_role_record_lines(self):
        ch = self.new_channel()
        await ch.start()
        await ch.send_ready(SECRET)
        await ch.send_role("client")
        self.assertEqual(
            self.mock.sent,
            [(PEER_ID, f"{READY_PREFIX}{SECRET}"), (PEER_ID, f"{ROLE_PREFIX}client")],
        )

    async def test_wait_addr_roundtrip_ignores_echo(self):
        ch = self.new_channel()
        await ch.start()
        await ch.send_addr(("198.51.100.9", 4433))
        # The peer replies with its address; the API also redelivers our
        # own send as an update — the channel must ignore that echo.
        self.mock.enqueue(build_addr_line(("203.0.113.7", 48000)))
        self.mock.enqueue(build_addr_line(("198.51.100.9", 4433)), from_id=OWN_ID)
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.7", 48000))

    async def test_wait_addr_ignores_stale_line(self):
        ch = self.new_channel()
        await ch.start()
        self.mock.enqueue("PTUN v1 99.99.99.99:1", date=now() - 3600)
        self.mock.enqueue(build_addr_line(("203.0.113.7", 48000)))
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.7", 48000))
        # Only the fresh line was ever recorded.
        self.assertEqual(ch.latest["addr"].addr, ("203.0.113.7", 48000))

    async def test_wait_addr_timeout(self):
        ch = self.new_channel()
        await ch.start()
        with self.assertRaises(TelegramTimeoutError):
            await ch.wait_addr(timeout=0.4)

    async def test_wait_ready_roundtrip(self):
        ch = self.new_channel()
        await ch.start()
        await ch.send_ready(SECRET)
        self.mock.enqueue(f"PTUN READY {SECRET}")
        line = await ch.wait_ready(timeout=5)
        self.assertEqual(line.kind, "ready")
        self.assertEqual(line.secret, SECRET)

    async def test_wait_ready_ignores_wrong_secret_then_times_out(self):
        ch = self.new_channel()
        await ch.start()
        self.mock.enqueue("PTUN READY wrong-secret")
        with self.assertRaises(TelegramTimeoutError):
            await ch.wait_ready(timeout=0.4)

    async def test_wait_ready_requires_a_secret(self):
        ch = self.new_channel(secret=None)
        await ch.start()
        with self.assertRaises(TelegramError):
            await ch.wait_ready(timeout=0.4)
        ch2 = self.new_channel()
        await ch2.start()
        with self.assertRaises(TelegramError):
            await ch2.wait_ready("", timeout=0.4)

    async def test_wait_role_accepts_line(self):
        ch = self.new_channel()
        await ch.start()
        self.mock.enqueue("PTUN ROLE server")
        self.assertEqual(await ch.wait_role(grace=5), "server")

    async def test_wait_role_legacy_fallback_when_absent(self):
        # "Nothing at all ⇒ legacy fallback" — no ROLE line, no error.
        ch = self.new_channel()
        await ch.start()
        self.assertIsNone(await ch.wait_role(grace=0.3))

    async def test_wait_role_finds_line_processed_before_waiter(self):
        # The normal interleave: READY+ROLE land in one batch; the loop
        # processes the ROLE line (no waiter yet) before wait_role
        # registers. The per-kind buffer must hand it over anyway.
        ch = self.new_channel()
        await ch.start()
        self.mock.enqueue(f"PTUN READY {SECRET}")
        self.mock.enqueue("PTUN ROLE server")
        self.mock.enqueue(build_addr_line(("203.0.113.7", 48000)))
        await ch.wait_ready(timeout=5)
        self.assertEqual(await ch.wait_role(grace=5), "server")
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.7", 48000))

    async def test_late_role_line_still_recorded(self):
        # A ROLE line landing after the cross-check grace is not lost:
        # it stays recorded (buffer + latest) for the next waiter.
        ch = self.new_channel()
        await ch.start()
        self.assertIsNone(await ch.wait_role(grace=0.2))
        self.mock.enqueue("PTUN ROLE client")
        await self._wait_for(lambda: "role" in ch.latest)
        self.assertEqual(ch.latest["role"].role, "client")
        # And the next attempt's cross-check can still use it.
        self.assertEqual(await ch.wait_role(grace=5), "client")

    async def test_first_fresh_match_wins_duplicates_queued(self):
        # Two identical v1 lines: the first satisfies the waiter exactly
        # once; the duplicate is not re-triggered — it stays queued for
        # the next waiter of that kind (it is a fresh, valid line).
        ch = self.new_channel()
        await ch.start()
        self.mock.enqueue(build_addr_line(("203.0.113.7", 48000)))
        self.mock.enqueue(build_addr_line(("203.0.113.7", 48000)))
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.7", 48000))
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.7", 48000))


class TestOffsetFreshnessAcrossAttempts(_ChannelCase):
    """The Phase 8 done-when: the channel survives a simulated
    "attempt 2" with only *new* updates delivered — a line consumed by
    attempt 1 is never re-read by attempt 2."""

    async def test_attempt2_sees_only_new_lines(self):
        ch = self.new_channel()
        await ch.start()

        # --- attempt 1 -------------------------------------------------
        await ch.send_ready(SECRET)
        await ch.send_role("client")
        await ch.send_addr(("198.51.100.9", 4433))
        self.mock.enqueue(f"PTUN READY {SECRET}")
        self.mock.enqueue("PTUN ROLE server")
        self.mock.enqueue(build_addr_line(("203.0.113.7", 48000)))
        self.assertEqual((await ch.wait_ready(timeout=5)).secret, SECRET)
        self.assertEqual(await ch.wait_role(grace=5), "server")
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.7", 48000))
        offset_after_1 = ch.offset
        self.assertGreater(offset_after_1, 0)

        # --- attempt 2 (the tunnel was lost; re-negotiate) -------------
        # No new peer lines yet: the previous attempt's READY must NOT be
        # re-offered (its waiter must wait for a genuinely new one).
        waiter = asyncio.ensure_future(ch.wait_ready(timeout=2.0))
        await asyncio.sleep(0.5)
        self.assertFalse(waiter.done(), "attempt 1's READY was re-delivered to attempt 2")
        # The peer re-sends: only the new lines satisfy attempt 2's waiters.
        self.mock.enqueue(f"PTUN READY {SECRET}")
        self.mock.enqueue(build_addr_line(("203.0.113.8", 48000)))
        self.assertEqual((await waiter).secret, SECRET)
        # No new ROLE line this time → legacy fallback, not an error.
        self.assertIsNone(await ch.wait_role(grace=0.3))
        self.assertEqual(await ch.wait_addr(timeout=5), ("203.0.113.8", 48000))
        # The offset advanced past the new lines (no re-read on attempt 3).
        self.assertGreater(ch.offset, offset_after_1)


class TestErrorPaths(_ChannelCase):
    async def test_send_ok_false_raises_with_description(self):
        ch = self.new_channel()
        await ch.start()
        self.mock.fail_send = True
        with self.assertRaises(TelegramError) as cm:
            await ch.send_addr(("198.51.100.9", 4433))
        self.assertIn("Forbidden: bot can't send to other bots", str(cm.exception))
        # The bot-to-bot hint is attached to the failure.
        self.assertIn("Bot-to-Bot", str(cm.exception))

    async def test_send_ok_false_recovers_after_flag_cleared(self):
        ch = self.new_channel()
        await ch.start()
        self.mock.fail_send = True
        with self.assertRaises(TelegramError):
            await ch.send("PTUN v1 1.2.3.4:5")
        self.mock.fail_send = False
        await ch.send("PTUN v1 1.2.3.4:5")
        self.assertEqual(self.mock.sent[-1], (PEER_ID, "PTUN v1 1.2.3.4:5"))

    async def test_getme_failure_raises(self):
        ch = make_channel()
        # Point at a closed port: connection refused → TelegramError.
        with api_base_env(1):  # port 1: nothing listens
            with self.assertRaises(TelegramError) as cm:
                await ch.start()
        self.assertIn("getMe", str(cm.exception))
        ch.close()

    async def test_poll_loop_survives_getupdates_failure(self):
        # A getUpdates error must not kill the long-lived loop: after a
        # burst of failed polls (server down, then restarted on a new
        # port), the next poll still delivers updates.
        ch = self.new_channel()
        await ch.start()
        self.mock.close()  # the loop now fails its polls (connection refused)
        self.mock.start()  # same mock object, new port
        await asyncio.sleep(1.2)  # let it fail at least one poll
        # Re-point the env at the restarted server and enqueue a fresh line.
        self._env.__exit__(None, None, None)
        self._env = api_base_env(self.mock.port)
        self._env.__enter__()
        self.mock.enqueue(f"PTUN READY {SECRET}")
        line = await ch.wait_ready(timeout=10)
        self.assertEqual(line.secret, SECRET)

    async def test_empty_token_rejected(self):
        cfg = TelegramConfig(token="  ", peer_bot_id=PEER_ID)
        with self.assertRaises(TelegramError):
            TelegramChannel(cfg)


# ===========================================================================
# 3. End-to-end against the UNMODIFIED tests/telegram/mock_bot_api.py
#    (port of Rust's tests/telegram_exchange.rs).
# ===========================================================================


class TestExchangeAgainstUnmodifiedMockBotApi(unittest.IsolatedAsyncioTestCase):
    """Spawns the committed mock, points the channel at it via
    ``PTUN_TELEGRAM_API_BASE``, and runs the v1-style exchange:
    ``getMe`` → ``send`` our addr → poll → the peer's fresh addr, with
    the mock's stale line rejected and our own echo ignored."""

    def _python(self) -> str:
        return sys.executable or "python3"

    async def test_exchange(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        listener_port = self._find_free_port()
        proc = subprocess.Popen(
            [self._python(), "tests/telegram/mock_bot_api.py", str(listener_port)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        env = api_base_env(listener_port)
        try:
            await self._wait_for_port(listener_port)
            env.__enter__()
            ch = make_channel(timeout_secs=10)
            try:
                await ch.start()
                await ch.send_addr(("198.51.100.9", 4433))
                self.assertEqual(await ch.wait_addr(timeout=10), ("203.0.113.7", 48000))
            finally:
                ch.close()
                env.__exit__(None, None, None)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    @staticmethod
    def _find_free_port() -> int:
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @staticmethod
    async def _wait_for_port(port: int) -> None:
        import socket

        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                await asyncio.sleep(0.05)
        raise AssertionError(f"mock bot api did not start on port {port}")


if __name__ == "__main__":
    unittest.main()
