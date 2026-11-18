"""Telegram bot-to-bot signaling — PTUN protocol v1.1 (PLAN §5.3).

This module is the second, *automatic* address-exchange channel: this
machine's bot and the peer's bot DM each other in their private bot chat,
so nobody has to copy/paste an ``ip:port`` between terminals.

Protocol (all lines are plain text, trimmed, sent by the peer bot):

* ``PTUN READY <secret>`` — "I'm up and listening". Both sides exchange
  this at T1 *before* STUN, so the TUI can say "waiting for the other
  machine" instead of a bare timeout.
* ``PTUN ROLE <client|server>`` — *new in v1.1*: the peer's
  user-selected role. A peer that sends no role line within the short
  cross-check grace is treated as a legacy v1 peer (§5.2 legacy fallback).
* ``PTUN v1 <ip:port>`` — the peer's public address (Rust v1 line,
  unchanged).

Channel model (v2 divergence from the Rust oracle): one *long-lived*
:class:`TelegramChannel` per process, owned by the pipeline. The
``getUpdates`` long-poll loop runs for the app's lifetime; each attempt
registers a waiter — :meth:`TelegramChannel.wait_ready`,
:meth:`TelegramChannel.wait_role`, :meth:`TelegramChannel.wait_addr` —
and the channel satisfies the first fresh line of the kind it needs.

Line delivery is a small per-kind FIFO: every classified line is
*recorded* in the channel's buffer the moment it is processed, and a
waiter takes the oldest buffered line of its kind at registration (or
the next one of that kind as it arrives). A line is consumed exactly
once, by the first waiter of its kind — "first fresh match wins,
duplicates ignored". This is what makes the usual interleave work:
the peer's READY+ROLE lines normally land in one batch, and even though
``wait_role`` registers only after ``wait_ready`` returned, it still
finds the already-processed ROLE line in the buffer. A line that no
waiter of its kind consumed (e.g. a ROLE line landing after the
cross-check grace, "still recorded") stays buffered and can satisfy
the next attempt's waiter — the peer's declarations are stable across
attempts. The ``offset`` cursor (max consumed ``update_id`` + 1)
separately prevents the API from ever *re-delivering* a consumed
update.

Freshness / echo / sender rules (apply to every line):

* ``message.from`` missing → ignored.
* ``from.id == own bot id`` → our own echoed send → ignored.
* ``from.is_bot`` false → human in the chat → ignored (debug log).
* ``from.id != [telegram].peer_bot_id`` → unexpected sender → warn + ignore.
* ``date > 0`` and older than 600 s → stale → warn + ignore.
* ``date == 0`` or absent (mocks) → accepted.

Blocking HTTP goes through ``loop.run_in_executor`` (urllib + stdlib
json only — no new dependency). The API base is
``https://api.telegram.org`` unless ``PTUN_TELEGRAM_API_BASE`` overrides
it (the smoke tests point it at ``tests/telegram/mock_bot_api.py``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Any

from p2p_tunnel.cli import PeerAddrError, parse_peer_addr
from p2p_tunnel.config import TelegramConfig

log = logging.getLogger(__name__)

__all__ = [
    "GET_UPDATES_TIMEOUT_SECS",
    "MAX_ADDR_AGE_SECS",
    "MAX_READY_AGE_SECS",
    "MAX_ROLE_AGE_SECS",
    "PAYLOAD_PREFIX",
    "READY_PREFIX",
    "READY_TIMEOUT_SECS",
    "ROLE_GRACE_SECS",
    "ROLE_PREFIX",
    "ROLES",
    "PeerLine",
    "TelegramChannel",
    "TelegramError",
    "TelegramTimeoutError",
    "api_base",
    "build_addr_line",
    "build_ready_line",
    "build_role_line",
    "format_addr",
    "parse_update",
]

# ---------------------------------------------------------------------------
# Protocol constants (PLAN §5.3).
# ---------------------------------------------------------------------------

#: Prefix of the v1 address line, e.g. ``PTUN v1 203.0.113.7:48000``.
PAYLOAD_PREFIX = "PTUN v1 "
#: Prefix of the readiness line, e.g. ``PTUN READY mysecret``.
READY_PREFIX = "PTUN READY "
#: Prefix of the v1.1 role line, e.g. ``PTUN ROLE server``.
ROLE_PREFIX = "PTUN ROLE "
#: Roles a ``PTUN ROLE`` line may carry (anything else is ignored with a
#: warning — garbage must not crash the exchange).
ROLES = ("client", "server")

#: ``getUpdates`` long-poll timeout, in seconds (Rust: 10).
GET_UPDATES_TIMEOUT_SECS = 10
#: Lines older than this are stale (Rust: 600 s for ready and v1; the
#: role line is subject to the same freshness rule).
MAX_READY_AGE_SECS = 600
MAX_ROLE_AGE_SECS = 600
MAX_ADDR_AGE_SECS = 600
#: How long :meth:`TelegramChannel.wait_ready` blocks for the peer's
#: READY before the attempt falls back to the manual prompt (PLAN D2).
READY_TIMEOUT_SECS = 60
#: The role cross-check grace after READY completion (PLAN §5.2): the
#: peer's ROLE line normally lands right after its READY.
ROLE_GRACE_SECS = 2
#: Safety cap on the per-kind line buffer (a flaky peer must not grow
#: it without bound); the oldest line is dropped first.
_BUFFER_CAP = 16


class TelegramError(Exception):
    """A Telegram API request failed (transport, HTTP, or ``ok=false``)."""


class TelegramTimeoutError(TelegramError):
    """The peer bot did not send the awaited line in time.

    The pipeline (PLAN D2) treats this like any other Telegram failure:
    warn, and that attempt falls back to the manual "type the address"
    prompt.
    """

    def __init__(self, peer_bot_id: int, what: str, timeout_secs: float):
        super().__init__(
            f"timed out after {timeout_secs:.0f}s waiting for the peer bot "
            f"({peer_bot_id}) to send {what}"
        )


def api_base() -> str:
    """The Telegram Bot API base URL, honouring the test override.

    ``PTUN_TELEGRAM_API_BASE`` lets the smoke tests point the client at
    ``tests/telegram/mock_bot_api.py`` instead of the real API.
    """
    base = os.environ.get("PTUN_TELEGRAM_API_BASE", "https://api.telegram.org")
    return base.rstrip("/")


# ---------------------------------------------------------------------------
# Line building (sender side).
# ---------------------------------------------------------------------------


def build_ready_line(secret: str) -> str:
    """Build the ``PTUN READY <secret>`` line."""
    return f"{READY_PREFIX}{secret.strip()}"


def build_role_line(role: str) -> str:
    """Build the ``PTUN ROLE <client|server>`` line.

    Raises ``ValueError`` for an unknown role — the role is user-selected
    at startup, so an invalid value is a bug, not peer garbage.
    """
    r = role.strip()
    if r not in ROLES:
        raise ValueError(f"unknown role {role!r} (expected one of {', '.join(ROLES)})")
    return f"{ROLE_PREFIX}{r}"


def format_addr(addr: tuple[str, int]) -> str:
    """Format ``(host, port)`` the way ``SocketAddr`` displays: IPv6
    literals are bracketed (``[2001:db8::7]:4433``), IPv4 is bare."""
    host, port = addr
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def build_addr_line(addr: tuple[str, int]) -> str:
    """Build the ``PTUN v1 <ip:port>`` line for a ``(host, port)`` pair."""
    return f"{PAYLOAD_PREFIX}{format_addr(addr)}"


# ---------------------------------------------------------------------------
# Update parsing (receiver side).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Message:
    """One Telegram message, with the fields this module cares about."""

    from_id: int | None
    is_bot: bool
    text: str | None
    date: int  # unix seconds; 0 = absent/unknown (mocks) → accepted as fresh


@dataclass(frozen=True)
class _Update:
    """One ``getUpdates`` entry."""

    update_id: int
    message: _Message | None


@dataclass(frozen=True)
class PeerLine:
    """A classified, fresh PTUN line from the peer bot.

    ``kind`` is one of ``"ready"`` / ``"role"`` / ``"addr"``; the
    corresponding field (``secret`` / ``role`` / ``addr``) is set, the
    others are ``None``.
    """

    kind: str
    update_id: int
    date: int
    secret: str | None = None
    role: str | None = None
    addr: tuple[str, int] | None = None


def _as_int(value: Any) -> int | None:
    """Best-effort integer coercion (bools are *not* ints here)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def parse_update(obj: dict) -> _Update:
    """Parse one raw ``getUpdates`` entry.

    Lenient like the Rust serde model (``#[serde(default)]``): absent
    fields default rather than fail — a weird entry must not kill the
    poll loop.
    """
    uid = _as_int(obj.get("update_id"))
    message: _Message | None = None
    raw_msg = obj.get("message")
    if isinstance(raw_msg, dict):
        from_id: int | None = None
        is_bot = False
        raw_from = raw_msg.get("from")
        if isinstance(raw_from, dict):
            from_id = _as_int(raw_from.get("id"))
            is_bot = bool(raw_from.get("is_bot", False))
        text = raw_msg.get("text")
        date = _as_int(raw_msg.get("date"))
        message = _Message(
            from_id=from_id,
            is_bot=is_bot,
            text=text if isinstance(text, str) else None,
            date=date if date is not None else 0,
        )
    return _Update(update_id=uid if uid is not None else 0, message=message)


# ---------------------------------------------------------------------------
# The long-lived channel.
# ---------------------------------------------------------------------------


@dataclass
class _Waiter:
    kind: str
    fut: asyncio.Future


class TelegramChannel:
    """One long-lived bot-to-bot channel for the process (PLAN §5.3, v2).

    Lifecycle:

    1. :meth:`start` — ``getMe`` (identifies our own bot id) + starts the
       ``getUpdates`` long-poll loop.
    2. Per attempt: :meth:`send_ready` + :meth:`send_role` (T1), then
       :meth:`wait_ready` / :meth:`wait_role` / :meth:`wait_addr`.
    3. :meth:`close` — stops the loop and fails pending waiters.

    The channel never re-delivers a consumed update: ``offset`` tracks
    the max consumed ``update_id`` + 1, so each attempt only sees lines
    sent after the previous attempt consumed them. Classified lines are
    additionally buffered per kind (FIFO, capped) so a waiter registered
    slightly late — the normal case for ``wait_role`` after
    ``wait_ready`` — still finds the line the loop already processed;
    see the module docstring for the full delivery semantics.
    """

    def __init__(self, cfg: TelegramConfig):
        self.cfg = cfg
        self.token = cfg.token.strip()
        self.peer_bot_id = cfg.peer_bot_id
        if not self.token:
            raise TelegramError("config: `[telegram].token` must not be empty")
        self.own_bot_id: int | None = None
        self.offset = 0
        #: Last classified line per kind — recorded even when no waiter
        #: was pending (e.g. a ROLE line that lands after the cross-check
        #: grace: "still recorded", PLAN §5.3). Used by the TUI/pipeline
        #: for diagnostics.
        self.latest: dict[str, PeerLine] = {}
        #: Per-kind FIFO of classified lines not yet consumed by a
        #: waiter of that kind (see module docstring).
        self._buffers: dict[str, deque[PeerLine]] = {
            "ready": deque(maxlen=_BUFFER_CAP),
            "role": deque(maxlen=_BUFFER_CAP),
            "addr": deque(maxlen=_BUFFER_CAP),
        }
        self._waiters: list[_Waiter] = []
        self._task: asyncio.Task | None = None
        self._closed = False
        self._pending_ready_secret: str | None = None

    # -- lifecycle ---------------------------------------------------------

    @property
    def started(self) -> bool:
        """Whether :meth:`start` completed (``getMe`` succeeded)."""
        return self._task is not None

    async def start(self) -> None:
        """Identify our own bot (``getMe``) and start the poll loop."""
        if self._task is not None:
            return
        self.own_bot_id = await self._get_me()
        self._task = asyncio.create_task(self._poll_loop(), name="ptun-telegram-poll")
        log.debug(
            "telegram channel started (own bot %s, peer bot %s)",
            self.own_bot_id,
            self.peer_bot_id,
        )

    def close(self) -> None:
        """Stop the poll loop and fail any pending waiters (clean shutdown)."""
        self._closed = True
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
        for w in list(self._waiters):
            if not w.fut.done():
                w.fut.cancel()
        self._waiters.clear()

    # -- sender side -------------------------------------------------------

    async def send(self, text: str) -> None:
        """Send one line to the peer bot's private chat.

        A failed send is wrapped with the two most common causes (Bot-to-
        Bot mode, wrong peer id) because that is 95% of field reports.
        """
        try:
            await self._call(
                "sendMessage",
                {"chat_id": str(self.peer_bot_id), "text": text},
                http_timeout=30,
            )
        except TelegramError as e:
            raise TelegramError(
                f"{e} — is Bot-to-Bot Communication Mode enabled for BOTH "
                f"bots in @BotFather, and is `[telegram].peer_bot_id` "
                f"({self.peer_bot_id}) really the peer bot's numeric id "
                f"(what getMe prints)?"
            ) from e

    async def send_ready(self, secret: str) -> None:
        """T1: tell the peer bot we're up (readiness handshake)."""
        await self.send(build_ready_line(secret))
        log.info("sent PTUN READY to peer bot %s", self.peer_bot_id)

    async def send_role(self, role: str) -> None:
        """T1 (v1.1): declare our user-selected role to the peer bot."""
        await self.send(build_role_line(role))
        log.info("sent PTUN ROLE %s to peer bot %s", role, self.peer_bot_id)

    async def send_addr(self, addr: tuple[str, int]) -> None:
        """T3: send our public address to the peer bot."""
        await self.send(build_addr_line(addr))
        log.info(
            "sent our address %s to peer bot %s", format_addr(addr), self.peer_bot_id
        )

    # -- receiver side: waiters (one per attempt) ---------------------------

    async def wait_ready(self, secret: str | None = None, timeout: float = READY_TIMEOUT_SECS) -> PeerLine:
        """Wait for the peer's fresh ``PTUN READY <secret>`` (T1).

        ``secret`` defaults to ``[telegram].secret``; an empty secret is a
        config error (the handshake cannot verify anything). Raises
        :class:`TelegramTimeoutError` when the peer does not confirm in
        time — the pipeline falls back to the manual prompt (PLAN D2).
        """
        want = secret if secret is not None else self.cfg.secret
        want = (want or "").strip()
        if not want:
            raise TelegramError(
                "config: `[telegram].secret` is required for the bot-to-bot "
                "readiness handshake"
            )
        self._pending_ready_secret = want
        fut = self._register("ready", secret=want)
        try:
            try:
                line = await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                raise TelegramTimeoutError(self.peer_bot_id, "PTUN READY", timeout) from None
            if line.secret != want:
                raise TelegramError("peer READY line had a mismatched secret")
            log.info("peer bot confirmed it is up — readiness handshake complete")
            return line
        finally:
            self._pending_ready_secret = None
            self._remove_waiter(fut)

    async def wait_role(self, grace: float = ROLE_GRACE_SECS) -> str | None:
        """Wait up to ``grace`` seconds for the peer's ``PTUN ROLE`` line.

        Returns ``"client"``/``"server"``, or ``None`` when no role line
        arrived in time — a legacy v1 peer (PLAN §5.2: legacy fallback,
        no error). A ROLE line already recorded in the channel's buffer
        (e.g. one that landed after a previous attempt's grace) is used
        immediately.
        """
        fut = self._register("role")
        try:
            try:
                line = await asyncio.wait_for(fut, grace)
            except asyncio.TimeoutError:
                return None
            log.info("peer declared role %r", line.role)
            return line.role
        finally:
            self._remove_waiter(fut)

    async def wait_addr(self, timeout: float | None = None) -> tuple[str, int]:
        """Wait for the peer's fresh ``PTUN v1`` line (T3).

        ``timeout`` defaults to ``[telegram].timeout_secs``. Raises
        :class:`TelegramTimeoutError` when the peer does not show up in
        time — the pipeline falls back to the manual prompt (PLAN D2).
        """
        if timeout is None:
            timeout = self.cfg.timeout_secs
        fut = self._register("addr")
        try:
            try:
                line = await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                raise TelegramTimeoutError(self.peer_bot_id, "PTUN v1 address", timeout) from None
            assert line.addr is not None  # dispatch only sets addr waiters with addr lines
            log.info("received peer address %s via telegram", format_addr(line.addr))
            return line.addr
        finally:
            self._remove_waiter(fut)

    # -- classification (shared by the poll loop and the test suite) --------

    def classify(self, update: _Update, ready_secret: str | None = None) -> PeerLine | None:
        """Classify one ``getUpdates`` entry against the PTUN v1.1 rules.

        Returns a :class:`PeerLine` for a fresh, valid line from the peer
        bot, else ``None`` (ignored, with a warning for the
        operator-visible cases: unexpected sender, stale line, malformed
        payload, mismatched secret).

        ``ready_secret``, when given, is what a ``PTUN READY`` line must
        carry; a mismatch is warned and ignored. When it is ``None``,
        ready lines are accepted as-is (the caller decides).
        """
        msg = update.message
        if msg is None:
            return None
        if msg.from_id is None:
            return None
        if msg.from_id == self.own_bot_id:
            return None  # our own echoed send
        if not msg.is_bot:
            log.debug("ignoring non-bot message in the signaling chat")
            return None
        if msg.from_id != self.peer_bot_id:
            log.warning(
                "ignoring PTUN message from unexpected sender %s (expected peer bot %s)",
                msg.from_id,
                self.peer_bot_id,
            )
            return None
        text = (msg.text or "").strip()
        # Staleness (shared by all kinds): date 0 = unknown → accepted.
        if msg.date > 0:
            age = _now_secs() - msg.date
            max_age = self._max_age_for(text)
            if age > max_age:
                log.warning("ignoring stale PTUN line (age %ss > %ss)", age, max_age)
                return None
        if text.startswith(READY_PREFIX):
            secret = text[len(READY_PREFIX) :].strip()
            if not secret:
                log.warning("ignoring PTUN READY line with an empty secret")
                return None
            if ready_secret is not None and secret != ready_secret:
                log.warning("ignoring PTUN READY line with a mismatched secret")
                return None
            return PeerLine(kind="ready", update_id=update.update_id, date=msg.date, secret=secret)
        if text.startswith(ROLE_PREFIX):
            role = text[len(ROLE_PREFIX) :].strip()
            if role not in ROLES:
                log.warning("ignoring PTUN ROLE line with unknown role %r", role)
                return None
            return PeerLine(kind="role", update_id=update.update_id, date=msg.date, role=role)
        if text.startswith(PAYLOAD_PREFIX):
            body = text[len(PAYLOAD_PREFIX) :]
            try:
                addr = parse_peer_addr(body)
            except PeerAddrError as e:
                log.warning("ignoring malformed PTUN payload: %s: %s", text, e)
                return None
            return PeerLine(kind="addr", update_id=update.update_id, date=msg.date, addr=addr)
        return None  # not a PTUN line

    @staticmethod
    def _max_age_for(text: str) -> int:
        if text.startswith(READY_PREFIX):
            return MAX_READY_AGE_SECS
        if text.startswith(ROLE_PREFIX):
            return MAX_ROLE_AGE_SECS
        return MAX_ADDR_AGE_SECS

    # -- poll loop internals --------------------------------------------------

    def _process_update(self, upd: _Update) -> None:
        """Consume one update: advance the offset, classify, buffer, dispatch."""
        if upd.update_id + 1 > self.offset:
            self.offset = upd.update_id + 1
        ready_secret = self._pending_ready_secret
        if ready_secret is None:
            cfg_secret = (self.cfg.secret or "").strip()
            ready_secret = cfg_secret or None
        line = self.classify(upd, ready_secret=ready_secret)
        if line is None:
            return
        self.latest[line.kind] = line
        self._buffers[line.kind].append(line)
        self._dispatch(line.kind)

    def _dispatch(self, kind: str) -> None:
        """Hand the oldest acceptable buffered line to the first pending
        waiter of this kind ("first fresh match wins")."""
        for w in list(self._waiters):
            if w.kind != kind or w.fut.done():
                continue
            line = self._take_buffered(kind, secret=self._pending_ready_secret if kind == "ready" else None)
            if line is not None:
                w.fut.set_result(line)
            return  # only the first pending waiter may take a line

    def _take_buffered(self, kind: str, secret: str | None) -> PeerLine | None:
        """Remove and return the oldest buffered line of ``kind`` (a
        ready line must also carry ``secret`` when given)."""
        buf = self._buffers[kind]
        for i, line in enumerate(buf):
            if kind == "ready" and secret is not None and line.secret != secret:
                continue
            del buf[i]
            return line
        return None

    async def _poll_loop(self) -> None:
        log.debug(
            "getUpdates poll loop started (peer_bot_id=%s, timeout=%ss)",
            self.peer_bot_id,
            GET_UPDATES_TIMEOUT_SECS,
        )
        while not self._closed:
            try:
                updates = await self._fetch_updates()
            except TelegramError as e:
                if self._closed:
                    return
                log.warning("getUpdates failed; retrying: %s", e)
                await asyncio.sleep(1.0)
                continue
            if self._closed:
                return
            for upd in updates:
                if self._closed:
                    return
                self._process_update(upd)

    async def _fetch_updates(self) -> list[_Update]:
        result = await self._call(
            "getUpdates",
            {
                "offset": str(self.offset),
                "timeout": str(GET_UPDATES_TIMEOUT_SECS),
                "allowed_updates": json.dumps(["message"]),
            },
            # Generous client-side guard: the server long-polls for
            # GET_UPDATES_TIMEOUT_SECS, allow slack on top.
            http_timeout=GET_UPDATES_TIMEOUT_SECS + 30,
        )
        if result is None:
            return []
        if not isinstance(result, list):
            raise TelegramError("getUpdates returned a non-list result")
        return [parse_update(u) for u in result if isinstance(u, dict)]

    # -- waiter bookkeeping ----------------------------------------------------

    def _register(self, kind: str, secret: str | None = None) -> asyncio.Future:
        """Register a waiter and claim an already-buffered line, if any.

        No ``await`` between the buffer check and the registration, so
        the poll loop (same event loop) cannot interleave: a line is
        either already in the buffer (claimed here) or it will arrive
        later (delivered by :meth:`_dispatch`).
        """
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._waiters.append(_Waiter(kind=kind, fut=fut))
        line = self._take_buffered(kind, secret=secret)
        if line is not None:
            fut.set_result(line)
        return fut

    def _remove_waiter(self, fut: asyncio.Future) -> None:
        for w in list(self._waiters):
            if w.fut is fut:
                self._waiters.remove(w)
                return

    # -- HTTP plumbing -------------------------------------------------------

    async def _get_me(self) -> int:
        result = await self._call("getMe", {}, http_timeout=10)
        if not isinstance(result, dict):
            raise TelegramError("getMe returned no result object")
        bot_id = _as_int(result.get("id"))
        if bot_id is None:
            raise TelegramError(f"getMe returned no result.id (result={result!r})")
        log.debug("identified our own bot: %s", bot_id)
        return bot_id

    async def _call(self, method: str, fields: dict[str, str], http_timeout: float) -> Any:
        """POST one Bot API method (blocking urllib in an executor)."""
        url = f"{api_base()}/bot{self.token}/{method}"
        loop = asyncio.get_running_loop()
        try:
            value = await loop.run_in_executor(
                None, _http_post_sync, url, fields, http_timeout
            )
        except TelegramError:
            raise
        except Exception as e:  # URLError, socket.timeout, OSError, ...
            raise TelegramError(f"{method}: {e}") from e
        if not isinstance(value, dict):
            raise TelegramError(f"{method}: bad response (not a JSON object)")
        if value.get("ok") is not True:
            desc = value.get("description") or "(no description)"
            raise TelegramError(f"{method}: {desc}")
        return value.get("result")


def _now_secs() -> int:
    return int(time.time())


def _http_post_sync(url: str, fields: dict[str, str], timeout: float) -> Any:
    """Blocking form-encoded POST + JSON decode (runs in an executor)."""
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise TelegramError(f"HTTP {e.code} from the Telegram API: {body or e.reason}") from e
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise TelegramError(f"bad JSON from the Telegram API: {e}") from e
