"""Deterministic two-bot Telegram Bot API mock (a pure relay, no fixtures).

Two bot identities share one chat room: a ``sendMessage`` from bot A to
bot B's id enqueues a fresh update (monotonic ``update_id``, current
``date``) into B's ``getUpdates`` queue — and vice versa. Nothing is
seeded and nothing is scripted: whatever one bot says is exactly what the
peer bot receives (real Bot-to-Bot semantics, as in the two-phone
deployment). This is the Phase 10/14 loopback counterpart of
``mock_bot_api.py`` (which seeds a single client's queue with fixtures).

Standalone (drives two local ``p2p-tunnel`` processes):

    python3 tests/telegram/mock_two_bot_api.py [port]      # default 8932
    # then in each side's config [telegram]:
    #     api base via env: PTUN_TELEGRAM_API_BASE=http://127.0.0.1:8932
    #     token = "1001" (A) / "1002" (B); peer_bot_id = the other id

In-process (for the Phase 14 e2e tests):

    api = TwoBotApi(); api.start()          # binds 127.0.0.1:0 (ephemeral)
    ...                                     # point both channels at api.api_base()
    api.stop()

Offset semantics match the real Bot API: ``getUpdates(offset=N)`` returns
updates with ``update_id > N``.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOT_A_ID = 1001
BOT_B_ID = 1002
DEFAULT_PORT = 8932


class TwoBotApi:
    """The relay: one per-bot update queue + a stdlib HTTP server."""

    def __init__(self, bot_a: int = BOT_A_ID, bot_b: int = BOT_B_ID) -> None:
        self.bot_a = bot_a
        self.bot_b = bot_b
        self._bot_ids = (bot_a, bot_b)
        self._queues: dict[int, list[dict]] = {bot_a: [], bot_b: []}
        self._next_id = 0
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int | None = None

    # -- the relay ---------------------------------------------------------

    def enqueue(self, from_bot: int, to_bot: int, text: str) -> None:
        self.enqueue_batch(from_bot, to_bot, [text])

    def enqueue_batch(self, from_bot: int, to_bot: int, texts: list[str]) -> None:
        """Commit several messages atomically (one notify at the end) —
        the deterministic counterpart of "both commits land before the
        receiver's long-poll check"."""
        with self._cond:
            for text in texts:
                self._next_id += 1
                self._queues[to_bot].append(
                    {
                        "update_id": self._next_id,
                        "message": {
                            "message_id": self._next_id,
                            "from": {"id": from_bot, "is_bot": True, "first_name": f"bot{from_bot}"},
                            "chat": {"id": to_bot, "type": "private"},
                            "date": int(time.time()),
                            "text": text,
                        },
                    }
                )
            self._cond.notify_all()

    def updates_since(self, bot_id: int, offset: int) -> list[dict]:
        with self._lock:
            return [u for u in self._queues[bot_id] if u["update_id"] > offset]

    def updates_since_blocking(self, bot_id: int, offset: int, deadline: float) -> list[dict]:
        """The long-poll the real API does: if nothing is new yet, hold up
        to ``deadline`` (monotonic) for an update to arrive."""
        while True:
            with self._cond:
                updates = [u for u in self._queues[bot_id] if u["update_id"] > offset]
            if updates:
                return updates
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return []
            with self._cond:
                self._cond.wait(timeout=min(remaining, 0.5))

    def queue_depth(self, bot_id: int) -> int:
        with self._lock:
            return len(self._queues[bot_id])

    # -- the server --------------------------------------------------------

    def api_base(self) -> str:
        if self.port is None:
            raise RuntimeError("TwoBotApi.start() not called")
        return f"http://127.0.0.1:{self.port}"

    def start(self, host: str = "127.0.0.1", port: int = 0) -> "TwoBotApi":
        if self._server is not None:
            raise RuntimeError("already started")
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # keep the log clean
                pass

            def do_POST(self) -> None:  # noqa: N802 (http.server API)
                # /bot<token>/<method> — the token is glued onto "bot"
                parts = self.path.lstrip("/").split("/", 1)
                if len(parts) != 2 or not parts[0].startswith("bot"):
                    self._reply({"ok": False, "description": "not found"})
                    return
                token = parts[0][len("bot"):]
                if token not in (str(api.bot_a), str(api.bot_b)):
                    self._reply({"ok": False, "description": "not found"})
                    return
                bot_id = int(token)
                method = parts[1]
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length).decode("utf-8", "replace")
                fields: dict[str, str] = {}
                for pair in body.split("&"):
                    if not pair:
                        continue
                    k, _, v = pair.partition("=")
                    fields[k] = urllib.parse.unquote_plus(v)  # '+' is a space (form encoding)
                if method == "getMe":
                    self._reply(
                        {
                            "ok": True,
                            "result": {
                                "id": bot_id,
                                "is_bot": True,
                                "first_name": f"bot{bot_id}",
                                "username": f"ptun_{bot_id}",
                            },
                        }
                    )
                elif method == "sendMessage":
                    to_raw = fields.get("chat_id", "")
                    text = fields.get("text", "")
                    if to_raw not in (str(api.bot_a), str(api.bot_b)) or int(to_raw) == bot_id:
                        self._reply({"ok": False, "description": "chat not found"})
                        return
                    api.enqueue_batch(bot_id, int(to_raw), [text])
                    self._reply(
                        {
                            "ok": True,
                            "result": {
                                "message_id": api.queue_depth(int(to_raw)),
                                "from": {"id": bot_id, "is_bot": True},
                                "chat": {"id": int(to_raw), "type": "private"},
                                "date": int(time.time()),
                                "text": text,
                            },
                        }
                    )
                elif method == "getUpdates":
                    offset = int(fields.get("offset", "0") or "0")
                    # Emulate the real long-poll, capped at 5s (the client's
                    # own http_timeout is GET_UPDATES_TIMEOUT_SECS + 30).
                    raw_timeout = int(fields.get("timeout", "0") or "0")
                    deadline = time.monotonic() + min(max(raw_timeout, 0), 5)
                    updates = api.updates_since_blocking(bot_id, offset, deadline)
                    self._reply({"ok": True, "result": updates})
                else:
                    self._reply({"ok": False, "description": f"unknown method {method}"})

            def _reply(self, payload: dict) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._server = ThreadingHTTPServer((host, port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="two-bot-mock", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        self.port = None


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    api = TwoBotApi()
    api.start(port=port)
    print(
        f"two-bot mock listening on {api.api_base()} "
        f"(bots {BOT_A_ID} / {BOT_B_ID}; tokens are the bot ids)",
        flush=True,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        api.stop()


if __name__ == "__main__":
    main()
