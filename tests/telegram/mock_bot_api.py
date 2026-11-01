"""Mock Telegram Bot API server for smoke-testing p2p-tunnel's telegram module.

Serves the three endpoints the client uses:
  POST /bot<token>/getMe          -> ok, result {id: OWN_ID}
  POST /bot<token>/sendMessage    -> ok, result {...}  (logs the payload)
  POST /bot<token>/getUpdates     -> first call: empty; after that: the
                                     preconfigured peer message, then empty.

Run: python3 tests/telegram/mock_bot_api.py <port>
"""
import http.server
import json
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
OWN_ID = 1001          # this bot's id (echo sender)
PEER_ID = 9001         # the peer bot's id
PEER_ADDR = "203.0.113.7:48000"

# Stale messages already in the queue when the run starts. The client must
# drain and discard these (via offset) and never treat them as a fresh peer
# address — this is the regression the backlog-reset fix addresses.
STALE = [
    {"update_id": 100, "message": {
        "message_id": 1,
        "from": {"id": PEER_ID, "is_bot": True, "username": "peer_bot"},
        "chat": {"id": OWN_ID, "type": "private"},
        "text": "PTUN v1 99.99.99.99:1",   # stale, must be ignored
    }},
]
# The peer's fresh address arrives *after* the run starts. Its update_id is
# strictly higher than every stale one (real Telegram ids are monotonic), so
# it survives the client's backlog reset and is the one that must be accepted.
FRESH = {
    "update_id": 102, "message": {
        "message_id": 2,
        "from": {"id": PEER_ID, "is_bot": True, "username": "peer_bot"},
        "chat": {"id": OWN_ID, "type": "private"},
        "text": f"PTUN v1 {PEER_ADDR}",
    }
}
# Our own echoed send, which the client must ignore (loop safety).
ECHO = {
    "update_id": 103, "message": {
        "message_id": 3,
        "from": {"id": OWN_ID, "is_bot": True, "username": "own_bot"},
        "chat": {"id": PEER_ID, "type": "private"},
        "text": "PTUN v1 198.51.100.9:4433",
    }
}

# The full, time-ordered queue: stale backlog, then (once the peer "starts
# up") the fresh peer msg + our echo. The client only sees entries whose
# update_id > the offset it passes.
QUEUE = STALE + [FRESH, ECHO]

state = {"peer_started": False}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = self.rfile.read(length).decode() if length else ""
        fields = {}
        for part in form.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k] = v

        path = self.path
        if path.endswith("/getMe"):
            print(f"  getMe -> id {OWN_ID}", flush=True)
            self._send({"ok": True, "result": {"id": OWN_ID, "is_bot": True, "username": "own_bot"}})
        elif path.endswith("/sendMessage"):
            print(f"  sendMessage chat_id={fields.get('chat_id')} text={fields.get('text')!r}", flush=True)
            if fields.get("chat_id") == str(PEER_ID):
                # The peer sees our send and starts up, posting its address.
                state["peer_started"] = True
                self._send({"ok": True, "result": {"message_id": 1}})
            else:
                self._send({"ok": False, "description": "chat not found"})
        elif path.endswith("/getUpdates"):
            offset = int(fields.get("offset", "0") or 0)
            # Simulate the peer starting up after the first poll: before the
            # client has sent its own address, only the stale backlog exists.
            if not state["peer_started"]:
                visible = [u for u in STALE if u["update_id"] > offset]
            else:
                visible = [u for u in QUEUE if u["update_id"] > offset]
            print(f"  getUpdates offset={offset} -> {len(visible)} upd", flush=True)
            self._send({"ok": True, "result": visible})
        else:
            print(f"  ??? {path}", flush=True)
            self._send({"ok": False, "description": "unknown method"})


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
