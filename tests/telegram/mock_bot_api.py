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

state = {"get_updates_calls": 0}


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
                self._send({"ok": True, "result": {"message_id": 1}})
            else:
                self._send({"ok": False, "description": "chat not found"})
        elif path.endswith("/getUpdates"):
            state["get_updates_calls"] += 1
            n = state["get_updates_calls"]
            if n == 1:
                # First poll: nothing yet (mirrors real crossing of messages).
                print("  getUpdates #1 -> []", flush=True)
                self._send({"ok": True, "result": []})
            else:
                # Peer has "started up" and sent its address.
                upd = {"update_id": 7, "message": {
                    "message_id": 2,
                    "from": {"id": PEER_ID, "is_bot": True, "username": "peer_bot"},
                    "chat": {"id": OWN_ID, "type": "private"},
                    "text": f"PTUN v1 {PEER_ADDR}",
                }}
                # Also include our own echoed send, which the client must ignore.
                echo = {"update_id": 8, "message": {
                    "message_id": 3,
                    "from": {"id": OWN_ID, "is_bot": True, "username": "own_bot"},
                    "chat": {"id": PEER_ID, "type": "private"},
                    "text": "PTUN v1 198.51.100.9:4433",
                }}
                print(f"  getUpdates #{n} -> peer msg + own echo", flush=True)
                self._send({"ok": True, "result": [echo, upd]})
        else:
            print(f"  ??? {path}", flush=True)
            self._send({"ok": False, "description": "unknown method"})


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
