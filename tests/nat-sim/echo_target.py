#!/usr/bin/env python3
"""TCP echo target for the NAT simulation.

Runs inside natA on 127.0.0.1 (the address the tunnel's server side is
configured to forward to). On connect it sends a banner, then echoes every
byte until the peer's write side reaches EOF.
"""

import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 14012
BANNER = b"PONG: "

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(1)
print(f"echo target listening on 127.0.0.1:{PORT}", flush=True)

conn, addr = s.accept()
print(f"accepted {addr}", flush=True)
conn.sendall(BANNER)
total = 0
while True:
    data = conn.recv(4096)
    if not data:
        break
    total += len(data)
    conn.sendall(data)
conn.close()
print(f"target closed (echoed {total} bytes)", flush=True)
