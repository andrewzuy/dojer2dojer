#!/usr/bin/env python3
"""Probe client for the NAT simulation.

Runs inside natB, connects to the tunnel's local TCP listener, sends
b"hello\\n", expects exactly b"PONG: hello\\n" back, then half-closes and
expects a clean EOF. Exit 0 on success.
"""

import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 14011
SEND = b"hello\n"
EXPECT = b"PONG: hello\n"

s = socket.create_connection(("127.0.0.1", PORT), timeout=15)
s.sendall(SEND)

buf = b""
while not buf.endswith(EXPECT):
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk

if buf != EXPECT:
    print(f"PROBE-FAIL: expected {EXPECT!r}, got {buf!r}", flush=True)
    sys.exit(1)
print("PROBE-OK: exact echo received", flush=True)

s.shutdown(socket.SHUT_WR)
rest = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    rest += chunk
if rest != b"":
    print(f"PROBE-FAIL: unexpected data after echo: {rest!r}", flush=True)
    sys.exit(1)
print("PROBE-EOF: clean shutdown", flush=True)
sys.exit(0)
