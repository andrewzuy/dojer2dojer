#!/usr/bin/env python3
"""Fake STUN server for the p2p-tunnel NAT simulation.

Lives in the "box" (router) netns and pretends to be two separate NATs'
egress points. For each RFC 5389 binding request it:

  1. identifies the client by its real (private) IP,
  2. replies with a *fake* public address (XOR-MAPPED-ADDRESS),
  3. programs the DNAT rule that makes that fake address actually
     reachable — i.e. it IS the NAT's port mapping, done live.

So `natA` (10.0.0.1) believes its public address is 172.16.0.1:<port> and
`natB` (10.1.0.1) believes it is 172.16.0.2:<port>, exactly as if each sat
behind its own home NAT.

Logs one line per assignment:
    ASSIGNED natA fake=172.16.0.1:<port> real=10.0.0.1:<port>
"""

import socket
import struct
import subprocess
import sys

MAGIC = 0x2112A442
LISTEN_PORT = 19302

# real (private) client IP -> (fake public IP, label)
NATS = {
    "10.0.0.1": ("172.16.0.1", "natA"),
    "10.1.0.1": ("172.16.0.2", "natB"),
}


def ip_to_int(ip: str) -> int:
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def xor_mapped_v4(ip: str, port: int) -> bytes:
    """XOR-MAPPED-ADDRESS attribute value for an IPv4 address (RFC 5389 §15.2)."""
    return struct.pack(
        ">BBHI", 0x00, 0x01, port ^ (MAGIC >> 16), ip_to_int(ip) ^ MAGIC
    )


def ensure_dnat(fake_ip: str, port: int, real_ip: str) -> None:
    """Add the NAT mapping: fake_ip:port -> real_ip:port (idempotent)."""
    base = [
        "iptables", "-t", "nat",
        "-d", fake_ip, "-p", "udp", "--dport", str(port),
        "-j", "DNAT", "--to-destination", f"{real_ip}:{port}",
    ]
    if subprocess.run(["iptables", "-t", "nat", "-C", "PREROUTING"] + base,
                      capture_output=True).returncode != 0:
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING"] + base,
                       check=True, capture_output=True)


def handle(sock: socket.socket, data: bytes, from_addr) -> None:
    if len(data) < 20:
        return
    msg_type, _length, magic = struct.unpack_from(">HHI", data, 0)
    if msg_type != 0x0001 or magic != MAGIC:  # binding request only
        return
    txn = data[8:20]
    real_ip, real_port = from_addr[0], from_addr[1]
    fake_ip, label = NATS.get(real_ip, (None, None))
    if fake_ip is None:
        print(f"STUN: ignoring request from unknown {from_addr}", flush=True)
        return

    value = xor_mapped_v4(fake_ip, real_port)
    resp = (
        struct.pack(">HHI", 0x0101, len(value) + 4, MAGIC)
        + txn
        + struct.pack(">HH", 0x0020, len(value))
        + value
    )
    sock.sendto(resp, from_addr)
    ensure_dnat(fake_ip, real_port, real_ip)
    print(f"ASSIGNED {label} fake={fake_ip}:{real_port} real={real_ip}:{real_port}",
          flush=True)


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    print(f"fake STUN server listening on 0.0.0.0:{LISTEN_PORT}", flush=True)
    while True:
        data, addr = sock.recvfrom(1500)
        try:
            handle(sock, data, addr)
        except Exception as e:  # keep serving
            print(f"STUN: error handling {addr}: {e}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
