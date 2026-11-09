"""Tests for :mod:`p2p_tunnel.stun`.

The seven unit tests are a direct port of the Rust ``stun.rs`` test suite
(branch ``main``); the async tests exercise :func:`discover_public_addr`
end-to-end on loopback against an in-test responder that mirrors the reply
logic of ``tests/nat-sim/stun_server.py`` (which itself only answers the
netns-sim client IPs, so a loopback test needs its own responder).
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import unittest

from p2p_tunnel.stun import (
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    MSG_BINDING_REQUEST,
    MSG_BINDING_RESPONSE,
    MSG_BINDING_ERROR,
    STUN_MAGIC_COOKIE,
    UdpSocket,
    discover_public_addr,
    encode_binding_request,
    parse_binding_response,
    resolve_server,
    StunError,
    StunMalformed,
    StunRejected,
)


def make_response(txn: bytes, attr_type: int, value: bytes) -> bytes:
    """Build a binding response carrying a single attribute (Rust test helper)."""
    resp = bytearray(encode_binding_request(txn))
    resp[0:2] = MSG_BINDING_RESPONSE.to_bytes(2, "big")
    resp[2:4] = (4 + len(value)).to_bytes(2, "big")
    resp += attr_type.to_bytes(2, "big")
    resp += len(value).to_bytes(2, "big")
    resp += value
    return bytes(resp)


def xor_mapped_value_v4(ip: str, port: int) -> bytes:
    return struct.pack(
        ">BBHI",
        0,
        0x01,
        port ^ (STUN_MAGIC_COOKIE >> 16),
        int.from_bytes(socket.inet_aton(ip), "big") ^ STUN_MAGIC_COOKIE,
    )


class EncodeTests(unittest.TestCase):
    def test_encodes_binding_request(self):
        txn = bytes([7] * 12)
        req = encode_binding_request(txn)
        self.assertEqual(req[0:2], MSG_BINDING_REQUEST.to_bytes(2, "big"))
        self.assertEqual(req[2:4], (0).to_bytes(2, "big"))
        self.assertEqual(req[4:8], STUN_MAGIC_COOKIE.to_bytes(4, "big"))
        self.assertEqual(req[8:20], txn)
        self.assertEqual(len(req), 20)

    def test_rejects_wrong_txn_length(self):
        with self.assertRaises(ValueError):
            encode_binding_request(b"\x00" * 11)


class ParseTests(unittest.TestCase):
    def test_parses_xor_mapped_response_v4(self):
        txn = bytes([3] * 12)
        resp = make_response(txn, ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value_v4("93.184.216.34", 12345))
        self.assertEqual(parse_binding_response(resp, txn), ("93.184.216.34", 12345))

    def test_parses_plain_mapped_response_v4(self):
        txn = bytes([3] * 12)
        value = struct.pack(">BBHI", 0, 0x01, 1234, int.from_bytes(socket.inet_aton("192.0.2.1"), "big"))
        resp = make_response(txn, ATTR_MAPPED_ADDRESS, value)
        self.assertEqual(parse_binding_response(resp, txn), ("192.0.2.1", 1234))

    def test_parses_xor_mapped_response_v6(self):
        txn = bytes([5] * 12)
        ip = "2001:db8::42"
        # RFC 5389: v6 addresses XOR against the 16-byte key magic||txn.
        key = STUN_MAGIC_COOKIE.to_bytes(4, "big") + txn
        addr_octets = socket.inet_pton(socket.AF_INET6, ip)
        value = struct.pack(">BBH", 0, 0x02, 443 ^ (STUN_MAGIC_COOKIE >> 16))
        value += bytes(a ^ b for a, b in zip(addr_octets, key))
        resp = make_response(txn, ATTR_XOR_MAPPED_ADDRESS, value)
        self.assertEqual(parse_binding_response(resp, txn), (ip, 443))

    def test_skips_unknown_attrs_and_finds_mapped_later(self):
        txn = bytes([3] * 12)
        # Two attributes: an unknown one, then the mapped address.
        attrs = 0x8022.to_bytes(2, "big") + (2).to_bytes(2, "big") + b"\xAA\xBB" + b"\x00\x00"
        value = xor_mapped_value_v4("10.1.2.3", 99)
        attrs += ATTR_XOR_MAPPED_ADDRESS.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
        resp = bytearray(encode_binding_request(txn))
        resp[0:2] = MSG_BINDING_RESPONSE.to_bytes(2, "big")
        resp[2:4] = len(attrs).to_bytes(2, "big")
        resp += attrs
        self.assertEqual(parse_binding_response(bytes(resp), txn), ("10.1.2.3", 99))

    def test_rejects_wrong_transaction_id(self):
        txn = bytes([3] * 12)
        resp = make_response(txn, ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value_v4("1.2.3.4", 1))
        with self.assertRaises(StunMalformed):
            parse_binding_response(resp, bytes([4] * 12))

    def test_rejects_non_stun_packet(self):
        with self.assertRaises(StunMalformed):
            parse_binding_response(b"\x00" * 8, bytes([3] * 12))

    def test_rejects_error_response(self):
        txn = bytes([3] * 12)
        resp = bytearray(encode_binding_request(txn))
        resp[0:2] = MSG_BINDING_ERROR.to_bytes(2, "big")
        with self.assertRaises(StunRejected):
            parse_binding_response(bytes(resp), txn)

    def test_rejects_bad_magic_cookie(self):
        txn = bytes([3] * 12)
        resp = bytearray(make_response(txn, ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value_v4("1.2.3.4", 1)))
        resp[4:8] = (0xDEADBEEF).to_bytes(4, "big")
        with self.assertRaises(StunMalformed):
            parse_binding_response(bytes(resp), txn)

    def test_rejects_response_without_mapped_attr(self):
        txn = bytes([3] * 12)
        # A valid header but a vendor attribute instead of a mapped address.
        resp = make_response(txn, 0x8022, b"\xAA\xBB\xCC\xDD\xEE")
        with self.assertRaises(StunMalformed):
            parse_binding_response(resp, txn)


class ResolveServerAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_port_applied(self):
        addrs = await resolve_server("127.0.0.1")
        self.assertEqual(addrs, [("127.0.0.1", 19302)])

    async def test_explicit_port(self):
        addrs = await resolve_server("127.0.0.1:12345")
        self.assertEqual(addrs, [("127.0.0.1", 12345)])

    async def test_bad_port(self):
        with self.assertRaises(ValueError):
            await resolve_server("127.0.0.1:notaport")

    async def test_port_out_of_range(self):
        with self.assertRaises(ValueError):
            await resolve_server("127.0.0.1:70000")

    async def test_empty_host(self):
        with self.assertRaises(ValueError):
            await resolve_server(":1234")

    async def test_unresolvable_host(self):
        with self.assertRaises(OSError):
            await resolve_server("no-such-host.invalid:19302")


class FakeStunServer(asyncio.DatagramProtocol):
    """Loopback STUN responder; reply logic mirrors tests/nat-sim/stun_server.py.

    Every client is told its public address is ``FAKE_IP`` on the same port
    it actually used — i.e. it plays the role of "the NAT's egress point".
    """

    FAKE_IP = "203.0.113.7"

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.requests = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 20:
            return
        msg_type, _length, magic = struct.unpack_from(">HHI", data, 0)
        if msg_type != MSG_BINDING_REQUEST or magic != STUN_MAGIC_COOKIE:
            return
        self.requests += 1
        txn = data[8:20]
        value = struct.pack(
            ">BBHI",
            0,
            0x01,
            addr[1] ^ (STUN_MAGIC_COOKIE >> 16),
            int.from_bytes(socket.inet_aton(self.FAKE_IP), "big") ^ STUN_MAGIC_COOKIE,
        )
        resp = (
            struct.pack(">HHI", 0x0101, len(value) + 4, STUN_MAGIC_COOKIE)
            + txn
            + ATTR_XOR_MAPPED_ADDRESS.to_bytes(2, "big")
            + len(value).to_bytes(2, "big")
            + value
        )
        assert self.transport is not None
        self.transport.sendto(resp, addr)

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None


class DiscoverAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def _start_fake_server(self) -> tuple[FakeStunServer, int]:
        protocol = FakeStunServer()
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("127.0.0.1", 0))
        transport, _ = await loop.create_datagram_endpoint(lambda: protocol, sock=sock)
        port = sock.getsockname()[1]
        return protocol, port

    async def test_discovers_public_addr_on_loopback(self):
        server, port = await self._start_fake_server()
        try:
            sock = await UdpSocket.create()
            try:
                public = await discover_public_addr(sock, [f"127.0.0.1:{port}"])
                self.assertEqual(public, (FakeStunServer.FAKE_IP, sock.local_port))
                self.assertEqual(server.requests, 1)
            finally:
                await sock.close()
        finally:
            server.close()

    async def test_ignores_stray_traffic(self):
        server, port = await self._start_fake_server()
        try:
            sock = await UdpSocket.create()
            try:
                # A stranger's datagram must be ignored, not misparsed.
                stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                stranger.sendto(b"hello, definitely not STUN", ("127.0.0.1", sock.local_port))
                stranger.close()
                public = await discover_public_addr(sock, [f"127.0.0.1:{port}"])
                self.assertEqual(public[0], FakeStunServer.FAKE_IP)
            finally:
                await sock.close()
        finally:
            server.close()

    async def test_unreachable_server_gives_actionable_error(self):
        # A port on loopback with no listener: both rounds time out.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]
        sock.close()
        udp = await UdpSocket.create()
        try:
            with self.assertRaises(StunError) as ctx:
                await discover_public_addr(
                    udp, [f"127.0.0.1:{dead_port}"], per_attempt_timeout=0.2
                )
            msg = str(ctx.exception)
            self.assertTrue(msg.startswith("STUN discovery failed:"), msg)
            self.assertIn("timed out", msg)
            self.assertIn(f"127.0.0.1:{dead_port}", msg)
        finally:
            await udp.close()

    async def test_all_servers_unresolvable(self):
        udp = await UdpSocket.create()
        try:
            with self.assertRaises(StunError) as ctx:
                await discover_public_addr(
                    udp, ["no-such-host.invalid:19302"], per_attempt_timeout=0.2
                )
            self.assertTrue(str(ctx.exception).startswith("STUN discovery failed:"))
        finally:
            await udp.close()


class UdpSocketHelperTests(unittest.IsolatedAsyncioTestCase):
    async def test_create_binds_ephemeral_port(self):
        sock = await UdpSocket.create()
        try:
            self.assertGreater(sock.local_port, 0)
            self.assertEqual(sock.local_addr[0], "0.0.0.0")
            # A round-trip through the loop.sock_* wrappers works: send to a
            # blocking echo socket (in a thread) and receive the reply.
            echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            echo.bind(("127.0.0.1", 0))
            echo_port = echo.getsockname()[1]
            try:
                await sock.send_to(b"ping", ("127.0.0.1", echo_port))
                echo_data, echo_from = await asyncio.to_thread(echo.recvfrom, 1024)
                await asyncio.to_thread(echo.sendto, echo_data, echo_from)
                data, from_addr = await asyncio.wait_for(sock.recv_from(), 2.0)
            finally:
                echo.close()
            self.assertEqual(data, b"ping")
            self.assertEqual(from_addr[0], "127.0.0.1")
            echo.close()
        finally:
            await sock.close()

    async def test_into_raw_detaches(self):
        sock = await UdpSocket.create()
        raw = sock.into_raw()
        self.assertGreater(raw.getsockname()[1], 0)
        with self.assertRaises(RuntimeError):
            sock.into_raw()
        raw.close()


class LiveStunTests(unittest.IsolatedAsyncioTestCase):
    """Real-world round-trip; run with ``PTUN_LIVE_STUN=1`` (skipped in CI)."""

    async def test_real_stun_server(self):
        if not os.environ.get("PTUN_LIVE_STUN"):
            self.skipTest("set PTUN_LIVE_STUN=1 to run the live STUN test")
        async with await UdpSocket.create() as sock:
            public = await discover_public_addr(sock, ["stun.l.google.com:19302"])
        self.assertTrue(public[0].count(".") == 3 or ":" in public[0], public)
        self.assertGreater(public[1], 0)
        print(f"\nLIVE STUN: public address is {public[0]}:{public[1]}")


if __name__ == "__main__":
    unittest.main()
