"""Tests for :mod:`p2p_tunnel.punch`.

Direct port of the three Rust ``punch.rs`` tests (timeouts already small in
the Rust suite; the timeout test runs at 1 s as in Rust).
"""

from __future__ import annotations

import asyncio
import socket
import unittest

from p2p_tunnel.punch import PunchError, PunchTimeout, punch
from p2p_tunnel.stun import UdpSocket


class PunchTests(unittest.IsolatedAsyncioTestCase):
    async def test_punch_succeeds_when_peer_sends(self):
        sock = await UdpSocket.create()
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(("127.0.0.1", 0))
        peer_addr = ("127.0.0.1", peer.getsockname()[1])
        my_port = sock.local_port

        # Fake peer: waits a bit (so our punch packets are "in flight"),
        # then sends us a packet — as a real peer would once its NAT lets us in.
        async def fake_peer():
            await asyncio.sleep(0.12)
            peer.sendto(b"hello from peer", ("127.0.0.1", my_port))

        peer_task = asyncio.create_task(fake_peer())
        try:
            await asyncio.wait_for(punch(sock, peer_addr, interval_ms=50, timeout_secs=5), 10)
        finally:
            peer.close()
            peer_task.cancel()
            await asyncio.gather(peer_task, return_exceptions=True)
            await sock.close()

    async def test_punch_ignores_other_senders(self):
        sock = await UdpSocket.create()
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(("127.0.0.1", 0))
        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stranger.bind(("127.0.0.1", 0))
        peer_addr = ("127.0.0.1", peer.getsockname()[1])
        my_port = sock.local_port

        async def fake_stranger():
            await asyncio.sleep(0.05)
            stranger.sendto(b"not you", ("127.0.0.1", my_port))

        async def fake_peer():
            await asyncio.sleep(0.15)
            peer.sendto(b"the real one", ("127.0.0.1", my_port))

        stranger_task = asyncio.create_task(fake_stranger())
        peer_task = asyncio.create_task(fake_peer())
        try:
            # Should ignore the stranger's packet and succeed on the peer's.
            await asyncio.wait_for(punch(sock, peer_addr, interval_ms=50, timeout_secs=5), 10)
        finally:
            stranger.close()
            peer.close()
            for t in (stranger_task, peer_task):
                t.cancel()
            await asyncio.gather(stranger_task, peer_task, return_exceptions=True)
            await sock.close()

    async def test_punch_times_out_without_peer(self):
        sock = await UdpSocket.create()
        try:
            # 127.0.0.1:9 (discard) never answers.
            with self.assertRaises(PunchTimeout) as ctx:
                await punch(sock, ("127.0.0.1", 9), interval_ms=50, timeout_secs=1)
            self.assertIn("timed out", str(ctx.exception))
            self.assertIn("127.0.0.1:9", str(ctx.exception))
            self.assertIn("punch packets", str(ctx.exception))
        finally:
            await sock.close()

    async def test_timeout_error_reports_packets_sent(self):
        sock = await UdpSocket.create()
        try:
            with self.assertRaises(PunchTimeout) as ctx:
                # 200 ms interval, 0.5 s timeout → a handful of packets.
                await punch(sock, ("127.0.0.1", 9), interval_ms=200, timeout_secs=0.5)
            self.assertRegex(str(ctx.exception), r"sent [1-9]\d* punch packets")
        finally:
            await sock.close()

    async def test_peer_packet_arriving_before_first_recv_is_still_seen(self):
        # The peer answers almost immediately; the first punch is sent at
        # once, so the reply can land before the first recv starts.
        sock = await UdpSocket.create()
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(("127.0.0.1", 0))
        peer_addr = ("127.0.0.1", peer.getsockname()[1])

        async def eager_peer():
            data, from_addr = await asyncio.to_thread(peer.recvfrom, 64)  # our punch
            peer.sendto(b"right back", from_addr)

        peer_task = asyncio.create_task(eager_peer())
        try:
            await asyncio.wait_for(punch(sock, peer_addr, interval_ms=50, timeout_secs=5), 10)
        finally:
            peer.close()
            peer_task.cancel()
            await asyncio.gather(peer_task, return_exceptions=True)
            await sock.close()


if __name__ == "__main__":
    unittest.main()
