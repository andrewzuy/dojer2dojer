"""Tests for :mod:`p2p_tunnel.tunnel` (Phase 6/7: TCP↔QUIC bridge).

Ports the Rust ``tunnel.rs`` bridge tests (the two ``bridge_halves`` unit
tests) with in-memory duplex pipes standing in for the TCP/QUIC ends, plus
a loopback e2e: a real QUIC connection, ``run_client_side`` on the client,
an echo stream handler on the server — bytes round-trip through the
tunnel.

The in-memory pipe is a Python stand-in for ``tokio::io::duplex`` +
``split``: each *end* has a ``reader`` (fed by the *other* end's writer)
and a ``writer`` (feeding the *other* end's reader).
"""

from __future__ import annotations

import asyncio
import socket
import unittest

from p2p_tunnel.quic import (
    attach_client,
    attach_server,
    build_client_config,
    build_server_config,
    close_endpoint,
    connect,
    generate_self_signed_cert,
)
from p2p_tunnel.stun import UdpSocket
from p2p_tunnel.tunnel import TunnelError, bridge_halves, run_client_side


# ---------------------------------------------------------------------------
# In-memory duplex pipes
# ---------------------------------------------------------------------------


class _MemWriter:
    """Write side of an in-memory pipe: feeds the *remote* end's reader."""

    def __init__(self, remote_reader: asyncio.StreamReader) -> None:
        self._remote = remote_reader

    def write(self, data: bytes) -> None:
        self._remote.feed_data(data)

    async def drain(self) -> None:
        pass

    async def write_eof(self) -> None:
        self._remote.feed_eof()


class _MemEnd:
    """One end of a duplex pipe.

    ``reader`` is the local reader (fed by the *other* end's writer);
    ``writer`` feeds the *other* end's reader. This is the critical
    cross-wiring: writing to one end makes the bytes readable at the other
    end, never at the same end.
    """

    def __init__(self, local_reader: asyncio.StreamReader, remote_reader: asyncio.StreamReader) -> None:
        self.reader = local_reader
        self.writer = _MemWriter(remote_reader)


class _MemPipe:
    """A bidirectional in-memory pipe with two ends."""

    def __init__(self) -> None:
        self._r1 = asyncio.StreamReader()  # fed by end2's writer, read by end1
        self._r2 = asyncio.StreamReader()  # fed by end1's writer, read by end2
        self.end1 = _MemEnd(self._r1, self._r2)
        self.end2 = _MemEnd(self._r2, self._r1)


class _FailingWriter:
    """A write side whose ``drain()`` errors — for the error-propagation
    test (Rust: ``copy read_a → write_a`` context)."""

    def write(self, data: bytes) -> None:
        pass

    async def drain(self) -> None:
        raise ConnectionError("write side exploded")

    async def write_eof(self) -> None:
        pass


# ---------------------------------------------------------------------------
# bridge_halves — the two ported Rust tests + one error test
# ---------------------------------------------------------------------------


class BridgeHalvesTests(unittest.IsolatedAsyncioTestCase):
    def _pipes(self) -> tuple[_MemEnd, _MemEnd, _MemEnd, _MemEnd]:
        pipe_a = _MemPipe()
        pipe_b = _MemPipe()
        # end_a / end_b are the app-side ends; the bridge takes the other
        # halves (read + write) of each pipe.
        return pipe_a.end1, pipe_b.end1, pipe_a.end2, pipe_b.end2

    async def test_bridge_halves_moves_bytes_both_ways(self):
        end_a, end_b, half_a, half_b = self._pipes()

        # Direction A: a → b. Direction B: b → a.
        bridge = asyncio.create_task(
            bridge_halves(half_a.reader, half_b.writer, half_b.reader, half_a.writer)
        )

        end_a.writer.write(b"hello ")  # 6 bytes, A → B
        await end_a.writer.drain()
        end_b.writer.write(b"world")  # 5 bytes, B → A
        await end_b.writer.drain()

        # Deterministic: wait for both messages to actually arrive.
        self.assertEqual(await end_b.reader.readexactly(6), b"hello ")
        self.assertEqual(await end_a.reader.readexactly(5), b"world")

        # Close both write sides → both copies see EOF → bridge resolves.
        await end_a.writer.write_eof()
        await end_b.writer.write_eof()

        up, down = await asyncio.wait_for(bridge, 5)
        self.assertEqual((up, down), (6, 5))

    async def test_bridge_halves_propagates_half_close(self):
        end_a, end_b, half_a, half_b = self._pipes()

        bridge = asyncio.create_task(
            bridge_halves(half_a.reader, half_b.writer, half_b.reader, half_a.writer)
        )

        # B sends, then half-closes its write side.
        end_b.writer.write(b"bye")
        await end_b.writer.drain()
        await end_b.writer.write_eof()

        # A must see "bye" followed by EOF (bridge shut A's write side).
        self.assertEqual(await asyncio.wait_for(end_a.reader.read(), 5), b"bye")

        # A → B direction is still open and still flows.
        end_a.writer.write(b"still here")
        await end_a.writer.drain()
        self.assertEqual(await end_b.reader.readexactly(10), b"still here")

        # A half-closes → both directions done → bridge resolves.
        await end_a.writer.write_eof()
        up, down = await asyncio.wait_for(bridge, 5)
        self.assertEqual((up, down), (10, 3))

    async def test_direction_error_surfaces_with_copy_context(self):
        end_a, end_b, half_a, half_b = self._pipes()

        # Give direction B a clean EOF so gather doesn't hang on it.
        half_b.reader.feed_eof()
        # Feed direction A one chunk so it actually attempts a write to the
        # failing writer (an empty read would EOF before touching drain()).
        end_a.writer.write(b"boom")
        await end_a.writer.drain()

        with self.assertRaises(TunnelError) as ctx:
            await bridge_halves(
                half_a.reader, _FailingWriter(), half_b.reader, half_a.writer
            )
        self.assertIn("copy read_a → write_a", str(ctx.exception))
        self.assertIn("write side exploded", str(ctx.exception))


# ---------------------------------------------------------------------------
# Loopback e2e: run_client_side ↔ echo stream over a real QUIC connection
# ---------------------------------------------------------------------------


class ClientSideE2ETests(unittest.IsolatedAsyncioTestCase):
    async def _free_tcp_port(self) -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def test_client_side_echo_over_real_quic(self):
        server_sock = await UdpSocket.create()
        client_sock = await UdpSocket.create()
        server_port = server_sock.local_port

        cert_der, key, _ = generate_self_signed_cert()

        # NOTE: aioquic calls the stream handler SYNCHRONOUSLY
        # (quic_event_received → self._stream_handler(reader, writer)), so
        # this must be a plain function that spawns the echo task — not an
        # async def (whose coroutine would be created and never awaited).
        def on_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            async def echo() -> None:
                try:
                    while True:
                        data = await reader.read(65_536)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        writer.write_eof()
                    except Exception:
                        pass

            asyncio.create_task(echo())

        server = await attach_server(
            server_sock.into_raw(),
            config=build_server_config(cert_der, key),
            stream_handler=on_stream,
        )
        client = await attach_client(
            client_sock.into_raw(), config=build_client_config()
        )
        try:
            await connect(client, ("127.0.0.1", server_port), timeout=10)

            tcp_port = await self._free_tcp_port()
            runner = asyncio.create_task(run_client_side(client, tcp_port))

            # Connect to the local tunnel port (retry: the runner task may
            # not have bound yet).
            reader: asyncio.StreamReader | None = None
            writer: asyncio.StreamWriter | None = None
            for _ in range(100):
                try:
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", tcp_port
                    )
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            self.assertIsNotNone(reader, "could not connect to local tunnel port")
            assert writer is not None

            payload = b"hello tunnel"
            writer.write(payload)
            await writer.drain()
            got = await asyncio.wait_for(reader.readexactly(len(payload)), 10)
            self.assertEqual(got, payload)

            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 5)

            # QUIC connection closes → run_client_side must return (the
            # local TCP listener is stopped).
            close_endpoint(client)
            await asyncio.wait_for(runner, 10)
        finally:
            close_endpoint(server)
            try:
                await asyncio.wait_for(client.wait_closed(), 5)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
