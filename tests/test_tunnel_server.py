"""Tests for :mod:`p2p_tunnel.tunnel.run_server_side` (Phase 7).

Server-side bridge: each incoming QUIC stream → TCP connect to the
configured private target → bidirectional copy with half-close
propagation; unreachable target → warn + FIN (stream-level only).

**QUIC stream visibility (why the e2e tests are client-first).** A QUIC
stream is only visible to the peer after the first frame carrying its
stream ID arrives — there is no empty "OPEN" frame (quinn and aioquic
behave the same here). The server's stream handler therefore fires on
the client's *first byte*, and only then does the server connect to the
target. Every e2e test below writes before it reads — the same
client-first order as the Rust ``tests/nat-sim/probe_client.py`` drill —
because a test that waits for the target's banner before sending
anything deadlocks (the server never connects to the target without
seeing the stream).

In-memory server-side tests (no QUIC): unreachable target → FIN only;
bytes + half-close round-trip through an in-process echo target.

Real-QUIC loopback e2es:
  1. bytes round-trip through a local TCP echo target (the
     ``tests/nat-sim/echo_target.py`` behavior, in-process),
  2. unreachable target → client sees EOF (FIN), the connection and
     subsequent streams are untouched,
  3. concurrent streams are independent (two simultaneous tunnelled
     connections to the echo target).

Plus the done-when drill: ``nc`` through a loopback tunnel (a raw TCP
socket standing in for ``nc``) reaches the out-of-process
``tests/nat-sim/echo_target.py`` banner + echo.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
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
from p2p_tunnel.tunnel import ServerEndpoint, bridge_halves, run_server_side

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ECHO_TARGET = os.path.join(THIS_DIR, "nat-sim", "echo_target.py")
ECHO_BANNER = b"PONG: "


class _EchoTarget:
    """In-process stand-in for ``tests/nat-sim/echo_target.py``: on
    connect sends a banner, then echoes every byte until the peer's
    write side reaches EOF.

    Serves each connection in its own task (independent connections, like
    a real multi-client target). The real ``tests/nat-sim/echo_target.py``
    accepts a single connection; this stand-in is the multi-connection
    generalization of the same behavior.
    """

    def __init__(self) -> None:
        self.port: int | None = None
        self.echoed: list[int] = []
        self._pending: list[asyncio.Future] = []
        # Strong references to serve tasks. The event loop only keeps weak
        # references to tasks; if a serve task were garbage-collected mid-
        # execution its ``finally: writer.close()`` would still run (closing
        # the target connection) while the future is never completed, so
        # ``wait_all_done`` would hang. (Observed on CPython 3.14: the
        # concurrent-streams e2e test failed 100% without this.)
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accept_conn, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    def _accept_conn(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending.append(fut)
        task = asyncio.create_task(self._serve_conn(reader, writer, fut))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _serve_conn(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        fut: asyncio.Future,
    ) -> None:
        try:
            writer.write(ECHO_BANNER)
            await writer.drain()
            total = 0
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                total += len(data)
                writer.write(data)
                await writer.drain()
            self.echoed.append(total)
            fut.set_result(total)
        except Exception as e:
            if not fut.done():
                fut.set_exception(e)
        finally:
            writer.close()

    async def wait_all_done(self) -> None:
        """Wait until every connection the target has served has fully
        closed (EOF seen, writer closed)."""
        for fut in self._pending:
            await asyncio.wait_for(fut, 10)
        self._pending.clear()

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None


class _MemWriter:
    """Write side of an in-memory pipe: feeds the *remote* end's reader.

    Same minimal interface contract as the real adapters used by
    ``bridge_halves``: sync ``write`` + ``write_eof``, awaitable
    ``drain`` (``bridge_halves`` also accepts a sync ``write_eof``; here
    it is async, exercising that branch).
    """

    def __init__(self, remote_reader: asyncio.StreamReader) -> None:
        self._remote = remote_reader

    def write(self, data: bytes) -> None:
        self._remote.feed_data(data)

    async def drain(self) -> None:
        pass

    async def write_eof(self) -> None:
        self._remote.feed_eof()


class _MemEnd:
    """One end of a duplex pipe: ``reader`` is fed by the *other* end's
    writer; ``writer`` feeds the *other* end's reader (cross-wired)."""

    def __init__(
        self, local_reader: asyncio.StreamReader, remote_reader: asyncio.StreamReader
    ) -> None:
        self.reader = local_reader
        self.writer = _MemWriter(remote_reader)


class _MemPipe:
    """A bidirectional in-memory pipe with two ends (stands in for the
    QUIC stream pair ``run_server_side`` is handed)."""

    def __init__(self) -> None:
        self._r1 = asyncio.StreamReader()  # fed by end2's writer, read by end1
        self._r2 = asyncio.StreamReader()  # fed by end1's writer, read by end2
        self.end1 = _MemEnd(self._r1, self._r2)
        self.end2 = _MemEnd(self._r2, self._r1)


class _FakeProtocol:
    """Stand-in for the aioquic server-side ``QuicConnectionProtocol``.

    ``run_server_side`` installs the per-stream handler on it and awaits
    :meth:`wait_closed`; :meth:`close` resolves that (test teardown).
    """

    def __init__(self) -> None:
        self._stream_handler = lambda reader, writer: None  # noqa: E731
        self._closed = asyncio.Event()

    def close(self) -> None:
        self._closed.set()

    async def wait_closed(self) -> None:
        await self._closed.wait()


async def _free_tcp_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _connect_with_retry(
    port: int, retries: int = 100
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    for _ in range(retries):
        try:
            return await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
    raise AssertionError(f"could not connect to 127.0.0.1:{port}")


class _Tunnel:
    """A loopback QUIC tunnel with the server side driven by
    ``run_server_side`` toward ``target``.

    The client half is a minimal local TCP listener (one fresh QUIC
    stream per accepted connection — the test analogue of
    ``run_client_side``), so tests connect to ``tcp_port`` the way ``nc``
    or ``ssh`` would.
    """

    def __init__(self, target: tuple[str, int]) -> None:
        self.target = target
        self.tcp_port: int | None = None
        self.client: object | None = None
        self.server: object | None = None
        self.runner: asyncio.Task | None = None
        self.listener: asyncio.AbstractServer | None = None
        self.stream_tasks: set[asyncio.Task] = set()

    async def start(self) -> "_Tunnel":
        server_sock = await UdpSocket.create()
        client_sock = await UdpSocket.create()
        server_port = server_sock.local_port

        cert_der, key, _ = generate_self_signed_cert()
        endpoints: list[ServerEndpoint] = []
        self.server = await attach_server(
            server_sock.into_raw(),
            config=build_server_config(cert_der, key),
            stream_handler=lambda reader, writer: None,  # placeholder
            server_endpoints=endpoints,
        )
        self.client = await attach_client(
            client_sock.into_raw(), config=build_client_config()
        )

        conn_task = asyncio.create_task(
            connect(self.client, ("127.0.0.1", server_port), timeout=10)
        )
        # The server records the endpoint when the client's Initial packet
        # arrives. Interleave the poll with event-loop yields (an await on
        # an already-resolved future may not let other tasks run on CPython
        # 3.14's single-task-per-iteration scheduling, so use sleep).
        deadline = asyncio.get_running_loop().time() + 15
        while not endpoints:
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError("server did not record a connection endpoint")
            await asyncio.sleep(0.025)
        await conn_task

        self.tcp_port = await _free_tcp_port()

        async def _bridge_local(reader, writer):
            try:
                quic_reader, quic_writer = await self.client.create_stream(
                    is_unidirectional=False
                )
                # Local TCP → QUIC / QUIC → local TCP.
                await bridge_halves(reader, quic_writer, quic_reader, writer)
            except Exception:
                pass
            finally:
                writer.close()

        def _on_connect(reader, writer) -> None:
            task = asyncio.create_task(_bridge_local(reader, writer))
            self.stream_tasks.add(task)
            task.add_done_callback(self.stream_tasks.discard)

        self.listener = await asyncio.start_server(
            _on_connect, "127.0.0.1", self.tcp_port
        )
        self.runner = asyncio.create_task(run_server_side(endpoints[0], self.target))
        return self

    async def close(self) -> None:
        # Close the QUIC client first, but do NOT await the tunnel runner
        # here: the runner can be blocked in bridge_halves copying to/from a
        # still-open local TCP connection (whose writer only EOFs when the
        # QUIC *connection* tears down — awaiting the runner would
        # deadlock). The connection close propagates to the runner.
        close_endpoint(self.client)
        if self.listener is not None:
            self.listener.close()
            await self.listener.wait_closed()
        close_endpoint(self.server)

    def cancel_runner(self) -> None:
        """Cancel the runner + per-stream tasks (teardown after a failed
        test, where some stream may be wedged on a half-open state)."""
        for task in list(self.stream_tasks):
            task.cancel()
        if self.runner is not None and not self.runner.done():
            self.runner.cancel()

    async def reap(self) -> None:
        """Wait for the runner + per-stream tasks after teardown.

        Only valid when the data round-trip completed (so the stream
        copies are finishing and the runner unblocks on the connection
        close); otherwise use :meth:`cancel_runner`.
        """
        if self.runner is not None:
            await asyncio.wait_for(self.runner, 10)
        if self.stream_tasks:
            await asyncio.wait_for(
                asyncio.gather(*list(self.stream_tasks), return_exceptions=True), 10
            )


class ServerSideInMemTests(unittest.IsolatedAsyncioTestCase):
    """Server-side bridge without QUIC: ``run_server_side`` pointed at a
    fake protocol + an in-memory QUIC-stream stand-in, with the target
    being a real local TCP endpoint."""

    async def _start_runner(
        self, target: tuple[str, int]
    ) -> tuple[_FakeProtocol, ServerEndpoint, asyncio.Task]:
        proto = _FakeProtocol()
        endpoint = ServerEndpoint(proto)
        placeholder = proto._stream_handler
        runner = asyncio.create_task(run_server_side(endpoint, target))
        # run_server_side installs the real handler synchronously before
        # its first await; wait for that (bounded spin).
        for _ in range(1000):
            if proto._stream_handler is not placeholder:
                break
            await asyncio.sleep(0)
        self.assertIsNot(
            proto._stream_handler,
            placeholder,
            "run_server_side did not install the stream handler",
        )
        return proto, endpoint, runner

    async def test_unreachable_target_fins_stream_only(self):
        dead_port = await _free_tcp_port()
        proto, _endpoint, runner = await self._start_runner(("127.0.0.1", dead_port))
        pipe = _MemPipe()
        self._ok = False
        try:
            # The server's QUIC-stream end is end1; the fake client is
            # end2. aioquic fires the handler on the stream's first data;
            # call it directly (the in-mem stand-in for that moment).
            proto._stream_handler(pipe.end1.reader, pipe.end1.writer)
            # Target unreachable → warn + FIN: the fake client sees EOF
            # with no data, and nothing else happens to the connection.
            data = await asyncio.wait_for(pipe.end2.reader.read(), 5)
            self.assertEqual(data, b"")
            self._ok = True
        finally:
            proto.close()
            if self._ok:
                await asyncio.wait_for(runner, 5)
            else:
                runner.cancel()

    async def test_roundtrip_and_half_close_to_in_process_echo(self):
        echo = _EchoTarget()
        await echo.start()
        proto, _endpoint, runner = await self._start_runner(("127.0.0.1", echo.port))
        pipe = _MemPipe()
        self._ok = False
        try:
            proto._stream_handler(pipe.end1.reader, pipe.end1.writer)
            line = b"hello\n"
            pipe.end2.writer.write(line)
            await pipe.end2.writer.drain()
            # Banner + echo come back over the (fake) QUIC stream.
            got = await asyncio.wait_for(
                pipe.end2.reader.readexactly(len(ECHO_BANNER) + len(line)), 10
            )
            self.assertEqual(got, ECHO_BANNER + line)
            # Half-close the up direction; the echo target closes on EOF,
            # so the server FINs the return direction → fake client EOF.
            await pipe.end2.writer.write_eof()
            data = await asyncio.wait_for(pipe.end2.reader.read(), 10)
            self.assertEqual(data, b"")
            await echo.wait_all_done()
            self.assertEqual(echo.echoed, [len(line)])
            self._ok = True
        finally:
            proto.close()
            if self._ok:
                await asyncio.wait_for(runner, 5)
            else:
                runner.cancel()
            echo.close()


class ServerSideE2ETests(unittest.IsolatedAsyncioTestCase):
    async def test_bytes_roundtrip_through_echo_target(self):
        self._ok = False
        echo = _EchoTarget()
        await echo.start()
        tunnel = await _Tunnel(("127.0.0.1", echo.port)).start()
        try:
            reader, writer = await _connect_with_retry(tunnel.tcp_port)
            payload = b"hello server-side"
            # Client-first (Rust probe_client.py parity): the first byte
            # is what makes the QUIC stream visible to the server, which
            # then connects to the target — only after that can the
            # banner flow back.
            writer.write(payload)
            await writer.drain()
            got = await asyncio.wait_for(
                reader.readexactly(len(ECHO_BANNER) + len(payload)), 10
            )
            self.assertEqual(got, ECHO_BANNER + payload)

            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 5)

            await echo.wait_all_done()
            self.assertEqual(echo.echoed, [len(payload)])
            self._ok = True
        finally:
            await tunnel.close()
            if self._ok:
                await tunnel.reap()
            else:
                tunnel.cancel_runner()
            echo.close()

    async def test_unreachable_target_fin_only_connection_survives(self):
        self._ok = False
        # A port nothing listens on (bind, check free, close it).
        dead_port = await _free_tcp_port()
        tunnel = await _Tunnel(("127.0.0.1", dead_port)).start()
        try:
            # The server side cannot reach the target → FINs the stream →
            # the client sees EOF (no hang, no RST). Write one byte first:
            # the stream only becomes visible to the server once that byte
            # arrives, and the FIN lands as soon as it does.
            reader, writer = await _connect_with_retry(tunnel.tcp_port)
            writer.write(b"x")
            await writer.drain()
            with self.assertRaises(asyncio.IncompleteReadError):
                await asyncio.wait_for(reader.readexactly(1), 10)
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 5)

            # The QUIC connection itself is alive: a second stream still
            # gets FIN'd the same way (not RST'd / dropped).
            reader2, writer2 = await _connect_with_retry(tunnel.tcp_port)
            writer2.write(b"x")
            await writer2.drain()
            with self.assertRaises(asyncio.IncompleteReadError):
                await asyncio.wait_for(reader2.readexactly(1), 10)
            writer2.close()
            await asyncio.wait_for(writer2.wait_closed(), 5)
            self._ok = True
        finally:
            await tunnel.close()
            if self._ok:
                await tunnel.reap()
            else:
                tunnel.cancel_runner()

    async def test_concurrent_streams_are_independent(self):
        self._ok = False
        echo = _EchoTarget()
        await echo.start()
        tunnel = await _Tunnel(("127.0.0.1", echo.port)).start()
        try:
            # Client-first per stream: each stream is only visible to the
            # server after its first byte, so write before reading the
            # banner — and interleave, since stream 2's server-side target
            # connect is independent of stream 1's.
            r1, w1 = await _connect_with_retry(tunnel.tcp_port)
            w1.write(b"one")
            await w1.drain()
            self.assertEqual(
                await asyncio.wait_for(r1.readexactly(len(ECHO_BANNER)), 10),
                ECHO_BANNER,
            )

            r2, w2 = await _connect_with_retry(tunnel.tcp_port)
            w2.write(b"two-two")
            await w2.drain()
            self.assertEqual(
                await asyncio.wait_for(r2.readexactly(len(ECHO_BANNER)), 10),
                ECHO_BANNER,
            )

            self.assertEqual(await asyncio.wait_for(r1.readexactly(3), 10), b"one")
            self.assertEqual(await asyncio.wait_for(r2.readexactly(7), 10), b"two-two")

            w1.close()
            await asyncio.wait_for(w1.wait_closed(), 5)
            # Stream 2 keeps flowing after stream 1 closes.
            w2.write(b"still")
            await w2.drain()
            self.assertEqual(await asyncio.wait_for(r2.readexactly(5), 10), b"still")
            w2.close()
            await asyncio.wait_for(w2.wait_closed(), 5)

            await echo.wait_all_done()
            self.assertEqual(sorted(echo.echoed), [3, 12])
            self._ok = True
        finally:
            await tunnel.close()
            if self._ok:
                await tunnel.reap()
            else:
                tunnel.cancel_runner()
            echo.close()


class NcDrillTests(unittest.IsolatedAsyncioTestCase):
    """Done-when: ``nc`` through a loopback tunnel reaches the
    out-of-process ``tests/nat-sim/echo_target.py`` (banner + echo)."""

    async def test_nc_through_loopback_tunnel_reaches_echo_target(self):
        self._ok = False
        port = await _free_tcp_port()
        proc = subprocess.Popen(
            [sys.executable, ECHO_TARGET, str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        tunnel: _Tunnel | None = None
        try:
            line_wait = await asyncio.wait_for(
                asyncio.to_thread(proc.stdout.readline), 10
            )
            self.assertIn(b"listening", line_wait)

            tunnel = await _Tunnel(("127.0.0.1", port)).start()
            # "nc" = a raw TCP socket: send a line first (client-first —
            # that byte opens the stream server-side), then read the
            # banner + echo.
            reader, writer = await _connect_with_retry(tunnel.tcp_port)
            line = b"ping from nc\n"
            writer.write(line)
            await writer.drain()
            got = await asyncio.wait_for(
                reader.readexactly(len(ECHO_BANNER) + len(line)), 10
            )
            self.assertEqual(got, ECHO_BANNER + line)
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 5)
            self._ok = True
        finally:
            if tunnel is not None:
                await tunnel.close()
                if self._ok:
                    await tunnel.reap()
                else:
                    tunnel.cancel_runner()
            proc.terminate()
            proc.wait(timeout=10)
            if proc.stdout is not None:
                proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
