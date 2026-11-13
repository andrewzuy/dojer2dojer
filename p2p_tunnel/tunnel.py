"""TCP↔QUIC stream bridge.

Client side (Phase 6): a local TCP listener whose accepted connections
are each bridged to a fresh bidirectional QUIC stream, so
``ssh -p <port> user@127.0.0.1`` reaches the other machine's target
through the tunnel.
Server side (Phase 7): incoming QUIC streams → TCP connections to the
configured private target.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aioquic.asyncio.protocol import QuicConnectionProtocol

log = logging.getLogger(__name__)

__all__ = [
    "TunnelError",
    "bridge_halves",
    "run_client_side",
]

_CHUNK = 65_536


class TunnelError(Exception):
    """Tunnel-level error (listener bind failure, bridge direction failure)."""


async def bridge_halves(
    read_a: Any,
    write_a: Any,
    read_b: Any,
    write_b: Any,
) -> tuple[int, int]:
    """Copy bytes in both directions between two stream pairs, propagating
    half-closes.

    Rust parity for ``tunnel::bridge_halves``. Direction A: ``read_a`` →
    ``write_a``. Direction B: ``read_b`` → ``write_b``. Each direction runs
    in its own task: copy until EOF, then half-close the write side
    (``write_eof``) so the peer sees EOF. Resolves only when BOTH
    directions are done, with ``(bytes_a, bytes_b)``.

    Half-close semantics: EOF on one side does not kill the other
    direction. E.g. when the local app closes its write side (EOF on A),
    the QUIC send stream is finished (remote target sees EOF) while
    QUIC→TCP keeps flowing until the remote closes its side.

    If a direction *errors* (not just EOF), the other one keeps running
    until it completes too; in practice both copies share the same QUIC
    connection, so a dead connection fails both directions within the
    QUIC idle timeout. The first error (A before B) is what surfaces,
    matching Rust's ``tokio::join!`` + ``context`` ordering.

    ``read_*`` need ``await read(n) -> bytes`` (b"" at EOF); ``write_*``
    need ``write(data)``, ``await drain()`` and ``write_eof()`` — exactly
    the interfaces of asyncio's StreamReader/StreamWriter and aioquic's
    QUIC stream adapters, which is what makes this unit-testable with
    in-memory duplex streams. ``write_eof()`` is sync on both real
    adapters (returns None); an async adapter returning a coroutine is
    also supported, so the call works on either.
    """

    async def _copy(read: Any, write: Any, name: str) -> int:
        n = 0
        while True:
            data = await read.read(_CHUNK)
            if not data:
                break
            n += len(data)
            write.write(data)
            await write.drain()
        eof = write.write_eof()
        if asyncio.iscoroutine(eof):
            await eof
        return n

    task_a = asyncio.create_task(_copy(read_a, write_a, "read_a → write_a"))
    task_b = asyncio.create_task(_copy(read_b, write_b, "read_b → write_b"))
    results = await asyncio.gather(task_a, task_b, return_exceptions=True)
    for name, res in zip(
        ("read_a → write_a", "read_b → write_b"), results, strict=True
    ):
        if isinstance(res, BaseException):
            raise TunnelError(f"copy {name}: {res}") from res
    return int(results[0]), int(results[1])


async def run_client_side(
    protocol: QuicConnectionProtocol,
    listen_port: int,
) -> None:
    """Client side of the tunnel: expose a local TCP port through the QUIC
    connection.

    Rust parity for ``tunnel::run_client_side``. Binds
    ``127.0.0.1:<listen_port>`` (loopback only — the tunnel port is not
    exposed to the LAN) and gives every accepted TCP connection its own
    bidirectional QUIC stream, so concurrent connections (e.g. several
    ``ssh`` sessions) are independent. Runs until the QUIC connection
    closes, then returns.
    """
    tasks: set[asyncio.Task] = set()

    def _on_connect(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        log.info("new local connection; opening QUIC stream: peer=%s", peer)
        task = asyncio.create_task(
            _bridge_client_stream(protocol, reader, writer, peer)
        )
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    try:
        server = await asyncio.start_server(_on_connect, "127.0.0.1", listen_port)
    except OSError as e:
        raise TunnelError(
            f"bind local TCP listener on 127.0.0.1:{listen_port} "
            f"(is the port already in use?): {e}"
        ) from e

    log.info(
        "tunnel client listening — connect to 127.0.0.1:%d "
        "(e.g. ssh -p %d user@127.0.0.1)",
        listen_port,
        listen_port,
    )
    try:
        await protocol.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
        log.info("QUIC connection closed; stopping local TCP listener")


async def _bridge_client_stream(
    protocol: QuicConnectionProtocol,
    tcp_reader: asyncio.StreamReader,
    tcp_writer: asyncio.StreamWriter,
    peer: object,
) -> None:
    """Bridge one local TCP connection to one fresh bidirectional QUIC
    stream (client side: we open the stream).

    Resolves once both directions are finished. Errors are logged, not
    raised — one bad local connection must not take down the tunnel.
    """
    try:
        quic_reader, quic_writer = await protocol.create_stream(
            is_unidirectional=False
        )
    except Exception as e:
        log.warning(
            "tunneled connection failed: peer=%s error=open bidirectional "
            "QUIC stream: %r",
            peer,
            e,
        )
        tcp_writer.close()
        return
    try:
        up, down = await bridge_halves(
            tcp_reader, quic_writer, quic_reader, tcp_writer
        )
        log.info(
            "tunneled connection closed: peer=%s bytes_up=%d bytes_down=%d",
            peer,
            up,
            down,
        )
    except Exception as e:
        log.warning("tunneled connection failed: peer=%s error=%r", peer, e)
    finally:
        tcp_writer.close()
