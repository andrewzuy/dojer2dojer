"""UDP hole punching.

Port of ``src/punch.rs`` (Rust reference, branch ``main``). We send a small
UDP packet (with a random session nonce) to the peer's public address every
``punch_interval_ms``, while concurrently waiting on the *same* socket for a
packet FROM the peer. The first packet from the peer means our NAT binding
is (or will be) open: "hole punched".

Both sides run the exact same code simultaneously; when both NATs have seen
outbound traffic to each other, the inbound packets flow through.
"""

from __future__ import annotations

import asyncio
import logging
import random

from .stun import UdpSocket, fmt_addr

__all__ = ["PunchError", "PunchTimeout", "punch"]

log = logging.getLogger("p2p_tunnel.punch")


class PunchError(Exception):
    """Hole punching failed."""


class PunchTimeout(PunchError):
    """No packet from the peer before the deadline."""


async def punch(
    sock: UdpSocket,
    peer_addr: tuple[str, int],
    *,
    interval_ms: int,
    timeout_secs: float,
) -> None:
    """Punch a hole toward ``peer_addr``, resolving when a packet from the
    peer arrives (or raising :class:`PunchTimeout`).

    Uses the same ``sock`` we'll later run QUIC on — the outbound punch
    packets establish the NAT binding that lets QUIC's Initial packets in.
    """
    loop = asyncio.get_running_loop()
    nonce = random.randbytes(8)
    interval = max(interval_ms, 10) / 1000.0
    timeout = float(timeout_secs)

    log.info(
        "starting hole punching: peer=%s interval_ms=%.0f timeout_secs=%d nonce=%s",
        fmt_addr(peer_addr),
        interval * 1000,
        int(timeout),
        nonce.hex(),
    )

    start = loop.time()
    deadline = start + timeout
    sent = 0

    async def _send_punch() -> None:
        nonlocal sent
        try:
            await sock.send_to(nonce, peer_addr)
        except OSError as e:
            raise PunchError(f"sending punch packet: {e}") from e
        sent += 1
        log.debug("sent punch packet: peer=%s sent=%d", fmt_addr(peer_addr), sent)

    # First punch goes out at once (Rust's first tick completes immediately).
    await _send_punch()

    while True:
        now = loop.time()
        if now >= deadline:
            break
        # Sleep until the next send tick (capped by the deadline); a packet
        # from the peer interrupts the sleep any time.
        sleep_task = asyncio.create_task(asyncio.sleep(min(now + interval, deadline) - now))
        recv_task = asyncio.create_task(sock.recv_from())
        done, _ = await asyncio.wait(
            {recv_task, sleep_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in (recv_task, sleep_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(recv_task, sleep_task, return_exceptions=True)

        if sleep_task in done:
            await _send_punch()

        if recv_task in done and not recv_task.cancelled():
            try:
                data, from_addr = recv_task.result()
            except OSError as e:
                # On Windows, ICMP "port/host unreachable" replies to our
                # outbound punch packets surface as *recv errors* (Linux
                # drops them silently). Expected while the peer's NAT is
                # still closed — log and keep punching until timeout.
                log.debug(
                    "recv error during punch (likely ICMP unreachable); continuing: error=%s",
                    e,
                )
                continue
            if from_addr == peer_addr:
                log.info(
                    "hole punched: packet received from peer: from=%s bytes=%d sent=%d elapsed_ms=%d",
                    fmt_addr(from_addr),
                    len(data),
                    sent,
                    int((loop.time() - start) * 1000),
                )
                return
            log.debug(
                "ignoring packet from non-peer address while punching: from=%s",
                fmt_addr(from_addr),
            )

    raise PunchTimeout(
        f"hole punching timed out after {int(timeout)}s: "
        f"no packet from {fmt_addr(peer_addr)} (sent {sent} punch packets)"
    )
