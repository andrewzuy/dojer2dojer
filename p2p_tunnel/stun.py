"""Manual STUN client (RFC 5389).

Port of ``src/stun.rs`` (Rust reference, branch ``main``). We implement just
enough STUN to send a Binding Request and read back the XOR-MAPPED-ADDRESS.
No libraries: raw UDP bytes, because we need full control of the socket (it
is reused for hole punching and QUIC later).
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket as _socket
import struct

__all__ = [
    "DEFAULT_STUN_PORT",
    "STUN_MAGIC_COOKIE",
    "MSG_BINDING_REQUEST",
    "MSG_BINDING_RESPONSE",
    "MSG_BINDING_ERROR",
    "ATTR_MAPPED_ADDRESS",
    "ATTR_XOR_MAPPED_ADDRESS",
    "PER_ATTEMPT_TIMEOUT",
    "MAX_ROUNDS",
    "MAX_RESP_LEN",
    "StunError",
    "StunRejected",
    "StunMalformed",
    "StunIo",
    "encode_binding_request",
    "parse_binding_response",
    "resolve_server",
    "UdpSocket",
    "discover_public_addr",
]

log = logging.getLogger("p2p_tunnel.stun")

DEFAULT_STUN_PORT: int = 19302

STUN_MAGIC_COOKIE: int = 0x21_12_A4_42

MSG_BINDING_REQUEST: int = 0x0001
MSG_BINDING_RESPONSE: int = 0x0101
MSG_BINDING_ERROR: int = 0x0111
ATTR_MAPPED_ADDRESS: int = 0x0001
ATTR_XOR_MAPPED_ADDRESS: int = 0x0020

PER_ATTEMPT_TIMEOUT: float = 3.0
MAX_ROUNDS: int = 2
MAX_RESP_LEN: int = 512


class StunError(Exception):
    """Base class for all STUN discovery errors."""


class StunRejected(StunError):
    """The STUN server answered with a Binding Error Response."""

    def __init__(self, server: str, reason: str) -> None:
        super().__init__(f"STUN server {server} rejected request: {reason}")
        self.server = server
        self.reason = reason


class StunMalformed(StunError):
    """The reply was not a valid Binding Response for our request."""

    def __init__(self, server: str, reason: str) -> None:
        super().__init__(f"malformed STUN response from {server}: {reason}")
        self.server = server
        self.reason = reason


class StunIo(StunError):
    """A raw I/O error while talking to a STUN server."""

    def __init__(self, server: str, source: Exception) -> None:
        super().__init__(f"I/O error talking to STUN server {server}: {source}")
        self.server = server
        self.source = source


def encode_binding_request(transaction_id: bytes) -> bytes:
    """Encode a minimal STUN Binding Request (20 bytes, no attributes)."""
    if len(transaction_id) != 12:
        raise ValueError("transaction ID must be 12 bytes")
    return struct.pack(">HHI", MSG_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + transaction_id


def parse_binding_response(
    data: bytes,
    expected_txn: bytes,
    server: str = "<unknown>",
) -> tuple[str, int]:
    """Parse a STUN Binding Response and return the mapped (public) address.

    Validates message type, magic cookie, transaction ID, then extracts
    XOR-MAPPED-ADDRESS (falling back to plain MAPPED-ADDRESS).
    """
    if len(data) < 20:
        raise StunMalformed(server, f"short packet ({len(data)} bytes)")
    msg_type, msg_len = struct.unpack_from(">HH", data, 0)
    if msg_type == MSG_BINDING_ERROR:
        raise StunRejected(server, "STUN Binding Error Response received")
    if msg_type != MSG_BINDING_RESPONSE:
        raise StunMalformed(server, f"unexpected message type 0x{msg_type:04x}")
    if len(data) < 20 + msg_len:
        raise StunMalformed(
            server,
            f"truncated: header says {msg_len} attr bytes, got {len(data) - 20}",
        )
    (magic,) = struct.unpack_from(">I", data, 4)
    if magic != STUN_MAGIC_COOKIE:
        raise StunMalformed(server, "bad magic cookie (not a STUN Binding Response?)")
    if data[8:20] != expected_txn:
        raise StunMalformed(server, "transaction ID mismatch")

    # Walk attributes: type(2) + length(2) + value(length), padded to 4 bytes.
    attrs = data[20 : 20 + msg_len]
    offset = 0
    while offset + 4 <= len(attrs):
        attr_type, attr_len = struct.unpack_from(">HH", attrs, offset)
        offset += 4
        if offset + attr_len > len(attrs):
            break
        value = attrs[offset : offset + attr_len]
        offset += attr_len + attr_len % 4  # value + padding
        if attr_len < 8:
            continue
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            addr = xor_mapped_address(value, expected_txn)
            if addr is None:
                raise StunMalformed(server, "bad XOR-MAPPED-ADDRESS value")
            return addr
        if attr_type == ATTR_MAPPED_ADDRESS:
            addr = mapped_address(value)
            if addr is None:
                raise StunMalformed(server, "bad MAPPED-ADDRESS value")
            return addr
    raise StunMalformed(server, "no mapped-address attribute found")


def mapped_address(value: bytes) -> tuple[str, int] | None:
    """Decode a plain MAPPED-ADDRESS attribute value.

    Layout: reserved(1) family(1) port(2) address(4|16).
    """
    family = value[1]
    port = struct.unpack_from(">H", value, 2)[0]
    if family == 0x01 and len(value) >= 8:
        return _socket.inet_ntoa(value[4:8]), port
    if family == 0x02 and len(value) >= 20:
        return _socket.inet_ntop(_socket.AF_INET6, value[4:20]), port
    return None


def xor_mapped_address(value: bytes, txn: bytes) -> tuple[str, int] | None:
    """Decode an XOR-MAPPED-ADDRESS attribute value (RFC 5389 §15).

    Layout: reserved(1) family(1) xor-port(2) xor-address(4|16). The port is
    XORed with the high 16 bits of the magic cookie; the address is XORed
    with the 32-bit cookie (v4) or the 16-byte key cookie||txn (v6).
    """
    family = value[1]
    port = struct.unpack_from(">H", value, 2)[0] ^ (STUN_MAGIC_COOKIE >> 16)
    if family == 0x01 and len(value) >= 8:
        ip_int = struct.unpack_from(">I", value, 4)[0] ^ STUN_MAGIC_COOKIE
        return _socket.inet_ntoa(struct.pack(">I", ip_int)), port
    if family == 0x02 and len(value) >= 20:
        key = struct.pack(">I", STUN_MAGIC_COOKIE) + txn
        octets = bytes(a ^ b for a, b in zip(value[4:20], key))
        return _socket.inet_ntop(_socket.AF_INET6, octets), port
    return None


def fmt_addr(addr: tuple[str, int]) -> str:
    """Format ``(host, port)`` the way the Rust code prints ``SocketAddr``."""
    host, port = addr
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


async def resolve_server(server: str) -> list[tuple[str, int]]:
    """Resolve a ``"host:port"`` (or bare ``"host"``, defaulting to port
    19302) STUN server to concrete socket addresses. Numeric literals work
    too.

    Raises ``ValueError`` for malformed server strings and ``OSError``
    (``socket.gaierror``) for resolution failures.
    """
    if ":" in server:
        host, _, port_s = server.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            raise ValueError(f"bad port in STUN server {server!r}") from None
        if not 0 < port <= 65535:
            raise ValueError(f"bad port in STUN server {server!r}")
    else:
        host, port = server, DEFAULT_STUN_PORT
    if not host:
        raise ValueError(f"empty host in STUN server {server!r}")
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=_socket.SOCK_DGRAM)
    addrs: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for info in infos:
        host_addr, port_addr = info[4][:2]
        if (host_addr, port_addr) not in seen:
            seen.add((host_addr, port_addr))
            addrs.append((host_addr, port_addr))
    if not addrs:
        raise ValueError(f"no addresses for STUN server {host}")
    return addrs


class UdpSocket:
    """The one UDP socket: STUN, hole punching and QUIC all share it.

    I/O goes through the asyncio ``loop.sock_*`` wrappers — the
    asyncio-sanctioned way to drive a raw socket from the event loop. After
    the punch, :meth:`into_raw` detaches the underlying socket so it can be
    handed to ``loop.create_datagram_endpoint(sock=...)`` for QUIC.
    """

    def __init__(self, sock: _socket.socket, loop: asyncio.AbstractEventLoop) -> None:
        self._sock = sock
        self._loop = loop

    @classmethod
    async def create(cls) -> "UdpSocket":
        """Bind a fresh non-blocking IPv4 UDP socket to ``0.0.0.0:0``."""
        loop = asyncio.get_running_loop()
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", 0))
        return cls(sock, loop)

    @property
    def local_port(self) -> int:
        return self._sock.getsockname()[1]

    @property
    def local_addr(self) -> tuple[str, int]:
        host, port = self._sock.getsockname()[:2]
        return host, port

    async def send_to(self, data: bytes, peer: tuple[str, int]) -> int:
        return await self._loop.sock_sendto(self._sock, data, peer)

    async def recv_from(self, bufsize: int = MAX_RESP_LEN) -> tuple[bytes, tuple[str, int]]:
        data, addr = await self._loop.sock_recvfrom(self._sock, bufsize)
        return data, (addr[0], addr[1])

    def into_raw(self) -> _socket.socket:
        """Detach and return the underlying socket (the QUIC handover point).

        The :class:`UdpSocket` is unusable afterwards.
        """
        if self._sock is None:
            raise RuntimeError("UdpSocket already consumed")
        sock, self._sock = self._sock, None
        return sock

    async def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    async def __aenter__(self) -> "UdpSocket":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


async def discover_public_addr(
    sock: UdpSocket,
    servers: list[str],
    *,
    per_attempt_timeout: float = PER_ATTEMPT_TIMEOUT,
) -> tuple[str, int]:
    """Discover this host's public IP:port.

    Sends a Binding Request from ``sock`` to each server in ``servers`` (in
    order, up to ``MAX_ROUNDS`` rounds) until one answers. The caller keeps
    ownership of ``sock`` — it is the same socket used later for punching
    and QUIC.

    Raises :class:`StunError` (message starts with ``"STUN discovery
    failed"``) when every server is unreachable or unresponsive.
    """
    txn = random.randbytes(12)
    req = encode_binding_request(txn)
    last_err: str | None = None

    for round_ in range(MAX_ROUNDS):
        for server in servers:
            try:
                addrs = await resolve_server(server)
            except (OSError, ValueError) as e:
                log.warning("cannot resolve STUN server: server=%s error=%s", server, e)
                last_err = str(e)
                continue
            for server_addr in addrs:
                label = fmt_addr(server_addr)
                log.debug("sending STUN binding request: server=%s round=%d", label, round_)
                try:
                    public_addr = await asyncio.wait_for(
                        _send_and_wait(sock, server_addr, req, txn),
                        per_attempt_timeout,
                    )
                except asyncio.TimeoutError:
                    log.warning(
                        "STUN server timed out: server=%s timeout_secs=%.0f",
                        label,
                        per_attempt_timeout,
                    )
                    last_err = f"{label}: timed out after {per_attempt_timeout:.0f}s"
                    continue
                except StunError as e:
                    log.warning("STUN server failed: server=%s error=%s", label, e)
                    last_err = str(e)
                    continue
                log.debug("STUN response received: server=%s", label)
                return public_addr

    last = last_err or "no STUN servers configured"
    raise StunError(f"STUN discovery failed: {last} (tried servers: {servers!r})")


async def _send_and_wait(
    sock: UdpSocket,
    server: tuple[str, int],
    req: bytes,
    txn: bytes,
) -> tuple[str, int]:
    """Send one binding request to ``server`` and wait for its reply.

    Ignores datagrams from anyone else (this socket later carries
    punch/peer traffic too).
    """
    label = fmt_addr(server)
    try:
        await sock.send_to(req, server)
    except OSError as source:
        raise StunIo(label, source) from source
    while True:
        try:
            data, from_addr = await sock.recv_from(MAX_RESP_LEN)
        except OSError as source:
            raise StunIo(label, source) from source
        if from_addr != server:
            log.debug(
                "ignoring non-STUN traffic on discovery socket: from=%s",
                fmt_addr(from_addr),
            )
            continue
        return parse_binding_response(data, txn, server=label)
