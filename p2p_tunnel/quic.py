"""Self-signed certificates and QUIC configuration (aioquic).

Port of the Phase 4/5 surface of Rust ``src/quic.rs`` (branch ``main``).

**Security model (MVP).** QUIC mandates TLS 1.3, so every connection
presents a certificate. We generate a fresh self-signed ECDSA P-256
certificate at startup, and the client *accepts any* server certificate:
no chain verification, no hostname check. The trust anchor is the human:
the peer address is typed in by hand, and both sides log the SHA-256
fingerprint of the certificate they use/see, so two people can compare
out-of-band if they want more assurance (like an SSH host-key prompt).

TLS 1.3 *handshake signatures* are still really verified by the crypto
stack (``cryptography``) — a real signature check, just with a
deliberately permissive trust policy (``verify_mode=ssl.CERT_NONE``).

Note: no ALPN is configured, matching the Rust peer (quinn default), so
Python↔Rust and Python↔Python handshakes agree.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import socket
import ssl

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .stun import fmt_addr

__all__ = [
    "CERT_CN",
    "DEFAULT_IDLE_TIMEOUT",
    "QuicError",
    "generate_self_signed_cert",
    "fingerprint",
    "build_client_config",
    "build_server_config",
    "attach_client",
    "attach_server",
    "connect",
    "close_endpoint",
    "peer_certificate_fingerprint",
    "start_keep_alive",
]

log = logging.getLogger("p2p_tunnel.quic")

# Common name / DNS SAN for the self-signed certificate; also the TLS
# SNI the client sends (Rust: endpoint.connect(peer_addr, CERT_CN)).
CERT_CN: str = "p2p-tunnel"

# quinn's default idle timeout (Rust does not override it).
DEFAULT_IDLE_TIMEOUT: float = 30.0


class QuicError(Exception):
    """QUIC setup or handshake failure."""


def fingerprint(cert_der: bytes) -> str:
    """SHA-256 fingerprint of a certificate DER — for out-of-band
    comparison between the two peers (our MVP answer to "how do I know
    it's really you?")."""
    return hashlib.sha256(cert_der).hexdigest()


def generate_self_signed_cert() -> tuple[bytes, ec.EllipticCurvePrivateKey, str]:
    """Generate a fresh self-signed certificate + private key.

    Returns ``(cert_der, private_key, fingerprint)``. The fingerprint is
    logged so the user can share it with their peer out-of-band.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_CN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # Small skew slack on the start (rcgen starts at "now").
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(CERT_CN)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fp = fingerprint(cert_der)
    log.info(
        "generated self-signed certificate for this session (share this fingerprint with your peer): "
        "fingerprint=%s subject=%s",
        fp,
        CERT_CN,
    )
    return cert_der, key, fp


def build_client_config() -> QuicConfiguration:
    """Build the QUIC **client** configuration (accept-any certificate
    policy). Keep-alive PINGs are driven separately (see
    :func:`start_keep_alive`) because aioquic has no built-in interval."""
    return QuicConfiguration(
        is_client=True,
        server_name=CERT_CN,
        verify_mode=ssl.CERT_NONE,  # MVP: accept any server certificate
        idle_timeout=DEFAULT_IDLE_TIMEOUT,
    )


def build_server_config(
    cert_der: bytes,
    key: ec.EllipticCurvePrivateKey,
) -> QuicConfiguration:
    """Build the QUIC **server** configuration presenting our self-signed
    certificate.

    aioquic 1.7 wants the leaf as ``configuration.certificate`` (an
    ``x509.Certificate`` object) and the rest of the chain in
    ``certificate_chain``; a server connection is rejected without it.
    """
    cert = x509.load_der_x509_certificate(cert_der)
    return QuicConfiguration(
        is_client=False,
        certificate=cert,
        certificate_chain=[],
        private_key=key,
        idle_timeout=DEFAULT_IDLE_TIMEOUT,
    )


async def attach_client(
    sock: socket.socket,
    config: QuicConfiguration,
    stream_handler: object | None = None,
) -> QuicConnectionProtocol:
    """Attach aioquic to a pre-bound (STUN'd, hole-punched) UDP socket as
    the QUIC **client**.

    Rust parity for the client half of ``create_endpoint``. The socket is
    handed to the event loop as-is: ``create_datagram_endpoint(sock=…)``
    reuses the same fd, so the punched 4-tuple (and its NAT mapping)
    survives the handover. ``connection_made`` has already run by the time
    this returns (the loop schedules it before resolving the creation
    waiter), so the protocol is ready for :func:`connect` immediately.
    """
    loop = asyncio.get_running_loop()
    quic_conn = QuicConnection(configuration=config)
    protocol = QuicConnectionProtocol(quic_conn, stream_handler=stream_handler)
    await loop.create_datagram_endpoint(lambda: protocol, sock=sock)
    local = sock.getsockname()[:2]
    log.info("QUIC client endpoint ready: local=%s:%d", local[0], local[1])
    return protocol


async def attach_server(
    sock: socket.socket,
    config: QuicConfiguration,
    stream_handler: object | None = None,
    on_connection: object | None = None,
) -> QuicServer:
    """Attach aioquic to a pre-bound UDP socket as the QUIC **server**.

    Rust parity for the server half of ``create_endpoint``. ``QuicServer``
    is a plain ``asyncio.DatagramProtocol``, so we instantiate it directly
    and hand it to the loop on our socket.

    aioquic has no quinn-style ``accept()``: connections appear as the
    server creates one ``QuicConnectionProtocol`` per peer. Pass
    ``on_connection`` (called synchronously with each new
    ``QuicConnectionProtocol``) to be told about them — the pipeline uses
    it to await the first connection.
    """
    loop = asyncio.get_running_loop()
    if on_connection is None:
        server = QuicServer(configuration=config, stream_handler=stream_handler)
    else:

        def _create_protocol(connection: QuicConnection, stream_handler=stream_handler):
            protocol = QuicConnectionProtocol(connection, stream_handler=stream_handler)
            on_connection(protocol)
            return protocol

        server = QuicServer(
            configuration=config,
            create_protocol=_create_protocol,
            stream_handler=stream_handler,
        )
    await loop.create_datagram_endpoint(lambda: server, sock=sock)
    local = sock.getsockname()[:2]
    log.info("QUIC server endpoint ready: local=%s:%d", local[0], local[1])
    return server


async def connect(
    protocol: QuicConnectionProtocol,
    peer_addr: tuple[str, int],
    *,
    timeout: float = 30.0,
) -> QuicConnectionProtocol:
    """Connect to ``peer_addr`` as the QUIC client (handshake included).

    Rust parity for ``quic::connect``. The socket is already punched
    toward the peer, so the Initial packets go through the hole.
    """
    protocol.connect(peer_addr, transmit=True)
    try:
        await asyncio.wait_for(protocol.wait_connected(), timeout)
    except asyncio.TimeoutError as e:
        raise QuicError(
            f"QUIC handshake with {fmt_addr(peer_addr)} timed out after {int(timeout)}s"
        ) from e
    except ConnectionError as e:
        raise QuicError(f"QUIC handshake with {fmt_addr(peer_addr)} failed: {e}") from e
    log.info("QUIC connection established: peer=%s", fmt_addr(peer_addr))
    return protocol


def close_endpoint(endpoint: QuicConnectionProtocol | QuicServer) -> None:
    """Tear down an endpoint created by :func:`attach_client` / :func:`attach_server`.

    Closes the QUIC connection(s) and the datagram transport. Closing the
    transport also closes the underlying UDP socket (asyncio's selector
    datagram transport owns the socket it is handed), fully releasing the
    shared socket for the supervisor's next fresh-socket attempt.
    """
    transport = getattr(endpoint, "_transport", None)
    try:
        endpoint.close()
    except Exception:
        log.debug("error closing endpoint", exc_info=True)
    if transport is not None and not transport.is_closing():
        transport.close()


def peer_certificate_fingerprint(protocol: QuicConnectionProtocol) -> str | None:
    """SHA-256 fingerprint of the peer's leaf certificate (client side).

    For out-of-band comparison between peers (our MVP trust anchor). Uses
    aioquic's private ``_quic.tls._peer_certificate`` (a
    ``cryptography`` x509.Certificate); returns ``None`` rather than
    raising if the API moves — the fingerprint is a nice-to-have trust
    aid, not load-bearing.
    """
    try:
        cert = protocol._quic.tls._peer_certificate  # noqa: SLF001
    except AttributeError:
        return None
    if cert is None:
        return None
    return fingerprint(cert.public_bytes(serialization.Encoding.DER))


def start_keep_alive(
    protocol: asyncio.Protocol,
    interval_secs: float | None,
) -> asyncio.Task | None:
    """Send a QUIC PING every ``interval_secs`` while the tunnel is idle.

    Rust parity for ``transport_config_with_keep_alive``: NAT devices drop
    the port mapping of a silent connection after their own idle timeout,
    so without these periodic packets a healthy but idle tunnel is
    silently killed. aioquic has no built-in interval, so we drive it
    manually; a PING is enough to keep NAT mappings alive.

    ``interval_secs <= 0`` or ``None`` disables keep-alive. Start this only
    after the connection is established; the task cancels itself when the
    connection goes away.
    """
    if not interval_secs or interval_secs <= 0:
        return None

    async def _ping_loop() -> None:
        while True:
            await asyncio.sleep(interval_secs)
            try:
                await protocol.ping()
            except Exception:  # connection is gone; stop pinging
                return

    return asyncio.create_task(_ping_loop(), name="quic-keep-alive")
