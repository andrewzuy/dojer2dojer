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
import ssl

from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

__all__ = [
    "CERT_CN",
    "DEFAULT_IDLE_TIMEOUT",
    "QuicError",
    "generate_self_signed_cert",
    "fingerprint",
    "build_client_config",
    "build_server_config",
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
    certificate."""
    return QuicConfiguration(
        is_client=False,
        certificate_chain=[cert_der],
        private_key=key,
        idle_timeout=DEFAULT_IDLE_TIMEOUT,
    )


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
