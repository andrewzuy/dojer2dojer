"""Tests for :mod:`p2p_tunnel.quic` (Phase 4: certs + configuration;
Phase 5: endpoint attach + loopback handshake).

Ports the four Rust ``quic.rs`` tests. Documented deviation from Rust:
the Rust project skipped loopback QUIC tests (quinn socket-ownership
ambiguity); with aioquic + ``create_datagram_endpoint(sock=…)`` they are
deterministic, so Phase 5 adds a full loopback handshake (both sides
attached on pre-used sockets).
"""

from __future__ import annotations

import asyncio
import socket
import unittest

from aioquic.asyncio.protocol import QuicConnectionProtocol
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from p2p_tunnel.quic import (
    CERT_CN,
    QuicError,
    attach_client,
    attach_server,
    build_client_config,
    build_server_config,
    close_endpoint,
    connect,
    fingerprint,
    generate_self_signed_cert,
    peer_certificate_fingerprint,
    start_keep_alive,
)
from p2p_tunnel.stun import UdpSocket, encode_binding_request


class CertTests(unittest.TestCase):
    def test_generates_cert_and_key(self):
        cert_der, key, fp = generate_self_signed_cert()
        self.assertIsInstance(cert_der, bytes)
        self.assertTrue(cert_der)
        self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
        # PKCS8 DER encoding of the key works and is non-empty.
        from cryptography.hazmat.primitives import serialization

        pkcs8 = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.assertTrue(pkcs8)
        # It really is a P-256 key (rcgen's default in the Rust reference).
        self.assertEqual(key.curve.name, "secp256r1")
        # The certificate is self-signed with CN=p2p-tunnel and a DNS SAN.
        cert = x509.load_der_x509_certificate(cert_der)
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        self.assertEqual([a.value for a in cn_attrs], [CERT_CN])
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), [CERT_CN])

    def test_fingerprint_is_stable_and_distinct(self):
        c1, _, _ = generate_self_signed_cert()
        c2, _, _ = generate_self_signed_cert()

        self.assertEqual(fingerprint(c1), fingerprint(c1), "same cert → same fingerprint")
        self.assertNotEqual(fingerprint(c1), fingerprint(c2), "different certs → different fingerprints")
        self.assertEqual(len(fingerprint(c1)), 64, "SHA-256 hex is 64 chars")
        self.assertTrue(all(c in "0123456789abcdef" for c in fingerprint(c1)))

    def test_fresh_key_per_call(self):
        _, k1, _ = generate_self_signed_cert()
        _, k2, _ = generate_self_signed_cert()
        self.assertNotEqual(k1.private_numbers().private_value, k2.private_numbers().private_value)


class ConfigTests(unittest.TestCase):
    def test_client_and_server_configs_build(self):
        client = build_client_config()
        self.assertTrue(client.is_client)
        self.assertEqual(client.server_name, CERT_CN)
        self.assertEqual(client.verify_mode, 0)  # ssl.CERT_NONE

        cert_der, key, _ = generate_self_signed_cert()
        server = build_server_config(cert_der, key)
        self.assertFalse(server.is_client)
        # aioquic 1.7: leaf in .certificate (x509 object), rest of chain in
        # .certificate_chain; a server connection is rejected without it.
        self.assertEqual(
            server.certificate.public_bytes(serialization.Encoding.DER), cert_der
        )
        self.assertEqual(server.certificate_chain, [])
        self.assertIs(server.private_key, key)

    def test_no_alpn_matches_rust_peer(self):
        # The Rust peer sets no ALPN (quinn default); we must not either.
        self.assertIsNone(build_client_config().alpn_protocols)
        cert_der, key, _ = generate_self_signed_cert()
        self.assertIsNone(build_server_config(cert_der, key).alpn_protocols)


async def _preuse_sock(sock: UdpSocket) -> tuple[bytes, tuple[str, int], bytes]:
    """Bounce one real datagram (a STUN Binding Request) through the raw
    socket *before* aioquic takes it over — the Phase 5 requirement that
    ``create_datagram_endpoint(sock=pre_used_sock)`` works on a socket
    that already carried STUN traffic (the 4-tuple must survive).

    Returns ``(received, from_addr, sent)``.
    """
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    echo_addr = echo.getsockname()
    try:
        task = asyncio.create_task(asyncio.to_thread(echo.recvfrom, 512))
        req = encode_binding_request(b"prequic12345")
        await sock.send_to(req, echo_addr)
        data, from_addr = await asyncio.wait_for(task, 5)
        return data, from_addr, req
    finally:
        echo.close()


class LoopbackHandshakeTests(unittest.IsolatedAsyncioTestCase):
    """The Phase 5 done-when: a real QUIC/TLS 1.3 handshake over the
    reused socket, both sides attached via ``sock=`` handover."""

    async def test_loopback_handshake_and_stream_roundtrip(self):
        loop = asyncio.get_running_loop()
        server_sock = await UdpSocket.create()
        client_sock = await UdpSocket.create()

        # STUN-style pre-use of both sockets (Phase 5 requirement).
        for sock in (server_sock, client_sock):
            data, from_addr, req = await _preuse_sock(sock)
            self.assertEqual(data, req, "pre-use datagram round-trips")

        # Capture the port before into_raw() detaches the socket.
        server_port = server_sock.local_port

        cert_der, key, fp = generate_self_signed_cert()
        server_cfg = build_server_config(cert_der, key)
        client_cfg = build_client_config()

        first_conn: asyncio.Future = loop.create_future()
        stream_evt: asyncio.Future = loop.create_future()

        def on_connection(proto):
            if not first_conn.done():
                first_conn.set_result(proto)

        def on_stream(reader, writer):
            if not stream_evt.done():
                stream_evt.set_result((reader, writer))

        server = await attach_server(
            server_sock.into_raw(),
            config=server_cfg,
            stream_handler=on_stream,
            on_connection=on_connection,
        )
        client = await attach_client(client_sock.into_raw(), config=client_cfg)
        server_conn: QuicConnectionProtocol | None = None
        try:
            peer_addr = ("127.0.0.1", server_port)

            # Kick off the client handshake (its first Initial packet goes
            # straight out the punched socket), then watch the server side
            # accept the connection as that packet lands.
            conn_task = asyncio.create_task(connect(client, peer_addr, timeout=10))
            server_conn = await asyncio.wait_for(first_conn, 10)
            await conn_task

            # Our self-signed cert came back as the peer cert (client side
            # logged/accepted it — MVP trust model).
            self.assertEqual(peer_certificate_fingerprint(client), fp)

            # Stream round-trip over the real QUIC connection.
            reader, writer = await client.create_stream()
            writer.write(b"ping")
            writer.write_eof()
            s_reader, s_writer = await asyncio.wait_for(stream_evt, 10)
            self.assertEqual(await asyncio.wait_for(s_reader.read(-1), 10), b"ping")
            s_writer.write(b"pong")
            s_writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(-1), 10), b"pong")

            # Connection stays healthy across an idle keep-alive ping.
            ka = start_keep_alive(client, 0.1)
            await asyncio.sleep(0.35)
            self.assertFalse(ka.done())
            ka.cancel()
        finally:
            close_endpoint(server)
            close_endpoint(client)
            if server_conn is not None:
                await asyncio.gather(
                    server_conn.wait_closed(),
                    client.wait_closed(),
                    return_exceptions=True,
                )

    async def test_connect_times_out_against_closed_port(self):
        sock = await UdpSocket.create()
        client = await attach_client(sock.into_raw(), config=build_client_config())
        try:
            with self.assertRaises(QuicError) as ctx:
                await connect(client, ("127.0.0.1", 9), timeout=2)
            self.assertIn("timed out", str(ctx.exception))
        finally:
            close_endpoint(client)


class KeepAliveTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_keep_alive_accepts_values(self):
        # With keep-alive enabled (the default in main) and disabled.
        task = start_keep_alive(object(), 5.0)
        self.assertIsNotNone(task)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertIsNone(start_keep_alive(object(), None))
        self.assertIsNone(start_keep_alive(object(), 0))

    async def test_keep_alive_pings_until_connection_goes(self):
        class FakeProtocol:
            def __init__(self) -> None:
                self.pings = 0
                self.fail_after = 2

            async def ping(self) -> None:
                self.pings += 1
                if self.pings >= self.fail_after:
                    raise RuntimeError("connection closed")

        proto = FakeProtocol()
        task = start_keep_alive(proto, 0.05)
        await asyncio.sleep(0.3)
        self.assertTrue(task.done(), "keep-alive task should stop when the connection dies")
        self.assertGreaterEqual(proto.pings, 2)
        self.assertLessEqual(proto.pings, 4)


if __name__ == "__main__":
    unittest.main()
