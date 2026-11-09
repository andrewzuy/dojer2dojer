"""Tests for :mod:`p2p_tunnel.quic` (Phase 4: certs + configuration).

Ports the four Rust ``quic.rs`` tests. Per project decision there is no
loopback QUIC handshake test here — the real handshake is verified in the
loopback e2e phase (PLAN.md Phase 14).
"""

from __future__ import annotations

import asyncio
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from p2p_tunnel.quic import (
    CERT_CN,
    build_client_config,
    build_server_config,
    fingerprint,
    generate_self_signed_cert,
    start_keep_alive,
)


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
        self.assertEqual(server.certificate_chain, [cert_der])
        self.assertIs(server.private_key, key)

    def test_no_alpn_matches_rust_peer(self):
        # The Rust peer sets no ALPN (quinn default); we must not either.
        self.assertIsNone(build_client_config().alpn_protocols)
        cert_der, key, _ = generate_self_signed_cert()
        self.assertIsNone(build_server_config(cert_der, key).alpn_protocols)


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
