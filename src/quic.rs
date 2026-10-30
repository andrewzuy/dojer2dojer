//! Self-signed certificates (Phase 6) and QUIC endpoint (Phase 7).
//!
//! **Security model (MVP).** QUIC mandates TLS 1.3, so every connection
//! presents a certificate. We generate a fresh self-signed ECDSA P-256
//! certificate at startup, and the client *accepts any* server certificate:
//! no chain verification, no hostname check. The trust anchor is the human:
//! the peer address is typed in by hand, and both sides log the SHA-256
//! fingerprint of the certificate they use/see, so two people can compare
//! out-of-band if they want more assurance (like an SSH host-key prompt).
//!
//! We still cryptographically verify the TLS 1.2/1.3 *handshake signatures*:
//! rustls calls us for it, and we delegate to the crypto provider's
//! verification algorithms. That binds the key exchange to the presented
//! certificate — a real signature check, just with a deliberately permissive
//! trust policy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use quinn::rustls::{DigitallySignedStruct, crypto};
use sha2::Digest;
use tracing::{debug, info};

/// Common name / DNS SAN for the self-signed certificate.
pub const CERT_CN: &str = "p2p-tunnel";

/// Generate a fresh self-signed certificate + private key for this session.
///
/// Returns `(cert_chain, private_key)` in rustls/pki-types form, ready to be
/// handed to [`build_server_config`]. The certificate's SHA-256 fingerprint
/// is logged so the user can share it with their peer out-of-band.
pub fn generate_self_signed_cert()
-> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let keypair = rcgen::KeyPair::generate().context("generating ECDSA P-256 key pair")?;

    // `CertificateParams::new` takes SANs (auto-detecting DNS vs IP); we add
    // the common name to the subject for human-readable display.
    let mut params = rcgen::CertificateParams::new(vec![CERT_CN.to_string()])
        .context("building certificate parameters")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, CERT_CN);

    let cert = params
        .self_signed(&keypair)
        .context("creating self-signed certificate")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = fingerprint(&cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));

    info!(
        fingerprint,
        subject = CERT_CN,
        "generated self-signed certificate for this session (share this fingerprint with your peer)"
    );
    Ok((vec![cert_der], key))
}

/// SHA-256 fingerprint of a certificate DER — for out-of-band comparison
/// between the two peers (our MVP answer to "how do I know it's really you?").
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    hex::encode(sha2::Sha256::digest(cert.as_ref()))
}

/// A server-certificate verifier that accepts **any** certificate.
///
/// Trust policy: no chain verification, no hostname check (see module docs).
/// Handshake signatures are still verified for real via the crypto provider.
#[derive(Debug)]
pub struct AcceptAnyServerCert {
    provider: Arc<crypto::CryptoProvider>,
}

impl AcceptAnyServerCert {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(crypto::ring::default_provider()),
        })
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, quinn::rustls::Error> {
        // Deliberately permissive: log the fingerprint and trust the human
        // who typed in the peer address (and can compare fingerprints).
        let fingerprint = fingerprint(end_entity);
        info!(
            fingerprint,
            "accepting peer certificate (MVP: no chain/hostname verification)"
        );
        debug!(
            "peer certificate subject bytes: {} bytes of DER",
            end_entity.len()
        );
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a QUIC transport config that keeps an idle connection alive.
///
/// `keep_alive = Some(interval)` makes the endpoint send a QUIC PING frame
/// every `interval` once the connection is established. NAT devices drop the
/// port mapping of a silent connection after their own idle timeout, so
/// without these periodic packets a healthy but idle tunnel is silently
/// killed. `None` disables keep-alive (quinn's default).
///
/// Only one side of the connection needs it, but we enable it on both
/// (client and server role) so the tunnel survives regardless of role.
pub fn transport_config_with_keep_alive(keep_alive: Option<Duration>) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(keep_alive);
    transport
}

/// Build the QUIC **client** configuration (accept-any certificate policy),
/// with QUIC keep-alive PINGs every `keep_alive` while idle (`None`: off).
pub fn build_client_config(keep_alive: Option<Duration>) -> anyhow::Result<quinn::ClientConfig> {
    let provider: Arc<crypto::CryptoProvider> = Arc::new(crypto::ring::default_provider());
    let rustls_config = quinn::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(AcceptAnyServerCert::new())
        .with_no_client_auth();
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .context("building QUIC client crypto configuration")?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client.transport_config(Arc::new(transport_config_with_keep_alive(keep_alive)));
    Ok(client)
}

/// Build the QUIC **server** configuration presenting our self-signed cert,
/// with QUIC keep-alive PINGs every `keep_alive` while idle (`None`: off).
pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    keep_alive: Option<Duration>,
) -> anyhow::Result<quinn::ServerConfig> {
    let mut server = quinn::ServerConfig::with_single_cert(cert_chain, key)
        .context("building QUIC server configuration")?;
    server.transport_config(Arc::new(transport_config_with_keep_alive(keep_alive)));
    Ok(server)
}

/// Create a QUIC endpoint over an existing (STUN'd, hole-punched) UDP socket.
///
/// `server_config` is `Some(...)` if this side also accepts incoming QUIC
/// connections (QUIC server role) and `None` for a client-only endpoint.
pub fn create_endpoint(
    socket: std::net::UdpSocket,
    server_config: Option<quinn::ServerConfig>,
) -> anyhow::Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime().context("no async runtime available (need tokio)")?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )
    .context("creating QUIC endpoint")?;
    info!(local = ?endpoint.local_addr(), "QUIC endpoint ready");
    Ok(endpoint)
}

/// Connect to `peer_addr` as the QUIC client (handshake included).
pub async fn connect(
    endpoint: &quinn::Endpoint,
    peer_addr: SocketAddr,
) -> anyhow::Result<quinn::Connection> {
    let connection = endpoint
        .connect(peer_addr, CERT_CN)
        .with_context(|| format!("starting QUIC connection to {peer_addr}"))?
        .await
        .with_context(|| format!("QUIC handshake with {peer_addr}"))?;
    info!(%peer_addr, "QUIC connection established");
    Ok(connection)
}

/// Wait for and accept an incoming QUIC connection (server side).
pub async fn accept(endpoint: &quinn::Endpoint) -> anyhow::Result<quinn::Connection> {
    let incoming = endpoint
        .accept()
        .await
        .context("waiting for incoming QUIC connection (endpoint closed)")?;
    let connection = incoming
        .await
        .context("accepting incoming QUIC connection")?;
    info!(peer = ?connection.remote_address(), "QUIC connection accepted");
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: no loopback QUIC test (server + client on localhost) — by
    // project decision the real handshake is verified in Phase 12 between
    // two real machines on different networks.

    #[test]
    fn generates_cert_and_key() {
        let (certs, key) = generate_self_signed_cert().unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].as_ref().is_empty());
        let PrivateKeyDer::Pkcs8(pkcs8) = &key else {
            panic!("expected PKCS8 private key")
        };
        assert!(!pkcs8.secret_pkcs8_der().is_empty());
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let (c1, _) = generate_self_signed_cert().unwrap();
        let (c2, _) = generate_self_signed_cert().unwrap();

        let fp = |c: &CertificateDer<'_>| fingerprint(c);
        assert_eq!(fp(&c1[0]), fp(&c1[0]), "same cert → same fingerprint");
        assert_ne!(
            fp(&c1[0]),
            fp(&c2[0]),
            "different certs → different fingerprints"
        );
        assert_eq!(fp(&c1[0]).len(), 64, "SHA-256 hex is 64 chars");
        assert!(fp(&c1[0]).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn client_and_server_configs_build() {
        let (certs, key) = generate_self_signed_cert().unwrap();
        // With keep-alive enabled (the default in main) and disabled.
        build_client_config(Some(Duration::from_secs(5))).expect("client config builds");
        build_client_config(None).expect("client config builds without keep-alive");
        build_server_config(certs, key, Some(Duration::from_secs(5)))
            .expect("server config builds");
    }

    #[test]
    fn transport_config_accepts_keep_alive_values() {
        let with_ka = transport_config_with_keep_alive(Some(Duration::from_secs(5)));
        let _ = with_ka; // builds; the value is applied inside quinn-proto
        let without_ka = transport_config_with_keep_alive(None);
        let _ = without_ka;
    }
}
