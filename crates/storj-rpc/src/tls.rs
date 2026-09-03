//! rustls client config with Storj NodeID pinning (no WebPKI).

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, OtherError, ServerConfig};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme,
};

use crate::identity::{Identity, IdentityError, NodeId, verify_chain};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// rustls `ServerCertVerifier` that checks the peer CA NodeID.
#[derive(Debug)]
pub struct NodeIdVerifier {
    expected: NodeId,
    provider: Arc<CryptoProvider>,
}

impl NodeIdVerifier {
    /// Pin handshakes to `expected` (Go `tlsopts.ClientTLSConfig(id)`).
    #[must_use]
    pub fn new(expected: NodeId) -> Self {
        Self {
            expected,
            provider: provider(),
        }
    }

    /// NodeID this verifier requires.
    #[must_use]
    pub fn expected(&self) -> NodeId {
        self.expected
    }
}

impl ServerCertVerifier for NodeIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let ca = intermediates
            .first()
            .ok_or_else(|| cert_err("invalid certificate chain: missing CA"))?;
        // Go `VerifyPeerCertChains`: leaf <- CA <- ... <- self-signed root.
        // Production peers are signed identities with a signer above the CA.
        let mut chain: Vec<&[u8]> = vec![end_entity.as_ref()];
        chain.extend(intermediates.iter().map(|c| c.as_ref()));
        verify_chain(&chain).map_err(tls_err)?;
        let got = NodeId::from_certificate_der(ca.as_ref()).map_err(tls_err)?;
        if got != self.expected {
            return Err(cert_err("peer ID did not match requested ID"));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
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
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Require any Storj client cert chain (Go `tls.RequireAnyClientCert` + chain check).
#[derive(Debug)]
struct AnyStorjClientVerifier {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyStorjClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if intermediates.is_empty() {
            return Err(cert_err("invalid certificate chain: missing CA"));
        }
        let mut chain: Vec<&[u8]> = vec![end_entity.as_ref()];
        chain.extend(intermediates.iter().map(|c| c.as_ref()));
        verify_chain(&chain).map_err(tls_err)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
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
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client rustls config: present `identity`, pin `expected` NodeID, no WebPKI.
pub fn client_config(identity: &Identity, expected: NodeId) -> Result<ClientConfig, IdentityError> {
    let verifier = Arc::new(NodeIdVerifier::new(expected));
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| IdentityError::Certificate(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(identity.cert_chain(), identity.private_key())
        .map_err(|e| IdentityError::Certificate(e.to_string()))
}

/// Server rustls config for tests / mock peers: require a client cert chain.
pub fn server_config(identity: &Identity) -> Result<ServerConfig, IdentityError> {
    let verifier = Arc::new(AnyStorjClientVerifier {
        provider: provider(),
    });
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| IdentityError::Certificate(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.cert_chain(), identity.private_key())
        .map_err(|e| IdentityError::Certificate(e.to_string()))
}

#[derive(Debug)]
struct VerifierError(String);

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VerifierError {}

fn cert_err(msg: &str) -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
        VerifierError(msg.into()),
    ))))
}

fn tls_err(e: IdentityError) -> RustlsError {
    cert_err(&e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    const GO_DUMP: &str = include_str!("../testdata/go-identity.pem");

    async fn handshake(
        client_ident: &Identity,
        server_ident: &Identity,
        pin: NodeId,
    ) -> Result<(), String> {
        let client_cfg = client_config(client_ident, pin).map_err(|e| e.to_string())?;
        let server_cfg = server_config(server_ident).map_err(|e| e.to_string())?;
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let name = ServerName::try_from("us1.storj.io").map_err(|e| e.to_string())?;

        let server = tokio::spawn(async move { acceptor.accept(server_io).await });
        let client = connector.connect(name, client_io).await;
        match (client, server.await.map_err(|e| e.to_string())?) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(e), _) => Err(e.to_string()),
            (_, Err(e)) => Err(e.to_string()),
        }
    }

    #[tokio::test]
    async fn handshake_pins_generated_identity() {
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        handshake(&client, &server, server.node_id())
            .await
            .expect("pin match");
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_node_id() {
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let err = handshake(&client, &server, client.node_id())
            .await
            .expect_err("wrong pin");
        assert!(
            err.contains("peer ID did not match requested ID")
                || err.contains("invalid certificate"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn handshake_vs_go_dump() {
        let server = Identity::from_pem(GO_DUMP).expect("go dump");
        let client = Identity::generate().unwrap();
        handshake(&client, &server, server.node_id())
            .await
            .expect("Go dump as server");
        // Client identity is ours; pin still the Go CA NodeID.
        let go_id = server.node_id();
        assert_eq!(
            go_id.to_string(),
            "123tRdwfDZbVeCxX117eztrC2GLZP3hPWixgAphjoQoCoW7V51G"
        );
    }
}
