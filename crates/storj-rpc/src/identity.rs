//! Ephemeral ECDSA P-256 identity and NodeID (double-SHA256 of CA PKIX key).

use std::fmt;
use std::str::FromStr;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Storj identity-version x509 extension (`peertls/extensions.IdentityVersionExtID`).
///
/// BER contents of OID 2.999.2.1 (`0x88 0x37` is the 2.999 subidentifier).
/// `x509-parser` `to_id_string` mis-decodes that as `3.16.55.2.1`.
const IDENTITY_VERSION_OID_BER: &[u8] = &[0x88, 0x37, 0x02, 0x01];
const IDENTITY_VERSION_OID_COMPONENTS: &[u64] = &[2, 999, 2, 1];
const ID_VERSION_V0: u8 = 0;

/// Go `storj.NodeIDSize`.
pub const NODE_ID_SIZE: usize = 32;

/// Error from identity generation, NodeID, or NodeURL parsing.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Base58Check NodeID did not decode.
    #[error("invalid node ID")]
    NodeId,
    /// Host-only address is not in the KnownNodeID map.
    ///
    /// Exact Go `uplink.parseNodeURL` inner message.
    #[error("node id is required in satelliteNodeURL")]
    NodeIdRequired,
    /// `ParseNodeURL` rejected the string.
    #[error("invalid node URL: {0}")]
    NodeUrl(String),
    /// Certificate parse, chain, or generation failure.
    #[error("{0}")]
    Certificate(String),
    /// Generated identity is required for CA signing (PEM loads have no CA key).
    #[error("identity has no CA private key")]
    NoCaKey,
    /// ECDSA signature over SHA-256 digest did not verify.
    #[error("invalid signature")]
    Signature,
}

/// 32-byte Storj NodeID: double-SHA256 of the CA PKIX public key, last byte = ID version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeId([u8; NODE_ID_SIZE]);

impl NodeId {
    /// All-zero ID (unset).
    pub const ZERO: Self = Self([0u8; NODE_ID_SIZE]);

    /// True when no NodeID was present in the URL.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; NODE_ID_SIZE]
    }

    /// Raw 32 bytes (version in the last byte).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NODE_ID_SIZE] {
        &self.0
    }

    /// Construct from raw 32 bytes (including the version in the last byte).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NODE_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Decode a Base58Check NodeID (`storj.NodeIDFromString`).
    pub fn from_string(s: &str) -> Result<Self, IdentityError> {
        s.parse()
    }

    /// NodeID from a CA certificate DER (`identity.NodeIDFromCert`).
    pub fn from_certificate_der(der: &[u8]) -> Result<Self, IdentityError> {
        let cert = parse_cert(der)?;
        from_parsed_cert(&cert)
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&node_id_encode(self))
    }
}

impl FromStr for NodeId {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        node_id_decode(s)
    }
}

/// Satellite / storage-node address: `NodeID@host:port` after KnownNodeID fill-in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUrl {
    /// Peer NodeID (never zero after a successful [`crate::parse_node_url`]).
    pub id: NodeId,
    /// Host or `host:port` (Go `NodeURL.Address`).
    pub address: String,
}

impl fmt::Display for NodeUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.id.is_zero() {
            f.write_str(&self.address)
        } else {
            write!(f, "{}@{}", self.id, self.address)
        }
    }
}

/// CA + leaf chain and leaf private key. NodeID is taken from the CA public key.
#[derive(Clone)]
pub struct Identity {
    id: NodeId,
    leaf: CertificateDer<'static>,
    ca: CertificateDer<'static>,
    key_pkcs8: Vec<u8>,
    /// PKCS#8 of the CA key; present for [`Self::generate`], not PEM loads.
    ca_key_pkcs8: Option<Vec<u8>>,
}

impl Identity {
    /// Generate an ephemeral identity (Go `NewFullIdentity` with difficulty 0).
    pub fn generate() -> Result<Self, IdentityError> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params.extended_key_usages.clear();
        ca_params.distinguished_name = storj_dn();
        ca_params.custom_extensions = vec![CustomExtension::from_oid_content(
            IDENTITY_VERSION_OID_COMPONENTS,
            vec![ID_VERSION_V0],
        )];
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
        let mut leaf_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        leaf_params.distinguished_name = storj_dn();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;

        let ca_der: CertificateDer<'static> = ca_cert.der().clone();
        let leaf_der: CertificateDer<'static> = leaf_cert.der().clone();
        let id = NodeId::from_certificate_der(&ca_der)?;
        Ok(Self {
            id,
            leaf: leaf_der,
            ca: ca_der,
            key_pkcs8: leaf_key.serialize_der(),
            ca_key_pkcs8: Some(ca_key.serialize_der()),
        })
    }

    /// NodeID of this identity (hash of the CA public key).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.id
    }

    /// Leaf then CA (Go `FullIdentity.Chain`).
    #[must_use]
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.leaf.clone(), self.ca.clone()]
    }

    /// Leaf PKCS#8 private key for rustls.
    #[must_use]
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()))
    }

    /// CA certificate DER.
    #[must_use]
    pub fn ca_der(&self) -> &CertificateDer<'static> {
        &self.ca
    }

    /// Leaf certificate DER.
    #[must_use]
    pub fn leaf_der(&self) -> &CertificateDer<'static> {
        &self.leaf
    }

    /// Load leaf+CA PEMs and a leaf PKCS#8 key (Go identity dump).
    pub fn from_pem(pem: &str) -> Result<Self, IdentityError> {
        let mut certs = Vec::new();
        let mut keys = Vec::new();
        for item in x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()) {
            let pem = item.map_err(|e| IdentityError::Certificate(e.to_string()))?;
            match pem.label.as_str() {
                "CERTIFICATE" => certs.push(CertificateDer::from(pem.contents)),
                "PRIVATE KEY" => keys.push(pem.contents),
                _ => {}
            }
        }
        if certs.len() < 2 {
            return Err(IdentityError::Certificate(
                "identity chain does not contain a CA certificate".into(),
            ));
        }
        let key_pkcs8 = keys.into_iter().next().ok_or_else(|| {
            IdentityError::Certificate("identity dump missing PRIVATE KEY".into())
        })?;
        let leaf = certs[0].clone();
        let ca = certs[1].clone();
        verify_cert_pair(&leaf, &ca)?;
        let id = NodeId::from_certificate_der(&ca)?;
        Ok(Self {
            id,
            leaf,
            ca,
            key_pkcs8,
            ca_key_pkcs8: None,
        })
    }

    /// SHA-256 digest + ECDSA P-256 (Go `pkcrypto.HashAndSign`) using the CA key.
    pub fn hash_and_sign(&self, data: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let der = self.ca_key_pkcs8.as_deref().ok_or(IdentityError::NoCaKey)?;
        let sk = SigningKey::from_pkcs8_der(der)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
        let sig: Signature = sk.sign(data);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// SHA-256 + ECDSA P-256 verify using this identity's CA certificate.
    pub fn hash_and_verify(&self, data: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
        hash_and_verify(self.ca.as_ref(), data, signature)
    }
}

/// Verify `signature` as Go `pkcrypto.HashAndVerifySignature` against a CA cert.
pub fn hash_and_verify(
    ca_cert_der: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    let vk = verifying_key_from_cert_der(ca_cert_der)?;
    let sig = Signature::from_der(signature).map_err(|_| IdentityError::Signature)?;
    vk.verify(data, &sig).map_err(|_| IdentityError::Signature)
}

fn verifying_key_from_cert_der(der: &[u8]) -> Result<VerifyingKey, IdentityError> {
    let cert = parse_cert(der)?;
    let sec1 = cert.public_key().subject_public_key.as_ref();
    VerifyingKey::from_sec1_bytes(sec1).map_err(|e| IdentityError::Certificate(e.to_string()))
}

fn storj_dn() -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Storj");
    dn
}

pub(crate) fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, IdentityError> {
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|e| IdentityError::Certificate(e.to_string()))?;
    let _ = rest;
    Ok(cert)
}

fn is_identity_version_ext(ext: &X509Extension<'_>) -> bool {
    ext.oid.as_bytes() == IDENTITY_VERSION_OID_BER
}

fn id_version(cert: &X509Certificate<'_>) -> u8 {
    for ext in cert.extensions() {
        if is_identity_version_ext(ext) {
            return ext.value.first().copied().unwrap_or(ID_VERSION_V0);
        }
    }
    ID_VERSION_V0
}

fn from_parsed_cert(cert: &X509Certificate<'_>) -> Result<NodeId, IdentityError> {
    let version = id_version(cert);
    let spki = pkix_spki(cert)?;
    let mut id = double_sha256(&spki);
    id[NODE_ID_SIZE - 1] = version;
    Ok(NodeId(id))
}

fn pkix_spki(cert: &X509Certificate<'_>) -> Result<Vec<u8>, IdentityError> {
    // Prefer the SPKI bytes in the cert; fall back to a canonical P-256 re-encode.
    let spki = cert.public_key();
    if !spki.raw.is_empty() {
        return Ok(spki.raw.to_vec());
    }
    let sec1 = spki.subject_public_key.as_ref();
    let vk = VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|e| IdentityError::Certificate(e.to_string()))?;
    let der = vk
        .to_public_key_der()
        .map_err(|e| IdentityError::Certificate(e.to_string()))?;
    Ok(der.as_bytes().to_vec())
}

fn double_sha256(data: &[u8]) -> [u8; NODE_ID_SIZE] {
    let mid = Sha256::digest(data);
    Sha256::digest(mid).into()
}

/// Verify leaf is signed by CA and CA is self-signed (Go `VerifyPeerCertChains`).
pub(crate) fn verify_cert_pair(leaf_der: &[u8], ca_der: &[u8]) -> Result<(), IdentityError> {
    let leaf = parse_cert(leaf_der)?;
    let ca = parse_cert(ca_der)?;
    verify_signed_by(&leaf, &ca)?;
    verify_signed_by(&ca, &ca)?;
    Ok(())
}

fn verify_signed_by(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
) -> Result<(), IdentityError> {
    let sec1 = parent.public_key().subject_public_key.as_ref();
    let vk = VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|e| IdentityError::Certificate(e.to_string()))?;
    let sig = Signature::from_der(child.signature_value.as_ref())
        .map_err(|e| IdentityError::Certificate(e.to_string()))?;
    vk.verify(child.tbs_certificate.as_ref(), &sig)
        .map_err(|e| IdentityError::Certificate(format!("certificate chain invalid: {e}")))?;
    Ok(())
}

fn node_id_encode(id: &NodeId) -> String {
    let mut unversioned = id.0;
    unversioned[NODE_ID_SIZE - 1] = 0;
    check_encode(&unversioned, id.0[NODE_ID_SIZE - 1])
}

fn node_id_decode(s: &str) -> Result<NodeId, IdentityError> {
    let (payload, version) = check_decode(s)?;
    if payload.len() != NODE_ID_SIZE {
        return Err(IdentityError::NodeId);
    }
    let mut id = [0u8; NODE_ID_SIZE];
    id.copy_from_slice(&payload);
    id[NODE_ID_SIZE - 1] = version;
    Ok(NodeId(id))
}

fn check_encode(payload: &[u8], version: u8) -> String {
    let mut body = Vec::with_capacity(1 + payload.len() + 4);
    body.push(version);
    body.extend_from_slice(payload);
    let sum = checksum(&body);
    body.extend_from_slice(&sum);
    bs58::encode(body)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

fn check_decode(s: &str) -> Result<(Vec<u8>, u8), IdentityError> {
    let decoded = bs58::decode(s)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|_| IdentityError::NodeId)?;
    if decoded.len() < 5 {
        return Err(IdentityError::NodeId);
    }
    let (body, cksum) = decoded.split_at(decoded.len() - 4);
    if checksum(body) != cksum {
        return Err(IdentityError::NodeId);
    }
    Ok((body[1..].to_vec(), body[0]))
}

fn checksum(input: &[u8]) -> [u8; 4] {
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(h1);
    h2[..4].try_into().expect("sha256 is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GO_DUMP: &str = include_str!("../testdata/go-identity.pem");
    const GO_NODE_ID: &str = "123tRdwfDZbVeCxX117eztrC2GLZP3hPWixgAphjoQoCoW7V51G";

    #[test]
    fn known_ids_roundtrip() {
        for s in [
            "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S",
            "121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6",
            "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs",
            "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW",
            "1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE",
        ] {
            let id = NodeId::from_string(s).expect(s);
            assert_eq!(id.to_string(), s);
            assert!(!id.is_zero());
        }
    }

    #[test]
    fn generate_has_version_ext_and_self_consistent_id() {
        let ident = Identity::generate().expect("generate");
        let ca = parse_cert(ident.ca_der()).unwrap();
        assert_eq!(id_version(&ca), ID_VERSION_V0);
        assert!(
            ca.extensions().iter().any(is_identity_version_ext),
            "CA must carry PeerIDVersions extension 2.999.2.1"
        );
        assert_eq!(
            ident.node_id(),
            NodeId::from_certificate_der(ident.ca_der()).unwrap()
        );
        verify_cert_pair(ident.leaf_der(), ident.ca_der()).unwrap();
    }

    #[test]
    fn hash_and_sign_roundtrip() {
        let ident = Identity::generate().expect("generate");
        let msg = b"order-limit-bytes";
        let sig = ident.hash_and_sign(msg).expect("sign");
        ident.hash_and_verify(msg, &sig).expect("verify self");
        hash_and_verify(ident.ca_der().as_ref(), msg, &sig).expect("verify der");
        assert!(hash_and_verify(ident.ca_der().as_ref(), b"tampered", &sig).is_err());
        let other = Identity::generate().expect("other");
        assert!(other.hash_and_verify(msg, &sig).is_err());
    }

    #[test]
    fn pem_identity_cannot_sign() {
        let ident = Identity::from_pem(GO_DUMP).expect("go dump");
        assert!(matches!(
            ident.hash_and_sign(b"x"),
            Err(IdentityError::NoCaKey)
        ));
    }

    #[test]
    fn go_dump_node_id_and_extensions() {
        let ident = Identity::from_pem(GO_DUMP).expect("go dump");
        assert_eq!(ident.node_id().to_string(), GO_NODE_ID);
        let ca = parse_cert(ident.ca_der()).unwrap();
        assert_eq!(id_version(&ca), ID_VERSION_V0);
        assert!(ca.extensions().iter().any(is_identity_version_ext));
        let org = ca
            .subject()
            .iter_organization()
            .next()
            .expect("O=")
            .as_str()
            .unwrap();
        assert_eq!(org, "Storj");
    }
}
