//! Client configuration and caller-supplied TLS identities.
//!
//! `Config` is defined with the other public option types in [`crate::types`]
//! and re-exported here so the module layout matches the design (`config.rs`).

#[doc(inline)]
pub use crate::types::Config;

/// Validated Storj TLS identity. Debug output excludes certificate/key material.
/// Clones share the parsed identity; a certificate chain and matching key are
/// required together, so partially configured identities cannot be opened.
#[derive(Clone)]
pub struct TlsIdentity(std::sync::Arc<storj_rpc::Identity>);

impl TlsIdentity {
    /// Parse a leaf-first chain (leaf, CA, optional signers) and one unencrypted
    /// P-256 key, in PKCS#8 or SEC1 PEM format. Validates chain signatures and
    /// the key's match to the leaf before any network traffic is possible.
    pub fn from_pem(chain_pem: &str, key_pem: &str) -> crate::Result<Self> {
        storj_rpc::Identity::from_pem_parts(chain_pem, key_pem)
            .map(|identity| Self(std::sync::Arc::new(identity)))
            .map_err(|error| {
                crate::Error::new(
                    crate::ErrorKind::InvalidTlsIdentity,
                    "invalid certificate chain or private key",
                )
                .with_source(error)
            })
    }

    /// Public NodeID derived from this identity's CA certificate.
    pub fn node_id(&self) -> String {
        self.0.node_id().to_string()
    }

    pub(crate) fn identity(&self) -> &storj_rpc::Identity {
        &self.0
    }
}
impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("node_id", &self.0.node_id())
            .finish_non_exhaustive()
    }
}
impl PartialEq for TlsIdentity {
    fn eq(&self, other: &Self) -> bool {
        // Construction already proved each private key matches its leaf.
        self.0.cert_chain() == other.0.cert_chain()
    }
}
impl Eq for TlsIdentity {}
