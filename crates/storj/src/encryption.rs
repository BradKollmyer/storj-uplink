//! Encryption key derivation. Path/content ciphers land in later PRs.
//!
//! Matches `storj.io/common/encryption.DeriveRootKey`:
//! ```text
//! mixedSalt = HMAC-SHA256(key=password, data=salt)
//! pathSalt  = HMAC-SHA256(key=mixedSalt, data=path)
//! rootKey   = Argon2id(password, pathSalt, t=1, m=64MiB, p, 32)
//! ```
//! `EncryptionKey::derive` uses **p=1**. `request_with_passphrase` uses **p=8**.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN, ARGON2_PARALLELISM_DERIVE, ARGON2_TIME, PATH_HMAC_PREFIX,
};
use crate::error::{Error, ErrorKind, Result};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// 32-byte root/path key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    bytes: [u8; 32],
}

impl EncryptionKey {
    /// Argon2id with caller-supplied salt (multitenancy).
    /// Matches `uplink.DeriveEncryptionKey` (Argon2id **p=1**, empty path).
    pub fn derive(passphrase: &str, salt: &[u8]) -> Result<Self> {
        derive_root_key(passphrase.as_bytes(), salt, b"", ARGON2_PARALLELISM_DERIVE)
    }

    /// Raw key bytes. Callers must not log this.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Build from an already-derived 32-byte key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptionKey([REDACTED])")
    }
}

/// `DeriveRootKey` with explicit Argon2 parallelism.
///
/// `parallelism` is **8** for `Access::request_with_passphrase` and **1** for
/// `EncryptionKey::derive`. Using the wrong `p` yields a different root key
/// than Go/console.
pub fn derive_root_key(
    password: &[u8],
    salt: &[u8],
    path: &[u8],
    parallelism: u32,
) -> Result<EncryptionKey> {
    let mixed = hmac_sha256(password, salt)?;
    let path_salt = hmac_sha256(&mixed, path)?;

    let params = argon2::Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME,
        parallelism,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| Error::new(ErrorKind::Protocol, format!("argon2 params: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, &path_salt, &mut *out)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("argon2: {e}")))?;

    Ok(EncryptionKey { bytes: *out })
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("hmac: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Path-component HD step: `HMAC-SHA512(key, "path:" + component)[0..32]`.
pub fn derive_path_key_component(key: &[u8; 32], component: &str) -> [u8; 32] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC-SHA512 accepts 32-byte keys");
    mac.update(PATH_HMAC_PREFIX);
    mac.update(component.as_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ARGON2_PARALLELISM_REQUEST;

    #[test]
    fn derive_is_deterministic() {
        let a = EncryptionKey::derive("correct horse battery staple", b"0123456789abcdef").unwrap();
        let b = EncryptionKey::derive("correct horse battery staple", b"0123456789abcdef").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_changes_with_salt_and_password() {
        let a = EncryptionKey::derive("pw", b"salt-a-must-be-ok").unwrap();
        let b = EncryptionKey::derive("pw", b"salt-b-must-be-ok").unwrap();
        let c = EncryptionKey::derive("px", b"salt-a-must-be-ok").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn request_p8_differs_from_derive_p1() {
        let p1 =
            derive_root_key(b"pw", b"project-salt-bytes", b"", ARGON2_PARALLELISM_DERIVE).unwrap();
        let p8 = derive_root_key(
            b"pw",
            b"project-salt-bytes",
            b"",
            ARGON2_PARALLELISM_REQUEST,
        )
        .unwrap();
        assert_ne!(
            p1.as_bytes(),
            p8.as_bytes(),
            "p=1 vs p=8 must not collide; that would hide an interop bug"
        );
    }

    #[test]
    fn path_component_uses_path_prefix() {
        let key = [7u8; 32];
        let a = derive_path_key_component(&key, "logs");
        let mut mac = HmacSha512::new_from_slice(&key).unwrap();
        mac.update(b"path:logs");
        let expected = mac.finalize().into_bytes();
        assert_eq!(&a[..], &expected[..32]);
        assert_ne!(a, derive_path_key_component(&key, "path:logs"));
    }

    #[test]
    fn path_component_unicode_and_empty() {
        let key = [1u8; 32];
        let empty = derive_path_key_component(&key, "");
        let uni = derive_path_key_component(&key, "café");
        assert_ne!(empty, uni);
        assert_eq!(empty, derive_path_key_component(&key, ""));
    }

    #[test]
    fn debug_redacts_key_bytes() {
        let k = EncryptionKey::from_bytes([0xab; 32]);
        let s = format!("{k:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("ab"));
    }
}
