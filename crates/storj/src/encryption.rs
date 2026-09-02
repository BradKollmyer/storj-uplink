//! Encryption key derivation and path cipher (re-exported from `storj-encryption`).
//!
//! Matches `storj.io/common/encryption.DeriveRootKey`:
//! ```text
//! mixedSalt = HMAC-SHA256(key=password, data=salt)
//! pathSalt  = HMAC-SHA256(key=mixedSalt, data=path)
//! rootKey   = Argon2id(password, pathSalt, t=1, m=64MiB, p, 32)
//! ```
//! `EncryptionKey::derive` uses **p=1**. `request_with_passphrase` uses **p=8**.

use crate::constants::ARGON2_PARALLELISM_DERIVE;
use crate::error::{Error, ErrorKind, Result};

/// 32-byte root/path key. Zeroized on drop.
#[derive(Clone)]
pub struct EncryptionKey(storj_encryption::Key);

impl EncryptionKey {
    /// Argon2id with caller-supplied salt (multitenancy).
    /// Matches `uplink.DeriveEncryptionKey` (Argon2id **p=1**, empty path).
    pub fn derive(passphrase: &str, salt: &[u8]) -> Result<Self> {
        derive_root_key(passphrase.as_bytes(), salt, b"", ARGON2_PARALLELISM_DERIVE)
    }

    /// Raw key bytes. Callers must not log this.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Build from an already-derived 32-byte key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(storj_encryption::Key::from_bytes(bytes))
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
    storj_encryption::derive_root_key(password, salt, path, parallelism)
        .map(EncryptionKey)
        .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ARGON2_PARALLELISM_REQUEST;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use storj_encryption::derive_path_key_component;

    type HmacSha512 = Hmac<Sha512>;

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
