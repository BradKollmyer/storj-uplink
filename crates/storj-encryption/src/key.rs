//! Root-key derivation (Argon2id) and HMAC-SHA512 HD steps.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, ErrorKind, Result};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Argon2id time parameter (both request and derive).
pub const ARGON2_TIME: u32 = 1;
/// Argon2id memory in KiB (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id output length.
pub const ARGON2_OUTPUT_LEN: usize = 32;
/// Parallelism for `Access::request_with_passphrase` (Go `access.go` hardcodes 8).
pub const ARGON2_PARALLELISM_REQUEST: u32 = 8;
/// Parallelism for `EncryptionKey::derive` (Go `DeriveEncryptionKey`).
pub const ARGON2_PARALLELISM_DERIVE: u32 = 1;

/// HMAC info prefix for path-component derivation.
pub const PATH_HMAC_PREFIX: &[u8] = b"path:";
/// HMAC info for content-key derivation.
pub const CONTENT_HMAC_INFO: &str = "content";
/// HMAC info for path-component nonces.
pub const NONCE_HMAC_INFO: &[u8] = b"nonce";

/// 32-byte root/path/content key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    bytes: [u8; 32],
}

impl Key {
    /// Build from an already-derived 32-byte key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Argon2id with caller-supplied salt (multitenancy).
    /// Matches `uplink.DeriveEncryptionKey` (Argon2id **p=1**, empty path).
    pub fn derive(passphrase: &str, salt: &[u8]) -> Result<Self> {
        derive_root_key(passphrase.as_bytes(), salt, b"", ARGON2_PARALLELISM_DERIVE)
    }

    /// Raw key bytes. Callers must not log this.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Copy of the raw key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// HD step: `HMAC-SHA512(self, "path:" + component)[0..32]`.
    pub fn derive_path_component(&self, component: &[u8]) -> Self {
        let mut mac = hmac_sha512(self.as_bytes());
        mac.update(PATH_HMAC_PREFIX);
        mac.update(component);
        truncate_key(mac)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([REDACTED])")
    }
}

impl From<[u8; 32]> for Key {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// `DeriveRootKey` with explicit Argon2 parallelism.
///
/// `parallelism` is **8** for `Access::request_with_passphrase` and **1** for
/// `Key::derive`. Using the wrong `p` yields a different root key than Go/console.
pub fn derive_root_key(password: &[u8], salt: &[u8], path: &[u8], parallelism: u32) -> Result<Key> {
    // Both HMACs are derived from the passphrase: wipe them when done.
    let mixed = Zeroizing::new(hmac_sha256(password, salt)?);
    let path_salt = Zeroizing::new(hmac_sha256(&*mixed, path)?);

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
        .hash_password_into(password, &*path_salt, &mut *out)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("argon2: {e}")))?;

    Ok(Key { bytes: *out })
}

/// `DeriveKey`: `HMAC-SHA512(key, message)[0..32]`.
pub fn derive_key(key: &Key, message: &str) -> Key {
    let mut mac = hmac_sha512(key.as_bytes());
    mac.update(message.as_bytes());
    truncate_key(mac)
}

/// Path-component HD step: `HMAC-SHA512(key, "path:" + component)[0..32]`.
///
/// Returns a plain array: the caller owns zeroizing it (wrap in
/// [`zeroize::Zeroizing`] or turn it into a [`Key`], which zeroizes on drop).
pub fn derive_path_key_component(key: &[u8; 32], component: &str) -> [u8; 32] {
    Key::from_bytes(*key)
        .derive_path_component(component.as_bytes())
        .to_bytes()
}

/// 24-byte nonce: `HMAC-SHA512(derived_key, "nonce")[0..24]`.
pub fn derive_nonce(derived_key: &Key) -> [u8; 24] {
    let mut mac = hmac_sha512(derived_key.as_bytes());
    mac.update(NONCE_HMAC_INFO);
    // The full 64-byte MAC contains the derived key material; wipe it.
    let full = Zeroizing::new(mac.finalize().into_bytes());
    let mut out = [0u8; 24];
    out.copy_from_slice(&full[..24]);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("hmac: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn hmac_sha512(key: &[u8]) -> HmacSha512 {
    HmacSha512::new_from_slice(key).expect("HMAC-SHA512 accepts 32-byte keys")
}

fn truncate_key(mac: HmacSha512) -> Key {
    // The first 32 bytes *are* the derived key; wipe the whole 64-byte MAC.
    let full = Zeroizing::new(mac.finalize().into_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    Key { bytes: out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let a = Key::derive("correct horse battery staple", b"0123456789abcdef").unwrap();
        let b = Key::derive("correct horse battery staple", b"0123456789abcdef").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
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
        assert_ne!(p1.as_bytes(), p8.as_bytes());
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
    fn debug_redacts_key_bytes() {
        let k = Key::from_bytes([0xab; 32]);
        let s = format!("{k:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("ab"));
    }

    #[test]
    fn derive_key_is_hmac_sha512_truncated() {
        let key = Key::from_bytes([3u8; 32]);
        let got = derive_key(&key, "content");
        let mut mac = HmacSha512::new_from_slice(key.as_bytes()).unwrap();
        mac.update(b"content");
        let expected = mac.finalize().into_bytes();
        assert_eq!(&got.as_bytes()[..], &expected[..32]);
    }
}
