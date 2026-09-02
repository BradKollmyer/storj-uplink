//! Cipher suites and one-shot encrypt/decrypt (AES-256-GCM, EncNull).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::{Error, ErrorKind, Result};
use crate::key::Key;

/// Size of a Storj nonce (`storj.NonceSize`).
pub const NONCE_SIZE: usize = 24;
/// AES-GCM nonce size (`AESGCMNonceSize`).
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Path/content cipher identifier. Unknown values are preserved.
///
/// Matches `storj.CipherSuite`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CipherSuite(pub i32);

impl CipherSuite {
    /// Proto zero value.
    pub const UNSPECIFIED: Self = Self(0);
    /// No encryption (`ENC_NULL`).
    pub const NULL: Self = Self(1);
    /// AES-256-GCM (`ENC_AESGCM`). Default path cipher.
    pub const AES_GCM: Self = Self(2);
    /// NaCl secretbox (`ENC_SECRETBOX`). Content cipher; path support is later.
    pub const SECRET_BOX: Self = Self(3);
    /// Encryption-bypass listing mode (`ENC_NULL_BASE64URL`).
    pub const NULL_BASE64_URL: Self = Self(4);
}

/// Encrypt `data` with `cipher`, `key`, and `nonce`.
///
/// Empty input returns empty output without invoking the primitive (Go `Encrypt`).
/// AES-GCM uses the first 12 bytes of `nonce`.
pub fn encrypt(data: &[u8], cipher: CipherSuite, key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    match cipher {
        CipherSuite::NULL => Ok(data.to_vec()),
        CipherSuite::AES_GCM => encrypt_aes_gcm(data, key, nonce),
        CipherSuite::NULL_BASE64_URL => Err(Error::new(
            ErrorKind::InvalidConfig,
            "base64 encoding not supported for this operation",
        )),
        CipherSuite::SECRET_BOX => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", cipher.0),
        )),
        other => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", other.0),
        )),
    }
}

/// Decrypt `cipher_data` with `cipher`, `key`, and `nonce`.
///
/// Empty input returns empty output without invoking the primitive (Go `Decrypt`).
pub fn decrypt(
    cipher_data: &[u8],
    cipher: CipherSuite,
    key: &Key,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if cipher_data.is_empty() {
        return Ok(Vec::new());
    }
    match cipher {
        CipherSuite::NULL => Ok(cipher_data.to_vec()),
        CipherSuite::AES_GCM => decrypt_aes_gcm(cipher_data, key, nonce),
        CipherSuite::NULL_BASE64_URL => Err(Error::new(
            ErrorKind::InvalidConfig,
            "base64 encoding not supported for this operation",
        )),
        CipherSuite::SECRET_BOX => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", cipher.0),
        )),
        other => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", other.0),
        )),
    }
}

fn aes_gcm_nonce(nonce: &[u8]) -> Result<[u8; AES_GCM_NONCE_SIZE]> {
    nonce
        .get(..AES_GCM_NONCE_SIZE)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidConfig, "AES-GCM nonce too short"))
}

fn encrypt_aes_gcm(data: &[u8], key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    let gcm = Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256-GCM accepts 32-byte keys");
    let nonce = aes_gcm_nonce(nonce)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce);
    gcm.encrypt(nonce, data)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("aes-gcm encrypt: {e}")))
}

fn decrypt_aes_gcm(cipher_data: &[u8], key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    let gcm = Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256-GCM accepts 32-byte keys");
    let nonce = aes_gcm_nonce(nonce)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce);
    gcm.decrypt(nonce, cipher_data)
        .map_err(|_| Error::new(ErrorKind::DecryptionFailed, "aes-gcm decrypt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_noop() {
        let key = Key::from_bytes([9u8; 32]);
        let nonce = [1u8; 24];
        assert!(
            encrypt(b"", CipherSuite::AES_GCM, &key, &nonce)
                .unwrap()
                .is_empty()
        );
        assert!(
            decrypt(b"", CipherSuite::AES_GCM, &key, &nonce)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = Key::from_bytes([7u8; 32]);
        let nonce = [2u8; 24];
        let ct = encrypt(b"hello", CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert_ne!(ct, b"hello");
        let pt = decrypt(&ct, CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn aes_gcm_uses_first_12_nonce_bytes() {
        let key = Key::from_bytes([7u8; 32]);
        let mut n1 = [3u8; 24];
        let mut n2 = n1;
        n2[12] = 99;
        let a = encrypt(b"hello", CipherSuite::AES_GCM, &key, &n1).unwrap();
        let b = encrypt(b"hello", CipherSuite::AES_GCM, &key, &n2).unwrap();
        assert_eq!(a, b);
        n1[0] ^= 1;
        let c = encrypt(b"hello", CipherSuite::AES_GCM, &key, &n1).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn null_is_identity() {
        let key = Key::from_bytes([1u8; 32]);
        let nonce = [0u8; 24];
        let ct = encrypt(b"plain", CipherSuite::NULL, &key, &nonce).unwrap();
        assert_eq!(ct, b"plain");
        assert_eq!(
            decrypt(&ct, CipherSuite::NULL, &key, &nonce).unwrap(),
            b"plain"
        );
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key = Key::from_bytes([7u8; 32]);
        let other = Key::from_bytes([8u8; 32]);
        let nonce = [2u8; 24];
        let ct = encrypt(b"hello", CipherSuite::AES_GCM, &key, &nonce).unwrap();
        let err = decrypt(&ct, CipherSuite::AES_GCM, &other, &nonce).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptionFailed);
        assert!(!err.to_string().contains("hello"));
    }
}
