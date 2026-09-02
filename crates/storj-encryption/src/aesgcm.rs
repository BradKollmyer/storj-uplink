//! AES-256-GCM content-block transformer (Go `encryption` AES-GCM).
//!
//! Encrypted block size includes the 16-byte GCM tag. The starting nonce is
//! 12 bytes; each block adds `block_num` via little-endian [`crate::increment_bytes`].

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::cipher::AES_GCM_NONCE_SIZE;
use crate::error::{Error, ErrorKind, Result};
use crate::key::Key;
use crate::transform::{Transformer, increment_bytes};

/// AES-GCM tag size (`cipher.NewGCM` overhead).
pub const AES_GCM_TAG_SIZE: usize = 16;

/// AES-256-GCM encrypter. `InBlockSize = encryptedBlockSize - 16`.
#[derive(Clone)]
pub struct AesGcmEncrypter {
    cipher: Aes256Gcm,
    starting_nonce: [u8; AES_GCM_NONCE_SIZE],
    block_size: usize,
}

/// AES-256-GCM decrypter. `InBlockSize = encryptedBlockSize`.
#[derive(Clone)]
pub struct AesGcmDecrypter {
    cipher: Aes256Gcm,
    starting_nonce: [u8; AES_GCM_NONCE_SIZE],
    block_size: usize,
}

impl std::fmt::Debug for AesGcmEncrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmEncrypter")
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AesGcmDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmDecrypter")
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

fn new_cipher(key: &Key) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256-GCM accepts 32-byte keys")
}

fn check_block_size(encrypted_block_size: usize) -> Result<usize> {
    if encrypted_block_size <= AES_GCM_TAG_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encrypted block size {encrypted_block_size} too small"),
        ));
    }
    Ok(encrypted_block_size - AES_GCM_TAG_SIZE)
}

/// First 12 bytes of a Storj nonce (`ToAESGCMNonce`).
pub fn to_aes_gcm_nonce(nonce: &[u8]) -> Result<[u8; AES_GCM_NONCE_SIZE]> {
    nonce
        .get(..AES_GCM_NONCE_SIZE)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidConfig, "AES-GCM nonce too short"))
}

fn calc_gcm_nonce(
    starting_nonce: &[u8; AES_GCM_NONCE_SIZE],
    block_num: i64,
) -> Result<[u8; AES_GCM_NONCE_SIZE]> {
    let mut nonce = *starting_nonce;
    increment_bytes(&mut nonce, block_num)?;
    Ok(nonce)
}

impl AesGcmEncrypter {
    /// `NewAESGCMEncrypter`. `encrypted_block_size` includes the GCM tag.
    pub fn new(
        key: &Key,
        starting_nonce: &[u8; AES_GCM_NONCE_SIZE],
        encrypted_block_size: usize,
    ) -> Result<Self> {
        Ok(Self {
            cipher: new_cipher(key),
            starting_nonce: *starting_nonce,
            block_size: check_block_size(encrypted_block_size)?,
        })
    }
}

impl Transformer for AesGcmEncrypter {
    fn in_block_size(&self) -> usize {
        self.block_size
    }

    fn out_block_size(&self) -> usize {
        self.block_size + AES_GCM_TAG_SIZE
    }

    fn transform(&self, input: &[u8], block_num: i64) -> Result<Vec<u8>> {
        let nonce = calc_gcm_nonce(&self.starting_nonce, block_num)?;
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), input)
            .map_err(|e| Error::new(ErrorKind::Protocol, format!("aes-gcm encrypt: {e}")))
    }

    fn transform_into(&self, input: &[u8], block_num: i64, out: &mut Vec<u8>) -> Result<()> {
        use aes_gcm::aead::AeadInPlace;
        let nonce = calc_gcm_nonce(&self.starting_nonce, block_num)?;
        let start = out.len();
        out.extend_from_slice(input);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut out[start..])
            .map_err(|e| {
                out.truncate(start);
                Error::new(ErrorKind::Protocol, format!("aes-gcm encrypt: {e}"))
            })?;
        // Wire layout is ciphertext || tag.
        out.extend_from_slice(&tag);
        Ok(())
    }
}

impl AesGcmDecrypter {
    /// `NewAESGCMDecrypter`. `encrypted_block_size` includes the GCM tag.
    pub fn new(
        key: &Key,
        starting_nonce: &[u8; AES_GCM_NONCE_SIZE],
        encrypted_block_size: usize,
    ) -> Result<Self> {
        Ok(Self {
            cipher: new_cipher(key),
            starting_nonce: *starting_nonce,
            block_size: check_block_size(encrypted_block_size)?,
        })
    }
}

impl Transformer for AesGcmDecrypter {
    fn in_block_size(&self) -> usize {
        self.block_size + AES_GCM_TAG_SIZE
    }

    fn out_block_size(&self) -> usize {
        self.block_size
    }

    fn transform(&self, input: &[u8], block_num: i64) -> Result<Vec<u8>> {
        let nonce = calc_gcm_nonce(&self.starting_nonce, block_num)?;
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), input)
            .map_err(|_| Error::new(ErrorKind::DecryptionFailed, "aes-gcm decrypt"))
    }

    fn transform_into(&self, input: &[u8], block_num: i64, out: &mut Vec<u8>) -> Result<()> {
        use aes_gcm::aead::AeadInPlace;
        let nonce = calc_gcm_nonce(&self.starting_nonce, block_num)?;
        let Some(split) = input.len().checked_sub(AES_GCM_TAG_SIZE) else {
            return Err(Error::new(ErrorKind::DecryptionFailed, "aes-gcm decrypt"));
        };
        let (ct, tag) = input.split_at(split);
        let start = out.len();
        out.extend_from_slice(ct);
        let ok = self
            .cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                b"",
                &mut out[start..],
                aes_gcm::Tag::from_slice(tag),
            )
            .is_ok();
        if !ok {
            out.truncate(start);
            return Err(Error::new(ErrorKind::DecryptionFailed, "aes-gcm decrypt"));
        }
        Ok(())
    }
}

/// One-shot AES-256-GCM. Uses the first 12 bytes of `nonce`.
pub fn encrypt(data: &[u8], key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    let gcm = new_cipher(key);
    let nonce = to_aes_gcm_nonce(nonce)?;
    gcm.encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("aes-gcm encrypt: {e}")))
}

/// One-shot AES-256-GCM decrypt. Uses the first 12 bytes of `nonce`.
pub fn decrypt(cipher_data: &[u8], key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    let gcm = new_cipher(key);
    let nonce = to_aes_gcm_nonce(nonce)?;
    gcm.decrypt(Nonce::from_slice(&nonce), cipher_data)
        .map_err(|_| Error::new(ErrorKind::DecryptionFailed, "aes-gcm decrypt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transform::{Transformer, increment_bytes};

    fn key() -> Key {
        Key::from_bytes(std::array::from_fn(|i| u8::try_from(i).expect("i < 32")))
    }

    #[test]
    fn known_plaintext_hello() {
        let nonce = [0u8; 24];
        let ct = encrypt(b"hello", &key(), &nonce).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "66d9d9b2da0e0c4679f3a82524f5e0499271e16f30"
        );
        assert_eq!(decrypt(&ct, &key(), &nonce).unwrap(), b"hello");
    }

    #[test]
    fn transformer_known_blocks() {
        let starting = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let enc = AesGcmEncrypter::new(&key(), &starting, 48).unwrap();
        assert_eq!(enc.in_block_size(), 32);
        assert_eq!(enc.out_block_size(), 48);

        let b0 = vec![0x11u8; 32];
        let b1 = vec![0x22u8; 32];
        let c0 = enc.transform(&b0, 0).unwrap();
        let c1 = enc.transform(&b1, 1).unwrap();
        assert_eq!(
            hex::encode(&c0),
            "14fb4bc4fd85e1975db372560102fb395352f0ef867c41d4b04ee8358fa767d48ef044062b33329fcc88c8f58cbcf97a"
        );
        assert_eq!(
            hex::encode(&c1),
            "446f2bb42eedb9392c1ed6747f72fb08dd83aa859e30bbe7ccc06c5e4595a90cfb4f285f47395c6b595b8fdba57517d9"
        );

        let mut n1 = starting;
        increment_bytes(&mut n1, 1).unwrap();
        assert_eq!(hex::encode(n1), "0202030405060708090a0b0c");
        assert_eq!(encrypt(&b1, &key(), &n1).unwrap(), c1);

        let dec = AesGcmDecrypter::new(&key(), &starting, 48).unwrap();
        assert_eq!(dec.transform(&c0, 0).unwrap(), b0);
        assert_eq!(dec.transform(&c1, 1).unwrap(), b1);
    }

    #[test]
    fn too_small_block_size() {
        let n = [0u8; 12];
        let err = AesGcmEncrypter::new(&key(), &n, 16).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidConfig);
        assert!(err.message().contains("too small"));
    }

    #[test]
    fn debug_hides_key_and_nonce() {
        let n = [9u8; 12];
        let s = format!("{:?}", AesGcmEncrypter::new(&key(), &n, 48).unwrap());
        assert!(!s.contains("090909"));
        assert!(!s.contains("000102"));
    }
}
