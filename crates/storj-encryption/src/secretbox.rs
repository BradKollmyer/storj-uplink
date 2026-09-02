//! NaCl secretbox (XSalsa20-Poly1305) content-block transformer.
//!
//! Tag is 16 bytes **prepended** (NaCl `crypto_secretbox` / Go `nacl/secretbox`).
//! The starting nonce is 24 bytes; each block adds `block_num` via little-endian
//! [`crate::increment_bytes`].

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Nonce, XSalsa20Poly1305};

use crate::cipher::NONCE_SIZE;
use crate::error::{Error, ErrorKind, Result};
use crate::key::Key;
use crate::transform::{Transformer, increment_bytes};

/// Secretbox overhead (`secretbox.Overhead` / Poly1305 tag).
pub const SECRETBOX_OVERHEAD: usize = 16;

/// XSalsa20-Poly1305 encrypter. `InBlockSize = encryptedBlockSize - 16`.
#[derive(Clone)]
pub struct SecretboxEncrypter {
    cipher: XSalsa20Poly1305,
    starting_nonce: [u8; NONCE_SIZE],
    block_size: usize,
}

/// XSalsa20-Poly1305 decrypter. `InBlockSize = encryptedBlockSize`.
#[derive(Clone)]
pub struct SecretboxDecrypter {
    cipher: XSalsa20Poly1305,
    starting_nonce: [u8; NONCE_SIZE],
    block_size: usize,
}

impl std::fmt::Debug for SecretboxEncrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretboxEncrypter")
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SecretboxDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretboxDecrypter")
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

fn new_cipher(key: &Key) -> XSalsa20Poly1305 {
    XSalsa20Poly1305::new_from_slice(key.as_bytes()).expect("XSalsa20Poly1305 accepts 32-byte keys")
}

fn check_block_size(encrypted_block_size: usize) -> Result<usize> {
    if encrypted_block_size <= SECRETBOX_OVERHEAD {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encrypted block size {encrypted_block_size} too small"),
        ));
    }
    Ok(encrypted_block_size - SECRETBOX_OVERHEAD)
}

fn nonce24(nonce: &[u8]) -> Result<[u8; NONCE_SIZE]> {
    nonce
        .get(..NONCE_SIZE)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidConfig, "secretbox nonce too short"))
}

fn calc_nonce(starting_nonce: &[u8; NONCE_SIZE], block_num: i64) -> Result<[u8; NONCE_SIZE]> {
    let mut nonce = *starting_nonce;
    increment_bytes(&mut nonce, block_num)?;
    Ok(nonce)
}

impl SecretboxEncrypter {
    /// `NewSecretboxEncrypter`. `encrypted_block_size` includes the Poly1305 tag.
    pub fn new(
        key: &Key,
        starting_nonce: &[u8; NONCE_SIZE],
        encrypted_block_size: usize,
    ) -> Result<Self> {
        Ok(Self {
            cipher: new_cipher(key),
            starting_nonce: *starting_nonce,
            block_size: check_block_size(encrypted_block_size)?,
        })
    }
}

impl Transformer for SecretboxEncrypter {
    fn in_block_size(&self) -> usize {
        self.block_size
    }

    fn out_block_size(&self) -> usize {
        self.block_size + SECRETBOX_OVERHEAD
    }

    fn transform(&self, input: &[u8], block_num: i64) -> Result<Vec<u8>> {
        let nonce = calc_nonce(&self.starting_nonce, block_num)?;
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), input)
            .map_err(|e| Error::new(ErrorKind::Protocol, format!("secretbox encrypt: {e}")))
    }
}

impl SecretboxDecrypter {
    /// `NewSecretboxDecrypter`. `encrypted_block_size` includes the Poly1305 tag.
    pub fn new(
        key: &Key,
        starting_nonce: &[u8; NONCE_SIZE],
        encrypted_block_size: usize,
    ) -> Result<Self> {
        Ok(Self {
            cipher: new_cipher(key),
            starting_nonce: *starting_nonce,
            block_size: check_block_size(encrypted_block_size)?,
        })
    }
}

impl Transformer for SecretboxDecrypter {
    fn in_block_size(&self) -> usize {
        self.block_size + SECRETBOX_OVERHEAD
    }

    fn out_block_size(&self) -> usize {
        self.block_size
    }

    fn transform(&self, input: &[u8], block_num: i64) -> Result<Vec<u8>> {
        let nonce = calc_nonce(&self.starting_nonce, block_num)?;
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), input)
            .map_err(|_| Error::new(ErrorKind::DecryptionFailed, "secretbox decrypt"))
    }
}

/// One-shot NaCl secretbox. Requires a 24-byte nonce.
pub fn encrypt(data: &[u8], key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_cipher(key);
    let nonce = nonce24(nonce)?;
    cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| Error::new(ErrorKind::Protocol, format!("secretbox encrypt: {e}")))
}

/// One-shot NaCl secretbox decrypt. Requires a 24-byte nonce.
pub fn decrypt(cipher_data: &[u8], key: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_cipher(key);
    let nonce = nonce24(nonce)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), cipher_data)
        .map_err(|_| Error::new(ErrorKind::DecryptionFailed, "secretbox decrypt"))
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
            "9031d88e6447f0b8bf44357c58bf25f4226b9c2df7"
        );
        assert_eq!(ct.len(), 21);
        assert_eq!(decrypt(&ct, &key(), &nonce).unwrap(), b"hello");
    }

    #[test]
    fn transformer_known_blocks() {
        let starting: [u8; 24] = std::array::from_fn(|i| u8::try_from(i + 1).expect("i < 24"));
        let enc = SecretboxEncrypter::new(&key(), &starting, 48).unwrap();
        assert_eq!(enc.in_block_size(), 32);
        assert_eq!(enc.out_block_size(), 48);

        let b0 = vec![0x11u8; 32];
        let b1 = vec![0x22u8; 32];
        let c0 = enc.transform(&b0, 0).unwrap();
        let c1 = enc.transform(&b1, 1).unwrap();
        assert_eq!(
            hex::encode(&c0),
            "3ec123c6ecc80afab3663d23820cef6a1a3d8739114c366b1456e4ceb0eafe8423186ed948864db8e3b5262ebc59dcaa"
        );
        assert_eq!(
            hex::encode(&c1),
            "0fcb0834b19060a7d2995dc2245bf7940dbd4ff7d46b528d87b451cc5626bdb83d0140384b03332b60c226ed1144b3f3"
        );

        let mut n1 = starting;
        increment_bytes(&mut n1, 1).unwrap();
        assert_eq!(
            hex::encode(n1),
            "0202030405060708090a0b0c0d0e0f101112131415161718"
        );
        assert_eq!(encrypt(&b1, &key(), &n1).unwrap(), c1);

        let dec = SecretboxDecrypter::new(&key(), &starting, 48).unwrap();
        assert_eq!(dec.transform(&c0, 0).unwrap(), b0);
        assert_eq!(dec.transform(&c1, 1).unwrap(), b1);
    }

    #[test]
    fn uses_full_24_byte_nonce() {
        let mut n1 = [3u8; 24];
        let mut n2 = n1;
        n2[12] = 99;
        let a = encrypt(b"hello", &key(), &n1).unwrap();
        let b = encrypt(b"hello", &key(), &n2).unwrap();
        assert_ne!(a, b);
        n1[0] ^= 1;
        let c = encrypt(b"hello", &key(), &n1).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn too_small_block_size() {
        let n = [0u8; 24];
        let err = SecretboxEncrypter::new(&key(), &n, 16).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidConfig);
    }

    #[test]
    fn wrong_key_fails() {
        let nonce = [2u8; 24];
        let ct = encrypt(b"hello", &key(), &nonce).unwrap();
        let other = Key::from_bytes([8u8; 32]);
        let err = decrypt(&ct, &other, &nonce).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptionFailed);
        assert!(!err.to_string().contains("hello"));
    }
}
