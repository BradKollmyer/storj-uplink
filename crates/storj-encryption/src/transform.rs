//! Block transformer trait, nonce increment, encompassing blocks, encrypted size.
//!
//! Matches `storj.io/common/encryption` (`Transformer`, `Increment`,
//! `CalcEncompassingBlocks`, `CalcEncryptedSize`).

use crate::aesgcm::{AES_GCM_TAG_SIZE, AesGcmDecrypter, AesGcmEncrypter, to_aes_gcm_nonce};
use crate::cipher::{CipherSuite, NONCE_SIZE};
use crate::error::{Error, ErrorKind, Result};
use crate::key::Key;
use crate::pad::{UINT32_SIZE, pad, unpad};
use crate::secretbox::{SECRETBOX_OVERHEAD, SecretboxDecrypter, SecretboxEncrypter};

/// Uplink default encrypted block size (`29 * 256 = 7424`, including AEAD tag).
pub const DEFAULT_ENCRYPTED_BLOCK_SIZE: usize = 29 * 256;

/// Content-block transformation that changes size deterministically per block.
///
/// Go `encryption.Transformer`.
pub trait Transformer: Send + Sync + std::fmt::Debug {
    /// Plaintext (encrypter) or ciphertext (decrypter) block size.
    fn in_block_size(&self) -> usize;
    /// Ciphertext (encrypter) or plaintext (decrypter) block size.
    fn out_block_size(&self) -> usize;
    /// Transform one block. `block_num` is added to the starting nonce.
    fn transform(&self, input: &[u8], block_num: i64) -> Result<Vec<u8>>;

    /// Transform one block, appending the output to `out` (Go
    /// `Transformer.Transform(out, in, ...)`). The default delegates to
    /// [`Self::transform`]; cipher transformers override it to work in place
    /// without an intermediate allocation.
    fn transform_into(&self, input: &[u8], block_num: i64, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.transform(input, block_num)?);
        Ok(())
    }
}

/// Pass-through transformer (`EncNull`). In/out block size is 1.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopTransformer;

impl Transformer for NoopTransformer {
    fn in_block_size(&self) -> usize {
        1
    }

    fn out_block_size(&self) -> usize {
        1
    }

    fn transform(&self, input: &[u8], _block_num: i64) -> Result<Vec<u8>> {
        Ok(input.to_vec())
    }
}

/// Cipher suite and encrypted block size (Go `storj.EncryptionParameters`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionParameters {
    /// Content cipher.
    pub cipher_suite: CipherSuite,
    /// Encrypted block size in bytes (includes AEAD tag). Proto `int64`.
    pub block_size: i64,
}

/// Increment `buf` as a **little-endian** unsigned integer (Go `incrementBytes`).
///
/// `amount` must be non-negative. Returns `true` if the addition overflowed
/// `buf` (truncated). AES-GCM comments in Go say "big-endian"; the code is LE.
pub fn increment_bytes(buf: &mut [u8], mut amount: i64) -> Result<bool> {
    if amount < 0 {
        return Err(Error::new(ErrorKind::InvalidConfig, "amount was negative"));
    }
    let mut idx = 0;
    while amount > 0 && idx < buf.len() {
        let inc = amount as u8;
        amount >>= 8;
        let prev = buf[idx];
        buf[idx] = buf[idx].wrapping_add(inc);
        if buf[idx] < prev {
            amount += 1;
        }
        idx += 1;
    }
    Ok(amount != 0)
}

/// Increment a 24-byte Storj nonce (Go `Increment`).
pub fn increment(nonce: &mut [u8; NONCE_SIZE], amount: i64) -> Result<bool> {
    increment_bytes(nonce, amount)
}

/// Blocks that contain `[offset, offset+length)` (Go `CalcEncompassingBlocks`).
///
/// `block_size` must be positive. `length <= 0` yields `block_count = 0`.
pub fn calc_encompassing_blocks(offset: i64, length: i64, block_size: usize) -> (i64, i64) {
    let block_size = i64::try_from(block_size).expect("block size fits i64");
    let first_block = offset / block_size;
    if length <= 0 {
        return (first_block, 0);
    }
    let end = offset + length;
    let last_block = end / block_size;
    if end % block_size == 0 {
        (first_block, last_block - first_block)
    } else {
        (first_block, 1 + last_block - first_block)
    }
}

/// Encrypter `(in_block, out_block)` for `encrypted_block_size` (includes AEAD tag).
///
/// Used by [`calc_encrypted_size`] so size math does not construct a dummy
/// key or nonce.
fn encrypter_io_blocks(cipher: CipherSuite, encrypted_block_size: usize) -> Result<(usize, usize)> {
    match cipher {
        CipherSuite::NULL => Ok((1, 1)),
        CipherSuite::AES_GCM => {
            if encrypted_block_size <= AES_GCM_TAG_SIZE {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    format!("encrypted block size {encrypted_block_size} too small"),
                ));
            }
            Ok((
                encrypted_block_size - AES_GCM_TAG_SIZE,
                encrypted_block_size,
            ))
        }
        CipherSuite::SECRET_BOX => {
            if encrypted_block_size <= SECRETBOX_OVERHEAD {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    format!("encrypted block size {encrypted_block_size} too small"),
                ));
            }
            Ok((
                encrypted_block_size - SECRETBOX_OVERHEAD,
                encrypted_block_size,
            ))
        }
        CipherSuite::NULL_BASE64_URL => Err(Error::new(
            ErrorKind::InvalidConfig,
            "base64 encoding not supported for this operation",
        )),
        other => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", other.0),
        )),
    }
}

/// Cipher data size after padding + encrypting `data_size` bytes.
pub fn calc_encrypted_size(data_size: i64, parameters: EncryptionParameters) -> Result<i64> {
    let block_size = match parameters.cipher_suite {
        CipherSuite::NULL => 1,
        _ => usize::try_from(parameters.block_size).map_err(|_| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("encrypted block size {} too small", parameters.block_size),
            )
        })?,
    };
    let (in_block, out_block) = encrypter_io_blocks(parameters.cipher_suite, block_size)?;
    Ok(encrypted_size_from_blocks(data_size, in_block, out_block))
}

/// `CalcTransformerEncryptedSize`: includes the 4-byte padding trailer.
pub fn calc_transformer_encrypted_size(data_size: i64, transformer: &dyn Transformer) -> i64 {
    encrypted_size_from_blocks(
        data_size,
        transformer.in_block_size(),
        transformer.out_block_size(),
    )
}

fn encrypted_size_from_blocks(data_size: i64, in_block: usize, out_block: usize) -> i64 {
    let in_block = i64::try_from(in_block).expect("block size fits i64");
    let out_block = i64::try_from(out_block).expect("block size fits i64");
    let blocks =
        (data_size + i64::try_from(UINT32_SIZE).expect("4 fits") + in_block - 1) / in_block;
    blocks * out_block
}

/// `NewEncrypter`. `encrypted_block_size` includes the AEAD tag (ignored for `EncNull`).
pub fn new_encrypter(
    cipher: CipherSuite,
    key: &Key,
    starting_nonce: &[u8; NONCE_SIZE],
    encrypted_block_size: usize,
) -> Result<Box<dyn Transformer>> {
    match cipher {
        CipherSuite::NULL => Ok(Box::new(NoopTransformer)),
        CipherSuite::AES_GCM => {
            let nonce = to_aes_gcm_nonce(starting_nonce)?;
            Ok(Box::new(AesGcmEncrypter::new(
                key,
                &nonce,
                encrypted_block_size,
            )?))
        }
        CipherSuite::SECRET_BOX => Ok(Box::new(SecretboxEncrypter::new(
            key,
            starting_nonce,
            encrypted_block_size,
        )?)),
        CipherSuite::NULL_BASE64_URL => Err(Error::new(
            ErrorKind::InvalidConfig,
            "base64 encoding not supported for this operation",
        )),
        other => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", other.0),
        )),
    }
}

/// `NewDecrypter`. `encrypted_block_size` includes the AEAD tag (ignored for `EncNull`).
pub fn new_decrypter(
    cipher: CipherSuite,
    key: &Key,
    starting_nonce: &[u8; NONCE_SIZE],
    encrypted_block_size: usize,
) -> Result<Box<dyn Transformer>> {
    match cipher {
        CipherSuite::NULL => Ok(Box::new(NoopTransformer)),
        CipherSuite::AES_GCM => {
            let nonce = to_aes_gcm_nonce(starting_nonce)?;
            Ok(Box::new(AesGcmDecrypter::new(
                key,
                &nonce,
                encrypted_block_size,
            )?))
        }
        CipherSuite::SECRET_BOX => Ok(Box::new(SecretboxDecrypter::new(
            key,
            starting_nonce,
            encrypted_block_size,
        )?)),
        CipherSuite::NULL_BASE64_URL => Err(Error::new(
            ErrorKind::InvalidConfig,
            "base64 encoding not supported for this operation",
        )),
        other => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("encryption type {} is not supported", other.0),
        )),
    }
}

/// Transform every `in_block_size` chunk. `data.len()` must be a multiple of the in size.
pub fn transform_blocks(
    transformer: &dyn Transformer,
    data: &[u8],
    starting_block: i64,
) -> Result<Vec<u8>> {
    let in_size = transformer.in_block_size();
    if in_size == 0 || data.len() % in_size != 0 {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "invalid transformer and range reader combination.the range reader size is not a multiple of the block size",
        ));
    }
    let mut out = Vec::with_capacity((data.len() / in_size) * transformer.out_block_size());
    for (block_num, chunk) in (starting_block..).zip(data.chunks(in_size)) {
        transformer.transform_into(chunk, block_num, &mut out)?;
    }
    Ok(out)
}

/// Pad to `in_block_size` then encrypt (Go `TransformWriterPadded`).
pub fn transform_padded(transformer: &dyn Transformer, data: &[u8]) -> Result<Vec<u8>> {
    let padded = pad(data, transformer.in_block_size())?;
    transform_blocks(transformer, &padded, 0)
}

/// Decrypt full blocks then strip padding (inverse of [`transform_padded`]).
pub fn transform_unpad(transformer: &dyn Transformer, data: &[u8]) -> Result<Vec<u8>> {
    let plain = transform_blocks(transformer, data, 0)?;
    unpad(&plain).map(Vec::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes(std::array::from_fn(|i| u8::try_from(i).expect("i < 32")))
    }

    #[test]
    fn increment_is_little_endian() {
        let cases: &[(&[u8], i64, &str, bool)] = &[
            (&[0, 0, 0, 0], 1, "01000000", false),
            (&[255, 0, 0, 0], 1, "00010000", false),
            (&[255, 255, 0, 0], 1, "00000100", false),
            (&[0, 0, 0, 0], 256, "00010000", false),
            (&[255, 255, 255, 255], 1, "00000000", true),
            (
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                1,
                "0202030405060708090a0b0c",
                false,
            ),
            (&[255; 12], 1, "000000000000000000000000", true),
        ];
        for &(input, amount, out_hex, want_trunc) in cases {
            let mut buf = input.to_vec();
            let trunc = increment_bytes(&mut buf, amount).unwrap();
            assert_eq!(hex::encode(&buf), out_hex, "in={}", hex::encode(input));
            assert_eq!(trunc, want_trunc);
        }
        assert_eq!(
            increment_bytes(&mut [0u8; 4], -1).unwrap_err().kind(),
            ErrorKind::InvalidConfig
        );
    }

    #[test]
    fn increment_nonce_24() {
        let mut n = [0u8; 24];
        assert!(!increment(&mut n, 1).unwrap());
        assert_eq!(n[0], 1);
        assert!(n[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn encompassing_blocks_matches_go() {
        let cases: &[(i64, i64, usize, i64, i64)] = &[
            (0, 0, 10, 0, 0),
            (0, 10, 10, 0, 1),
            (0, 11, 10, 0, 2),
            (5, 10, 10, 0, 2),
            (10, 10, 10, 1, 1),
            (100, 0, 10, 10, 0),
            (0, 7424, 7424, 0, 1),
            (1, 7424, 7424, 0, 2),
            (7424, 1, 7424, 1, 1),
        ];
        for &(off, len, bs, first, count) in cases {
            assert_eq!(
                calc_encompassing_blocks(off, len, bs),
                (first, count),
                "off={off} len={len} bs={bs}"
            );
        }
    }

    #[test]
    fn encrypted_size_matches_go() {
        let aes = EncryptionParameters {
            cipher_suite: CipherSuite::AES_GCM,
            block_size: 1024,
        };
        let cases: &[(i64, i64)] = &[
            (0, 1024),
            (1, 1024),
            (1020, 2048),
            (1024, 2048),
            (32764, 33792),
            (32768, 33792),
            (32868, 33792),
        ];
        for &(ds, want) in cases {
            assert_eq!(calc_encrypted_size(ds, aes).unwrap(), want, "ds={ds}");
        }
        assert_eq!(
            calc_encrypted_size(
                0,
                EncryptionParameters {
                    cipher_suite: CipherSuite::NULL,
                    block_size: 1024,
                }
            )
            .unwrap(),
            4
        );
        assert_eq!(
            calc_encrypted_size(
                1,
                EncryptionParameters {
                    cipher_suite: CipherSuite::NULL,
                    block_size: 1024,
                }
            )
            .unwrap(),
            5
        );
        assert_eq!(
            calc_encrypted_size(
                1,
                EncryptionParameters {
                    cipher_suite: CipherSuite::SECRET_BOX,
                    block_size: 1024,
                }
            )
            .unwrap(),
            1024
        );
    }

    #[test]
    fn encrypted_size_matches_pad_then_encrypt() {
        for cipher in [
            CipherSuite::AES_GCM,
            CipherSuite::SECRET_BOX,
            CipherSuite::NULL,
        ] {
            for data_size in [0_i64, 1, 1020, 1024, 2000] {
                let params = EncryptionParameters {
                    cipher_suite: cipher,
                    block_size: 1024,
                };
                let want = calc_encrypted_size(data_size, params).unwrap();
                let enc = new_encrypter(cipher, &key(), &[7u8; 24], 1024).unwrap();
                let data = vec![0x5au8; data_size as usize];
                let got = transform_padded(enc.as_ref(), &data).unwrap();
                assert_eq!(got.len() as i64, want, "cipher={} ds={data_size}", cipher.0);

                let dec = new_decrypter(cipher, &key(), &[7u8; 24], 1024).unwrap();
                let back = transform_unpad(dec.as_ref(), &got).unwrap();
                assert_eq!(back, data);
            }
        }
    }

    #[test]
    fn default_block_is_one_stripe() {
        assert_eq!(DEFAULT_ENCRYPTED_BLOCK_SIZE, 7424);
        let enc = new_encrypter(
            CipherSuite::AES_GCM,
            &key(),
            &[0u8; 24],
            DEFAULT_ENCRYPTED_BLOCK_SIZE,
        )
        .unwrap();
        assert_eq!(enc.out_block_size(), 7424);
        assert_eq!(enc.in_block_size(), 7424 - 16);
    }

    #[test]
    fn nonce_increments_per_block() {
        let nonce = [1u8; 24];
        let enc = new_encrypter(CipherSuite::AES_GCM, &key(), &nonce, 48).unwrap();
        let p0 = vec![0x11u8; enc.in_block_size()];
        let p1 = vec![0x22u8; enc.in_block_size()];
        let c0 = enc.transform(&p0, 0).unwrap();
        let c1 = enc.transform(&p1, 1).unwrap();
        assert_ne!(c0, enc.transform(&p0, 1).unwrap());
        assert_ne!(c0, c1);

        let dec = new_decrypter(CipherSuite::AES_GCM, &key(), &nonce, 48).unwrap();
        assert_eq!(dec.transform(&c0, 0).unwrap(), p0);
        assert_eq!(dec.transform(&c1, 1).unwrap(), p1);
        assert!(dec.transform(&c1, 0).is_err());
    }

    #[test]
    fn unsupported_cipher() {
        let err =
            new_encrypter(CipherSuite::NULL_BASE64_URL, &key(), &[0u8; 24], 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidConfig);
        let err = new_encrypter(CipherSuite(99), &key(), &[0u8; 24], 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidConfig);
    }
}
