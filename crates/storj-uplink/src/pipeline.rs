//! Encrypt a segment and Reed-Solomon encode it into pieces.
//!
//! Inline objects use one-shot Encrypt (no block padding). Remote segments
//! use padded block transformers then pad to the RS stripe size.

use prost::Message;
use rand::RngCore;
use storj_ec::ReedSolomon;
use storj_encryption::{
    CipherSuite, DEFAULT_ENCRYPTED_BLOCK_SIZE, Key, NONCE_SIZE, encrypt, increment, new_encrypter,
    transform_padded,
};
use storj_proto::pointerdb::RedundancyScheme;

use crate::{Error, Result};

/// Encrypted segments at or below this size are stored inline (satellite default).
pub const MAX_INLINE_SEGMENT_SIZE: usize = 4 * 1024;
/// Maximum plaintext of a single segment (satellite `MaxSegmentSize`).
pub const MAX_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;

/// RS parameters from a [`RedundancyScheme`] (never hardcoded in production).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Redundancy {
    /// Data shares (`k` / `min_req`).
    pub k: usize,
    /// Repair threshold (`m`).
    pub m: usize,
    /// Long-tail success threshold (`o`).
    pub o: usize,
    /// Total pieces attempted (`n`).
    pub n: usize,
    /// Bytes per erasure share.
    pub share_size: usize,
}

impl Redundancy {
    /// Parse a satellite scheme. `k/m/o/n` come from BeginSegment, not constants.
    pub fn from_scheme(scheme: &RedundancyScheme) -> Result<Self> {
        let k = to_usize(scheme.min_req, "min_req")?;
        let n = to_usize(scheme.total, "total")?;
        let m = to_usize(scheme.repair_threshold, "repair_threshold")?;
        let o = to_usize(scheme.success_threshold, "success_threshold")?;
        let share_size = to_usize(scheme.erasure_share_size, "erasure_share_size")?;
        if k == 0 || n == 0 || o == 0 || share_size == 0 || k > n || o > n {
            return Err(Error::protocol(format!(
                "invalid redundancy k={k} m={m} o={o} n={n} share={share_size}"
            )));
        }
        Ok(Self {
            k,
            m,
            o,
            n,
            share_size,
        })
    }

    /// Stripe size in bytes (`k * share_size`).
    #[must_use]
    pub fn stripe_size(&self) -> usize {
        self.k * self.share_size
    }
}

fn to_usize(v: i32, name: &str) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::protocol(format!("{name} {v} does not fit usize")))
}

/// Random 32-byte content/segment key.
#[must_use]
pub fn random_key() -> Key {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Key::from_bytes(bytes)
}

/// Random 24-byte Storj nonce.
#[must_use]
pub fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut n = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// Content-block starting nonce for a segment position (Go `nonceForPosition`).
///
/// Increment is `(part_number << 32) | (index + 1)` so metadata can use zero.
#[must_use]
pub fn content_nonce(part_number: i32, index: i32) -> [u8; NONCE_SIZE] {
    let mut n = [0u8; NONCE_SIZE];
    let amount = (i64::from(part_number) << 32) | (i64::from(index) + 1);
    let _ = increment(&mut n, amount);
    n
}

/// One-shot encrypt (inline path). Empty input stays empty (Go `Encrypt`).
pub fn encrypt_inline(
    plain: &[u8],
    cipher: CipherSuite,
    key: &Key,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>> {
    Ok(encrypt(plain, cipher, key, nonce)?)
}

/// True when `encrypted` fits in an inline segment (≤ 4 KiB).
#[must_use]
pub fn is_inline(encrypted: &[u8]) -> bool {
    encrypted.len() <= MAX_INLINE_SEGMENT_SIZE
}

/// Pad + encrypt with the content-block transformer (remote path).
pub fn encrypt_remote(
    plain: &[u8],
    cipher: CipherSuite,
    key: &Key,
    nonce: &[u8; NONCE_SIZE],
    encrypted_block_size: usize,
) -> Result<Vec<u8>> {
    let block = if encrypted_block_size == 0 {
        DEFAULT_ENCRYPTED_BLOCK_SIZE
    } else {
        encrypted_block_size
    };
    let encrypter = new_encrypter(cipher, key, nonce, block)?;
    Ok(transform_padded(encrypter.as_ref(), plain)?)
}

/// Zero-pad `data` so its length is a multiple of `stripe_size`.
#[must_use]
pub fn pad_to_stripe(data: &[u8], stripe_size: usize) -> Vec<u8> {
    if stripe_size == 0 {
        return data.to_vec();
    }
    let rem = data.len() % stripe_size;
    if rem == 0 {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    out.resize(data.len() + (stripe_size - rem), 0);
    out
}

/// Encode padded ciphertext into `n` pieces (concatenation of per-stripe shares).
pub fn encode_pieces(encrypted: &[u8], rs: &Redundancy) -> Result<Vec<Vec<u8>>> {
    let stripe = rs.stripe_size();
    let padded = pad_to_stripe(encrypted, stripe);
    let codec = ReedSolomon::new(rs.k, rs.n, rs.share_size)?;
    let mut pieces = vec![Vec::new(); rs.n];
    if padded.is_empty() {
        return Ok(pieces);
    }
    for chunk in padded.chunks(stripe) {
        let shares = codec.encode_stripe(chunk)?;
        for (i, share) in shares.into_iter().enumerate() {
            pieces[i].extend_from_slice(&share);
        }
    }
    Ok(pieces)
}

/// Encrypt a 32-byte key with `parent` (Go `EncryptKey`).
pub fn encrypt_key(
    key: &Key,
    cipher: CipherSuite,
    parent: &Key,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>> {
    Ok(encrypt(key.as_bytes(), cipher, parent, nonce)?)
}

/// `pb.SerializableMeta` (custom metadata map).
#[derive(Clone, PartialEq, Message)]
pub struct SerializableMeta {
    /// User-defined key/value pairs.
    #[prost(map = "string, string", tag = "1")]
    pub user_defined: ::std::collections::HashMap<String, String>,
}

/// `pb.StreamInfo` (encrypted inside [`StreamMeta`]).
#[derive(Clone, PartialEq, Message)]
pub struct StreamInfo {
    #[prost(int64, tag = "1")]
    pub deprecated_number_of_segments: i64,
    #[prost(int64, tag = "2")]
    pub segments_size: i64,
    #[prost(int64, tag = "3")]
    pub last_segment_size: i64,
    #[prost(bytes = "vec", tag = "4")]
    pub metadata: Vec<u8>,
}

/// `pb.StreamMeta` stored as object encrypted_metadata.
#[derive(Clone, PartialEq, Message)]
pub struct StreamMeta {
    #[prost(bytes = "vec", tag = "1")]
    pub encrypted_stream_info: Vec<u8>,
    #[prost(int32, tag = "2")]
    pub encryption_type: i32,
    #[prost(int32, tag = "3")]
    pub encryption_block_size: i32,
    #[prost(int64, tag = "5")]
    pub number_of_segments: i64,
}

/// Encrypted object metadata for `CommitObject` (Go `EncryptedUserData`).
#[derive(Clone, Debug, Default)]
pub struct EncryptedUserData {
    /// Marshaled [`StreamMeta`].
    pub encrypted_metadata: Vec<u8>,
    /// Segment-style encrypted metadata key.
    pub encrypted_metadata_encrypted_key: Vec<u8>,
    /// Nonce used to encrypt the metadata key.
    pub encrypted_metadata_nonce: [u8; NONCE_SIZE],
    /// Optional encrypted ETag (nonce `{1}`).
    pub encrypted_etag: Vec<u8>,
}

/// Encrypt stream + custom metadata with a random metadata key (Go uplink).
pub fn encrypt_user_data(
    custom: &[(String, String)],
    segment_size: i64,
    last_segment_size: i64,
    cipher: CipherSuite,
    derived_content_key: &Key,
) -> Result<EncryptedUserData> {
    let mut user_defined = std::collections::HashMap::new();
    for (k, v) in custom {
        user_defined.insert(k.clone(), v.clone());
    }
    let metadata_bytes = SerializableMeta { user_defined }.encode_to_vec();
    let stream_info = StreamInfo {
        deprecated_number_of_segments: 0,
        segments_size: segment_size,
        last_segment_size,
        metadata: metadata_bytes,
    }
    .encode_to_vec();

    let metadata_key = random_key();
    let encrypted_metadata_nonce = random_nonce();
    let encrypted_metadata_encrypted_key = encrypt_key(
        &metadata_key,
        cipher,
        derived_content_key,
        &encrypted_metadata_nonce,
    )?;
    let encrypted_stream_info = encrypt(&stream_info, cipher, &metadata_key, &[0u8; NONCE_SIZE])?;
    let encrypted_metadata = StreamMeta {
        encrypted_stream_info,
        encryption_type: cipher.0,
        encryption_block_size: 0,
        number_of_segments: 1,
    }
    .encode_to_vec();
    let encrypted_etag = encrypt(&[], cipher, &metadata_key, &{
        let mut n = [0u8; NONCE_SIZE];
        n[0] = 1;
        n
    })?;

    Ok(EncryptedUserData {
        encrypted_metadata,
        encrypted_metadata_encrypted_key,
        encrypted_metadata_nonce,
        encrypted_etag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use storj_ec::decode_stripe;

    #[test]
    fn inline_empty_and_small() {
        let key = Key::from_bytes([7u8; 32]);
        let nonce = [1u8; NONCE_SIZE];
        let empty = encrypt_inline(b"", CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert!(empty.is_empty());
        assert!(is_inline(&empty));
        let one = encrypt_inline(b"x", CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert_eq!(one.len(), 1 + 16);
        assert!(is_inline(&one));
    }

    #[test]
    fn inline_threshold_is_encrypted_size() {
        let key = Key::from_bytes([3u8; 32]);
        let nonce = [2u8; NONCE_SIZE];
        let just = vec![0u8; MAX_INLINE_SEGMENT_SIZE - 16];
        let enc = encrypt_inline(&just, CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert_eq!(enc.len(), MAX_INLINE_SEGMENT_SIZE);
        assert!(is_inline(&enc));
        let over = vec![0u8; MAX_INLINE_SEGMENT_SIZE - 15];
        let enc = encrypt_inline(&over, CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert!(enc.len() > MAX_INLINE_SEGMENT_SIZE);
        assert!(!is_inline(&enc));
    }

    #[test]
    fn encode_pieces_round_trips_first_k() {
        let rs = Redundancy {
            k: 2,
            m: 3,
            o: 3,
            n: 4,
            share_size: 8,
        };
        let data = vec![0x11u8; rs.stripe_size() * 3];
        let pieces = encode_pieces(&data, &rs).unwrap();
        assert_eq!(pieces.len(), 4);
        let codec = ReedSolomon::new(rs.k, rs.n, rs.share_size).unwrap();
        for stripe_i in 0..3 {
            let mut slots = vec![None; rs.n];
            for (i, piece) in pieces.iter().enumerate().take(rs.k) {
                let off = stripe_i * rs.share_size;
                slots[i] = Some(&piece[off..off + rs.share_size]);
            }
            let got = codec.decode_stripe(&slots).unwrap();
            assert_eq!(
                got,
                data[stripe_i * rs.stripe_size()..(stripe_i + 1) * rs.stripe_size()]
            );
        }
        let _ = decode_stripe;
    }

    #[test]
    fn content_nonce_skips_zero() {
        let n = content_nonce(0, 0);
        assert_eq!(n[0], 1);
        assert!(n[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn redundancy_rejects_zero() {
        let bad = RedundancyScheme {
            min_req: 0,
            total: 4,
            repair_threshold: 3,
            success_threshold: 3,
            erasure_share_size: 32,
            r#type: 1,
        };
        assert!(Redundancy::from_scheme(&bad).is_err());
    }
}
