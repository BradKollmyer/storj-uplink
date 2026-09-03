//! Encrypt a segment and Reed-Solomon encode it into pieces.
//!
//! Inline objects use one-shot Encrypt (no block padding). Remote segments
//! use padded block transformers then pad to the RS stripe size.

use prost::Message;
use rand::RngCore;
use storj_ec::ReedSolomon;
use storj_encryption::{
    CipherSuite, DEFAULT_ENCRYPTED_BLOCK_SIZE, Key, NONCE_SIZE, decrypt, encrypt, increment,
    new_encrypter, transform_padded,
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
/// Go `eestream.CalcPieceSize`: the piece size the satellite expects for an
/// encrypted segment of `encrypted_size` bytes. The `+ 4` is the padding
/// length trailer that [`storj_encryption::pad`] always appends before
/// erasure coding, so an exact stripe multiple still gains a stripe.
pub fn calc_piece_size(encrypted_size: i64, rs: &Redundancy) -> i64 {
    let stripe = rs.stripe_size() as i64;
    if stripe == 0 || rs.k == 0 {
        return 0;
    }
    let stripes = (encrypted_size + storj_encryption::UINT32_SIZE as i64 + stripe - 1) / stripe;
    stripes * stripe / rs.k as i64
}

/// Encode padded ciphertext into `n` pieces (concatenation of per-stripe shares).
pub fn encode_pieces(encrypted: &[u8], rs: &Redundancy) -> Result<Vec<Vec<u8>>> {
    let stripe = rs.stripe_size();
    // Go `segmentupload`: `encryption.PadReader(segment, stripeSize)` pads the
    // *encrypted* segment with the length-trailer padding (at least 4 bytes,
    // total a multiple of the stripe), so a segment that is already an exact
    // stripe multiple still gains a whole stripe. The satellite verifies
    // piece sizes against `CalcPieceSize`, which assumes exactly this.
    let padded = storj_encryption::pad(encrypted, stripe)?;
    let codec = ReedSolomon::new(rs.k, rs.n, rs.share_size)?;
    if padded.is_empty() {
        return Ok(vec![Vec::new(); rs.n]);
    }
    let n_stripes = padded.len() / stripe;
    let ss = rs.share_size;
    // Encode each stripe directly into its slot of every piece: no per-stripe
    // share allocations or copies.
    let mut pieces = vec![vec![0u8; n_stripes * ss]; rs.n];
    for (s, chunk) in padded.chunks(stripe).enumerate() {
        let off = s * ss;
        let mut slots: Vec<&mut [u8]> = pieces.iter_mut().map(|p| &mut p[off..off + ss]).collect();
        codec.encode_stripe_into(chunk, &mut slots)?;
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

/// Decrypt a 32-byte key with `parent` (Go `DecryptKey`).
pub fn decrypt_key(
    encrypted: &[u8],
    cipher: CipherSuite,
    parent: &Key,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Key> {
    let raw = decrypt(encrypted, cipher, parent, nonce)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::protocol("decrypted key is not 32 bytes"))?;
    Ok(Key::from_bytes(bytes))
}

/// Copy a Storj nonce from a protobuf bytes field (24 bytes, extra ignored).
pub fn nonce_from_slice(b: &[u8]) -> Result<[u8; NONCE_SIZE]> {
    if b.len() < NONCE_SIZE {
        return Err(Error::protocol("nonce is shorter than 24 bytes"));
    }
    let mut n = [0u8; NONCE_SIZE];
    n.copy_from_slice(&b[..NONCE_SIZE]);
    Ok(n)
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
    number_of_segments: i64,
    cipher: CipherSuite,
    derived_content_key: &Key,
    encryption_block_size: usize,
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
    let block = if encryption_block_size == 0 {
        DEFAULT_ENCRYPTED_BLOCK_SIZE
    } else {
        encryption_block_size
    };
    let encrypted_metadata = StreamMeta {
        encrypted_stream_info,
        encryption_type: cipher.0,
        encryption_block_size: i32::try_from(block).unwrap_or(i32::MAX),
        number_of_segments,
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

/// Decrypt object `encrypted_metadata` (Go `DecryptUserData`).
pub fn decrypt_user_data(
    encrypted_metadata: &[u8],
    encrypted_metadata_encrypted_key: &[u8],
    encrypted_metadata_nonce: &[u8],
    cipher: CipherSuite,
    derived_content_key: &Key,
) -> Result<(StreamMeta, SerializableMeta)> {
    let (meta, _info, custom) = decrypt_user_data_full(
        encrypted_metadata,
        encrypted_metadata_encrypted_key,
        encrypted_metadata_nonce,
        cipher,
        derived_content_key,
    )?;
    Ok((meta, custom))
}

/// Decrypt user data and the inner [`StreamInfo`] (needed to replace custom metadata).
pub fn decrypt_user_data_full(
    encrypted_metadata: &[u8],
    encrypted_metadata_encrypted_key: &[u8],
    encrypted_metadata_nonce: &[u8],
    cipher: CipherSuite,
    derived_content_key: &Key,
) -> Result<(StreamMeta, StreamInfo, SerializableMeta)> {
    let meta = StreamMeta::decode(encrypted_metadata)?;
    let cipher = if meta.encryption_type != 0 {
        CipherSuite(meta.encryption_type)
    } else {
        cipher
    };
    let nonce = nonce_from_slice(encrypted_metadata_nonce)?;
    let metadata_key = decrypt_key(
        encrypted_metadata_encrypted_key,
        cipher,
        derived_content_key,
        &nonce,
    )?;
    let stream_info = decrypt(
        &meta.encrypted_stream_info,
        cipher,
        &metadata_key,
        &[0u8; NONCE_SIZE],
    )?;
    let info = StreamInfo::decode(stream_info.as_slice())?;
    let custom = if info.metadata.is_empty() {
        SerializableMeta::default()
    } else {
        SerializableMeta::decode(info.metadata.as_slice())?
    };
    Ok((meta, info, custom))
}

#[cfg(test)]
mod piece_size_tests {
    use super::*;

    fn rs() -> Redundancy {
        Redundancy::from_scheme(&storj_proto::pointerdb::RedundancyScheme {
            r#type: 1,
            min_req: 2,
            total: 4,
            repair_threshold: 3,
            success_threshold: 3,
            erasure_share_size: 32,
        })
        .unwrap()
    }

    #[test]
    fn pieces_match_go_calc_piece_size_including_exact_stripe_multiples() {
        let rs = rs();
        let stripe = rs.stripe_size();
        for len in [
            0usize,
            1,
            stripe - 5,
            stripe - 4,
            stripe - 3,
            stripe,
            stripe + 1,
            3 * stripe,
        ] {
            let data = vec![0xabu8; len];
            let pieces = encode_pieces(&data, &rs).unwrap();
            let want = calc_piece_size(len as i64, &rs) as usize;
            assert_eq!(pieces[0].len(), want, "encrypted len {len}");
        }
        // An exact stripe multiple gains a whole stripe for the trailer.
        assert_eq!(
            calc_piece_size(stripe as i64, &rs),
            2 * rs.share_size as i64
        );
    }
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
    fn stream_meta_block_size_is_encrypted_block() {
        let key = Key::from_bytes([9u8; 32]);
        let user =
            encrypt_user_data(&[], 64 * 1024 * 1024, 11, 1, CipherSuite::AES_GCM, &key, 0).unwrap();
        let meta = StreamMeta::decode(user.encrypted_metadata.as_slice()).unwrap();
        assert_eq!(
            meta.encryption_block_size,
            DEFAULT_ENCRYPTED_BLOCK_SIZE as i32
        );
        assert_eq!(meta.encryption_block_size, 7424);
        let user = encrypt_user_data(
            &[],
            64 * 1024 * 1024,
            11,
            1,
            CipherSuite::AES_GCM,
            &key,
            DEFAULT_ENCRYPTED_BLOCK_SIZE,
        )
        .unwrap();
        let meta = StreamMeta::decode(user.encrypted_metadata.as_slice()).unwrap();
        assert_eq!(meta.encryption_block_size, 7424);
    }

    #[test]
    fn user_data_round_trips() {
        let key = Key::from_bytes([9u8; 32]);
        let user = encrypt_user_data(
            &[("app:title".into(), "hi".into())],
            64 * 1024 * 1024,
            11,
            1,
            CipherSuite::AES_GCM,
            &key,
            0,
        )
        .unwrap();
        let (meta, custom) = decrypt_user_data(
            &user.encrypted_metadata,
            &user.encrypted_metadata_encrypted_key,
            &user.encrypted_metadata_nonce,
            CipherSuite::AES_GCM,
            &key,
        )
        .unwrap();
        assert_eq!(meta.number_of_segments, 1);
        assert_eq!(
            custom.user_defined.get("app:title").map(String::as_str),
            Some("hi")
        );
        assert!(
            decrypt_user_data(
                &user.encrypted_metadata,
                &[0xAAu8; 48],
                &user.encrypted_metadata_nonce,
                CipherSuite::AES_GCM,
                &key,
            )
            .is_err()
        );
        let user =
            encrypt_user_data(&[], 64 * 1024 * 1024, 1, 2, CipherSuite::AES_GCM, &key, 0).unwrap();
        let (meta, _) = decrypt_user_data(
            &user.encrypted_metadata,
            &user.encrypted_metadata_encrypted_key,
            &user.encrypted_metadata_nonce,
            CipherSuite::AES_GCM,
            &key,
        )
        .unwrap();
        assert_eq!(meta.encryption_type, CipherSuite::AES_GCM.0);
        let (_, custom) = decrypt_user_data(
            &user.encrypted_metadata,
            &user.encrypted_metadata_encrypted_key,
            &user.encrypted_metadata_nonce,
            CipherSuite::NULL,
            &key,
        )
        .unwrap();
        assert!(custom.user_defined.is_empty());
        assert_eq!(meta.number_of_segments, 2);
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
