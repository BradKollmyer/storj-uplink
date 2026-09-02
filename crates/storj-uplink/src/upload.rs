//! Per-segment upload: inline (≤ 4 KiB encrypted) vs remote RS pieces.

use storj_encryption::{CipherSuite, DEFAULT_ENCRYPTED_BLOCK_SIZE, Key, NONCE_SIZE};
use storj_proto::pointerdb::RedundancyScheme;

use crate::Result;
use crate::pipeline::{
    Redundancy, content_nonce, encode_pieces, encrypt_inline, encrypt_key, encrypt_remote,
    is_inline, random_key, random_nonce,
};

pub use crate::pipeline::{
    EncryptedUserData, MAX_INLINE_SEGMENT_SIZE, MAX_SEGMENT_SIZE, encrypt_user_data,
};
pub use crate::segment::{
    LongTailUpload, PieceAssignment, SnPool, SnTransport, cohort_needed, cohort_satisfied, dial_sn,
    upload_pieces_long_tail,
};

/// Result of encrypting one segment's plaintext.
pub struct PreparedSegment {
    /// Plaintext byte count.
    pub plain_size: i64,
    /// Encrypted segment key.
    pub encrypted_key: Vec<u8>,
    /// Nonce used to encrypt the segment key.
    pub encrypted_key_nonce: [u8; NONCE_SIZE],
    /// Starting content nonce (also used for inline one-shot encrypt).
    pub content_nonce: [u8; NONCE_SIZE],
    /// Random segment content key (not sent in the clear).
    pub segment_key: Key,
    /// Inline ciphertext or remote pieces.
    pub kind: PreparedKind,
}

/// Inline satellite storage vs Reed-Solomon pieces.
pub enum PreparedKind {
    /// `MakeInlineSegment` payload.
    Inline {
        /// One-shot ciphertext.
        data: Vec<u8>,
    },
    /// Long-tail piecestore upload.
    Remote {
        /// `n` pieces (share concatenations).
        pieces: Vec<Vec<u8>>,
        /// Encrypted size before RS (after block padding, before stripe pad).
        encrypted_size: i64,
        /// Scheme from BeginSegment.
        rs: Redundancy,
    },
}

/// Encrypt `plain` and choose inline vs remote.
///
/// Inline uses one-shot Encrypt. Remote uses padded block encryption + RS.
/// `scheme` is required only when the ciphertext exceeds the inline threshold;
/// pass `None` to force the inline check first (scheme is unused if inline).
pub fn prepare_segment(
    plain: &[u8],
    cipher: CipherSuite,
    derived_content_key: &Key,
    encrypted_block_size: usize,
    part_number: i32,
    index: i32,
    scheme: Option<&RedundancyScheme>,
) -> Result<PreparedSegment> {
    let segment_key = random_key();
    let encrypted_key_nonce = random_nonce();
    let encrypted_key = encrypt_key(
        &segment_key,
        cipher,
        derived_content_key,
        &encrypted_key_nonce,
    )?;
    let content_nonce = content_nonce(part_number, index);
    let kind = if plain.len() > MAX_INLINE_SEGMENT_SIZE {
        remote_kind(
            plain,
            cipher,
            &segment_key,
            &content_nonce,
            encrypted_block_size,
            scheme,
        )?
    } else {
        let inline_data = encrypt_inline(plain, cipher, &segment_key, &content_nonce)?;
        if is_inline(&inline_data) {
            PreparedKind::Inline { data: inline_data }
        } else {
            remote_kind(
                plain,
                cipher,
                &segment_key,
                &content_nonce,
                encrypted_block_size,
                scheme,
            )?
        }
    };
    Ok(PreparedSegment {
        plain_size: i64::try_from(plain.len()).unwrap_or(i64::MAX),
        encrypted_key,
        encrypted_key_nonce,
        content_nonce,
        segment_key,
        kind,
    })
}

fn remote_kind(
    plain: &[u8],
    cipher: CipherSuite,
    segment_key: &Key,
    content_nonce: &[u8; NONCE_SIZE],
    encrypted_block_size: usize,
    scheme: Option<&RedundancyScheme>,
) -> Result<PreparedKind> {
    let block = if encrypted_block_size == 0 {
        DEFAULT_ENCRYPTED_BLOCK_SIZE
    } else {
        encrypted_block_size
    };
    let encrypted = encrypt_remote(plain, cipher, segment_key, content_nonce, block)?;
    let scheme =
        scheme.ok_or_else(|| crate::Error::protocol("remote segment missing redundancy scheme"))?;
    let rs = Redundancy::from_scheme(scheme)?;
    let pieces = encode_pieces(&encrypted, &rs)?;
    Ok(PreparedKind::Remote {
        encrypted_size: i64::try_from(encrypted.len()).unwrap_or(i64::MAX),
        pieces,
        rs,
    })
}
