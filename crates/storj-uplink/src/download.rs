//! Segment download: CompressedBatch limits, RS from k pieces, decrypt, ranges.

use std::time::Duration;

use storj_ec::ReedSolomon;
use storj_encryption::{
    CipherSuite, Key, NONCE_SIZE, calc_encompassing_blocks, decrypt, new_decrypter,
    transform_blocks,
};
use storj_proto::metainfo::{Range, RangeStart, RangeStartLimit, RangeSuffix, range};
use storj_proto::orders::OrderLimit;
use storj_rpc::Identity;
use tokio::task::JoinSet;

use crate::orders::PiecePrivateKey;
use crate::piecestore::{Client, Config as PieceConfig};
use crate::pipeline::Redundancy;
use crate::pool::Pooled;
use crate::segment::{PieceAssignment, SnPool, SnTransport, dial_sn};
use crate::{Error, Result};

/// Resolve Go `DownloadOptions` against `object_size` → `(plain_start, plain_len)`.
///
/// Negative `offset` is a suffix (`-n` = last n bytes). Negative `length` means
/// until EOF. Negative offset with non-negative length is rejected (Go
/// `NewStreamRange`: suffix requires length to be negative). Offset at or past
/// EOF is an empty range (Go `Normalize` / `NewDownloadRange` clamp).
pub fn resolve_range(offset: i64, length: i64, object_size: i64) -> Result<(i64, i64)> {
    if offset < 0 && length >= 0 {
        return Err(Error::protocol("suffix requires length to be negative"));
    }
    if object_size < 0 {
        return Err(Error::protocol("object size is negative"));
    }
    if offset < 0 {
        let suffix = offset.saturating_neg();
        let start = if suffix >= object_size {
            0
        } else {
            object_size - suffix
        };
        return Ok((start, object_size - start));
    }
    // Go: if start > size { start = size }; shrink length to remaining.
    let start = offset.min(object_size);
    let end = if length < 0 {
        object_size
    } else {
        start.saturating_add(length).min(object_size)
    };
    Ok((start, end.saturating_sub(start)))
}

/// Segment-local `(start, len)` for the overlap of an object range with a segment.
///
/// `object_start`/`object_len` are plaintext coordinates on the whole object.
/// Empty overlap is `(0, 0)`.
#[must_use]
pub fn segment_plain_range(
    object_start: i64,
    object_len: i64,
    seg_offset: i64,
    seg_plain: i64,
) -> (i64, i64) {
    if object_len <= 0 || seg_plain <= 0 {
        return (0, 0);
    }
    let object_end = object_start.saturating_add(object_len);
    let seg_end = seg_offset.saturating_add(seg_plain);
    let start = object_start.max(seg_offset);
    let end = object_end.min(seg_end);
    if end <= start {
        return (0, 0);
    }
    (start - seg_offset, end - start)
}

/// Protobuf `Range` for `DownloadObjectRequest` (None = whole object).
#[must_use]
pub fn proto_range(offset: i64, length: i64) -> Option<Range> {
    if offset < 0 {
        if length >= 0 {
            return None;
        }
        return Some(Range {
            range: Some(range::Range::Suffix(RangeSuffix {
                plain_suffix: offset.saturating_neg(),
            })),
        });
    }
    if length < 0 {
        if offset == 0 {
            return None;
        }
        return Some(Range {
            range: Some(range::Range::Start(RangeStart {
                plain_start: offset,
            })),
        });
    }
    Some(Range {
        range: Some(range::Range::StartLimit(RangeStartLimit {
            plain_start: offset,
            plain_limit: offset.saturating_add(length),
        })),
    })
}

/// Piece offset/size covering the encryption blocks for a plaintext range.
///
/// Stripe-aligned so RS can decode; `share_size` units on every piece.
#[must_use]
pub fn piece_byte_range(
    plain_start: i64,
    plain_len: i64,
    plain_block: usize,
    enc_block: usize,
    rs: &Redundancy,
) -> (i64, i64) {
    let (first_block, nblocks) = calc_encompassing_blocks(plain_start, plain_len, plain_block);
    if nblocks <= 0 || enc_block == 0 || rs.share_size == 0 {
        return (0, 0);
    }
    // Sizes come from the satellite: saturate rather than wrap on extremes.
    let enc_start = first_block.saturating_mul(enc_block as i64);
    let enc_end = first_block
        .saturating_add(nblocks)
        .saturating_mul(enc_block as i64);
    let stripe = rs.stripe_size() as i64;
    let share = rs.share_size as i64;
    if stripe == 0 {
        return (0, 0);
    }
    let first_stripe = enc_start / stripe;
    let last_stripe = enc_end.saturating_add(stripe - 1) / stripe;
    (
        first_stripe.saturating_mul(share),
        (last_stripe - first_stripe).saturating_mul(share),
    )
}

/// Reconstruct encrypted bytes from any `k` indexed piece buffers (same length).
pub fn decode_encrypted(shares: &[(i32, Vec<u8>)], rs: &Redundancy) -> Result<Vec<u8>> {
    if shares.len() < rs.k {
        return Err(Error::protocol(format!(
            "need {} pieces to decode, have {}",
            rs.k,
            shares.len()
        )));
    }
    let share_size = rs.share_size;
    if share_size == 0 {
        return Err(Error::protocol("share size is zero"));
    }
    let piece_len = shares[0].1.len();
    if !shares.iter().all(|(_, d)| d.len() == piece_len) {
        return Err(Error::protocol("piece lengths differ"));
    }
    if piece_len % share_size != 0 {
        return Err(Error::protocol(
            "piece length is not a multiple of share size",
        ));
    }
    let n_stripes = piece_len / share_size;
    let codec = ReedSolomon::new(rs.k, rs.n, share_size)?;
    let mut out = Vec::with_capacity(n_stripes.saturating_mul(rs.stripe_size()));
    for s in 0..n_stripes {
        let mut slots: Vec<Option<&[u8]>> = vec![None; rs.n];
        for (num, data) in shares {
            let idx = usize::try_from(*num).unwrap_or(usize::MAX);
            if idx < rs.n {
                let off = s * share_size;
                slots[idx] = Some(&data[off..off + share_size]);
            }
        }
        out.extend_from_slice(&codec.decode_stripe(&slots)?);
    }
    Ok(out)
}

/// One-shot decrypt (inline path). Empty ciphertext stays empty.
pub fn decrypt_inline(
    cipher_data: &[u8],
    cipher: CipherSuite,
    key: &Key,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>> {
    Ok(decrypt(cipher_data, cipher, key, nonce)?)
}

/// Inputs for [`decrypt_remote`].
pub struct RemoteDecrypt<'a> {
    /// RS-decoded ciphertext (stripe output).
    pub decoded: &'a [u8],
    /// Encrypted-stream offset of `decoded[0]`.
    pub decoded_offset: usize,
    /// Encrypted size before stripe padding (`segment_size`).
    pub encrypted_size: usize,
    /// Content cipher.
    pub cipher: CipherSuite,
    /// Segment content key.
    pub key: &'a Key,
    /// Starting content nonce.
    pub nonce: &'a [u8; NONCE_SIZE],
    /// Encrypted block size (includes AEAD tag).
    pub encrypted_block_size: usize,
    /// Requested plaintext start.
    pub plain_start: i64,
    /// Requested plaintext length.
    pub plain_len: i64,
    /// Segment plaintext size (padding is not returned).
    pub plain_size: i64,
}

/// Decrypt a (possibly ranged) remote segment after RS decode.
pub fn decrypt_remote(job: RemoteDecrypt<'_>) -> Result<Vec<u8>> {
    if job.plain_len <= 0 || job.plain_size <= 0 {
        return Ok(Vec::new());
    }
    let decrypter = new_decrypter(job.cipher, job.key, job.nonce, job.encrypted_block_size)?;
    let enc_block = decrypter.in_block_size();
    let plain_block = decrypter.out_block_size();
    if enc_block == 0 || plain_block == 0 {
        return Err(Error::protocol("invalid encryption block size"));
    }
    let (first_block, nblocks) =
        calc_encompassing_blocks(job.plain_start, job.plain_len, plain_block);
    if nblocks <= 0 {
        return Ok(Vec::new());
    }
    let want_start = usize::try_from(first_block)
        .unwrap_or(0)
        .saturating_mul(enc_block);
    let want_len = usize::try_from(nblocks)
        .unwrap_or(0)
        .saturating_mul(enc_block);
    let avail_end = job
        .decoded_offset
        .saturating_add(job.decoded.len())
        .min(job.encrypted_size);
    if want_start < job.decoded_offset || want_start + want_len > avail_end {
        return Err(Error::protocol(
            "decoded ciphertext does not cover requested blocks",
        ));
    }
    let local = want_start - job.decoded_offset;
    let blocks = &job.decoded[local..local + want_len];
    let decrypted = transform_blocks(decrypter.as_ref(), blocks, first_block)?;
    let block_plain_start = first_block.saturating_mul(plain_block as i64);
    let skip = usize::try_from(job.plain_start.saturating_sub(block_plain_start)).unwrap_or(0);
    let take = usize::try_from(job.plain_len).unwrap_or(0);
    let valid = decrypted.len().saturating_sub(skip);
    let take = take.min(valid);
    // Drop encryption padding past `plain_size`.
    let abs_end = (job.plain_start + take as i64).min(job.plain_size);
    let take = usize::try_from(abs_end.saturating_sub(job.plain_start)).unwrap_or(0);
    Ok(decrypted[skip..skip + take].to_vec())
}

/// Inputs for [`download_pieces_long_tail`].
pub struct LongTailDownload {
    /// Addressed GET limits (index = piece number; empty slots omitted).
    pub assignments: Vec<PieceAssignment>,
    /// Piece private key from the download response.
    pub piece_key: PiecePrivateKey,
    /// Satellite CA DER (order-limit verify).
    pub satellite_cert: Vec<u8>,
    /// Uplink identity for SN TLS.
    pub identity: Identity,
    /// SN connection pool.
    pub pool: SnPool,
    /// Scheme from the **download response** (not hardcoded).
    pub rs: Redundancy,
    /// Byte offset within each piece.
    pub offset: i64,
    /// Bytes to read from each piece.
    pub size: i64,
    /// Dial timeout per storage node.
    pub dial_timeout: Duration,
}

/// Extra pieces requested beyond `k` up front so one slow/failed node does
/// not stall the download (Go starts `k` readers plus a small margin and
/// promotes the rest lazily rather than ordering every piece).
const LAUNCH_MARGIN: usize = 1;

/// Download pieces until `k` succeed, then cancel the rest (long-tail).
///
/// Only `k + LAUNCH_MARGIN` pieces are requested initially; each failure
/// promotes the next unused assignment. Every launched piece signs an order
/// for its full byte range, so this bounds egress to roughly `k + 1` pieces
/// instead of all `n`.
pub async fn download_pieces_long_tail(job: LongTailDownload) -> Result<Vec<(i32, Vec<u8>)>> {
    if job.size < 0 || job.offset < 0 {
        return Err(Error::protocol("piece download offset/size must be >= 0"));
    }
    if job.size == 0 {
        return Ok(Vec::new());
    }
    let LongTailDownload {
        assignments,
        piece_key,
        satellite_cert,
        identity,
        pool,
        rs,
        offset,
        size,
        dial_timeout,
    } = job;
    let mut queue: std::collections::VecDeque<PieceAssignment> = assignments.into();
    let mut set = JoinSet::new();
    let spawn = |set: &mut JoinSet<_>, asg: PieceAssignment| {
        let key = piece_key.clone();
        let sat_cert = satellite_cert.clone();
        let ident = identity.clone();
        let pool = pool.clone();
        set.spawn(async move {
            download_one_piece(
                asg,
                key,
                sat_cert,
                ident,
                pool,
                (offset, size),
                dial_timeout,
            )
            .await
        });
    };
    let want = rs.k.saturating_add(LAUNCH_MARGIN);
    while set.len() < want {
        let Some(asg) = queue.pop_front() else { break };
        spawn(&mut set, asg);
    }

    let mut successes = Vec::new();
    let mut last_err: Option<Error> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(piece)) => {
                successes.push(piece);
                if successes.len() >= rs.k {
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                    break;
                }
            }
            Ok(Err((_piece_num, err))) => {
                last_err = Some(err);
                // Promote the next unused piece to replace the failed one.
                if let Some(asg) = queue.pop_front() {
                    spawn(&mut set, asg);
                }
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => return Err(Error::protocol(format!("piece download join: {e}"))),
        }
    }
    let job = LongTailDownloadTail { rs };
    if successes.len() < job.rs.k {
        return Err(last_err.unwrap_or_else(|| {
            Error::protocol(format!(
                "need {} pieces to decode, have {}",
                job.rs.k,
                successes.len()
            ))
        }));
    }
    Ok(successes)
}

struct LongTailDownloadTail {
    rs: Redundancy,
}

async fn download_one_piece(
    asg: PieceAssignment,
    piece_key: PiecePrivateKey,
    satellite_cert: Vec<u8>,
    identity: Identity,
    pool: SnPool,
    range: (i64, i64),
    dial_timeout: Duration,
) -> std::result::Result<(i32, Vec<u8>), (i32, Error)> {
    let (offset, size) = range;
    let node = asg.node_id;
    let pooled: Pooled<SnTransport> = pool
        .checkout(node, || async {
            dial_sn(&identity, node, &asg.address, dial_timeout).await
        })
        .await
        .map_err(|e| (asg.piece_num, e))?;
    struct RecycleOnDrop {
        pooled: Option<Pooled<SnTransport>>,
    }
    impl Drop for RecycleOnDrop {
        fn drop(&mut self) {
            if let Some(mut pooled) = self.pooled.take() {
                if pooled.get().is_none_or(|t| t.conn.is_none()) {
                    pooled.skip_recycle();
                }
            }
        }
    }
    let mut held = RecycleOnDrop {
        pooled: Some(pooled),
    };
    let transport = held
        .pooled
        .as_mut()
        .and_then(Pooled::get_mut)
        .ok_or_else(|| (asg.piece_num, Error::protocol("pooled SN conn missing")))?;
    match get_piece(
        transport,
        &satellite_cert,
        &piece_key,
        &asg.limit,
        offset,
        size,
    )
    .await
    {
        Ok(data) => Ok((asg.piece_num, data)),
        Err(e) => Err((asg.piece_num, e)),
    }
}

async fn get_piece(
    transport: &mut SnTransport,
    satellite_cert: &[u8],
    piece_key: &PiecePrivateKey,
    limit: &OrderLimit,
    offset: i64,
    size: i64,
) -> Result<Vec<u8>> {
    let conn = transport
        .conn
        .take()
        .ok_or_else(|| Error::protocol("storage-node connection in use"))?;
    let peer_cert = transport.peer_cert.clone();
    let mut client =
        Client::new(conn, satellite_cert.to_vec(), peer_cert).with_config(PieceConfig::default());
    let result = client.download(limit, piece_key, offset, size).await;
    let conn = client.into_conn();
    // Keep the connection only if the transport is still healthy; a poisoned
    // or transport-failed conn must not go back into the idle pool.
    if !conn.is_poisoned() && !crate::segment::is_transport_error(&result) {
        transport.conn = Some(conn);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{
        encode_pieces, encrypt_inline, encrypt_remote, random_key, random_nonce,
    };
    use storj_encryption::DEFAULT_ENCRYPTED_BLOCK_SIZE;

    fn test_rs() -> Redundancy {
        Redundancy {
            k: 2,
            m: 3,
            o: 3,
            n: 4,
            share_size: 32,
        }
    }

    #[test]
    fn resolve_range_matches_go() {
        assert_eq!(resolve_range(0, -1, 11).unwrap(), (0, 11));
        assert_eq!(resolve_range(6, 5, 11).unwrap(), (6, 5));
        assert_eq!(resolve_range(6, 100, 11).unwrap(), (6, 5));
        assert_eq!(resolve_range(-4, -1, 11).unwrap(), (7, 4));
        assert_eq!(resolve_range(-100, -1, 11).unwrap(), (0, 11));
        assert_eq!(resolve_range(0, 0, 11).unwrap(), (0, 0));
        assert_eq!(resolve_range(0, -1, 0).unwrap(), (0, 0));
        assert_eq!(resolve_range(11, -1, 11).unwrap(), (11, 0));
        assert_eq!(resolve_range(100, 5, 11).unwrap(), (11, 0));
        assert_eq!(resolve_range(1, -1, 0).unwrap(), (0, 0));
        assert!(resolve_range(-4, 2, 11).is_err());
        assert!(resolve_range(-4, 0, 11).is_err());
    }

    #[test]
    fn segment_plain_range_clips_and_skips() {
        assert_eq!(segment_plain_range(0, 100, 0, 64), (0, 64));
        assert_eq!(segment_plain_range(10, 20, 0, 64), (10, 20));
        assert_eq!(segment_plain_range(60, 20, 0, 64), (60, 4));
        assert_eq!(segment_plain_range(64, 1, 0, 64), (0, 0));
        assert_eq!(segment_plain_range(64, 1, 64, 1), (0, 1));
        let max = 64 * 1024 * 1024i64;
        assert_eq!(segment_plain_range(max - 16, 17, 0, max), (max - 16, 16));
        assert_eq!(segment_plain_range(max - 16, 17, max, 1), (0, 1));
        assert_eq!(segment_plain_range(0, 0, 0, 64), (0, 0));
    }

    #[test]
    fn proto_range_shapes() {
        assert!(proto_range(0, -1).is_none());
        assert!(matches!(
            proto_range(10, -1).unwrap().range,
            Some(range::Range::Start(_))
        ));
        assert!(matches!(
            proto_range(10, 5).unwrap().range,
            Some(range::Range::StartLimit(_))
        ));
        assert!(matches!(
            proto_range(-7, -1).unwrap().range,
            Some(range::Range::Suffix(_))
        ));
        assert!(proto_range(-7, 0).is_none());
        assert!(proto_range(-7, 3).is_none());
    }

    #[test]
    fn decode_encrypted_from_any_k() {
        let rs = test_rs();
        let data = vec![0xABu8; rs.stripe_size() * 3];
        let pieces = encode_pieces(&data, &rs).unwrap();
        let shares: Vec<(i32, Vec<u8>)> = vec![(1, pieces[1].clone()), (3, pieces[3].clone())];
        let got = decode_encrypted(&shares, &rs).unwrap();
        assert_eq!(got, data);
        let too_few = vec![(0, pieces[0].clone())];
        assert!(decode_encrypted(&too_few, &rs).is_err());
    }

    #[test]
    fn inline_and_remote_round_trip() {
        let key = random_key();
        let nonce = random_nonce();
        let plain = b"hello storj";
        let enc = encrypt_inline(plain, CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert_eq!(
            decrypt_inline(&enc, CipherSuite::AES_GCM, &key, &nonce).unwrap(),
            plain
        );

        let rs = test_rs();
        let remote = vec![7u8; 200];
        let encrypted = encrypt_remote(
            &remote,
            CipherSuite::AES_GCM,
            &key,
            &nonce,
            DEFAULT_ENCRYPTED_BLOCK_SIZE,
        )
        .unwrap();
        let pieces = encode_pieces(&encrypted, &rs).unwrap();
        let shares: Vec<(i32, Vec<u8>)> = (0..rs.k as i32)
            .map(|i| (i, pieces[i as usize].clone()))
            .collect();
        let decoded = decode_encrypted(&shares, &rs).unwrap();
        let got = decrypt_remote(RemoteDecrypt {
            decoded: &decoded,
            decoded_offset: 0,
            encrypted_size: encrypted.len(),
            cipher: CipherSuite::AES_GCM,
            key: &key,
            nonce: &nonce,
            encrypted_block_size: DEFAULT_ENCRYPTED_BLOCK_SIZE,
            plain_start: 0,
            plain_len: remote.len() as i64,
            plain_size: remote.len() as i64,
        })
        .unwrap();
        assert_eq!(got, remote);

        let ranged = decrypt_remote(RemoteDecrypt {
            decoded: &decoded,
            decoded_offset: 0,
            encrypted_size: encrypted.len(),
            cipher: CipherSuite::AES_GCM,
            key: &key,
            nonce: &nonce,
            encrypted_block_size: DEFAULT_ENCRYPTED_BLOCK_SIZE,
            plain_start: 10,
            plain_len: 20,
            plain_size: remote.len() as i64,
        })
        .unwrap();
        assert_eq!(ranged, &remote[10..30]);
    }

    #[test]
    fn empty_inline_stays_empty() {
        let key = random_key();
        let nonce = random_nonce();
        let enc = encrypt_inline(b"", CipherSuite::AES_GCM, &key, &nonce).unwrap();
        assert!(enc.is_empty());
        assert!(
            decrypt_inline(&enc, CipherSuite::AES_GCM, &key, &nonce)
                .unwrap()
                .is_empty()
        );
    }
}
