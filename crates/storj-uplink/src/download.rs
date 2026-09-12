//! Segment download: CompressedBatch limits, RS from k pieces, decrypt, ranges.

use std::collections::{HashSet, VecDeque};
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
use crate::pool::{HeldPooled, Pooled};
use crate::segment::{PieceAssignment, SnPool, SnTransport};
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
    let refs: Vec<(i32, &[u8])> = shares.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    decode_encrypted_slices(&refs, rs, 0, None)
}

fn decode_encrypted_slices(
    shares: &[(i32, &[u8])],
    rs: &Redundancy,
    stripe0: usize,
    n_stripes: Option<usize>,
) -> Result<Vec<u8>> {
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
    if !piece_len.is_multiple_of(share_size) {
        return Err(Error::protocol(
            "piece length is not a multiple of share size",
        ));
    }
    let total_stripes = piece_len / share_size;
    if stripe0 > total_stripes {
        return Err(Error::protocol("stripe offset past piece length"));
    }
    let n_stripes = n_stripes
        .unwrap_or(total_stripes.saturating_sub(stripe0))
        .min(total_stripes.saturating_sub(stripe0));
    let codec = ReedSolomon::new(rs.k, rs.n, share_size)?;
    // Invert the decode matrix once for this piece set (Go `NewRebuilder`),
    // then decode every stripe straight into the output buffer.
    let mut by_index: Vec<Option<&[u8]>> = vec![None; rs.n];
    let mut available = Vec::with_capacity(shares.len());
    for (num, data) in shares {
        let idx = usize::try_from(*num).unwrap_or(usize::MAX);
        if idx < rs.n && by_index[idx].is_none() {
            by_index[idx] = Some(*data);
            available.push(idx);
        }
    }
    let plan = codec.decode_plan(&available)?;
    let inputs: Vec<&[u8]> = plan
        .indexes()
        .iter()
        .map(|&idx| by_index[idx].ok_or_else(|| Error::protocol("decode plan index missing")))
        .collect::<Result<_>>()?;
    let stripe = rs.stripe_size();
    let mut out = vec![0u8; n_stripes.saturating_mul(stripe)];
    let mut slots: Vec<&[u8]> = Vec::with_capacity(rs.k);
    for s in 0..n_stripes {
        let off = (stripe0 + s) * share_size;
        slots.clear();
        slots.extend(inputs.iter().map(|d| &d[off..off + share_size]));
        plan.decode_into(&slots, &mut out[s * stripe..(s + 1) * stripe])?;
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
    decrypt_remote_tracking_failure(job, &mut None)
}

fn decrypt_remote_tracking_failure(
    job: RemoteDecrypt<'_>,
    failed_block: &mut Option<i64>,
) -> Result<Vec<u8>> {
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
    let mut decrypted = Vec::with_capacity((blocks.len() / enc_block) * plain_block);
    for (block_num, chunk) in (first_block..).zip(blocks.chunks(enc_block)) {
        if let Err(err) = decrypter.transform_into(chunk, block_num, &mut decrypted) {
            let err = Error::Encryption(err);
            if is_content_auth_failure(&err) {
                *failed_block = Some(block_num);
            }
            return Err(err);
        }
    }
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

/// Ciphertext-independent inputs for [`decrypt_remote`] / [`reconstruct_remote`].
pub struct DecryptParams<'a> {
    /// Encrypted-stream offset of reconstructed `decoded[0]`.
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

impl<'a> DecryptParams<'a> {
    fn as_remote(&'a self, decoded: &'a [u8]) -> RemoteDecrypt<'a> {
        RemoteDecrypt {
            decoded,
            decoded_offset: self.decoded_offset,
            encrypted_size: self.encrypted_size,
            cipher: self.cipher,
            key: self.key,
            nonce: self.nonce,
            encrypted_block_size: self.encrypted_block_size,
            plain_start: self.plain_start,
            plain_len: self.plain_len,
            plain_size: self.plain_size,
        }
    }
}

/// Rebuild and decrypt a remote segment from `k` or more shares.
///
/// Reed-Solomon erasure decode of any `k` shares always "succeeds", even when
/// one transferred piece is garbage; AES-GCM / secretbox then fails. Extra
/// shares are tried as alternate `k`-subsets until a set authenticates
/// (storj/uplink#176).
pub fn reconstruct_remote(
    shares: &[(i32, Vec<u8>)],
    rs: &Redundancy,
    params: &DecryptParams<'_>,
) -> Result<Vec<u8>> {
    if shares.len() < rs.k {
        return Err(Error::protocol(format!(
            "need {} pieces to decode, have {}",
            rs.k,
            shares.len()
        )));
    }
    let probe_first = shares.len() > rs.k;
    let mut failed_blocks = Vec::new();
    let mut last_err: Option<Error> = None;
    for combo in k_subsets(shares.len(), rs.k) {
        let subset: Vec<(i32, &[u8])> = combo
            .iter()
            .map(|&i| (shares[i].0, shares[i].1.as_slice()))
            .collect();
        if probe_first
            && (!probe_share_set(&subset, rs, params, None)
                || failed_blocks
                    .iter()
                    .any(|&block| !probe_share_set(&subset, rs, params, Some(block))))
        {
            last_err = Some(content_auth_error());
            continue;
        }
        #[cfg(test)]
        tests::FULL_DECODE_COUNT.with(|count| count.set(count.get() + 1));
        let decoded = match decode_encrypted_slices(&subset, rs, 0, None) {
            Ok(decoded) => decoded,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        let mut failed_block = None;
        match decrypt_remote_tracking_failure(params.as_remote(&decoded), &mut failed_block) {
            Ok(plain) => return Ok(plain),
            Err(err) => {
                if let Some(block) = failed_block {
                    // A valid first block says nothing about later corruption. Keep
                    // every failing block as a cheap filter for subsequent k-sets.
                    failed_blocks.push(block);
                } else {
                    return Err(err);
                }
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(content_auth_error))
}

fn content_auth_error() -> Error {
    Error::Encryption(storj_encryption::Error::new(
        storj_encryption::ErrorKind::DecryptionFailed,
        "piece set failed content authentication",
    ))
}

/// Whether `err` is an AEAD/content-authentication failure (retry with more pieces).
#[must_use]
pub fn is_content_auth_failure(err: &Error) -> bool {
    matches!(
        err,
        Error::Encryption(e) if e.kind() == storj_encryption::ErrorKind::DecryptionFailed
    )
}

/// Authenticate one block without decoding the whole segment. Success only
/// validates that block; the complete requested range must still authenticate.
fn probe_share_set(
    subset: &[(i32, &[u8])],
    rs: &Redundancy,
    params: &DecryptParams<'_>,
    block: Option<i64>,
) -> bool {
    if params.plain_len <= 0 || params.plain_size <= 0 {
        return true;
    }
    let Ok(decrypter) = new_decrypter(
        params.cipher,
        params.key,
        params.nonce,
        params.encrypted_block_size,
    ) else {
        return false;
    };
    let enc_block = decrypter.in_block_size();
    let plain_block = decrypter.out_block_size();
    if enc_block == 0 || plain_block == 0 {
        return false;
    }
    let (first_block, nblocks) =
        calc_encompassing_blocks(params.plain_start, params.plain_len, plain_block);
    if nblocks <= 0 {
        return true;
    }
    let first_block = block.unwrap_or(first_block);
    let want_start = usize::try_from(first_block)
        .unwrap_or(0)
        .saturating_mul(enc_block);
    if want_start < params.decoded_offset {
        return false;
    }
    let local = want_start - params.decoded_offset;
    let stripe = rs.stripe_size();
    if stripe == 0 {
        return false;
    }
    let stripe0 = local / stripe;
    let within = local % stripe;
    let n_stripes = within.saturating_add(enc_block).div_ceil(stripe).max(1);
    let Ok(decoded) = decode_encrypted_slices(subset, rs, stripe0, Some(n_stripes)) else {
        return false;
    };
    if decoded.len() < within.saturating_add(enc_block) {
        return false;
    }
    transform_blocks(
        decrypter.as_ref(),
        &decoded[within..within + enc_block],
        first_block,
    )
    .is_ok()
}

/// Combinations of `k` indexes from `0..n`, lexicographic.
fn k_subsets(n: usize, k: usize) -> KSubsets {
    KSubsets::new(n, k)
}

struct KSubsets {
    n: usize,
    k: usize,
    cur: Vec<usize>,
    done: bool,
}

impl KSubsets {
    fn new(n: usize, k: usize) -> Self {
        if k == 0 || k > n {
            return Self {
                n,
                k,
                cur: Vec::new(),
                done: true,
            };
        }
        Self {
            n,
            k,
            cur: (0..k).collect(),
            done: false,
        }
    }
}

impl Iterator for KSubsets {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Vec<usize>> {
        if self.done {
            return None;
        }
        let item = self.cur.clone();
        let mut i = self.k;
        while i > 0 {
            i -= 1;
            if self.cur[i] < i + self.n - self.k {
                self.cur[i] += 1;
                for j in i + 1..self.k {
                    self.cur[j] = self.cur[j - 1] + 1;
                }
                return Some(item);
            }
        }
        self.done = true;
        Some(item)
    }
}

/// Inputs for [`download_pieces_long_tail`].
pub struct LongTailDownload {
    /// Transport selection and connection telemetry.
    pub connection_options: storj_rpc::transport::ConnectionOptions,
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
    /// Per-read/write deadline on storage-node connections.
    pub message_timeout: Duration,
    /// Delay without a completed piece before trying another node. Zero disables
    /// speculative downloads; the original pieces are never timed out by this.
    pub hedge_delay: Duration,
}

/// Extra pieces requested beyond `k` up front so one slow/failed node does
/// not stall the download (Go starts `k` readers plus a small margin and
/// promotes the rest lazily rather than ordering every piece).
const LAUNCH_MARGIN: usize = 1;

/// Extra pieces fetched after AEAD failure so one malformed transferred
/// piece can be replaced (storj/uplink#176). Two extras cover one corrupt
/// share in the original `k` plus one more bad extra.
pub const MAX_DECODE_EXTRAS: usize = 2;

/// Successful piece buffers plus unused assignments for a reconstruct retry.
pub struct DownloadedPieces {
    /// Piece number + erasure share bytes.
    pub shares: Vec<(i32, Vec<u8>)>,
    unused: VecDeque<PieceAssignment>,
    connection_options: storj_rpc::transport::ConnectionOptions,
    piece_key: PiecePrivateKey,
    satellite_cert: Vec<u8>,
    identity: Identity,
    pool: SnPool,
    offset: i64,
    size: i64,
    dial_timeout: Duration,
    message_timeout: Duration,
}

impl DownloadedPieces {
    /// Download one more unused assignment, skipping transfer failures.
    pub async fn fetch_one_more(&mut self) -> Result<Option<(i32, Vec<u8>)>> {
        if self.unused.is_empty() {
            return Ok(None);
        }
        let assignments: Vec<PieceAssignment> = self.unused.drain(..).collect();
        let piece_key = self.piece_key.clone();
        let satellite_cert = self.satellite_cert.clone();
        let identity = self.identity.clone();
        let pool = self.pool.clone();
        let range = (self.offset, self.size);
        let timeouts = (self.dial_timeout, self.message_timeout);
        let connection_options = self.connection_options.clone();
        match collect_piece_downloads(
            assignments,
            1,
            0,
            Duration::ZERO,
            self.offset,
            self.size,
            move |asg| {
                download_one_piece(
                    asg,
                    piece_key.clone(),
                    satellite_cert.clone(),
                    identity.clone(),
                    pool.clone(),
                    range,
                    timeouts,
                    connection_options.clone(),
                )
            },
        )
        .await
        {
            Ok(collected) => {
                self.unused = collected.unused;
                Ok(collected.shares.into_iter().next())
            }
            Err(Error::PieceDownload(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Download pieces until `k` succeed, then cancel the rest (long-tail).
///
/// Only `k + LAUNCH_MARGIN` pieces are requested initially; each failure
/// promotes the next unused assignment. If no piece completes for `hedge_delay`,
/// another assignment starts without cancelling the slow pieces. Speculative
/// spares (including the initial margin) are capped at about 20% of `k`, with a
/// minimum of two and maximum of `k`. Failures can require further replacements.
/// Every launched piece signs an order for its full byte range. Unused assignments
/// (including cancelled ones) stay on [`DownloadedPieces`] so a later reconstruct
/// failure can fetch replacements.
pub async fn download_pieces_long_tail(job: LongTailDownload) -> Result<DownloadedPieces> {
    let LongTailDownload {
        connection_options,
        assignments,
        piece_key,
        satellite_cert,
        identity,
        pool,
        rs,
        offset,
        size,
        dial_timeout,
        message_timeout,
        hedge_delay,
    } = job;
    let collected = collect_piece_downloads(
        assignments.clone(),
        rs.k,
        LAUNCH_MARGIN,
        hedge_delay,
        offset,
        size,
        {
            let piece_key = piece_key.clone();
            let satellite_cert = satellite_cert.clone();
            let identity = identity.clone();
            let pool = pool.clone();
            let connection_options = connection_options.clone();
            move |asg| {
                download_one_piece(
                    asg,
                    piece_key.clone(),
                    satellite_cert.clone(),
                    identity.clone(),
                    pool.clone(),
                    (offset, size),
                    (dial_timeout, message_timeout),
                    connection_options.clone(),
                )
            }
        },
    )
    .await?;
    let have: HashSet<i32> = collected.shares.iter().map(|(n, _)| *n).collect();
    let unused = assignments
        .into_iter()
        .filter(|a| !have.contains(&a.piece_num))
        .collect();
    Ok(DownloadedPieces {
        shares: collected.shares,
        unused,
        connection_options,
        piece_key,
        satellite_cert,
        identity,
        pool,
        offset,
        size,
        dial_timeout,
        message_timeout,
    })
}

/// Stage at which a piece failed.
#[derive(Debug, Clone, Copy)]
pub enum DownloadStage {
    Connection,
    Validation,
    Transfer,
}

/// A failed piece attempt. Contains no grants, keys, or signed orders.
#[derive(Debug)]
pub struct PieceDownloadFailure {
    pub piece_num: i32,
    pub node_id: String,
    pub stage: DownloadStage,
    pub error: Error,
}

/// All failures from one unsuccessful long-tail download.
#[derive(Debug)]
pub struct PieceDownloadError {
    pub required: usize,
    pub obtained: usize,
    pub attempted: usize,
    pub offset: i64,
    pub size: i64,
    pub failures: Vec<PieceDownloadFailure>,
}

impl PieceDownloadError {
    /// Retrying is useful only if transient failures could supply the deficit.
    pub fn is_retryable(&self) -> bool {
        self.obtained
            + self
                .failures
                .iter()
                .filter(|f| f.error.is_retryable())
                .count()
            >= self.required
    }
}

impl std::fmt::Display for PieceDownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "insufficient pieces: obtained {} of {} required, attempted {}; range {}+{}",
            self.obtained, self.required, self.attempted, self.offset, self.size
        )?;
        // Display is lossy; inspect `failures` for every node and its typed cause.
        let mut groups = std::collections::BTreeMap::<&str, Vec<&PieceDownloadFailure>>::new();
        for failure in &self.failures {
            let kind = match &failure.error {
                Error::DownloadLimit { .. } | Error::InvalidDownloadRange { .. } => {
                    "range validation"
                }
                Error::DialTimeout => "dial timeout",
                error if error.is_retryable() => "transient transport",
                _ => "permanent failure",
            };
            groups.entry(kind).or_default().push(failure);
        }
        for (kind, mut group) in groups {
            group.sort_by_key(|failure| failure.piece_num);
            let first = group[0];
            write!(
                f,
                "; {kind}: {} (piece {}, node {}, {:?}: {})",
                group.len(),
                first.piece_num,
                first.node_id,
                first.stage,
                first.error
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for PieceDownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failures
            .iter()
            .find(|f| !f.error.is_retryable())
            .or_else(|| self.failures.first())
            .map(|failure| &failure.error as _)
    }
}

#[derive(Debug)]
struct Collected<A> {
    shares: Vec<(i32, Vec<u8>)>,
    unused: VecDeque<A>,
}

#[allow(clippy::too_many_arguments)]
async fn collect_piece_downloads<A, F, Fut>(
    assignments: Vec<A>,
    required: usize,
    margin: usize,
    hedge_delay: Duration,
    offset: i64,
    size: i64,
    download: F,
) -> Result<Collected<A>>
where
    F: Fn(A) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(i32, Vec<u8>), PieceDownloadFailure>>
        + Send
        + 'static,
{
    if offset < 0 || size < 0 || offset.checked_add(size).is_none() {
        return Err(Error::InvalidDownloadRange {
            offset,
            size,
            reason: "negative or overflowing range",
        });
    }
    if size == 0 {
        return Ok(Collected {
            shares: Vec::new(),
            unused: assignments.into(),
        });
    }
    let mut queue: VecDeque<A> = assignments.into();
    let mut set = JoinSet::new();
    let mut attempted = 0;
    while set.len() < required.saturating_add(margin) {
        let Some(asg) = queue.pop_front() else { break };
        set.spawn(download(asg));
        attempted += 1;
    }
    let mut successes = Vec::new();
    let mut failures = Vec::new();
    // Do not fan out to every node when the whole connection is slow. Count
    // speculative launches separately from failure replacements so even failed
    // hedges cannot replenish this budget. Production k=29 allows six spares
    // in total (35 attempts without failures), including the initial margin.
    let mut hedges_left = required
        .div_ceil(5)
        .max(2)
        .min(required)
        .saturating_sub(margin);
    while !set.is_empty() {
        let joined = tokio::select! {
            biased;
            // Prefer a ready result over an unnecessary extra download.
            joined = set.join_next() => joined,
            () = tokio::time::sleep(hedge_delay),
                if !hedge_delay.is_zero() && hedges_left > 0 && !queue.is_empty() => {
                if let Some(asg) = queue.pop_front() {
                    set.spawn(download(asg));
                    attempted += 1;
                    hedges_left -= 1;
                }
                continue;
            }
        };
        let Some(joined) = joined else { break };
        match joined {
            Ok(Ok(piece)) => {
                successes.push(piece);
                if successes.len() >= required {
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                    return Ok(Collected {
                        shares: successes,
                        unused: queue,
                    });
                }
            }
            Ok(Err(failure)) => {
                failures.push(failure);
                if let Some(asg) = queue.pop_front() {
                    set.spawn(download(asg));
                    attempted += 1;
                }
            }
            Err(e) => return Err(Error::protocol(format!("piece download join: {e}"))),
        }
    }
    failures.sort_by_key(|failure| failure.piece_num);
    Err(Error::PieceDownload(Box::new(PieceDownloadError {
        required,
        obtained: successes.len(),
        attempted,
        offset,
        size,
        failures,
    })))
}

#[allow(clippy::too_many_arguments)]
async fn download_one_piece(
    asg: PieceAssignment,
    piece_key: PiecePrivateKey,
    satellite_cert: Vec<u8>,
    identity: Identity,
    pool: SnPool,
    range: (i64, i64),
    (dial_timeout, message_timeout): (Duration, Duration),
    connection_options: storj_rpc::transport::ConnectionOptions,
) -> std::result::Result<(i32, Vec<u8>), PieceDownloadFailure> {
    let (offset, size) = range;
    let node = asg.node_id;
    let failure = |error: Error, stage| PieceDownloadFailure {
        piece_num: asg.piece_num,
        node_id: node.to_string(),
        stage,
        error,
    };
    let pooled: Pooled<SnTransport> = pool
        .checkout(node, || async {
            crate::segment::dial_sn_with_options(
                &identity,
                node,
                &asg.address,
                dial_timeout,
                message_timeout,
                &connection_options,
                asg.noise_info.as_ref(),
                asg.fast_open,
            )
            .await
        })
        .await
        .map_err(|e| failure(e, DownloadStage::Connection))?;
    let mut held = HeldPooled::new(pooled);
    let transport = held.get_mut().ok_or_else(|| {
        failure(
            Error::protocol("pooled SN conn missing"),
            DownloadStage::Connection,
        )
    })?;
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
        Ok(data) => {
            if held.get().is_some_and(|t| t.conn.is_some()) {
                held.keep();
            }
            Ok((asg.piece_num, data))
        }
        Err(e) => {
            let stage = match e {
                Error::InvalidDownloadRange { .. }
                | Error::DownloadLimit { .. }
                | Error::OrderLimitSignature => DownloadStage::Validation,
                _ => DownloadStage::Transfer,
            };
            Err(failure(e, stage))
        }
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
    std::thread_local! {
        pub(super) static FULL_DECODE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    fn failure(piece_num: i32, error: Error) -> PieceDownloadFailure {
        PieceDownloadFailure {
            piece_num,
            node_id: format!("node-{piece_num}"),
            stage: DownloadStage::Transfer,
            error,
        }
    }

    async fn scheduled(
        jobs: Vec<(i32, u64, Option<Error>)>,
        required: usize,
    ) -> Result<Vec<(i32, Vec<u8>)>> {
        collect_piece_downloads(
            jobs,
            required,
            LAUNCH_MARGIN,
            Duration::from_secs(1),
            496384,
            256,
            |(piece, delay, error)| async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                match error {
                    Some(e) => Err(failure(piece, e)),
                    None => Ok((piece, vec![42])),
                }
            },
        )
        .await
        .map(|c| c.shares)
    }

    #[tokio::test(start_paused = true)]
    async fn failures_survive_both_completion_orders() {
        let mut displays = Vec::new();
        for (first, second) in [(1, 2), (2, 1)] {
            let err = scheduled(
                vec![
                    (
                        0,
                        first,
                        Some(Error::DownloadLimit {
                            offset: 496384,
                            size: 256,
                            limit: 128,
                        }),
                    ),
                    (1, second, Some(Error::DialTimeout)),
                ],
                2,
            )
            .await
            .unwrap_err();
            assert!(
                !err.is_retryable(),
                "one retryable piece cannot supply two missing pieces"
            );
            let Error::PieceDownload(ref aggregate) = err else {
                panic!("missing aggregate")
            };
            assert_eq!(aggregate.failures.len(), 2);
            assert_eq!(aggregate.attempted, 2);
            assert!(aggregate.to_string().contains("range validation: 1"));
            assert!(aggregate.to_string().contains("dial timeout: 1"));
            displays.push(aggregate.to_string());
        }
        assert_eq!(displays[0], displays[1]);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_only_when_transient_pieces_can_supply_deficit() {
        assert!(
            scheduled(
                vec![
                    (0, 1, Some(Error::DialTimeout)),
                    (1, 2, Some(Error::DialTimeout))
                ],
                2
            )
            .await
            .unwrap_err()
            .is_retryable()
        );
        assert!(
            scheduled(
                vec![
                    (0, 1, None),
                    (1, 2, Some(Error::DialTimeout)),
                    (2, 3, Some(Error::protocol("bad piece")))
                ],
                2
            )
            .await
            .unwrap_err()
            .is_retryable()
        );
        let err = scheduled(vec![(0, 1, None)], 2).await.unwrap_err();
        assert!(!err.is_retryable());
        assert!(
            err.to_string()
                .contains("obtained 1 of 2 required, attempted 1")
        );
        assert!(!scheduled(Vec::new(), 2).await.unwrap_err().is_retryable());
    }

    #[tokio::test(start_paused = true)]
    async fn fallback_succeeds_and_cancels_surplus_downloads() {
        let now = tokio::time::Instant::now();
        let pieces = scheduled(
            vec![
                (0, 1, Some(Error::protocol("bad node"))),
                (1, 2, None),
                (2, 60_000, None),
                (3, 1, None),
            ],
            2,
        )
        .await
        .unwrap();
        assert_eq!(pieces.len(), 2);
        assert!(now.elapsed() < Duration::from_secs(1));
        assert!(pieces.iter().any(|(num, _)| *num == 3));
    }

    #[tokio::test(start_paused = true)]
    async fn leftover_assignments_are_returned() {
        let collected = collect_piece_downloads(
            vec![0, 1, 2, 3],
            2,
            1,
            Duration::from_secs(1),
            0,
            1,
            |n| async move { Ok((n, vec![1])) },
        )
        .await
        .unwrap();
        assert_eq!(collected.shares.len(), 2);
        assert_eq!(
            collected.unused.len(),
            1,
            "k+margin launched, the rest stay unused"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_successes_are_hedged_without_waiting_for_a_timeout() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Finished(Arc<AtomicUsize>);
        impl Drop for Finished {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let finished = Arc::new(AtomicUsize::new(0));
        let started = tokio::time::Instant::now();
        let collected = collect_piece_downloads(
            vec![(0, 10), (1, 60_000), (2, 60_000), (3, 10), (4, 10)],
            2,
            1,
            Duration::from_secs(1),
            0,
            256,
            |(piece, delay)| {
                let guard = Finished(Arc::clone(&finished));
                async move {
                    let _guard = guard;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    Ok((piece, vec![42]))
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            collected.shares.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 3]
        );
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            finished.load(Ordering::SeqCst),
            4,
            "slow surplus tasks are cancelled and drained"
        );
        assert_eq!(collected.unused.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_downloads_do_not_start_speculative_pieces() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let launched = AtomicUsize::new(0);
        collect_piece_downloads(
            (0..80).collect(),
            29,
            1,
            Duration::from_secs(1),
            0,
            256,
            |piece| {
                launched.fetch_add(1, Ordering::SeqCst);
                async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok((piece, vec![42]))
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(launched.load(Ordering::SeqCst), 30);
    }

    #[tokio::test(start_paused = true)]
    async fn speculative_downloads_have_a_fixed_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let launched = AtomicUsize::new(0);
        let collected = collect_piece_downloads(
            (0..80).collect(),
            29,
            1,
            Duration::from_secs(1),
            0,
            256,
            |piece| {
                launched.fetch_add(1, Ordering::SeqCst);
                async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok((piece, vec![42]))
                }
            },
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(10), collected)
                .await
                .is_err()
        );
        assert_eq!(
            launched.load(Ordering::SeqCst),
            35,
            "do not fan out to all 80 nodes on a slow link"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hedging_can_be_disabled() {
        let started = tokio::time::Instant::now();
        let collected = collect_piece_downloads(
            vec![(0, 10), (1, 2_000), (2, 3_000), (3, 10)],
            2,
            1,
            Duration::ZERO,
            0,
            256,
            |(piece, delay)| async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                Ok((piece, vec![42]))
            },
        )
        .await
        .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(
            collected.shares.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(collected.unused.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failures_still_get_replacements_after_the_hedge_budget_is_spent() {
        let pieces = scheduled(
            vec![
                (0, 10, None),
                (1, 60_000, None),
                (2, 60_000, None),
                (3, 10, Some(Error::DialTimeout)),
                (4, 10, None),
            ],
            2,
        )
        .await
        .unwrap();
        assert_eq!(
            pieces.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 4]
        );
    }

    #[tokio::test]
    async fn invalid_ranges_fail_before_spawning_downloads() {
        for (offset, size) in [(-1, 1), (1, -1), (i64::MAX, 1)] {
            let err = collect_piece_downloads(
                vec![()],
                1,
                0,
                Duration::from_secs(1),
                offset,
                size,
                |_| async {
                    panic!("invalid request must not start a node connection");
                },
            )
            .await
            .unwrap_err();
            assert!(matches!(err, Error::InvalidDownloadRange { .. }));
        }
    }
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
        assert_eq!(
            &got[..data.len()],
            &data[..],
            "decoded prefix must be the encrypted data; the rest is the Go padding trailer"
        );
        let too_few = vec![(0, pieces[0].clone())];
        assert!(decode_encrypted(&too_few, &rs).is_err());
    }

    #[test]
    fn k_subsets_are_lexicographic_combinations() {
        let got: Vec<Vec<usize>> = k_subsets(4, 2).collect();
        assert_eq!(
            got,
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![0, 3],
                vec![1, 2],
                vec![1, 3],
                vec![2, 3]
            ]
        );
        assert_eq!(k_subsets(2, 2).collect::<Vec<_>>(), vec![vec![0, 1]]);
        assert!(k_subsets(2, 3).next().is_none());
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
    fn reconstruct_skips_one_malformed_piece() {
        let key = random_key();
        let nonce = random_nonce();
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
        let mut pieces = encode_pieces(&encrypted, &rs).unwrap();
        pieces[0][0] ^= 0xFF;
        let params = DecryptParams {
            decoded_offset: 0,
            encrypted_size: encrypted.len(),
            cipher: CipherSuite::AES_GCM,
            key: &key,
            nonce: &nonce,
            encrypted_block_size: DEFAULT_ENCRYPTED_BLOCK_SIZE,
            plain_start: 0,
            plain_len: remote.len() as i64,
            plain_size: remote.len() as i64,
        };
        let bad_k: Vec<(i32, Vec<u8>)> = vec![(0, pieces[0].clone()), (1, pieces[1].clone())];
        let err = reconstruct_remote(&bad_k, &rs, &params).unwrap_err();
        assert!(is_content_auth_failure(&err), "{err}");

        let with_extra: Vec<(i32, Vec<u8>)> = vec![
            (0, pieces[0].clone()),
            (1, pieces[1].clone()),
            (3, pieces[3].clone()),
        ];
        let got = reconstruct_remote(&with_extra, &rs, &params).unwrap();
        assert_eq!(got, remote);
    }

    #[test]
    fn late_corruption_probes_failed_blocks_before_full_decode() {
        let rs = Redundancy {
            k: 29,
            m: 29,
            o: 31,
            n: 31,
            share_size: 256,
        };
        let remote = vec![7; 256 * 1024];
        let key = random_key();
        let nonce = random_nonce();
        for cipher in [CipherSuite::AES_GCM, CipherSuite::SECRET_BOX] {
            let encrypted =
                encrypt_remote(&remote, cipher, &key, &nonce, DEFAULT_ENCRYPTED_BLOCK_SIZE)
                    .unwrap();
            let clean = encode_pieces(&encrypted, &rs).unwrap();
            for second_bad in [1, rs.k] {
                let mut pieces = clean.clone();
                // Two different late blocks exercise learning more than one
                // failing block, including corruption in the first extra piece.
                let stripes = encrypted.len() / rs.stripe_size();
                pieces[0][(stripes / 3) * rs.share_size] ^= 0xff;
                pieces[second_bad][(2 * stripes / 3) * rs.share_size] ^= 0xff;
                for ranged in [false, true] {
                    let (start, len) = if ranged {
                        (remote.len() / 5, remote.len() * 3 / 4)
                    } else {
                        (0, remote.len())
                    };
                    let decrypter =
                        new_decrypter(cipher, &key, &nonce, DEFAULT_ENCRYPTED_BLOCK_SIZE).unwrap();
                    let (offset, size) = piece_byte_range(
                        start as i64,
                        len as i64,
                        decrypter.out_block_size(),
                        decrypter.in_block_size(),
                        &rs,
                    );
                    let shares: Vec<_> = pieces
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            (
                                i as i32,
                                p[offset as usize..(offset + size) as usize].to_vec(),
                            )
                        })
                        .collect();
                    let params = DecryptParams {
                        decoded_offset: offset as usize * rs.k,
                        encrypted_size: encrypted.len(),
                        cipher,
                        key: &key,
                        nonce: &nonce,
                        encrypted_block_size: DEFAULT_ENCRYPTED_BLOCK_SIZE,
                        plain_start: start as i64,
                        plain_len: len as i64,
                        plain_size: remote.len() as i64,
                    };
                    FULL_DECODE_COUNT.set(0);
                    assert_eq!(
                        reconstruct_remote(&shares, &rs, &params).unwrap(),
                        remote[start..start + len]
                    );
                    assert!(
                        FULL_DECODE_COUNT.get() <= 3,
                        "two corrupt blocks should need at most two failed full decodes and one successful decode, got {}",
                        FULL_DECODE_COUNT.get()
                    );
                }
            }
        }
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
