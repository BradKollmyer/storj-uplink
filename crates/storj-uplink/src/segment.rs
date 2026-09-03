//! Long-tail remote segment upload: n pieces, stop at o, retry failed limits.
//!
//! `CohortRequirements` is evaluated for the success threshold. Failed piece
//! numbers are replaced via `RetryBeginSegmentPieces`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use storj_proto::metainfo::{
    AddressedOrderLimit, CohortRequirements, SegmentPieceUploadResult, cohort_requirements,
};
use storj_proto::orders::OrderLimit;
use storj_rpc::tls::client_config;
use storj_rpc::{Conn, Identity, NodeId, write_tls_mux_prefix};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::orders::PiecePrivateKey;
use crate::piecestore::{Client, Config as PieceConfig};
use crate::pipeline::Redundancy;
use crate::pool::{ConnectionPool, Pooled};
use crate::{Error, Result};

/// TLS piecestore connection plus the peer CA (piece-hash verify).
pub struct SnTransport {
    /// Established DRPC connection. `None` while a piece RPC owns it.
    pub conn: Option<Conn<TlsStream<TcpStream>>>,
    /// Storage-node CA DER from the handshake.
    pub peer_cert: Vec<u8>,
}

/// Pool of SN transports keyed by NodeID.
pub type SnPool = ConnectionPool<SnTransport>;

/// One addressed piece assignment from BeginSegment / retry.
#[derive(Clone, Debug)]
pub struct PieceAssignment {
    /// Piece index (`0..n`).
    pub piece_num: i32,
    /// Satellite-signed order limit.
    pub limit: OrderLimit,
    /// `host:port` from [`AddressedOrderLimit::storage_node_address`].
    pub address: String,
    /// Storage-node id (order limit / NodeID pin).
    pub node_id: NodeId,
    /// Placement tags for [`cohort_requirements::Requirement::Withhold`].
    pub tags: HashMap<String, Vec<u8>>,
}

impl PieceAssignment {
    /// Parse an addressed limit at array index `idx` (piece number).
    pub fn from_addressed(idx: usize, addressed: AddressedOrderLimit) -> Result<Self> {
        let limit = addressed
            .limit
            .ok_or_else(|| Error::protocol("addressed order limit missing limit"))?;
        let address = addressed
            .storage_node_address
            .as_ref()
            .map(|a| a.address.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::protocol("addressed order limit missing node address"))?;
        let node_id = node_id_from_bytes(&limit.storage_node_id)?;
        Ok(Self {
            piece_num: i32::try_from(idx).unwrap_or(i32::MAX),
            limit,
            address,
            node_id,
            tags: addressed.tags,
        })
    }
}

fn node_id_from_bytes(b: &[u8]) -> Result<NodeId> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| Error::protocol("storage node id is not 32 bytes"))?;
    Ok(NodeId::from_bytes(arr))
}

/// Lower bound on successful pieces for [`CohortRequirements`] (Go `min()`).
#[must_use]
pub fn cohort_needed(req: Option<&CohortRequirements>, default_o: i32) -> i32 {
    let Some(req) = req else {
        return default_o;
    };
    match req.requirement.as_ref() {
        Some(cohort_requirements::Requirement::Literal(lit)) => {
            if lit.value > 0 {
                lit.value
            } else {
                default_o
            }
        }
        Some(cohort_requirements::Requirement::And(and)) => and
            .requirements
            .iter()
            .map(|r| cohort_needed(Some(r), default_o))
            .max()
            .unwrap_or(default_o),
        Some(cohort_requirements::Requirement::Withhold(w)) => {
            let child = w
                .child
                .as_deref()
                .map(|c| cohort_needed(Some(c), default_o))
                .unwrap_or(default_o);
            child.saturating_add(w.amount.max(0))
        }
        None => default_o,
    }
}

/// Whether the successful pieces’ tags satisfy `req` (Go `meetsCohortRequirements`).
#[must_use]
pub fn cohort_satisfied(
    req: Option<&CohortRequirements>,
    tags: &[HashMap<String, Vec<u8>>],
) -> bool {
    let Some(req) = req else {
        return true;
    };
    cohort_valid(req, tags)
}

fn cohort_valid(req: &CohortRequirements, tags: &[HashMap<String, Vec<u8>>]) -> bool {
    match req.requirement.as_ref() {
        Some(cohort_requirements::Requirement::Literal(lit)) => (tags.len() as i32) >= lit.value,
        Some(cohort_requirements::Requirement::And(and)) => {
            and.requirements.iter().all(|r| cohort_valid(r, tags))
        }
        Some(cohort_requirements::Requirement::Withhold(w)) => {
            let remaining = withhold_tags(w.tag_key.as_str(), w.amount, tags);
            match w.child.as_deref() {
                Some(child) => cohort_valid(child, &remaining),
                None => true,
            }
        }
        None => true,
    }
}

/// Remove pieces whose tag value is among the top `amount` values by count (Go matcherWithhold).
fn withhold_tags(
    key: &str,
    amount: i32,
    tags: &[HashMap<String, Vec<u8>>],
) -> Vec<HashMap<String, Vec<u8>>> {
    if amount <= 0 {
        return tags.to_vec();
    }
    let amount = amount as usize;
    let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
    for t in tags {
        let v = t.get(key).cloned().unwrap_or_default();
        *counts.entry(v).or_insert(0) += 1;
    }
    let mut topn: HashMap<Vec<u8>, usize> = HashMap::new();
    for (value, count) in &counts {
        if value.is_empty() {
            continue;
        }
        if topn.len() < amount {
            topn.insert(value.clone(), *count);
            continue;
        }
        let replace = topn
            .iter()
            .find(|(_, c)| count > *c)
            .map(|(k, _)| k.clone());
        if let Some(old) = replace {
            topn.remove(&old);
            topn.insert(value.clone(), *count);
        }
    }
    tags.iter()
        .filter(|t| {
            let v = t.get(key).cloned().unwrap_or_default();
            !topn.contains_key(&v)
        })
        .cloned()
        .collect()
}

/// Dial a storage node: TCP + `DRPC!!!1` + NodeID-pinned TLS.
pub async fn dial_sn(
    identity: &Identity,
    node_id: NodeId,
    address: &str,
    timeout: Duration,
    message_timeout: Duration,
) -> Result<SnTransport> {
    let dial = async {
        let mut tcp = TcpStream::connect(address).await?;
        let _ = tcp.set_nodelay(true);
        write_tls_mux_prefix(&mut tcp).await?;
        let tls_cfg = client_config(identity, node_id)?;
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let host = host_from_address(address);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| Error::protocol(format!("invalid storage-node host {host:?}: {e}")))?;
        let tls = connector.connect(server_name, tcp).await?;
        // The node signs piece hashes with its leaf key (Go
        // `SigneeFromPeerIdentity` uses `Leaf.PublicKey`), so keep the leaf
        // (chain[0]), not the CA.
        let peer_cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec())
            .unwrap_or_default();
        Ok::<_, Error>(SnTransport {
            conn: Some(Conn::new(tls).with_timeout(message_timeout)),
            peer_cert,
        })
    };
    tokio::time::timeout(timeout, dial)
        .await
        .map_err(|_| Error::protocol("storage-node dial timed out"))?
}

fn host_from_address(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    }
    match address.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => address,
    }
}

/// Successful piece upload used in `CommitSegment`.
pub type PieceResult = SegmentPieceUploadResult;

/// Inputs for [`upload_pieces_long_tail`].
pub struct LongTailUpload {
    /// Addressed limits from BeginSegment (index = piece number).
    pub assignments: Vec<PieceAssignment>,
    /// Segment id (updated if RetryBeginSegmentPieces returns a new one).
    pub segment_id: Vec<u8>,
    /// Piece private key from BeginSegment.
    pub piece_key: PiecePrivateKey,
    /// Reed-Solomon pieces (`n` buffers), shared with the per-piece upload
    /// tasks instead of cloned into each (≈3× less memory per segment).
    pub pieces: Arc<Vec<Vec<u8>>>,
    /// Satellite CA DER (order-limit verify).
    pub satellite_cert: Vec<u8>,
    /// Uplink identity for SN TLS.
    pub identity: Identity,
    /// SN connection pool.
    pub pool: SnPool,
    /// Scheme from BeginSegment.
    pub rs: Redundancy,
    /// Optional cohort tree from BeginSegment.
    pub cohort: Option<CohortRequirements>,
    /// Dial timeout per storage node.
    pub dial_timeout: Duration,
    /// Per-read/write deadline on storage-node connections.
    pub message_timeout: Duration,
}

/// Upload `pieces` with long-tail cancellation and limit retry.
///
/// `retry` is `RetryBeginSegmentPieces(segment_id, failed_piece_nums)`.
/// Returns the latest `segment_id` (rotated on retry) and the successful pieces.
pub async fn upload_pieces_long_tail<F, Fut>(
    mut job: LongTailUpload,
    mut retry: F,
) -> Result<(Vec<u8>, Vec<PieceResult>)>
where
    F: FnMut(Vec<u8>, Vec<i32>) -> Fut,
    Fut: std::future::Future<Output = Result<(Vec<u8>, Vec<AddressedOrderLimit>)>>,
{
    let mut successes: Vec<PieceResult> = Vec::new();
    let mut attempts = 0u32;
    // Most recent piece errors, so a threshold failure explains itself.
    let mut last_errors: Vec<(i32, String)> = Vec::new();

    while !requirements_met(&job, &successes) && attempts < 4 {
        attempts += 1;
        let done_nums: std::collections::HashSet<i32> =
            successes.iter().map(|s| s.piece_num).collect();
        let pending: Vec<PieceAssignment> = job
            .assignments
            .iter()
            .filter(|a| !done_nums.contains(&a.piece_num))
            .cloned()
            .collect();
        if pending.is_empty() {
            break;
        }

        let (round_ok, failed_nums, errors) = upload_round(&job, pending, &successes).await?;
        successes.extend(round_ok);
        last_errors.extend(errors);
        if last_errors.len() > MAX_KEPT_PIECE_ERRORS {
            let drop = last_errors.len() - MAX_KEPT_PIECE_ERRORS;
            last_errors.drain(..drop);
        }

        if requirements_met(&job, &successes) {
            break;
        }
        if failed_nums.is_empty() {
            break;
        }
        let (new_id, new_limits) = retry(job.segment_id.clone(), failed_nums.clone()).await?;
        job.segment_id = new_id;
        // The satellite returns the FULL n-length limit list indexed by piece
        // number (Go `pieceupload/manager.go`: `mgr.limits = limits`, then
        // `limits[num]`), not a list aligned to the retried piece numbers.
        for &piece_num in &failed_nums {
            let idx = usize::try_from(piece_num)
                .map_err(|_| Error::protocol("negative piece number in retry"))?;
            let Some(limit) = new_limits.get(idx).cloned().filter(|l| l.limit.is_some()) else {
                // No replacement for this piece: leave it failed.
                job.assignments.retain(|x| x.piece_num != piece_num);
                continue;
            };
            let mut a = PieceAssignment::from_addressed(idx, limit)?;
            a.piece_num = piece_num;
            if let Some(slot) = job
                .assignments
                .iter_mut()
                .find(|x| x.piece_num == piece_num)
            {
                *slot = a;
            } else {
                job.assignments.push(a);
            }
        }
    }

    if !requirements_met(&job, &successes) {
        let causes = last_errors
            .iter()
            .map(|(n, e)| format!("piece {n}: {e}"))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::protocol(format!(
            "segment upload: {} successful pieces do not meet cohort/o (o={}); recent piece errors: [{causes}]",
            successes.len(),
            job.rs.o
        )));
    }
    // The satellite's metabase requires CommitSegment pieces sorted by piece
    // number ("pieces should be ordered"); long-tail completion order is not.
    successes.sort_by_key(|s| s.piece_num);
    successes.dedup_by_key(|s| s.piece_num);
    Ok((job.segment_id, successes))
}

fn success_tags(job: &LongTailUpload, successes: &[PieceResult]) -> Vec<HashMap<String, Vec<u8>>> {
    successes
        .iter()
        .filter_map(|s| {
            job.assignments
                .iter()
                .find(|a| a.piece_num == s.piece_num)
                .map(|a| a.tags.clone())
        })
        .collect()
}

fn requirements_met(job: &LongTailUpload, successes: &[PieceResult]) -> bool {
    let tags = success_tags(job, successes);
    match job.cohort.as_ref() {
        None => tags.len() >= job.rs.o,
        Some(req) => cohort_valid(req, &tags),
    }
}

async fn upload_round(
    job: &LongTailUpload,
    pending: Vec<PieceAssignment>,
    already: &[PieceResult],
) -> Result<(Vec<PieceResult>, Vec<i32>, Vec<(i32, String)>)> {
    let mut set = JoinSet::new();
    for asg in pending {
        let idx = usize::try_from(asg.piece_num).unwrap_or(usize::MAX);
        let pieces = Arc::clone(&job.pieces);
        let key = job.piece_key.clone();
        let sat_cert = job.satellite_cert.clone();
        let ident = job.identity.clone();
        let pool = job.pool.clone();
        let dial_timeout = job.dial_timeout;
        let message_timeout = job.message_timeout;
        set.spawn(async move {
            upload_one_piece(
                asg,
                key,
                pieces,
                idx,
                sat_cert,
                ident,
                pool,
                (dial_timeout, message_timeout),
            )
            .await
        });
    }

    let mut successes = Vec::new();
    let mut failed = Vec::new();
    let mut errors = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(result)) => {
                successes.push(result);
                let mut all = already.to_vec();
                all.extend(successes.iter().cloned());
                if requirements_met(job, &all) {
                    set.abort_all();
                    // Pieces that already finished but were still queued in
                    // the set are durably stored: report them to the
                    // satellite rather than dropping them (Go records every
                    // finished piece before cancelling the long tail).
                    while let Some(rest) = set.join_next().await {
                        if let Ok(Ok(result)) = rest {
                            successes.push(result);
                        }
                    }
                    break;
                }
            }
            Ok(Err((piece_num, err))) => {
                errors.push((piece_num, err.to_string()));
                failed.push(piece_num);
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => {
                return Err(Error::protocol(format!("piece upload join: {e}")));
            }
        }
    }
    Ok((successes, failed, errors))
}

/// How many recent piece errors are kept for the terminal error message.
const MAX_KEPT_PIECE_ERRORS: usize = 5;

#[allow(clippy::too_many_arguments)]
async fn upload_one_piece(
    asg: PieceAssignment,
    piece_key: PiecePrivateKey,
    pieces: Arc<Vec<Vec<u8>>>,
    idx: usize,
    satellite_cert: Vec<u8>,
    identity: Identity,
    pool: SnPool,
    (dial_timeout, message_timeout): (Duration, Duration),
) -> std::result::Result<PieceResult, (i32, Error)> {
    let node = asg.node_id;
    let pooled: Pooled<SnTransport> = pool
        .checkout(node, || async {
            dial_sn(&identity, node, &asg.address, dial_timeout, message_timeout).await
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
    let data: &[u8] = pieces.get(idx).map(Vec::as_slice).unwrap_or(&[]);
    match put_piece(transport, &satellite_cert, &piece_key, &asg.limit, data).await {
        Ok(hash) => Ok(SegmentPieceUploadResult {
            piece_num: asg.piece_num,
            node_id: asg.node_id.as_bytes().to_vec(),
            hash: Some(hash),
        }),
        Err(e) => Err((asg.piece_num, e)),
    }
}

/// True when `result` failed at the transport level (the DRPC connection is
/// dead or in an unknown framing state), as opposed to a remote error or a
/// verification failure on an otherwise healthy connection.
pub(crate) fn is_transport_error<T>(result: &Result<T>) -> bool {
    matches!(
        result,
        Err(Error::Rpc(
            storj_rpc::Error::Io(_)
                | storj_rpc::Error::Closed
                | storj_rpc::Error::Truncated
                | storj_rpc::Error::Frame(_)
                | storj_rpc::Error::MuxPrefix { .. }
        ))
    )
}

async fn put_piece(
    transport: &mut SnTransport,
    satellite_cert: &[u8],
    piece_key: &PiecePrivateKey,
    limit: &OrderLimit,
    data: &[u8],
) -> Result<storj_proto::orders::PieceHash> {
    let conn = transport
        .conn
        .take()
        .ok_or_else(|| Error::protocol("storage-node connection in use"))?;
    let peer_cert = transport.peer_cert.clone();
    let mut client =
        Client::new(conn, satellite_cert.to_vec(), peer_cert).with_config(PieceConfig::default());
    let result = client.upload(limit, piece_key, data).await;
    let conn = client.into_conn();
    // Keep the connection only if the transport is still healthy; a poisoned
    // or transport-failed conn must not go back into the idle pool.
    if !conn.is_poisoned() && !is_transport_error(&result) {
        transport.conn = Some(conn);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.as_bytes().to_vec()))
            .collect()
    }

    fn withhold(amount: i32, literal: i32) -> CohortRequirements {
        CohortRequirements {
            requirement: Some(cohort_requirements::Requirement::Withhold(Box::new(
                cohort_requirements::Withhold {
                    tag_key: "region".into(),
                    amount,
                    child: Some(Box::new(CohortRequirements {
                        requirement: Some(cohort_requirements::Requirement::Literal(
                            cohort_requirements::Literal { value: literal },
                        )),
                    })),
                },
            ))),
        }
    }

    #[test]
    fn withhold_same_tag_fails_mixed_passes() {
        let req = withhold(1, 2);
        let same = vec![
            tags(&[("region", "us")]),
            tags(&[("region", "us")]),
            tags(&[("region", "us")]),
        ];
        assert!(
            !cohort_satisfied(Some(&req), &same),
            "same-tag o-set must fail withhold"
        );
        let mixed = vec![
            tags(&[("region", "us")]),
            tags(&[("region", "eu")]),
            tags(&[("region", "ap")]),
        ];
        assert!(
            cohort_satisfied(Some(&req), &mixed),
            "mixed-tag set must pass withhold"
        );
    }

    #[test]
    fn literal_counts_pieces() {
        let req = CohortRequirements {
            requirement: Some(cohort_requirements::Requirement::Literal(
                cohort_requirements::Literal { value: 3 },
            )),
        };
        assert!(!cohort_satisfied(Some(&req), &[tags(&[])],));
        assert!(cohort_satisfied(
            Some(&req),
            &[tags(&[]), tags(&[]), tags(&[])]
        ));
    }

    #[test]
    fn cohort_needed_withhold_adds_amount() {
        let req = withhold(1, 3);
        assert_eq!(cohort_needed(Some(&req), 3), 4);
    }
}
