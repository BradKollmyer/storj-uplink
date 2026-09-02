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
    pub peer_ca: Vec<u8>,
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
    /// Placement tags for [`CohortRequirements::Withhold`].
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

/// Required successful pieces from [`CohortRequirements`], else `default_o`.
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
            child.saturating_sub(w.amount.max(0))
        }
        None => default_o,
    }
}

/// Dial a storage node: TCP + `DRPC!!!1` + NodeID-pinned TLS.
pub async fn dial_sn(
    identity: &Identity,
    node_id: NodeId,
    address: &str,
    timeout: Duration,
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
        let peer_ca = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.last())
            .map(|c| c.as_ref().to_vec())
            .unwrap_or_default();
        Ok::<_, Error>(SnTransport {
            conn: Some(Conn::new(tls)),
            peer_ca,
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
    /// Reed-Solomon pieces (`n` buffers).
    pub pieces: Vec<Vec<u8>>,
    /// Satellite CA DER (order-limit verify).
    pub satellite_ca: Vec<u8>,
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
}

/// Upload `pieces` with long-tail cancellation and limit retry.
///
/// `retry` is `RetryBeginSegmentPieces(segment_id, failed_piece_nums)`.
pub async fn upload_pieces_long_tail<F, Fut>(
    mut job: LongTailUpload,
    mut retry: F,
) -> Result<Vec<PieceResult>>
where
    F: FnMut(Vec<u8>, Vec<i32>) -> Fut,
    Fut: std::future::Future<Output = Result<(Vec<u8>, Vec<AddressedOrderLimit>)>>,
{
    let needed = cohort_needed(
        job.cohort.as_ref(),
        i32::try_from(job.rs.o).unwrap_or(i32::MAX),
    )
    .max(1) as usize;
    let needed = needed.min(job.rs.n).min(job.assignments.len().max(1));
    let mut successes: Vec<PieceResult> = Vec::new();
    let mut attempts = 0u32;

    while successes.len() < needed && attempts < 4 {
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

        let remaining = needed.saturating_sub(successes.len());
        let (round_ok, failed_nums) = upload_round(&job, pending, remaining).await?;
        successes.extend(round_ok);

        if successes.len() >= needed {
            break;
        }
        if failed_nums.is_empty() {
            break;
        }
        let (new_id, new_limits) = retry(job.segment_id.clone(), failed_nums.clone()).await?;
        job.segment_id = new_id;
        for (i, limit) in new_limits.into_iter().enumerate() {
            let piece_num = failed_nums.get(i).copied().unwrap_or(i as i32);
            match PieceAssignment::from_addressed(piece_num as usize, limit) {
                Ok(mut a) => {
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
                Err(e) => return Err(e),
            }
        }
    }

    if successes.len() < needed {
        return Err(Error::protocol(format!(
            "segment upload: {} successful pieces, need {needed}",
            successes.len()
        )));
    }
    Ok(successes)
}

async fn upload_round(
    job: &LongTailUpload,
    pending: Vec<PieceAssignment>,
    stop_at: usize,
) -> Result<(Vec<PieceResult>, Vec<i32>)> {
    let mut set = JoinSet::new();
    for asg in pending {
        let idx = usize::try_from(asg.piece_num).unwrap_or(usize::MAX);
        let data = job.pieces.get(idx).cloned().unwrap_or_default();
        let key = job.piece_key.clone();
        let sat_ca = job.satellite_ca.clone();
        let ident = job.identity.clone();
        let pool = job.pool.clone();
        let dial_timeout = job.dial_timeout;
        set.spawn(async move {
            upload_one_piece(asg, key, data, sat_ca, ident, pool, dial_timeout).await
        });
    }

    let mut successes = Vec::new();
    let mut failed = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(result)) => {
                successes.push(result);
                if successes.len() >= stop_at {
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                    break;
                }
            }
            Ok(Err((piece_num, _err))) => failed.push(piece_num),
            Err(e) if e.is_cancelled() => {}
            Err(e) => {
                return Err(Error::protocol(format!("piece upload join: {e}")));
            }
        }
    }
    Ok((successes, failed))
}

async fn upload_one_piece(
    asg: PieceAssignment,
    piece_key: PiecePrivateKey,
    data: Vec<u8>,
    satellite_ca: Vec<u8>,
    identity: Identity,
    pool: SnPool,
    dial_timeout: Duration,
) -> std::result::Result<PieceResult, (i32, Error)> {
    let node = asg.node_id;
    let mut pooled: Pooled<SnTransport> = pool
        .checkout(node, || async {
            dial_sn(&identity, node, &asg.address, dial_timeout).await
        })
        .await
        .map_err(|e| (asg.piece_num, e))?;
    let transport = pooled
        .get_mut()
        .ok_or_else(|| (asg.piece_num, Error::protocol("pooled SN conn missing")))?;
    match put_piece(transport, &satellite_ca, &piece_key, &asg.limit, &data).await {
        Ok(hash) => Ok(SegmentPieceUploadResult {
            piece_num: asg.piece_num,
            node_id: asg.node_id.as_bytes().to_vec(),
            hash: Some(hash),
        }),
        Err(e) => Err((asg.piece_num, e)),
    }
}

async fn put_piece(
    transport: &mut SnTransport,
    satellite_ca: &[u8],
    piece_key: &PiecePrivateKey,
    limit: &OrderLimit,
    data: &[u8],
) -> Result<storj_proto::orders::PieceHash> {
    let conn = transport
        .conn
        .take()
        .ok_or_else(|| Error::protocol("storage-node connection in use"))?;
    let peer_ca = transport.peer_ca.clone();
    let mut client =
        Client::new(conn, satellite_ca.to_vec(), peer_ca).with_config(PieceConfig::default());
    let result = client.upload(limit, piece_key, data).await;
    transport.conn = Some(client.into_conn());
    result
}
