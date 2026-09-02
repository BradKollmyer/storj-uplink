//! In-process mock satellite: loopback TLS + DRPC unary for ProjectInfo and buckets.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use storj_proto::metainfo::{
    AddressedOrderLimit, BeginDeleteObjectRequest, BeginDeleteObjectResponse, BeginObjectRequest,
    BeginObjectResponse, BeginSegmentRequest, BeginSegmentResponse, Bucket as ProtoBucket,
    BucketListItem, CohortRequirements, CommitObjectRequest, CommitObjectResponse,
    CommitSegmentRequest, CommitSegmentResponse, CompressedBatchRequest, CreateBucketRequest,
    CreateBucketResponse, DeleteBucketRequest, DeleteBucketResponse, FinishDeleteObjectRequest,
    FinishDeleteObjectResponse, GetBucketRequest, GetBucketResponse, ListBucketsRequest,
    ListBucketsResponse, ListDirection, MakeInlineSegmentRequest, MakeInlineSegmentResponse,
    Object as ProtoObject, ProjectInfoRequest, ProjectInfoResponse, RequestHeader,
    RetryBeginSegmentPiecesRequest, RetryBeginSegmentPiecesResponse, batch_request_item,
    batch_response_item, cohort_requirements,
};
use storj_proto::node::NodeAddress;
use storj_proto::orders::{OrderLimit, PieceAction};
use storj_proto::pointerdb::RedundancyScheme;
use storj_proto::rpc;
use storj_proto::{decode_batch_request, encode_batch_response};
use storj_rpc::tls::server_config;
use storj_rpc::{Conn, Identity, Kind, Packet, marshal_error, read_tls_mux_prefix};
use storj_uplink::orders::{PiecePrivateKey, sign_order_limit};

use crate::mock_sn::MockStorageNode;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const RPC_INVALID_ARGUMENT: u64 = 3;
const RPC_NOT_FOUND: u64 = 5;
const RPC_ALREADY_EXISTS: u64 = 6;
const RPC_PERMISSION_DENIED: u64 = 7;
const RPC_FAILED_PRECONDITION: u64 = 9;
const RPC_UNIMPLEMENTED: u64 = 12;

const PROJECT_SALT: &[u8] = b"0123456789abcdef";

#[derive(Clone)]
struct BucketRec {
    created: SystemTime,
    objects: usize,
}

struct PendingObject {
    bucket: String,
    enc_key: Vec<u8>,
    stream_id: Vec<u8>,
}

struct MockState {
    api_key: Vec<u8>,
    project_salt: Vec<u8>,
    buckets: BTreeMap<String, BucketRec>,
    get_bucket_denied: BTreeSet<String>,
    pending: BTreeMap<Vec<u8>, PendingObject>,
    committed: BTreeMap<(String, Vec<u8>), ProtoObject>,
    aborted: BTreeSet<Vec<u8>>,
    inline_segments: usize,
    remote_segments: usize,
    retry_begin: usize,
    next_id: u64,
    piece_key: Vec<u8>,
}

/// Loopback TLS satellite that speaks `ProjectInfo`, buckets, and upload RPCs.
pub struct MockSatellite {
    node_url: String,
    api_key: String,
    api_key_raw: Vec<u8>,
    project_salt: Vec<u8>,
    state: Arc<Mutex<MockState>>,
    sns: Vec<Arc<MockStorageNode>>,
    join: JoinHandle<()>,
}

impl MockSatellite {
    /// Bind `127.0.0.1:0`, serve DRPC over TLS with NodeID pinning.
    pub async fn start() -> Self {
        let identity = Identity::generate().expect("mock satellite identity");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock satellite");
        let addr = listener.local_addr().expect("local addr");
        let node_url = format!("{}@{}", identity.node_id(), addr);

        let api = storj_access::ApiKey::from_parts(b"mock-api-key-head".to_vec(), &[0x42; 32]);
        let api_key = api.serialize();
        let api_key_raw = api.serialize_raw();
        let project_salt = PROJECT_SALT.to_vec();
        let sat_ca = identity.ca_der().as_ref().to_vec();
        let piece_key = PiecePrivateKey::generate().to_bytes().to_vec();

        let mut sns = Vec::new();
        for _ in 0..6 {
            sns.push(Arc::new(MockStorageNode::start(sat_ca.clone()).await));
        }

        let state = Arc::new(Mutex::new(MockState {
            api_key: api_key_raw.clone(),
            project_salt: project_salt.clone(),
            buckets: BTreeMap::new(),
            get_bucket_denied: BTreeSet::new(),
            pending: BTreeMap::new(),
            committed: BTreeMap::new(),
            aborted: BTreeSet::new(),
            inline_segments: 0,
            remote_segments: 0,
            retry_begin: 0,
            next_id: 1,
            piece_key,
        }));

        let server_cfg = server_config(&identity).expect("mock server tls");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let join_state = Arc::clone(&state);
        let join_sns = sns.clone();
        let join_ident = identity.clone();
        let join = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&join_state);
                let sns = join_sns.clone();
                let ident = join_ident.clone();
                tokio::spawn(async move {
                    let _ = serve_conn(tcp, acceptor, state, sns, ident).await;
                });
            }
        });

        Self {
            node_url,
            api_key,
            api_key_raw,
            project_salt,
            state,
            sns,
            join,
        }
    }

    /// `NodeID@127.0.0.1:port` for grants and `request_with_passphrase`.
    pub fn node_url(&self) -> &str {
        &self.node_url
    }

    /// Serialized (Base58Check) API key accepted by this mock.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// `ProjectInfo.project_salt`.
    pub fn project_salt(&self) -> &[u8] {
        &self.project_salt
    }

    /// Access grant pointing at this mock (dummy root key, no Argon2).
    pub fn access(&self) -> storj::Access {
        let grant = storj_access::Grant::from_parts(
            self.node_url.clone(),
            self.api_key_raw.clone(),
            storj_access::EncryptionAccess {
                default_key: Some([1u8; 32]),
                default_path_cipher: storj_access::CipherSuite::AES_GCM,
                store_entries: Vec::new(),
                default_encryption_parameters: None,
            },
        );
        let serialized = grant.serialize().expect("serialize mock grant");
        storj::Access::parse(&serialized).expect("parse mock grant")
    }

    /// Make `GetBucket` return permission-denied for `bucket` (stat-failure tests).
    pub fn deny_get_bucket(&self, bucket: &str) {
        self.state
            .lock()
            .expect("mock state")
            .get_bucket_denied
            .insert(bucket.to_owned());
    }

    /// Storage nodes started with this satellite (long-tail / piece upload).
    pub fn storage_nodes(&self) -> &[Arc<MockStorageNode>] {
        &self.sns
    }

    /// Delay Upload on storage node `idx` (long-tail tests).
    pub async fn set_sn_delay(&self, idx: usize, d: std::time::Duration) {
        if let Some(sn) = self.sns.get(idx) {
            sn.set_delay(d).await;
        }
    }

    /// Number of MakeInlineSegment calls.
    pub fn inline_segment_count(&self) -> usize {
        self.state.lock().expect("mock state").inline_segments
    }

    /// Number of BeginSegment (remote) calls.
    pub fn remote_segment_count(&self) -> usize {
        self.state.lock().expect("mock state").remote_segments
    }

    /// Number of RetryBeginSegmentPieces calls.
    pub fn retry_begin_count(&self) -> usize {
        self.state.lock().expect("mock state").retry_begin
    }

    /// Committed objects (encrypted key).
    pub fn committed_count(&self) -> usize {
        self.state.lock().expect("mock state").committed.len()
    }

    /// Aborted stream ids.
    pub fn aborted_count(&self) -> usize {
        self.state.lock().expect("mock state").aborted.len()
    }

    /// Mark `bucket` as containing an object (for `BucketNotEmpty` tests).
    pub fn put_object(&self, bucket: &str) {
        let mut state = self.state.lock().expect("mock state");
        state
            .buckets
            .entry(bucket.to_owned())
            .or_insert_with(|| BucketRec {
                created: SystemTime::now(),
                objects: 0,
            })
            .objects += 1;
    }
}

impl Drop for MockSatellite {
    fn drop(&mut self) {
        self.join.abort();
    }
}

async fn serve_conn(
    mut tcp: TcpStream,
    acceptor: TlsAcceptor,
    state: Arc<Mutex<MockState>>,
    sns: Vec<Arc<MockStorageNode>>,
    identity: Identity,
) -> Result<(), storj_rpc::Error> {
    read_tls_mux_prefix(&mut tcp).await?;
    let tls = acceptor.accept(tcp).await.map_err(storj_rpc::Error::Io)?;
    let mut conn = Conn::new(tls);
    loop {
        match serve_one(&mut conn, &state, &sns, &identity).await {
            Ok(()) => {}
            Err(storj_rpc::Error::Closed | storj_rpc::Error::Truncated) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

async fn serve_one(
    conn: &mut Conn<tokio_rustls::server::TlsStream<TcpStream>>,
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<(), storj_rpc::Error> {
    let invoke = loop {
        let pkt = conn.read_packet().await?;
        if pkt.kind == Kind::INVOKE {
            break pkt;
        }
    };
    let stream_id = invoke.stream_id;
    let rpc = String::from_utf8_lossy(&invoke.data).into_owned();

    let mut request = Vec::new();
    loop {
        let pkt = conn.read_packet().await?;
        if pkt.stream_id != stream_id {
            continue;
        }
        match pkt.kind {
            Kind::MESSAGE => request = pkt.data,
            Kind::CLOSE_SEND => break,
            _ => {}
        }
    }

    match handle_rpc(&rpc, &request, state, sns, identity) {
        Ok(body) => {
            conn.write_packet(&Packet {
                stream_id,
                message_id: 1,
                kind: Kind::MESSAGE,
                control: false,
                data: body,
            })
            .await?;
        }
        Err((code, message)) => {
            conn.write_packet(&Packet {
                stream_id,
                message_id: 1,
                kind: Kind::ERROR,
                control: false,
                data: marshal_error(code, &message),
            })
            .await?;
        }
    }
    Ok(())
}

fn handle_rpc(
    rpc: &str,
    body: &[u8],
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<Vec<u8>, (u64, String)> {
    match rpc {
        rpc::PROJECT_INFO => {
            let req = ProjectInfoRequest::decode(body).map_err(decode_err)?;
            let state = state.lock().expect("mock state");
            check_key(&req.header, &state)?;
            Ok(ProjectInfoResponse {
                project_salt: state.project_salt.clone(),
                ..Default::default()
            }
            .encode_to_vec())
        }
        rpc::CREATE_BUCKET => {
            let req = CreateBucketRequest::decode(body).map_err(decode_err)?;
            let mut state = state.lock().expect("mock state");
            check_key(&req.header, &state)?;
            let name = utf8_name(&req.name)?;
            if name.is_empty() {
                return Err((RPC_INVALID_ARGUMENT, "bucket name invalid".into()));
            }
            if state.buckets.contains_key(&name) {
                return Err((RPC_ALREADY_EXISTS, format!("bucket already exists: {name}")));
            }
            let created = SystemTime::now();
            state.buckets.insert(
                name.clone(),
                BucketRec {
                    created,
                    objects: 0,
                },
            );
            Ok(CreateBucketResponse {
                bucket: Some(proto_bucket(&name, created)),
            }
            .encode_to_vec())
        }
        rpc::GET_BUCKET => {
            let req = GetBucketRequest::decode(body).map_err(decode_err)?;
            let state = state.lock().expect("mock state");
            check_key(&req.header, &state)?;
            let name = utf8_name(&req.name)?;
            if state.get_bucket_denied.contains(&name) {
                return Err((RPC_PERMISSION_DENIED, "permission denied".into()));
            }
            let rec = state
                .buckets
                .get(&name)
                .ok_or_else(|| (RPC_NOT_FOUND, format!("bucket not found: {name}")))?;
            Ok(GetBucketResponse {
                bucket: Some(proto_bucket(&name, rec.created)),
            }
            .encode_to_vec())
        }
        rpc::DELETE_BUCKET => {
            let req = DeleteBucketRequest::decode(body).map_err(decode_err)?;
            let mut state = state.lock().expect("mock state");
            check_key(&req.header, &state)?;
            let name = utf8_name(&req.name)?;
            let rec = state
                .buckets
                .get(&name)
                .cloned()
                .ok_or_else(|| (RPC_NOT_FOUND, format!("bucket not found: {name}")))?;
            if rec.objects > 0 && !req.delete_all {
                return Err((RPC_FAILED_PRECONDITION, format!("bucket not empty: {name}")));
            }
            state.buckets.remove(&name);
            Ok(DeleteBucketResponse {
                bucket: Some(proto_bucket(&name, rec.created)),
                deleted_objects_count: rec.objects as i64,
            }
            .encode_to_vec())
        }
        rpc::LIST_BUCKETS => {
            let req = ListBucketsRequest::decode(body).map_err(decode_err)?;
            let state = state.lock().expect("mock state");
            check_key(&req.header, &state)?;
            let cursor = String::from_utf8_lossy(&req.cursor).into_owned();
            let after = req.direction != ListDirection::Forward as i32;
            let mut names: Vec<&String> = state.buckets.keys().collect();
            names.retain(|n| {
                if cursor.is_empty() {
                    true
                } else if after {
                    n.as_str() > cursor.as_str()
                } else {
                    n.as_str() >= cursor.as_str()
                }
            });
            let limit = if req.limit <= 0 {
                1000
            } else {
                req.limit as usize
            };
            let more = names.len() > limit;
            let page = names.into_iter().take(limit);
            let items = page
                .map(|name| {
                    let rec = &state.buckets[name];
                    BucketListItem {
                        name: name.as_bytes().to_vec(),
                        created_at: Some(timestamp(rec.created)),
                        user_agent: Vec::new(),
                    }
                })
                .collect();
            Ok(ListBucketsResponse { items, more }.encode_to_vec())
        }
        rpc::COMPRESSED_BATCH => {
            let req = CompressedBatchRequest::decode(body).map_err(decode_err)?;
            let batch = decode_batch_request(&req)
                .map_err(|e| (RPC_INVALID_ARGUMENT, format!("compressed batch: {e}")))?;
            {
                let st = state.lock().expect("mock state");
                check_key(&batch.header, &st)?;
            }
            let mut responses = Vec::new();
            for item in batch.requests {
                let resp = handle_batch_item(item.request, state, sns, identity)?;
                responses.push(resp);
            }
            let inner = storj_proto::metainfo::BatchResponse { responses };
            let wrapped = encode_batch_response(&inner, false)
                .map_err(|e| (RPC_INVALID_ARGUMENT, format!("encode batch: {e}")))?;
            Ok(wrapped.encode_to_vec())
        }
        _ => Err((RPC_UNIMPLEMENTED, format!("unknown rpc {rpc}"))),
    }
}

fn handle_batch_item(
    item: Option<batch_request_item::Request>,
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<storj_proto::metainfo::BatchResponseItem, (u64, String)> {
    use batch_request_item::Request;
    let response = match item {
        Some(Request::ObjectBegin(req)) => {
            batch_response_item::Response::ObjectBegin(begin_object(req, state)?)
        }
        Some(Request::ObjectCommit(req)) => {
            batch_response_item::Response::ObjectCommit(commit_object(req, state)?)
        }
        Some(Request::ObjectBeginDelete(req)) => {
            batch_response_item::Response::ObjectBeginDelete(begin_delete(req, state)?)
        }
        Some(Request::ObjectFinishDelete(req)) => {
            batch_response_item::Response::ObjectFinishDelete(finish_delete(req, state)?)
        }
        Some(Request::SegmentBegin(req)) => {
            batch_response_item::Response::SegmentBegin(begin_segment(req, state, sns, identity)?)
        }
        Some(Request::SegmentCommit(req)) => {
            batch_response_item::Response::SegmentCommit(commit_segment(req, state)?)
        }
        Some(Request::SegmentMakeInline(req)) => {
            batch_response_item::Response::SegmentMakeInline(make_inline(req, state)?)
        }
        Some(Request::SegmentBeginRetryPieces(req)) => {
            batch_response_item::Response::SegmentBeginRetryPieces(retry_pieces(
                req, state, sns, identity,
            )?)
        }
        Some(Request::BucketCreate(req)) => {
            let body = handle_rpc(
                rpc::CREATE_BUCKET,
                &req.encode_to_vec(),
                state,
                sns,
                identity,
            )?;
            batch_response_item::Response::BucketCreate(
                CreateBucketResponse::decode(body.as_slice()).map_err(decode_err)?,
            )
        }
        Some(Request::BucketGet(req)) => {
            let body = handle_rpc(rpc::GET_BUCKET, &req.encode_to_vec(), state, sns, identity)?;
            batch_response_item::Response::BucketGet(
                GetBucketResponse::decode(body.as_slice()).map_err(decode_err)?,
            )
        }
        None => return Err((RPC_INVALID_ARGUMENT, "empty batch item".into())),
        _ => return Err((RPC_UNIMPLEMENTED, "unimplemented batch item".into())),
    };
    Ok(storj_proto::metainfo::BatchResponseItem {
        response: Some(response),
    })
}

fn begin_object(
    req: BeginObjectRequest,
    state: &Mutex<MockState>,
) -> Result<BeginObjectResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    st.next_id += 1;
    let stream_id = st.next_id.to_be_bytes().to_vec();
    st.pending.insert(
        stream_id.clone(),
        PendingObject {
            bucket: name,
            enc_key: req.encrypted_object_key.clone(),
            stream_id: stream_id.clone(),
        },
    );
    Ok(BeginObjectResponse {
        bucket: req.bucket,
        encrypted_object_key: req.encrypted_object_key,
        stream_id,
        encryption_parameters: req.encryption_parameters.or(Some(
            storj_proto::encryption::EncryptionParameters {
                cipher_suite: storj_proto::encryption::CipherSuite::EncAesgcm as i32,
                block_size: 7424,
            },
        )),
        ..Default::default()
    })
}

fn commit_object(
    req: CommitObjectRequest,
    state: &Mutex<MockState>,
) -> Result<CommitObjectResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let pending = st
        .pending
        .remove(&req.stream_id)
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let obj = ProtoObject {
        bucket: pending.bucket.as_bytes().to_vec(),
        encrypted_object_key: pending.enc_key.clone(),
        stream_id: pending.stream_id.clone(),
        status: storj_proto::metainfo::object::Status::CommittedUnversioned as i32,
        created_at: Some(timestamp(SystemTime::now())),
        encrypted_metadata: req.encrypted_metadata,
        encrypted_metadata_nonce: req.encrypted_metadata_nonce,
        encrypted_metadata_encrypted_key: req.encrypted_metadata_encrypted_key,
        ..Default::default()
    };
    if let Some(rec) = st.buckets.get_mut(&pending.bucket) {
        rec.objects += 1;
    }
    st.committed
        .insert((pending.bucket, pending.enc_key), obj.clone());
    Ok(CommitObjectResponse { object: Some(obj) })
}

fn begin_delete(
    req: BeginDeleteObjectRequest,
    state: &Mutex<MockState>,
) -> Result<BeginDeleteObjectResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    st.pending.remove(&req.stream_id);
    st.aborted.insert(req.stream_id.clone());
    Ok(BeginDeleteObjectResponse {
        stream_id: req.stream_id,
        object: None,
    })
}

fn finish_delete(
    req: FinishDeleteObjectRequest,
    state: &Mutex<MockState>,
) -> Result<FinishDeleteObjectResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    Ok(FinishDeleteObjectResponse {})
}

fn begin_segment(
    req: BeginSegmentRequest,
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<BeginSegmentResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    if !st.pending.contains_key(&req.stream_id) {
        return Err((RPC_NOT_FOUND, "object not found".into()));
    }
    st.remote_segments += 1;
    st.next_id += 1;
    let segment_id = st.next_id.to_be_bytes().to_vec();
    let piece_key = st.piece_key.clone();
    drop(st);
    let pk = PiecePrivateKey::from_bytes(&piece_key)
        .map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))?;
    let n = sns.len().min(4);
    let mut addressed_limits = Vec::new();
    for (i, sn) in sns.iter().take(n).enumerate() {
        addressed_limits.push(signed_limit(
            identity,
            sn,
            &pk,
            i as i32,
            &segment_id,
            req.max_order_limit.max(64 * 1024),
        )?);
    }
    Ok(BeginSegmentResponse {
        segment_id,
        addressed_limits,
        private_key: piece_key,
        redundancy_scheme: Some(test_scheme()),
        cohort_requirements: Some(CohortRequirements {
            requirement: Some(cohort_requirements::Requirement::Literal(
                cohort_requirements::Literal { value: 3 },
            )),
        }),
    })
}

fn retry_pieces(
    req: RetryBeginSegmentPiecesRequest,
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<RetryBeginSegmentPiecesResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    st.retry_begin += 1;
    let piece_key = st.piece_key.clone();
    drop(st);
    let pk = PiecePrivateKey::from_bytes(&piece_key)
        .map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))?;
    let mut addressed_limits = Vec::new();
    for (i, num) in req.retry_piece_numbers.iter().enumerate() {
        let sn = sns
            .get((4 + i) % sns.len())
            .or_else(|| sns.first())
            .ok_or_else(|| (RPC_INVALID_ARGUMENT, "no storage nodes".into()))?;
        addressed_limits.push(signed_limit(
            identity,
            sn,
            &pk,
            *num,
            &req.segment_id,
            64 * 1024,
        )?);
    }
    Ok(RetryBeginSegmentPiecesResponse {
        segment_id: req.segment_id,
        addressed_limits,
    })
}

fn commit_segment(
    req: CommitSegmentRequest,
    state: &Mutex<MockState>,
) -> Result<CommitSegmentResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    Ok(CommitSegmentResponse {
        successful_pieces: req.upload_result.len() as i32,
    })
}

fn make_inline(
    req: MakeInlineSegmentRequest,
    state: &Mutex<MockState>,
) -> Result<MakeInlineSegmentResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    if req.encrypted_inline_data.len() > 4 * 1024 + 16 {
        return Err((
            RPC_INVALID_ARGUMENT,
            "inline segment size cannot be larger than 4.0 KB".into(),
        ));
    }
    st.inline_segments += 1;
    Ok(MakeInlineSegmentResponse {})
}

fn test_scheme() -> RedundancyScheme {
    RedundancyScheme {
        r#type: 1,
        min_req: 2,
        total: 4,
        repair_threshold: 3,
        success_threshold: 3,
        erasure_share_size: 32,
    }
}

fn signed_limit(
    satellite: &Identity,
    sn: &MockStorageNode,
    piece_key: &PiecePrivateKey,
    piece_num: i32,
    segment_id: &[u8],
    limit: i64,
) -> Result<AddressedOrderLimit, (u64, String)> {
    let now = timestamp(SystemTime::now());
    let mut piece_id = [0u8; 32];
    piece_id[0] = piece_num as u8;
    if segment_id.len() >= 8 {
        piece_id[1..9].copy_from_slice(&segment_id[..8.min(segment_id.len())]);
    }
    let mut ol = OrderLimit {
        serial_number: {
            let mut s = vec![piece_num as u8];
            s.extend_from_slice(segment_id);
            s.resize(16, 0);
            s
        },
        satellite_id: satellite.node_id().as_bytes().to_vec(),
        deprecated_uplink_id: Vec::new(),
        uplink_public_key: piece_key.public().to_bytes().to_vec(),
        storage_node_id: sn.identity().node_id().as_bytes().to_vec(),
        piece_id: piece_id.to_vec(),
        limit: limit.max(1),
        action: PieceAction::Put as i32,
        piece_expiration: Some(now),
        order_expiration: Some(now),
        order_creation: Some(now),
        encrypted_metadata_key_id: Vec::new(),
        encrypted_metadata: Vec::new(),
        satellite_signature: Vec::new(),
        deprecated_satellite_address: None,
    };
    sign_order_limit(&mut ol, satellite).map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))?;
    Ok(AddressedOrderLimit {
        limit: Some(ol),
        storage_node_address: Some(NodeAddress {
            address: sn.address().to_string(),
            ..Default::default()
        }),
        tags: Default::default(),
    })
}

fn check_key(header: &Option<RequestHeader>, state: &MockState) -> Result<(), (u64, String)> {
    let got = header.as_ref().map(|h| h.api_key.as_slice()).unwrap_or(&[]);
    if got != state.api_key.as_slice() {
        return Err((RPC_PERMISSION_DENIED, "permission denied".into()));
    }
    Ok(())
}

fn utf8_name(name: &[u8]) -> Result<String, (u64, String)> {
    String::from_utf8(name.to_vec())
        .map_err(|_| (RPC_INVALID_ARGUMENT, "bucket name invalid".into()))
}

fn decode_err(e: prost::DecodeError) -> (u64, String) {
    (RPC_INVALID_ARGUMENT, format!("decode: {e}"))
}

fn proto_bucket(name: &str, created: SystemTime) -> ProtoBucket {
    ProtoBucket {
        name: name.as_bytes().to_vec(),
        created_at: Some(timestamp(created)),
        ..Default::default()
    }
}

fn timestamp(t: SystemTime) -> prost_types::Timestamp {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    prost_types::Timestamp {
        seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos() as i32,
    }
}
