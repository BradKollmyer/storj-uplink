//! In-process mock satellite: loopback TLS + DRPC unary for ProjectInfo and buckets.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use storj_proto::metainfo::{
    AddressedOrderLimit, BeginDeleteObjectRequest, BeginDeleteObjectResponse, BeginObjectRequest,
    BeginObjectResponse, BeginSegmentRequest, BeginSegmentResponse, Bucket as ProtoBucket,
    BucketListItem, CohortRequirements, CommitObjectRequest, CommitObjectResponse,
    CommitSegmentRequest, CommitSegmentResponse, CompressedBatchRequest, CreateBucketRequest,
    CreateBucketResponse, DeleteBucketRequest, DeleteBucketResponse, DownloadObjectRequest,
    DownloadObjectResponse, DownloadSegmentRequest, DownloadSegmentResponse,
    FinishDeleteObjectRequest, FinishDeleteObjectResponse, GetBucketRequest, GetBucketResponse,
    ListBucketsRequest, ListBucketsResponse, ListDirection, ListObjectsRequest,
    ListObjectsResponse, ListSegmentsRequest, ListSegmentsResponse, MakeInlineSegmentRequest,
    MakeInlineSegmentResponse, Object as ProtoObject, ObjectListItem, ProjectInfoRequest,
    ProjectInfoResponse, Range, RequestHeader, RetryBeginSegmentPiecesRequest,
    RetryBeginSegmentPiecesResponse, SegmentListItem, SegmentPosition, batch_request_item,
    batch_response_item, cohort_requirements, range,
};
use storj_proto::node::NodeAddress;
use storj_proto::orders::{OrderLimit, PieceAction};
use storj_proto::pointerdb::RedundancyScheme;
use storj_proto::rpc;
use storj_proto::{decode_batch_request, encode_batch_response};
use storj_rpc::tls::server_config;
use storj_rpc::{Conn, Identity, Kind, Packet, marshal_error, read_tls_mux_prefix};
use storj_uplink::download::{resolve_range, segment_plain_range};
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
const RPC_INTERNAL: u64 = 13;
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
    expires: Option<SystemTime>,
    created: SystemTime,
    encryption_parameters: Option<storj_proto::encryption::EncryptionParameters>,
    segments: Vec<StoredSegment>,
    in_flight: HashMap<Vec<u8>, InFlightSegment>,
}

struct InFlightSegment {
    position: SegmentPosition,
    piece_limits: HashMap<i32, AddressedOrderLimit>,
}

#[derive(Clone)]
struct StoredPiece {
    piece_num: i32,
    piece_id: Vec<u8>,
    node_id: Vec<u8>,
}

#[derive(Clone)]
struct StoredSegment {
    position: SegmentPosition,
    encrypted_key: Vec<u8>,
    encrypted_key_nonce: Vec<u8>,
    plain_size: i64,
    encrypted_size: i64,
    inline_data: Vec<u8>,
    pieces: Vec<StoredPiece>,
    scheme: RedundancyScheme,
    encrypted_etag: Vec<u8>,
    created: SystemTime,
}

struct CommittedObject {
    object: ProtoObject,
    segments: Vec<StoredSegment>,
}

struct MockState {
    api_key: Vec<u8>,
    project_salt: Vec<u8>,
    buckets: BTreeMap<String, BucketRec>,
    get_bucket_denied: BTreeSet<String>,
    pending: BTreeMap<Vec<u8>, PendingObject>,
    committed: BTreeMap<(String, Vec<u8>), CommittedObject>,
    aborted: BTreeSet<Vec<u8>>,
    segment_to_stream: BTreeMap<Vec<u8>, Vec<u8>>,
    inline_segments: usize,
    remote_segments: usize,
    retry_begin: usize,
    next_id: u64,
    piece_key: Vec<u8>,
    fail_commit: bool,
    last_retry_segment_id: Option<Vec<u8>>,
    last_commit_segment_id: Option<Vec<u8>>,
    stale_segment_ids: BTreeSet<Vec<u8>>,
    sn_tags: Vec<HashMap<String, Vec<u8>>>,
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
            segment_to_stream: BTreeMap::new(),
            inline_segments: 0,
            remote_segments: 0,
            retry_begin: 0,
            next_id: 1,
            piece_key,
            fail_commit: false,
            last_retry_segment_id: None,
            last_commit_segment_id: None,
            stale_segment_ids: BTreeSet::new(),
            sn_tags: vec![HashMap::new(); 6],
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

    /// Next `CommitObject` returns an error (then clears).
    pub fn fail_next_commit_object(&self) {
        self.state.lock().expect("mock state").fail_commit = true;
    }

    /// Next Download on storage node `idx` fails (k-1 reconstruction tests).
    pub async fn fail_sn_download(&self, idx: usize) {
        if let Some(sn) = self.sns.get(idx) {
            sn.fail_next_download().await;
        }
    }

    /// Replace the metadata key ciphertext so user-data decrypt fails.
    pub fn corrupt_encrypted_metadata(&self) {
        let mut st = self.state.lock().expect("mock state");
        for rec in st.committed.values_mut() {
            rec.object.encrypted_metadata_encrypted_key = vec![0xAA; 48];
        }
    }

    /// Segment id last sent on `CommitSegment`.
    pub fn last_commit_segment_id(&self) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("mock state")
            .last_commit_segment_id
            .clone()
    }

    /// Segment id last returned by `RetryBeginSegmentPieces`.
    pub fn last_retry_segment_id(&self) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("mock state")
            .last_retry_segment_id
            .clone()
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
        Some(Request::ObjectDownload(req)) => batch_response_item::Response::ObjectDownload(
            download_object(req, state, sns, identity)?,
        ),
        Some(Request::SegmentDownload(req)) => batch_response_item::Response::SegmentDownload(
            download_segment(req, state, sns, identity)?,
        ),
        Some(Request::SegmentList(req)) => {
            batch_response_item::Response::SegmentList(list_segments(req, state)?)
        }
        Some(Request::ObjectList(req)) => {
            batch_response_item::Response::ObjectList(list_objects(req, state)?)
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
    let expires = req.expires_at.map(|t| {
        UNIX_EPOCH + std::time::Duration::new(t.seconds.max(0) as u64, t.nanos.max(0) as u32)
    });
    st.pending.insert(
        stream_id.clone(),
        PendingObject {
            bucket: name,
            enc_key: req.encrypted_object_key.clone(),
            stream_id: stream_id.clone(),
            expires,
            created: SystemTime::now(),
            encryption_parameters: req.encryption_parameters.or(Some(
                storj_proto::encryption::EncryptionParameters {
                    cipher_suite: storj_proto::encryption::CipherSuite::EncAesgcm as i32,
                    block_size: 7424,
                },
            )),
            segments: Vec::new(),
            in_flight: HashMap::new(),
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
    if st.fail_commit {
        st.fail_commit = false;
        return Err((RPC_INTERNAL, "commit object failed".into()));
    }
    {
        let pending = st
            .pending
            .get(&req.stream_id)
            .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
        let mut segments = pending.segments.clone();
        segments.sort_by_key(|s| (s.position.part_number, s.position.index));
        check_multipart_limits(&segments)?;
    }
    let pending = st
        .pending
        .remove(&req.stream_id)
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let mut segments = pending.segments;
    segments.sort_by_key(|s| (s.position.part_number, s.position.index));
    let total_plain: i64 = segments.iter().map(|s| s.plain_size).sum();
    let scheme = segments
        .first()
        .map(|s| s.scheme)
        .unwrap_or_else(test_scheme);
    let obj = ProtoObject {
        bucket: pending.bucket.as_bytes().to_vec(),
        encrypted_object_key: pending.enc_key.clone(),
        stream_id: pending.stream_id.clone(),
        status: storj_proto::metainfo::object::Status::CommittedUnversioned as i32,
        created_at: Some(timestamp(SystemTime::now())),
        encrypted_metadata: req.encrypted_metadata,
        encrypted_metadata_nonce: req.encrypted_metadata_nonce,
        encrypted_metadata_encrypted_key: req.encrypted_metadata_encrypted_key,
        plain_size: total_plain,
        encryption_parameters: Some(storj_proto::encryption::EncryptionParameters {
            cipher_suite: storj_proto::encryption::CipherSuite::EncAesgcm as i32,
            block_size: 7424,
        }),
        redundancy_scheme: Some(scheme),
        ..Default::default()
    };
    if let Some(rec) = st.buckets.get_mut(&pending.bucket) {
        rec.objects += 1;
    }
    st.committed.insert(
        (pending.bucket, pending.enc_key),
        CommittedObject {
            object: obj.clone(),
            segments,
        },
    );
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
    let stream_id = req.stream_id.clone();
    let position = req.position.unwrap_or_default();
    st.segment_to_stream
        .insert(segment_id.clone(), stream_id.clone());
    let piece_key = st.piece_key.clone();
    let sn_tags = st.sn_tags.clone();
    drop(st);
    let pk = PiecePrivateKey::from_bytes(&piece_key)
        .map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))?;
    let n = sns.len().min(4);
    let mut addressed_limits = Vec::new();
    for (i, sn) in sns.iter().take(n).enumerate() {
        let tags = sn_tags.get(i).cloned().unwrap_or_default();
        addressed_limits.push(signed_limit(
            identity,
            sn,
            &pk,
            i as i32,
            &segment_id,
            None,
            req.max_order_limit.max(64 * 1024),
            tags,
            PieceAction::Put,
        )?);
    }
    {
        let mut st = state.lock().expect("mock state");
        if let Some(pending) = st.pending.get_mut(&stream_id) {
            pending.in_flight.insert(
                segment_id.clone(),
                InFlightSegment {
                    position,
                    piece_limits: addressed_limits
                        .iter()
                        .enumerate()
                        .map(|(i, a)| (i as i32, a.clone()))
                        .collect(),
                },
            );
        }
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
    st.next_id += 1;
    let new_id = st.next_id.to_be_bytes().to_vec();
    st.last_retry_segment_id = Some(new_id.clone());
    st.stale_segment_ids.insert(req.segment_id.clone());
    let stream_id = st.segment_to_stream.remove(&req.segment_id);
    if let Some(ref sid) = stream_id {
        st.segment_to_stream.insert(new_id.clone(), sid.clone());
    }
    let piece_key = st.piece_key.clone();
    let sn_tags = st.sn_tags.clone();
    drop(st);
    let pk = PiecePrivateKey::from_bytes(&piece_key)
        .map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))?;
    let mut addressed_limits = Vec::new();
    for (i, num) in req.retry_piece_numbers.iter().enumerate() {
        let sn_idx = (4 + i) % sns.len().max(1);
        let sn = sns
            .get(sn_idx)
            .or_else(|| sns.first())
            .ok_or_else(|| (RPC_INVALID_ARGUMENT, "no storage nodes".into()))?;
        let tags = sn_tags.get(sn_idx).cloned().unwrap_or_default();
        addressed_limits.push(signed_limit(
            identity,
            sn,
            &pk,
            *num,
            &new_id,
            None,
            64 * 1024,
            tags,
            PieceAction::Put,
        )?);
    }
    if let Some(sid) = stream_id {
        let mut st = state.lock().expect("mock state");
        if let Some(pending) = st.pending.get_mut(&sid) {
            if let Some(mut inflight) = pending.in_flight.remove(&req.segment_id) {
                for (i, limit) in addressed_limits.iter().enumerate() {
                    let num = req.retry_piece_numbers.get(i).copied().unwrap_or(i as i32);
                    inflight.piece_limits.insert(num, limit.clone());
                }
                pending.in_flight.insert(new_id.clone(), inflight);
            }
        }
    }
    Ok(RetryBeginSegmentPiecesResponse {
        segment_id: new_id,
        addressed_limits,
    })
}

fn commit_segment(
    req: CommitSegmentRequest,
    state: &Mutex<MockState>,
) -> Result<CommitSegmentResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    if st.stale_segment_ids.contains(&req.segment_id) {
        return Err((
            RPC_INVALID_ARGUMENT,
            "stale segment id after RetryBeginSegmentPieces".into(),
        ));
    }
    st.last_commit_segment_id = Some(req.segment_id.clone());
    let stream_id = st.segment_to_stream.get(&req.segment_id).cloned();
    if let Some(sid) = stream_id {
        if let Some(pending) = st.pending.get_mut(&sid) {
            let inflight = pending.in_flight.remove(&req.segment_id);
            let mut pieces = Vec::new();
            let position = inflight.as_ref().map(|f| f.position).unwrap_or_default();
            if let Some(inflight) = inflight {
                for result in &req.upload_result {
                    if let Some(addr) = inflight.piece_limits.get(&result.piece_num) {
                        let limit = addr.limit.as_ref();
                        pieces.push(StoredPiece {
                            piece_num: result.piece_num,
                            piece_id: limit.map(|l| l.piece_id.clone()).unwrap_or_default(),
                            node_id: limit
                                .map(|l| l.storage_node_id.clone())
                                .unwrap_or_else(|| result.node_id.clone()),
                        });
                    }
                }
            }
            pending.segments.push(StoredSegment {
                position,
                encrypted_key: req.encrypted_key.clone(),
                encrypted_key_nonce: req.encrypted_key_nonce.clone(),
                plain_size: req.plain_size,
                encrypted_size: req.size_encrypted_data,
                inline_data: Vec::new(),
                pieces,
                scheme: test_scheme(),
                encrypted_etag: req.encrypted_e_tag.clone(),
                created: SystemTime::now(),
            });
        }
    }
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
    if let Some(pending) = st.pending.get_mut(&req.stream_id) {
        pending.segments.push(StoredSegment {
            position: req.position.unwrap_or_default(),
            encrypted_key: req.encrypted_key,
            encrypted_key_nonce: req.encrypted_key_nonce,
            plain_size: req.plain_size,
            encrypted_size: req.encrypted_inline_data.len() as i64,
            inline_data: req.encrypted_inline_data,
            pieces: Vec::new(),
            scheme: test_scheme(),
            encrypted_etag: req.encrypted_e_tag,
            created: SystemTime::now(),
        });
    }
    Ok(MakeInlineSegmentResponse {})
}

fn download_object(
    req: DownloadObjectRequest,
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<DownloadObjectResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    let committed = st
        .committed
        .get(&(name, req.encrypted_object_key.clone()))
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let obj = committed.object.clone();
    let segments = committed.segments.clone();
    let piece_key = st.piece_key.clone();
    drop(st);

    let total: i64 = segments.iter().map(|s| s.plain_size).sum();
    let window = resolve_mock_range(req.range.as_ref(), total)?;
    let (items, downloads) = build_segment_views(
        &obj,
        &segments,
        sns,
        identity,
        &piece_key,
        Some(window),
        true,
    )?;
    Ok(DownloadObjectResponse {
        object: Some(obj.clone()),
        segment_list: Some(ListSegmentsResponse {
            items,
            more: false,
            encryption_parameters: obj.encryption_parameters,
        }),
        segment_download: downloads,
    })
}

fn download_segment(
    req: DownloadSegmentRequest,
    state: &Mutex<MockState>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
) -> Result<DownloadSegmentResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let committed = st
        .committed
        .values()
        .find(|c| c.object.stream_id == req.stream_id)
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let obj = committed.object.clone();
    let segments = committed.segments.clone();
    let piece_key = st.piece_key.clone();
    drop(st);

    let want = req.cursor_position.unwrap_or_default();
    let idx = segments
        .iter()
        .position(|s| s.position.part_number == want.part_number && s.position.index == want.index)
        .ok_or_else(|| (RPC_NOT_FOUND, "segment not found".into()))?;
    let (_, downloads) =
        build_segment_views(&obj, &segments, sns, identity, &piece_key, None, false)?;
    downloads
        .into_iter()
        .nth(idx)
        .ok_or_else(|| (RPC_NOT_FOUND, "segment not found".into()))
}

fn list_segments(
    req: ListSegmentsRequest,
    state: &Mutex<MockState>,
) -> Result<ListSegmentsResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let (mut segments, encryption_parameters) = if let Some(committed) = st
        .committed
        .values()
        .find(|c| c.object.stream_id == req.stream_id)
    {
        (
            committed.segments.clone(),
            committed.object.encryption_parameters,
        )
    } else if let Some(pending) = st.pending.get(&req.stream_id) {
        (pending.segments.clone(), pending.encryption_parameters)
    } else {
        return Err((RPC_NOT_FOUND, "object not found".into()));
    };
    drop(st);
    segments.sort_by_key(|s| (s.position.part_number, s.position.index));

    let total: i64 = segments.iter().map(|s| s.plain_size).sum();
    let window = resolve_mock_range(req.range.as_ref(), total)?;
    let mut offset = 0i64;
    let mut items = Vec::new();
    for seg in &segments {
        let after_cursor = match req.cursor_position {
            None => true,
            Some(cursor) => {
                seg.position.part_number > cursor.part_number
                    || (seg.position.part_number == cursor.part_number
                        && seg.position.index > cursor.index)
            }
        };
        let (_, overlap) = segment_plain_range(window.0, window.1, offset, seg.plain_size);
        if after_cursor && overlap > 0 {
            items.push(SegmentListItem {
                position: Some(seg.position),
                plain_size: seg.plain_size,
                plain_offset: offset,
                created_at: Some(timestamp(seg.created)),
                encrypted_e_tag: seg.encrypted_etag.clone(),
                encrypted_key_nonce: seg.encrypted_key_nonce.clone(),
                encrypted_key: seg.encrypted_key.clone(),
                ..Default::default()
            });
        }
        offset += seg.plain_size;
    }
    Ok(ListSegmentsResponse {
        items,
        more: false,
        encryption_parameters,
    })
}

fn list_objects(
    req: ListObjectsRequest,
    state: &Mutex<MockState>,
) -> Result<ListObjectsResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    let uploading = req.status == storj_proto::metainfo::object::Status::Uploading as i32;
    if !uploading {
        return Ok(ListObjectsResponse {
            items: Vec::new(),
            more: false,
        });
    }
    let mut items: Vec<&PendingObject> = st
        .pending
        .values()
        .filter(|p| p.bucket == name)
        .filter(|p| req.encrypted_prefix.is_empty() || p.enc_key.starts_with(&req.encrypted_prefix))
        .filter(|p| {
            req.encrypted_cursor.is_empty()
                || p.enc_key.as_slice() > req.encrypted_cursor.as_slice()
        })
        .collect();
    items.sort_by(|a, b| a.enc_key.cmp(&b.enc_key));
    let delimiter = if req.recursive {
        None
    } else if req.delimiter.is_empty() {
        Some(b'/')
    } else {
        req.delimiter.first().copied()
    };
    let mut out = Vec::new();
    let mut seen_prefix = BTreeSet::new();
    for pending in items {
        let remainder = pending
            .enc_key
            .strip_prefix(req.encrypted_prefix.as_slice())
            .unwrap_or(pending.enc_key.as_slice());
        if let Some(del) = delimiter {
            if let Some(idx) = remainder.iter().position(|b| *b == del) {
                let mut prefix_key = req.encrypted_prefix.clone();
                prefix_key.extend_from_slice(&remainder[..=idx]);
                if seen_prefix.insert(prefix_key.clone()) {
                    out.push(ObjectListItem {
                        encrypted_object_key: prefix_key,
                        status: storj_proto::metainfo::object::Status::Prefix as i32,
                        created_at: Some(timestamp(pending.created)),
                        ..Default::default()
                    });
                }
                continue;
            }
        }
        let plain_size: i64 = pending.segments.iter().map(|s| s.plain_size).sum();
        out.push(ObjectListItem {
            encrypted_object_key: pending.enc_key.clone(),
            status: storj_proto::metainfo::object::Status::Uploading as i32,
            created_at: Some(timestamp(pending.created)),
            expires_at: pending.expires.map(timestamp),
            plain_size,
            stream_id: pending.stream_id.clone(),
            ..Default::default()
        });
    }
    Ok(ListObjectsResponse {
        items: out,
        more: false,
    })
}

fn check_multipart_limits(segments: &[StoredSegment]) -> Result<(), (u64, String)> {
    let mut by_part: BTreeMap<i32, i64> = BTreeMap::new();
    for seg in segments {
        *by_part.entry(seg.position.part_number).or_default() += seg.plain_size;
    }
    if by_part.len() as u32 > storj::constants::MAX_MULTIPART_PARTS {
        return Err((RPC_INVALID_ARGUMENT, "too many parts".into()));
    }
    if by_part.len() <= 1 {
        return Ok(());
    }
    let last = *by_part.keys().next_back().expect("non-empty");
    for (part, size) in &by_part {
        if *part != last && *size < storj::constants::MIN_MULTIPART_PART_SIZE as i64 {
            return Err((
                RPC_INVALID_ARGUMENT,
                format!("part {part} is smaller than the minimum allowed size"),
            ));
        }
    }
    Ok(())
}

fn resolve_mock_range(
    range: Option<&Range>,
    object_size: i64,
) -> Result<(i64, i64), (u64, String)> {
    let (offset, length) = match range.and_then(|r| r.range.as_ref()) {
        None => return Ok((0, object_size)),
        Some(range::Range::Start(s)) => (s.plain_start, -1),
        Some(range::Range::StartLimit(s)) => {
            (s.plain_start, s.plain_limit.saturating_sub(s.plain_start))
        }
        Some(range::Range::Suffix(s)) => (-s.plain_suffix, -1),
    };
    resolve_range(offset, length, object_size).map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))
}

fn build_segment_views(
    obj: &ProtoObject,
    segments: &[StoredSegment],
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
    piece_key: &[u8],
    window: Option<(i64, i64)>,
    first_download_only: bool,
) -> Result<(Vec<SegmentListItem>, Vec<DownloadSegmentResponse>), (u64, String)> {
    let pk = PiecePrivateKey::from_bytes(piece_key)
        .map_err(|e| (RPC_INVALID_ARGUMENT, e.to_string()))?;
    let mut items = Vec::new();
    let mut downloads = Vec::new();
    let mut offset = 0i64;
    for (i, seg) in segments.iter().enumerate() {
        let next = segments.get(i + 1).map(|s| s.position);
        let in_window = match window {
            None => true,
            Some((start, len)) => segment_plain_range(start, len, offset, seg.plain_size).1 > 0,
        };
        if in_window {
            items.push(SegmentListItem {
                position: Some(seg.position),
                plain_size: seg.plain_size,
                plain_offset: offset,
                created_at: Some(timestamp(seg.created)),
                encrypted_e_tag: seg.encrypted_etag.clone(),
                encrypted_key_nonce: seg.encrypted_key_nonce.clone(),
                encrypted_key: seg.encrypted_key.clone(),
                ..Default::default()
            });
            if !first_download_only || downloads.is_empty() {
                downloads.push(segment_download(
                    obj, seg, offset, next, sns, identity, piece_key, &pk,
                )?);
            }
        }
        offset += seg.plain_size;
    }
    Ok((items, downloads))
}

#[allow(clippy::too_many_arguments)]
fn segment_download(
    obj: &ProtoObject,
    seg: &StoredSegment,
    plain_offset: i64,
    next: Option<SegmentPosition>,
    sns: &[Arc<MockStorageNode>],
    identity: &Identity,
    piece_key: &[u8],
    pk: &PiecePrivateKey,
) -> Result<DownloadSegmentResponse, (u64, String)> {
    let n = usize::try_from(seg.scheme.total)
        .unwrap_or(0)
        .max(seg.pieces.len());
    let mut addressed_limits = vec![AddressedOrderLimit::default(); n];
    if seg.inline_data.is_empty() {
        for p in &seg.pieces {
            let sn = sns
                .iter()
                .find(|sn| sn.identity().node_id().as_bytes().as_slice() == p.node_id.as_slice());
            let Some(sn) = sn else {
                continue;
            };
            let idx = usize::try_from(p.piece_num).unwrap_or(usize::MAX);
            if idx >= addressed_limits.len() {
                addressed_limits.resize(idx + 1, AddressedOrderLimit::default());
            }
            addressed_limits[idx] = signed_limit(
                identity,
                sn,
                pk,
                p.piece_num,
                &p.piece_id,
                Some(p.piece_id.clone()),
                seg.encrypted_size.max(64 * 1024),
                HashMap::new(),
                PieceAction::Get,
            )?;
        }
    }
    Ok(DownloadSegmentResponse {
        segment_id: obj.stream_id.clone(),
        addressed_limits: if seg.inline_data.is_empty() {
            addressed_limits
        } else {
            Vec::new()
        },
        private_key: piece_key.to_vec(),
        encrypted_inline_data: seg.inline_data.clone(),
        plain_offset,
        plain_size: seg.plain_size,
        segment_size: seg.encrypted_size,
        encrypted_key_nonce: seg.encrypted_key_nonce.clone(),
        encrypted_key: seg.encrypted_key.clone(),
        redundancy_scheme: Some(seg.scheme),
        next,
        position: Some(seg.position),
    })
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

#[allow(clippy::too_many_arguments)]
fn signed_limit(
    satellite: &Identity,
    sn: &MockStorageNode,
    piece_key: &PiecePrivateKey,
    piece_num: i32,
    segment_id: &[u8],
    piece_id: Option<Vec<u8>>,
    limit: i64,
    tags: HashMap<String, Vec<u8>>,
    action: PieceAction,
) -> Result<AddressedOrderLimit, (u64, String)> {
    let now = timestamp(SystemTime::now());
    let piece_id = piece_id.unwrap_or_else(|| {
        let mut id = [0u8; 32];
        id[0] = piece_num as u8;
        if segment_id.len() >= 8 {
            id[1..9].copy_from_slice(&segment_id[..8.min(segment_id.len())]);
        }
        id.to_vec()
    });
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
        piece_id,
        limit: limit.max(1),
        action: action as i32,
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
        tags,
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
