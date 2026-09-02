//! In-process mock satellite: loopback TLS + DRPC unary for ProjectInfo and buckets.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use storj_proto::metainfo::{
    AddressedOrderLimit, BeginCopyObjectRequest, BeginCopyObjectResponse, BeginDeleteObjectRequest,
    BeginDeleteObjectResponse, BeginMoveObjectRequest, BeginMoveObjectResponse, BeginObjectRequest,
    BeginObjectResponse, BeginSegmentRequest, BeginSegmentResponse, Bucket as ProtoBucket,
    BucketListItem, CohortRequirements, CommitObjectRequest, CommitObjectResponse,
    CommitSegmentRequest, CommitSegmentResponse, CompressedBatchRequest, CreateBucketRequest,
    CreateBucketResponse, DeleteBucketRequest, DeleteBucketResponse, DownloadObjectRequest,
    DownloadObjectResponse, DownloadSegmentRequest, DownloadSegmentResponse, EncryptedKeyAndNonce,
    FinishCopyObjectRequest, FinishCopyObjectResponse, FinishDeleteObjectRequest,
    FinishDeleteObjectResponse, FinishMoveObjectRequest, FinishMoveObjectResponse,
    GetBucketRequest, GetBucketResponse, GetObjectRequest, GetObjectResponse, ListBucketsRequest,
    ListBucketsResponse, ListDirection, ListObjectsRequest, ListObjectsResponse,
    ListSegmentsRequest, ListSegmentsResponse, MakeInlineSegmentRequest, MakeInlineSegmentResponse,
    Object as ProtoObject, ObjectListItem, ProjectInfoRequest, ProjectInfoResponse, Range,
    RequestHeader, RetryBeginSegmentPiecesRequest, RetryBeginSegmentPiecesResponse,
    RevokeApiKeyRequest, RevokeApiKeyResponse, SegmentListItem, SegmentPosition,
    UpdateObjectMetadataRequest, UpdateObjectMetadataResponse, batch_request_item,
    batch_response_item, cohort_requirements, object::Status as ObjectStatus, range,
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
}

#[derive(Clone)]
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
    omit_delete_meta: bool,
    revoked: BTreeSet<Vec<u8>>,
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
            omit_delete_meta: false,
            revoked: BTreeSet::new(),
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
        self.access_with_path_cipher(storj_access::CipherSuite::AES_GCM)
    }

    /// Access grant with an explicit default path cipher (e.g. EncNull listing).
    pub fn access_with_path_cipher(&self, path_cipher: storj_access::CipherSuite) -> storj::Access {
        let grant = storj_access::Grant::from_parts(
            self.node_url.clone(),
            self.api_key_raw.clone(),
            storj_access::EncryptionAccess {
                default_key: Some([1u8; 32]),
                default_path_cipher: path_cipher,
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

    /// `BeginDeleteObject` succeeds but omits object metadata (no-read grant).
    pub fn omit_delete_object_metadata(&self) {
        self.state.lock().expect("mock state").omit_delete_meta = true;
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

    /// Insert a committed object at `enc_key` (undecryptable-sibling tests).
    pub fn put_encrypted_object(&self, bucket: &str, enc_key: Vec<u8>) {
        let mut st = self.state.lock().expect("mock state");
        st.next_id += 1;
        let stream_id = st.next_id.to_be_bytes().to_vec();
        st.buckets
            .entry(bucket.to_owned())
            .or_insert_with(|| BucketRec {
                created: SystemTime::now(),
                objects: 0,
            })
            .objects += 1;
        st.committed.insert(
            (bucket.to_owned(), enc_key.clone()),
            CommittedObject {
                object: ProtoObject {
                    bucket: bucket.as_bytes().to_vec(),
                    encrypted_object_key: enc_key,
                    stream_id,
                    status: storj_proto::metainfo::object::Status::CommittedUnversioned as i32,
                    created_at: Some(timestamp(SystemTime::now())),
                    encrypted_metadata: vec![0xFF; 8],
                    encrypted_metadata_nonce: vec![1, 2, 3],
                    encrypted_metadata_encrypted_key: vec![0xAA; 8],
                    ..Default::default()
                },
                segments: Vec::new(),
            },
        );
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
        rpc::REVOKE_API_KEY => {
            let req = RevokeApiKeyRequest::decode(body).map_err(decode_err)?;
            revoke_api_key(req, state)?;
            Ok(RevokeApiKeyResponse {}.encode_to_vec())
        }
        rpc::UPDATE_OBJECT_METADATA => {
            let req = UpdateObjectMetadataRequest::decode(body).map_err(decode_err)?;
            update_object_metadata(req, state)?;
            Ok(UpdateObjectMetadataResponse {}.encode_to_vec())
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
        Some(Request::ObjectGet(req)) => {
            batch_response_item::Response::ObjectGet(get_object(req, state)?)
        }
        Some(Request::ObjectList(req)) => {
            batch_response_item::Response::ObjectList(list_objects(req, state)?)
        }
        Some(Request::ObjectBeginCopy(req)) => {
            batch_response_item::Response::ObjectBeginCopy(begin_copy(req, state)?)
        }
        Some(Request::ObjectFinishCopy(req)) => {
            batch_response_item::Response::ObjectFinishCopy(finish_copy(req, state)?)
        }
        Some(Request::ObjectBeginMove(req)) => {
            batch_response_item::Response::ObjectBeginMove(begin_move(req, state)?)
        }
        Some(Request::ObjectFinishMove(req)) => {
            batch_response_item::Response::ObjectFinishMove(finish_move(req, state)?)
        }
        Some(Request::ObjectUpdateMetadata(req)) => {
            batch_response_item::Response::ObjectUpdateMetadata(update_object_metadata(req, state)?)
        }
        Some(Request::RevokeApiKey(req)) => {
            batch_response_item::Response::RevokeApiKey(revoke_api_key(req, state)?)
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
    if !req.stream_id.is_empty() {
        st.pending.remove(&req.stream_id);
        st.aborted.insert(req.stream_id.clone());
        return Ok(BeginDeleteObjectResponse {
            stream_id: req.stream_id,
            object: None,
        });
    }
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    let rec = st
        .committed
        .remove(&(name.clone(), req.encrypted_object_key.clone()))
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    if let Some(bucket) = st.buckets.get_mut(&name) {
        bucket.objects = bucket.objects.saturating_sub(1);
    }
    let object = if st.omit_delete_meta {
        None
    } else {
        Some(rec.object.clone())
    };
    Ok(BeginDeleteObjectResponse {
        stream_id: rec.object.stream_id,
        object,
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

fn get_object(
    req: GetObjectRequest,
    state: &Mutex<MockState>,
) -> Result<GetObjectResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    let rec = st
        .committed
        .get(&(name, req.encrypted_object_key))
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    Ok(GetObjectResponse {
        object: Some(rec.object.clone()),
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
    let recursive = req.recursive || req.delimiter.is_empty();
    let delim = if recursive {
        None
    } else if req.delimiter.is_empty() {
        Some(b"/".as_slice())
    } else {
        Some(req.delimiter.as_slice())
    };
    let include = req.object_includes.unwrap_or_default();
    let include_custom = req.use_object_includes && include.metadata;
    let include_system = !req.use_object_includes || !include.exclude_system_metadata;

    let mut entries: Vec<(Vec<u8>, Option<CommittedObject>)> = Vec::new();
    let mut prefixes = BTreeSet::new();
    for ((bucket, enc_key), rec) in &st.committed {
        if bucket != &name {
            continue;
        }
        let Some(remainder) =
            strip_list_prefix(enc_key, &req.encrypted_prefix, req.arbitrary_prefix)
        else {
            continue;
        };
        if !req.encrypted_cursor.is_empty()
            && remainder.as_slice() <= req.encrypted_cursor.as_slice()
        {
            continue;
        }
        if let Some(d) = delim {
            if let Some(idx) = remainder.windows(d.len()).position(|w| w == d) {
                let mut prefix_key = remainder[..idx + d.len()].to_vec();
                if prefixes.insert(prefix_key.clone()) {
                    entries.push((std::mem::take(&mut prefix_key), None));
                }
                continue;
            }
        }
        entries.push((
            remainder,
            Some(CommittedObject {
                object: rec.object.clone(),
                segments: rec.segments.clone(),
            }),
        ));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let limit = if req.limit <= 0 {
        1000
    } else {
        req.limit as usize
    };
    let more = entries.len() > limit;
    let items = entries
        .into_iter()
        .take(limit)
        .map(|(remainder, rec)| match rec {
            None => ObjectListItem {
                encrypted_object_key: remainder,
                status: ObjectStatus::Prefix as i32,
                ..Default::default()
            },
            Some(rec) => {
                let mut item = ObjectListItem {
                    encrypted_object_key: remainder,
                    status: rec.object.status,
                    stream_id: rec.object.stream_id.clone(),
                    ..Default::default()
                };
                if include_system {
                    item.created_at = rec.object.created_at;
                    item.expires_at = rec.object.expires_at;
                    item.plain_size = rec.object.plain_size;
                }
                if include_custom {
                    item.encrypted_metadata = rec.object.encrypted_metadata.clone();
                    item.encrypted_metadata_nonce = rec.object.encrypted_metadata_nonce.clone();
                    item.encrypted_metadata_encrypted_key =
                        rec.object.encrypted_metadata_encrypted_key.clone();
                    item.encrypted_etag = rec.object.encrypted_etag.clone();
                }
                item
            }
        })
        .collect();
    Ok(ListObjectsResponse { items, more })
}

fn strip_list_prefix(enc_key: &[u8], prefix: &[u8], arbitrary: bool) -> Option<Vec<u8>> {
    if prefix.is_empty() {
        return Some(enc_key.to_vec());
    }
    if !enc_key.starts_with(prefix) {
        return None;
    }
    let rest = &enc_key[prefix.len()..];
    if arbitrary {
        return Some(rest.to_vec());
    }
    if rest.is_empty() {
        return None;
    }
    if rest[0] == b'/' {
        Some(rest[1..].to_vec())
    } else {
        None
    }
}

fn begin_copy(
    req: BeginCopyObjectRequest,
    state: &Mutex<MockState>,
) -> Result<BeginCopyObjectResponse, (u64, String)> {
    let st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    let dest = utf8_name(&req.new_bucket)?;
    if !st.buckets.contains_key(&dest) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {dest}")));
    }
    let rec = st
        .committed
        .get(&(name, req.encrypted_object_key))
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    Ok(BeginCopyObjectResponse {
        stream_id: rec.object.stream_id.clone(),
        encrypted_metadata_key_nonce: rec.object.encrypted_metadata_nonce.clone(),
        encrypted_metadata_key: rec.object.encrypted_metadata_encrypted_key.clone(),
        segment_keys: rec
            .segments
            .iter()
            .map(|s| EncryptedKeyAndNonce {
                position: Some(s.position),
                encrypted_key_nonce: s.encrypted_key_nonce.clone(),
                encrypted_key: s.encrypted_key.clone(),
            })
            .collect(),
        encryption_parameters: rec.object.encryption_parameters,
        checksum_algorithm: rec.object.checksum_algorithm,
    })
}

fn finish_copy(
    req: FinishCopyObjectRequest,
    state: &Mutex<MockState>,
) -> Result<FinishCopyObjectResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let dest = utf8_name(&req.new_bucket)?;
    if !st.buckets.contains_key(&dest) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {dest}")));
    }
    let src = st
        .committed
        .iter()
        .find(|(_, rec)| rec.object.stream_id == req.stream_id)
        .map(|(_, rec)| rec.clone())
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let dest_obj = apply_relocated(
        &src,
        dest.clone(),
        req.new_encrypted_object_key.clone(),
        &req.new_encrypted_metadata_key,
        &req.new_encrypted_metadata_key_nonce,
        &req.new_segment_keys,
        true,
        &mut st,
    )?;
    Ok(FinishCopyObjectResponse {
        object: Some(dest_obj),
    })
}

fn begin_move(
    req: BeginMoveObjectRequest,
    state: &Mutex<MockState>,
) -> Result<BeginMoveObjectResponse, (u64, String)> {
    let copy = begin_copy(
        BeginCopyObjectRequest {
            header: req.header,
            bucket: req.bucket,
            encrypted_object_key: req.encrypted_object_key,
            new_bucket: req.new_bucket,
            new_encrypted_object_key: req.new_encrypted_object_key,
            object_version: Vec::new(),
        },
        state,
    )?;
    Ok(BeginMoveObjectResponse {
        stream_id: copy.stream_id,
        encrypted_metadata_key_nonce: copy.encrypted_metadata_key_nonce,
        encrypted_metadata_key: copy.encrypted_metadata_key,
        segment_keys: copy.segment_keys,
        encryption_parameters: copy.encryption_parameters,
    })
}

fn finish_move(
    req: FinishMoveObjectRequest,
    state: &Mutex<MockState>,
) -> Result<FinishMoveObjectResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let dest = utf8_name(&req.new_bucket)?;
    if !st.buckets.contains_key(&dest) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {dest}")));
    }
    let src_key = st
        .committed
        .iter()
        .find(|(_, rec)| rec.object.stream_id == req.stream_id)
        .map(|(k, _)| k.clone())
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let src = st
        .committed
        .remove(&src_key)
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    if let Some(bucket) = st.buckets.get_mut(&src_key.0) {
        bucket.objects = bucket.objects.saturating_sub(1);
    }
    apply_relocated(
        &src,
        dest,
        req.new_encrypted_object_key,
        &req.new_encrypted_metadata_key,
        &req.new_encrypted_metadata_key_nonce,
        &req.new_segment_keys,
        false,
        &mut st,
    )?;
    Ok(FinishMoveObjectResponse {})
}

#[allow(clippy::too_many_arguments)]
fn apply_relocated(
    src: &CommittedObject,
    dest_bucket: String,
    dest_enc: Vec<u8>,
    new_meta_key: &[u8],
    new_meta_nonce: &[u8],
    new_segment_keys: &[EncryptedKeyAndNonce],
    new_stream: bool,
    st: &mut MockState,
) -> Result<ProtoObject, (u64, String)> {
    let dest_exists = st
        .committed
        .contains_key(&(dest_bucket.clone(), dest_enc.clone()));
    let mut object = src.object.clone();
    if new_stream {
        st.next_id += 1;
        object.stream_id = st.next_id.to_be_bytes().to_vec();
    }
    object.bucket = dest_bucket.as_bytes().to_vec();
    object.encrypted_object_key = dest_enc.clone();
    if !new_meta_key.is_empty() {
        object.encrypted_metadata_encrypted_key = new_meta_key.to_vec();
        object.encrypted_metadata_nonce = new_meta_nonce.to_vec();
    }
    let mut segments = src.segments.clone();
    for seg in &mut segments {
        if let Some(k) = new_segment_keys.iter().find(|k| {
            k.position.as_ref().is_some_and(|p| {
                p.part_number == seg.position.part_number && p.index == seg.position.index
            })
        }) {
            seg.encrypted_key = k.encrypted_key.clone();
            seg.encrypted_key_nonce = k.encrypted_key_nonce.clone();
        }
    }
    if !dest_exists {
        if let Some(bucket) = st.buckets.get_mut(&dest_bucket) {
            bucket.objects += 1;
        }
    }
    st.committed.insert(
        (dest_bucket, dest_enc),
        CommittedObject {
            object: object.clone(),
            segments,
        },
    );
    Ok(object)
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
    let committed = st
        .committed
        .values()
        .find(|c| c.object.stream_id == req.stream_id)
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    let obj = committed.object.clone();
    let segments = committed.segments.clone();
    drop(st);

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
        encryption_parameters: obj.encryption_parameters,
    })
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
    if key_revoked(got, &state.revoked) {
        return Err((RPC_PERMISSION_DENIED, "permission denied".into()));
    }
    if same_macaroon_head(got, &state.api_key) {
        return Ok(());
    }
    Err((RPC_PERMISSION_DENIED, "permission denied".into()))
}

fn parse_api_key(raw: &[u8]) -> Option<storj_access::ApiKey> {
    storj_access::ApiKey::parse_raw(raw).ok()
}

fn same_macaroon_head(left: &[u8], right: &[u8]) -> bool {
    match (parse_api_key(left), parse_api_key(right)) {
        (Some(a), Some(b)) => a.head() == b.head(),
        _ => left == right,
    }
}

/// `ancestor` is a caveat-chain prefix of `descendant` (same head, ancestor caveats first).
fn caveat_prefix(ancestor: &storj_access::ApiKey, descendant: &storj_access::ApiKey) -> bool {
    ancestor.head() == descendant.head()
        && descendant
            .macaroon()
            .caveats()
            .starts_with(ancestor.macaroon().caveats())
}

fn key_revoked(got: &[u8], revoked: &BTreeSet<Vec<u8>>) -> bool {
    if revoked.iter().any(|k| k.as_slice() == got) {
        return true;
    }
    let Some(presented) = parse_api_key(got) else {
        return false;
    };
    revoked.iter().any(|k| {
        parse_api_key(k).is_some_and(|revoked_key| caveat_prefix(&revoked_key, &presented))
    })
}

/// Only an ancestor may revoke: header caveats must be a strict prefix of the target.
fn can_revoke(header: &[u8], target: &[u8]) -> bool {
    match (parse_api_key(header), parse_api_key(target)) {
        (Some(h), Some(t)) => {
            caveat_prefix(&h, &t) && h.macaroon().caveat_len() < t.macaroon().caveat_len()
        }
        _ => false,
    }
}

fn revoke_api_key(
    req: RevokeApiKeyRequest,
    state: &Mutex<MockState>,
) -> Result<RevokeApiKeyResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let header_key = req
        .header
        .as_ref()
        .map(|h| h.api_key.as_slice())
        .unwrap_or(&[]);
    if req.api_key == header_key {
        return Err((RPC_PERMISSION_DENIED, "API key cannot revoke itself".into()));
    }
    if !can_revoke(header_key, &req.api_key) {
        return Err((RPC_PERMISSION_DENIED, "permission denied".into()));
    }
    st.revoked.insert(req.api_key);
    Ok(RevokeApiKeyResponse {})
}

fn update_object_metadata(
    req: UpdateObjectMetadataRequest,
    state: &Mutex<MockState>,
) -> Result<UpdateObjectMetadataResponse, (u64, String)> {
    let mut st = state.lock().expect("mock state");
    check_key(&req.header, &st)?;
    let name = utf8_name(&req.bucket)?;
    if !st.buckets.contains_key(&name) {
        return Err((RPC_NOT_FOUND, format!("bucket not found: {name}")));
    }
    let rec = st
        .committed
        .get_mut(&(name, req.encrypted_object_key))
        .ok_or_else(|| (RPC_NOT_FOUND, "object not found".into()))?;
    if !req.stream_id.is_empty() && req.stream_id != rec.object.stream_id {
        return Err((RPC_NOT_FOUND, "object not found".into()));
    }
    rec.object.encrypted_metadata = req.encrypted_metadata;
    rec.object.encrypted_metadata_nonce = req.encrypted_metadata_nonce;
    rec.object.encrypted_metadata_encrypted_key = req.encrypted_metadata_encrypted_key;
    if req.set_encrypted_etag {
        rec.object.encrypted_etag = req.encrypted_etag;
    }
    Ok(UpdateObjectMetadataResponse {})
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
