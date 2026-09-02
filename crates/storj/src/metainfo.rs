//! Satellite metainfo client. Auth is protobuf [`storj_proto::RequestHeader`]
//! on every RPC (not DRPC metadata). RPC name is `ProjectInfo`.

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use storj_proto::metainfo::{
    self, BatchRequest, BatchRequestItem, BeginCopyObjectRequest, BeginDeleteObjectRequest,
    BeginMoveObjectRequest, BeginObjectRequest, BeginSegmentRequest, CommitObjectRequest,
    CommitSegmentRequest, CompressedBatchResponse, CreateBucketRequest, DeleteBucketRequest,
    DownloadObjectRequest, DownloadSegmentRequest, FinishCopyObjectRequest,
    FinishMoveObjectRequest, GetBucketObjectLockConfigurationRequest, GetBucketRequest,
    GetObjectLegalHoldRequest, GetObjectRequest, GetObjectRetentionRequest, ListBucketsRequest,
    ListObjectsRequest, ListSegmentsRequest, MakeInlineSegmentRequest, ObjectListItemIncludes,
    ProjectInfoRequest, ProjectInfoResponse, Range, RequestHeader, RetryBeginSegmentPiecesRequest,
    RevokeApiKeyRequest, SegmentPosition, SetBucketObjectLockConfigurationRequest,
    SetObjectLegalHoldRequest, SetObjectRetentionRequest, UpdateObjectMetadataRequest,
    batch_request_item, batch_response_item,
};
use storj_proto::rpc;
use storj_rpc::tls::client_config;
use storj_rpc::{Conn, Identity, NodeUrl, parse_node_url, write_tls_mux_prefix};

use crate::bucket::{bucket_from_list_item, bucket_from_proto, proto_timestamp};
use crate::error::{Error, ErrorKind, Result};
use crate::object_lock::{
    lock_config_from_proto, lock_config_to_proto, retention_from_proto, retention_to_proto,
};
use crate::types::{
    Bucket, BucketObjectLockConfiguration, Config, CustomMetadata, Object, Retention,
    SystemMetadata,
};

use storj_proto::{decode_batch_response, encode_batch_request};

/// gRPC / `rpcstatus` codes as encoded in DRPC `Kind::ERROR` payloads.
pub(crate) const RPC_CANCELED: u64 = 1;
pub(crate) const RPC_INVALID_ARGUMENT: u64 = 3;
pub(crate) const RPC_NOT_FOUND: u64 = 5;
pub(crate) const RPC_ALREADY_EXISTS: u64 = 6;
pub(crate) const RPC_PERMISSION_DENIED: u64 = 7;
pub(crate) const RPC_RESOURCE_EXHAUSTED: u64 = 8;
pub(crate) const RPC_FAILED_PRECONDITION: u64 = 9;
pub(crate) const RPC_UNAVAILABLE: u64 = 14;

/// `rpcstatus.ObjectLockEndpointsDisabled`.
pub(crate) const RPC_OBJECT_LOCK_ENDPOINTS_DISABLED: u64 = 10000;
/// `rpcstatus.ObjectLockDisabledForProject`.
pub(crate) const RPC_OBJECT_LOCK_DISABLED_FOR_PROJECT: u64 = 10001;
/// `rpcstatus.ObjectLockInvalidBucketState`.
pub(crate) const RPC_OBJECT_LOCK_INVALID_BUCKET_STATE: u64 = 10002;
/// `rpcstatus.ObjectLockBucketRetentionConfigurationMissing`.
pub(crate) const RPC_OBJECT_LOCK_BUCKET_CONFIG_MISSING: u64 = 10003;
/// `rpcstatus.ObjectLockObjectRetentionConfigurationMissing`.
pub(crate) const RPC_OBJECT_LOCK_OBJECT_RETENTION_MISSING: u64 = 10004;
/// `rpcstatus.ObjectLockObjectProtected`.
pub(crate) const RPC_OBJECT_LOCK_OBJECT_PROTECTED: u64 = 10005;
/// `rpcstatus.ObjectLockInvalidObjectState`.
pub(crate) const RPC_OBJECT_LOCK_INVALID_OBJECT_STATE: u64 = 10006;
/// `rpcstatus.ObjectLockInvalidBucketRetentionConfiguration`.
pub(crate) const RPC_OBJECT_LOCK_INVALID_BUCKET_CONFIG: u64 = 10007;
/// `rpcstatus.ObjectLockUploadWithTTL`.
pub(crate) const RPC_OBJECT_LOCK_UPLOAD_WITH_TTL: u64 = 10008;
/// `rpcstatus.ObjectLockUploadWithTTLAPIKey`.
pub(crate) const RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_API_KEY: u64 = 10009;
/// `rpcstatus.ObjectLockUploadWithTTLAndDefaultRetention`.
pub(crate) const RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_AND_DEFAULT_RETENTION: u64 = 10010;
/// `rpcstatus.ObjectLockUploadWithTTLAPIKeyAndDefaultRetention`.
pub(crate) const RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_API_KEY_AND_DEFAULT_RETENTION: u64 = 10011;

const RETENTION_NOT_FOUND_MSG: &str = "object has no retention configuration";

const SATELLITE_ATTEMPTS: u32 = 3;
const LIST_BUCKETS_LIMIT: i32 = 1000;
const LIST_OBJECTS_LIMIT: i32 = 1000;

pub(crate) struct ListObjectsParams {
    pub encrypted_prefix: Vec<u8>,
    pub encrypted_cursor: Vec<u8>,
    pub recursive: bool,
    pub include_custom: bool,
    pub include_system: bool,
    pub arbitrary_prefix: bool,
}

type SatelliteStream = TlsStream<TcpStream>;

/// Long-lived satellite metainfo connection (one in-flight RPC at a time).
pub(crate) struct MetainfoClient {
    node: NodeUrl,
    api_key: Vec<u8>,
    user_agent: Vec<u8>,
    identity: Identity,
    dial_timeout: Duration,
    satellite_cert: Mutex<Vec<u8>>,
    conn: Mutex<Option<Conn<SatelliteStream>>>,
}

impl MetainfoClient {
    /// Dial the satellite, pin NodeID, write the TLS mux prefix, complete TLS.
    pub(crate) async fn connect(node: NodeUrl, api_key: Vec<u8>, config: &Config) -> Result<Self> {
        let identity = Identity::generate().map_err(map_identity_err)?;
        let client = Self {
            node,
            api_key,
            user_agent: config
                .user_agent
                .as_deref()
                .unwrap_or("")
                .as_bytes()
                .to_vec(),
            identity,
            dial_timeout: config.dial_timeout_or_default(),
            satellite_cert: Mutex::new(Vec::new()),
            conn: Mutex::new(None),
        };
        client.ensure_connected().await?;
        Ok(client)
    }

    pub(crate) async fn close(&self) {
        *self.conn.lock().await = None;
    }

    #[cfg(test)]
    pub(crate) fn disconnected_placeholder() -> Self {
        Self {
            node: NodeUrl {
                id: storj_rpc::NodeId::ZERO,
                address: "127.0.0.1:1".into(),
            },
            api_key: Vec::new(),
            user_agent: Vec::new(),
            identity: Identity::generate().expect("ephemeral identity"),
            dial_timeout: Duration::from_secs(1),
            satellite_cert: Mutex::new(Vec::new()),
            conn: Mutex::new(None),
        }
    }

    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }

    pub(crate) fn api_key(&self) -> &[u8] {
        &self.api_key
    }

    pub(crate) async fn satellite_cert(&self) -> Vec<u8> {
        self.satellite_cert.lock().await.clone()
    }

    fn header(&self) -> RequestHeader {
        RequestHeader::new(self.api_key.clone(), self.user_agent.clone())
    }

    async fn ensure_connected(&self) -> Result<()> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            *guard = Some(self.dial().await?);
        }
        Ok(())
    }

    async fn dial(&self) -> Result<Conn<SatelliteStream>> {
        let dial = async {
            let mut tcp = TcpStream::connect(&self.node.address).await?;
            let _ = tcp.set_nodelay(true);
            write_tls_mux_prefix(&mut tcp).await?;

            let tls_cfg = client_config(&self.identity, self.node.id).map_err(map_identity_err)?;
            let connector = TlsConnector::from(Arc::new(tls_cfg));
            let server_name = server_name_from_address(&self.node.address)?;
            let tls = connector.connect(server_name, tcp).await?;
            // The satellite signs order limits with its leaf key (Go
            // `SignerFromFullIdentity` uses `FullIdentity.Key`), so keep the
            // leaf (chain[0]), not the CA.
            if let Some(leaf) = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec())
            {
                *self.satellite_cert.lock().await = leaf;
            }
            Ok::<_, Error>(Conn::new(tls))
        };
        tokio::time::timeout(self.dial_timeout, dial)
            .await
            .map_err(|_| Error::new(ErrorKind::Protocol, "satellite dial timed out"))?
    }

    /// Invoke `rpc`, retrying transport failures only when `idempotent`
    /// (design: `CommitSegment`/`CommitObject`/`Begin*` get no automatic retry
    /// because a lost response does not mean the satellite did not apply it).
    async fn invoke(&self, rpc: &str, request: &[u8], bucket: &str, key: &str) -> Result<Vec<u8>> {
        self.invoke_with(rpc, request, bucket, key, is_idempotent_rpc(rpc))
            .await
    }

    async fn invoke_with(
        &self,
        rpc: &str,
        request: &[u8],
        bucket: &str,
        key: &str,
        idempotent: bool,
    ) -> Result<Vec<u8>> {
        let attempts = if idempotent { SATELLITE_ATTEMPTS } else { 1 };
        let mut last_err = None;
        for attempt in 0..attempts {
            match self.invoke_once(rpc, request).await {
                Ok(body) => return Ok(body),
                Err(e) if attempt + 1 < attempts && is_retryable(&e) => {
                    last_err = Some(e);
                    // Exponential backoff with jitter, capped at 2 s.
                    let base = 200 * 2u64.pow(attempt);
                    let jitter = rand::random::<u64>() % (base / 2 + 1);
                    let backoff = Duration::from_millis(base + jitter);
                    tokio::time::sleep(backoff.min(Duration::from_secs(2))).await;
                }
                Err(e) => return Err(map_rpc_error(rpc, e, bucket, key)),
            }
        }
        Err(map_rpc_error(
            rpc,
            last_err.expect("retry loop ran"),
            bucket,
            key,
        ))
    }

    async fn invoke_once(
        &self,
        rpc: &str,
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, storj_rpc::Error> {
        {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                match self.dial().await {
                    Ok(conn) => *guard = Some(conn),
                    Err(e) => {
                        return Err(storj_rpc::Error::Io(std::io::Error::other(e.to_string())));
                    }
                }
            }
            if let Some(conn) = guard.as_mut() {
                match conn.invoke(rpc, request).await {
                    Ok(body) => return Ok(body),
                    Err(e) if is_conn_dead(&e) => {
                        *guard = None;
                        return Err(e);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Err(storj_rpc::Error::Closed)
    }

    pub(crate) async fn project_info(&self) -> Result<ProjectInfoResponse> {
        let req = ProjectInfoRequest {
            header: Some(self.header()),
        };
        let body = self
            .invoke(rpc::PROJECT_INFO, &req.encode_to_vec(), "", "")
            .await?;
        ProjectInfoResponse::decode(body.as_slice()).map_err(map_decode)
    }

    pub(crate) async fn create_bucket(&self, name: &str) -> Result<Bucket> {
        let req = CreateBucketRequest {
            header: Some(self.header()),
            name: name.as_bytes().to_vec(),
            ..Default::default()
        };
        let body = self
            .invoke(rpc::CREATE_BUCKET, &req.encode_to_vec(), name, "")
            .await?;
        let resp = metainfo::CreateBucketResponse::decode(body.as_slice()).map_err(map_decode)?;
        bucket_from_proto(resp.bucket, name)
    }

    pub(crate) async fn get_bucket(&self, name: &str) -> Result<Bucket> {
        let req = GetBucketRequest {
            header: Some(self.header()),
            name: name.as_bytes().to_vec(),
        };
        let body = self
            .invoke(rpc::GET_BUCKET, &req.encode_to_vec(), name, "")
            .await?;
        let resp = metainfo::GetBucketResponse::decode(body.as_slice()).map_err(map_decode)?;
        bucket_from_proto(resp.bucket, name)
    }

    pub(crate) async fn delete_bucket(&self, name: &str, delete_all: bool) -> Result<Bucket> {
        let req = DeleteBucketRequest {
            header: Some(self.header()),
            name: name.as_bytes().to_vec(),
            delete_all,
            bypass_governance_retention: false,
        };
        let body = self
            .invoke(rpc::DELETE_BUCKET, &req.encode_to_vec(), name, "")
            .await?;
        let resp = metainfo::DeleteBucketResponse::decode(body.as_slice()).map_err(map_decode)?;
        match resp.bucket {
            Some(b) if !b.name.is_empty() => bucket_from_proto(Some(b), name),
            _ => Ok(Bucket {
                name: name.to_owned(),
                created: proto_timestamp(None),
            }),
        }
    }

    pub(crate) async fn list_buckets_page(
        &self,
        cursor: &str,
        limit: i32,
    ) -> Result<(Vec<Bucket>, bool)> {
        let req = ListBucketsRequest {
            header: Some(self.header()),
            cursor: cursor.as_bytes().to_vec(),
            limit: if limit == 0 {
                LIST_BUCKETS_LIMIT
            } else {
                limit
            },
            direction: metainfo::ListDirection::After as i32,
        };
        let body = self
            .invoke(rpc::LIST_BUCKETS, &req.encode_to_vec(), "", "")
            .await?;
        let resp = metainfo::ListBucketsResponse::decode(body.as_slice()).map_err(map_decode)?;
        let items = resp
            .items
            .into_iter()
            .map(bucket_from_list_item)
            .collect::<Result<Vec<_>>>()?;
        Ok((items, resp.more))
    }

    async fn compressed_batch(
        &self,
        requests: Vec<BatchRequestItem>,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<batch_response_item::Response>> {
        let batch = BatchRequest {
            header: Some(self.header()),
            requests,
        };
        let idempotent = batch.requests.iter().all(is_idempotent_batch_item);
        let wrapped = encode_batch_request(&batch);
        let body = self
            .invoke_with(
                rpc::COMPRESSED_BATCH,
                &wrapped.encode_to_vec(),
                bucket,
                key,
                idempotent,
            )
            .await?;
        let resp = CompressedBatchResponse::decode(body.as_slice()).map_err(map_decode)?;
        let decoded = decode_batch_response(&resp)
            .map_err(|e| Error::new(ErrorKind::Protocol, format!("CompressedBatch: {e}")))?;
        decoded
            .responses
            .into_iter()
            .map(|item| {
                item.response.ok_or_else(|| {
                    Error::new(ErrorKind::Protocol, "empty CompressedBatch response item")
                })
            })
            .collect()
    }

    fn expect_one(
        mut items: Vec<batch_response_item::Response>,
        what: &str,
    ) -> Result<batch_response_item::Response> {
        if items.len() != 1 {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("{what}: expected 1 batch response, got {}", items.len()),
            ));
        }
        Ok(items.remove(0))
    }

    pub(crate) async fn begin_object(
        &self,
        bucket: &str,
        encrypted_object_key: Vec<u8>,
        expires: Option<std::time::SystemTime>,
        encryption_parameters: Option<storj_proto::encryption::EncryptionParameters>,
    ) -> Result<metainfo::BeginObjectResponse> {
        let req = BeginObjectRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key,
            expires_at: expires.map(system_time_to_proto),
            encryption_parameters,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectBegin(req)),
                }],
                bucket,
                "",
            )
            .await?;
        match Self::expect_one(items, "BeginObject")? {
            batch_response_item::Response::ObjectBegin(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected BeginObject response",
            )),
        }
    }

    pub(crate) async fn commit_object(
        &self,
        bucket: &str,
        key: &str,
        stream_id: Vec<u8>,
        user: storj_uplink::upload::EncryptedUserData,
    ) -> Result<metainfo::CommitObjectResponse> {
        let req = CommitObjectRequest {
            header: Some(self.header()),
            stream_id,
            encrypted_metadata: user.encrypted_metadata,
            encrypted_metadata_nonce: user.encrypted_metadata_nonce.to_vec(),
            encrypted_metadata_encrypted_key: user.encrypted_metadata_encrypted_key,
            encrypted_etag: user.encrypted_etag,
            skip_override_encrypted_metadata: false,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectCommit(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "CommitObject")? {
            batch_response_item::Response::ObjectCommit(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected CommitObject response",
            )),
        }
    }

    pub(crate) async fn begin_segment(
        &self,
        bucket: &str,
        key: &str,
        stream_id: Vec<u8>,
        position: SegmentPosition,
        max_order_limit: i64,
    ) -> Result<metainfo::BeginSegmentResponse> {
        let req = BeginSegmentRequest {
            header: Some(self.header()),
            stream_id,
            position: Some(position),
            max_order_limit,
            lite_request: false,
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::SegmentBegin(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "BeginSegment")? {
            batch_response_item::Response::SegmentBegin(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected BeginSegment response",
            )),
        }
    }

    pub(crate) async fn retry_begin_segment_pieces(
        &self,
        bucket: &str,
        key: &str,
        segment_id: Vec<u8>,
        retry_piece_numbers: Vec<i32>,
    ) -> Result<metainfo::RetryBeginSegmentPiecesResponse> {
        let req = RetryBeginSegmentPiecesRequest {
            header: Some(self.header()),
            segment_id,
            retry_piece_numbers,
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::SegmentBeginRetryPieces(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "RetryBeginSegmentPieces")? {
            batch_response_item::Response::SegmentBeginRetryPieces(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected RetryBeginSegmentPieces response",
            )),
        }
    }

    pub(crate) async fn commit_segment(
        &self,
        bucket: &str,
        key: &str,
        req: CommitSegmentRequest,
    ) -> Result<metainfo::CommitSegmentResponse> {
        let mut req = req;
        req.header = Some(self.header());
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::SegmentCommit(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "CommitSegment")? {
            batch_response_item::Response::SegmentCommit(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected CommitSegment response",
            )),
        }
    }

    pub(crate) async fn make_inline_segment(
        &self,
        bucket: &str,
        key: &str,
        req: MakeInlineSegmentRequest,
    ) -> Result<()> {
        let mut req = req;
        req.header = Some(self.header());
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::SegmentMakeInline(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "MakeInlineSegment")? {
            batch_response_item::Response::SegmentMakeInline(_) => Ok(()),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected MakeInlineSegment response",
            )),
        }
    }

    pub(crate) async fn download_object(
        &self,
        bucket: &str,
        key: &str,
        encrypted_object_key: Vec<u8>,
        range: Option<Range>,
    ) -> Result<metainfo::DownloadObjectResponse> {
        let req = DownloadObjectRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key,
            range,
            limit: 0,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectDownload(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "DownloadObject")? {
            batch_response_item::Response::ObjectDownload(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected DownloadObject response",
            )),
        }
    }

    pub(crate) async fn download_segment(
        &self,
        bucket: &str,
        key: &str,
        stream_id: Vec<u8>,
        position: SegmentPosition,
    ) -> Result<metainfo::DownloadSegmentResponse> {
        let req = DownloadSegmentRequest {
            header: Some(self.header()),
            stream_id,
            cursor_position: Some(position),
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::SegmentDownload(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "DownloadSegment")? {
            batch_response_item::Response::SegmentDownload(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected DownloadSegment response",
            )),
        }
    }

    pub(crate) async fn list_segments(
        &self,
        bucket: &str,
        key: &str,
        stream_id: Vec<u8>,
        cursor: Option<SegmentPosition>,
        range: Option<Range>,
    ) -> Result<metainfo::ListSegmentsResponse> {
        let req = ListSegmentsRequest {
            header: Some(self.header()),
            stream_id,
            cursor_position: cursor,
            limit: 0,
            range,
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::SegmentList(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "ListSegments")? {
            batch_response_item::Response::SegmentList(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected ListSegments response",
            )),
        }
    }

    pub(crate) async fn list_all_segments(
        &self,
        bucket: &str,
        key: &str,
        stream_id: Vec<u8>,
    ) -> Result<metainfo::ListSegmentsResponse> {
        let mut out = self
            .list_segments(bucket, key, stream_id.clone(), None, None)
            .await?;
        while out.more {
            let cursor = out.items.last().and_then(|i| i.position);
            let page = self
                .list_segments(bucket, key, stream_id.clone(), cursor, None)
                .await?;
            if page.items.is_empty() {
                break;
            }
            out.more = page.more;
            if out.encryption_parameters.is_none() {
                out.encryption_parameters = page.encryption_parameters;
            }
            out.items.extend(page.items);
        }
        Ok(out)
    }

    pub(crate) async fn list_pending_uploads(
        &self,
        bucket: &str,
        encrypted_prefix: Vec<u8>,
        encrypted_cursor: Vec<u8>,
        arbitrary_prefix: bool,
        opts: &crate::types::ListUploadsOptions,
    ) -> Result<metainfo::ListObjectsResponse> {
        let req = ListObjectsRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            delimiter: if opts.recursive {
                Vec::new()
            } else {
                b"/".to_vec()
            },
            encrypted_prefix,
            encrypted_cursor,
            arbitrary_prefix,
            recursive: opts.recursive,
            limit: 0,
            status: metainfo::object::Status::Uploading as i32,
            object_includes: Some(metainfo::ObjectListItemIncludes {
                metadata: opts.custom,
                exclude_system_metadata: !opts.system,
                ..Default::default()
            }),
            use_object_includes: true,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectList(req)),
                }],
                bucket,
                "",
            )
            .await?;
        match Self::expect_one(items, "ListObjects")? {
            batch_response_item::Response::ObjectList(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected ListObjects response",
            )),
        }
    }

    pub(crate) async fn begin_delete_object(
        &self,
        bucket: &str,
        encrypted_object_key: Vec<u8>,
        stream_id: Vec<u8>,
        status: i32,
    ) -> Result<metainfo::BeginDeleteObjectResponse> {
        let req = BeginDeleteObjectRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key,
            stream_id,
            status,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectBeginDelete(req)),
                }],
                bucket,
                "",
            )
            .await?;
        match Self::expect_one(items, "BeginDeleteObject")? {
            batch_response_item::Response::ObjectBeginDelete(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected BeginDeleteObject response",
            )),
        }
    }

    pub(crate) async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        encrypted_object_key: Vec<u8>,
    ) -> Result<metainfo::GetObjectResponse> {
        let req = GetObjectRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key,
            redundancy_scheme_per_segment: true,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectGet(req)),
                }],
                bucket,
                key,
            )
            .await?;
        match Self::expect_one(items, "GetObject")? {
            batch_response_item::Response::ObjectGet(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected GetObject response",
            )),
        }
    }

    pub(crate) async fn list_objects(
        &self,
        bucket: &str,
        params: ListObjectsParams,
    ) -> Result<metainfo::ListObjectsResponse> {
        let req = ListObjectsRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            delimiter: if params.recursive {
                Vec::new()
            } else {
                b"/".to_vec()
            },
            encrypted_prefix: params.encrypted_prefix,
            encrypted_cursor: params.encrypted_cursor,
            recursive: params.recursive,
            limit: LIST_OBJECTS_LIMIT,
            object_includes: Some(ObjectListItemIncludes {
                metadata: params.include_custom,
                exclude_system_metadata: !params.include_system,
                ..Default::default()
            }),
            use_object_includes: true,
            arbitrary_prefix: params.arbitrary_prefix,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectList(req)),
                }],
                bucket,
                "",
            )
            .await?;
        match Self::expect_one(items, "ListObjects")? {
            batch_response_item::Response::ObjectList(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected ListObjects response",
            )),
        }
    }

    pub(crate) async fn begin_copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        encrypted_object_key: Vec<u8>,
        new_bucket: &str,
        new_encrypted_object_key: Vec<u8>,
    ) -> Result<metainfo::BeginCopyObjectResponse> {
        let req = BeginCopyObjectRequest {
            header: Some(self.header()),
            bucket: src_bucket.as_bytes().to_vec(),
            encrypted_object_key,
            new_bucket: new_bucket.as_bytes().to_vec(),
            new_encrypted_object_key,
            ..Default::default()
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectBeginCopy(req)),
                }],
                src_bucket,
                src_key,
            )
            .await?;
        match Self::expect_one(items, "BeginCopyObject")? {
            batch_response_item::Response::ObjectBeginCopy(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected BeginCopyObject response",
            )),
        }
    }

    pub(crate) async fn finish_copy_object(
        &self,
        dst_bucket: &str,
        dst_key: &str,
        mut req: FinishCopyObjectRequest,
    ) -> Result<metainfo::FinishCopyObjectResponse> {
        req.header = Some(self.header());
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectFinishCopy(req)),
                }],
                dst_bucket,
                dst_key,
            )
            .await?;
        match Self::expect_one(items, "FinishCopyObject")? {
            batch_response_item::Response::ObjectFinishCopy(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected FinishCopyObject response",
            )),
        }
    }

    pub(crate) async fn begin_move_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        encrypted_object_key: Vec<u8>,
        new_bucket: &str,
        new_encrypted_object_key: Vec<u8>,
    ) -> Result<metainfo::BeginMoveObjectResponse> {
        let req = BeginMoveObjectRequest {
            header: Some(self.header()),
            bucket: src_bucket.as_bytes().to_vec(),
            encrypted_object_key,
            new_bucket: new_bucket.as_bytes().to_vec(),
            new_encrypted_object_key,
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectBeginMove(req)),
                }],
                src_bucket,
                src_key,
            )
            .await?;
        match Self::expect_one(items, "BeginMoveObject")? {
            batch_response_item::Response::ObjectBeginMove(r) => Ok(r),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected BeginMoveObject response",
            )),
        }
    }

    pub(crate) async fn finish_move_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        mut req: FinishMoveObjectRequest,
    ) -> Result<()> {
        req.header = Some(self.header());
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectFinishMove(req)),
                }],
                src_bucket,
                src_key,
            )
            .await?;
        match Self::expect_one(items, "FinishMoveObject")? {
            batch_response_item::Response::ObjectFinishMove(_) => Ok(()),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected FinishMoveObject response",
            )),
        }
    }

    pub(crate) async fn update_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        encrypted_object_key: Vec<u8>,
        stream_id: Vec<u8>,
        user: storj_uplink::upload::EncryptedUserData,
    ) -> Result<()> {
        let req = UpdateObjectMetadataRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key,
            stream_id,
            encrypted_metadata: user.encrypted_metadata,
            encrypted_metadata_nonce: user.encrypted_metadata_nonce.to_vec(),
            encrypted_metadata_encrypted_key: user.encrypted_metadata_encrypted_key,
            encrypted_etag: user.encrypted_etag,
            set_encrypted_etag: false,
            ..Default::default()
        };
        let body = self
            .invoke(
                rpc::UPDATE_OBJECT_METADATA,
                &req.encode_to_vec(),
                bucket,
                key,
            )
            .await?;
        let _ =
            metainfo::UpdateObjectMetadataResponse::decode(body.as_slice()).map_err(map_decode)?;
        Ok(())
    }

    pub(crate) async fn revoke_api_key(&self, api_key: Vec<u8>) -> Result<()> {
        let req = RevokeApiKeyRequest {
            header: Some(self.header()),
            api_key,
        };
        let body = self
            .invoke(rpc::REVOKE_API_KEY, &req.encode_to_vec(), "", "")
            .await?;
        let _ = metainfo::RevokeApiKeyResponse::decode(body.as_slice()).map_err(map_decode)?;
        Ok(())
    }

    pub(crate) async fn get_object_retention(
        &self,
        bucket: &str,
        encrypted_object_key: &[u8],
        object_version: &[u8],
        key: &str,
    ) -> Result<Option<Retention>> {
        let req = GetObjectRetentionRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key: encrypted_object_key.to_vec(),
            object_version: object_version.to_vec(),
        };
        match self
            .invoke(rpc::GET_OBJECT_RETENTION, &req.encode_to_vec(), bucket, key)
            .await
        {
            Ok(body) => {
                let resp = metainfo::GetObjectRetentionResponse::decode(body.as_slice())
                    .map_err(map_decode)?;
                match resp.retention {
                    Some(r) => Ok(Some(retention_from_proto(r)?)),
                    None => Ok(None),
                }
            }
            Err(e) if is_retention_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn set_object_retention(
        &self,
        bucket: &str,
        encrypted_object_key: &[u8],
        object_version: &[u8],
        retention: &Retention,
        bypass_governance_retention: bool,
        key: &str,
    ) -> Result<()> {
        let req = SetObjectRetentionRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key: encrypted_object_key.to_vec(),
            object_version: object_version.to_vec(),
            retention: Some(retention_to_proto(retention)),
            bypass_governance_retention,
        };
        self.invoke(rpc::SET_OBJECT_RETENTION, &req.encode_to_vec(), bucket, key)
            .await?;
        Ok(())
    }

    pub(crate) async fn get_object_legal_hold(
        &self,
        bucket: &str,
        encrypted_object_key: &[u8],
        object_version: &[u8],
        key: &str,
    ) -> Result<bool> {
        let req = GetObjectLegalHoldRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key: encrypted_object_key.to_vec(),
            object_version: object_version.to_vec(),
        };
        let body = self
            .invoke(
                rpc::GET_OBJECT_LEGAL_HOLD,
                &req.encode_to_vec(),
                bucket,
                key,
            )
            .await?;
        let resp =
            metainfo::GetObjectLegalHoldResponse::decode(body.as_slice()).map_err(map_decode)?;
        Ok(resp.enabled)
    }

    pub(crate) async fn set_object_legal_hold(
        &self,
        bucket: &str,
        encrypted_object_key: &[u8],
        object_version: &[u8],
        enabled: bool,
        key: &str,
    ) -> Result<()> {
        let req = SetObjectLegalHoldRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key: encrypted_object_key.to_vec(),
            object_version: object_version.to_vec(),
            enabled,
        };
        self.invoke(
            rpc::SET_OBJECT_LEGAL_HOLD,
            &req.encode_to_vec(),
            bucket,
            key,
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn get_bucket_object_lock_configuration(
        &self,
        bucket: &str,
    ) -> Result<BucketObjectLockConfiguration> {
        let req = GetBucketObjectLockConfigurationRequest {
            header: Some(self.header()),
            name: bucket.as_bytes().to_vec(),
        };
        let body = self
            .invoke(
                rpc::GET_BUCKET_OBJECT_LOCK_CONFIGURATION,
                &req.encode_to_vec(),
                bucket,
                "",
            )
            .await?;
        let resp = metainfo::GetBucketObjectLockConfigurationResponse::decode(body.as_slice())
            .map_err(map_decode)?;
        let Some(cfg) = resp.configuration else {
            return Err(Error::new(
                ErrorKind::Protocol,
                "satellite returned no Object Lock configuration",
            ));
        };
        lock_config_from_proto(cfg)
    }

    pub(crate) async fn set_bucket_object_lock_configuration(
        &self,
        bucket: &str,
        config: &BucketObjectLockConfiguration,
    ) -> Result<()> {
        let req = SetBucketObjectLockConfigurationRequest {
            header: Some(self.header()),
            name: bucket.as_bytes().to_vec(),
            configuration: Some(lock_config_to_proto(config)),
        };
        self.invoke(
            rpc::SET_BUCKET_OBJECT_LOCK_CONFIGURATION,
            &req.encode_to_vec(),
            bucket,
            "",
        )
        .await?;
        Ok(())
    }
}

fn system_time_to_proto(t: std::time::SystemTime) -> prost_types::Timestamp {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    prost_types::Timestamp {
        seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos() as i32,
    }
}

pub(crate) fn object_from_proto(pb: Option<metainfo::Object>, plaintext_key: &str) -> Object {
    let (created, expires, content_length, version) = match &pb {
        Some(o) => (
            o.created_at.map(|t| proto_timestamp(Some(t))),
            o.expires_at.map(|t| proto_timestamp(Some(t))),
            o.plain_size,
            o.object_version.clone(),
        ),
        None => (None, None, 0, Vec::new()),
    };
    Object {
        key: plaintext_key.to_owned(),
        is_prefix: false,
        version,
        system: SystemMetadata {
            created,
            expires,
            content_length,
        },
        custom: CustomMetadata::new(),
    }
}

fn server_name_from_address(address: &str) -> Result<ServerName<'static>> {
    let host = host_from_address(address);
    ServerName::try_from(host.to_string()).map_err(|e| {
        Error::new(
            ErrorKind::Protocol,
            format!("invalid satellite host {host:?}: {e}"),
        )
    })
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

/// Unary RPCs that are safe to re-send after a lost response.
fn is_idempotent_rpc(rpc: &str) -> bool {
    matches!(
        rpc,
        rpc::PROJECT_INFO
            | rpc::GET_BUCKET
            | rpc::LIST_BUCKETS
            | rpc::GET_OBJECT_RETENTION
            | rpc::GET_OBJECT_LEGAL_HOLD
            | rpc::GET_BUCKET_OBJECT_LOCK_CONFIGURATION
    )
}

/// Batch items that are safe to re-send after a lost response: reads and
/// listings. `Begin*`, `Commit*`, `MakeInline`, `Delete`, `Finish{Copy,Move}`
/// and `RetryBeginSegmentPieces` mutate satellite state and are never retried.
fn is_idempotent_batch_item(item: &BatchRequestItem) -> bool {
    use batch_request_item::Request as R;
    matches!(
        item.request,
        Some(
            R::BucketGet(_)
                | R::BucketList(_)
                | R::ObjectGet(_)
                | R::ObjectList(_)
                | R::ObjectDownload(_)
                | R::SegmentDownload(_)
                | R::SegmentList(_)
        )
    )
}

fn is_retryable(err: &storj_rpc::Error) -> bool {
    match err {
        storj_rpc::Error::Io(_)
        | storj_rpc::Error::Truncated
        | storj_rpc::Error::Closed
        | storj_rpc::Error::MuxPrefix { .. } => true,
        storj_rpc::Error::Remote { code, message } => {
            *code == RPC_UNAVAILABLE
                || (*code == RPC_RESOURCE_EXHAUSTED && message.contains("Too Many Requests"))
        }
        _ => false,
    }
}

fn is_conn_dead(err: &storj_rpc::Error) -> bool {
    matches!(
        err,
        storj_rpc::Error::Io(_)
            | storj_rpc::Error::Truncated
            | storj_rpc::Error::Closed
            | storj_rpc::Error::MuxPrefix { .. }
    )
}

fn map_decode(e: prost::DecodeError) -> Error {
    Error::new(ErrorKind::Protocol, format!("metainfo decode: {e}")).with_source(e)
}

pub(crate) fn map_identity_err(e: storj_rpc::IdentityError) -> Error {
    match e {
        storj_rpc::IdentityError::NodeIdRequired
        | storj_rpc::IdentityError::NodeId
        | storj_rpc::IdentityError::NodeUrl(_) => {
            Error::new(ErrorKind::InvalidGrant, e.to_string()).with_source(e)
        }
        storj_rpc::IdentityError::Certificate(_) | storj_rpc::IdentityError::Signature => {
            Error::new(ErrorKind::Protocol, e.to_string()).with_source(e)
        }
    }
}

pub(crate) fn parse_satellite_url(address: &str) -> Result<NodeUrl> {
    parse_node_url(address).map_err(map_identity_err)
}

pub(crate) fn map_rpc_error(rpc: &str, err: storj_rpc::Error, bucket: &str, key: &str) -> Error {
    match err {
        storj_rpc::Error::Remote { code, message } => map_remote(rpc, code, &message, bucket, key),
        storj_rpc::Error::Io(e) => Error::from(e),
        other => Error::new(ErrorKind::Protocol, other.to_string()).with_source(other),
    }
}

/// gRPC code 16.
const RPC_UNAUTHENTICATED: u64 = 16;

/// Map a satellite error the way Go uplink's `convertKnownErrors` plus its
/// per-call-site checks do: generic codes are only turned into bucket/object
/// kinds when the RPC (or the satellite's message) says so, never merely
/// because a bucket or key happened to be in scope.
fn map_remote(rpc: &str, code: u64, message: &str, bucket: &str, key: &str) -> Error {
    let lower = message.to_ascii_lowercase();
    match code {
        RPC_CANCELED => Error::new(ErrorKind::Canceled, message),
        // Go: CreateBucket maps InvalidArgument to ErrBucketNameInvalid.
        RPC_INVALID_ARGUMENT if rpc == rpc::CREATE_BUCKET || lower.contains("bucket name") => {
            Error::new(
                ErrorKind::BucketNameInvalid,
                format!("bucket name invalid ({bucket:?})"),
            )
        }
        RPC_INVALID_ARGUMENT
            if !key.is_empty()
                && (lower.contains("object key") || lower.contains("encrypted path")) =>
        {
            Error::new(
                ErrorKind::ObjectKeyInvalid,
                format!("object key invalid ({key:?})"),
            )
        }
        RPC_INVALID_ARGUMENT => Error::new(ErrorKind::Protocol, message),
        RPC_NOT_FOUND => {
            if lower.starts_with("bucket not found") {
                let name = bucket_from_not_found(message).unwrap_or(bucket);
                Error::new(
                    ErrorKind::BucketNotFound,
                    format!("bucket not found ({name:?})"),
                )
            } else if lower.starts_with("object not found") {
                Error::new(
                    ErrorKind::ObjectNotFound,
                    format!("object not found ({key:?})"),
                )
            } else if rpc == rpc::GET_BUCKET || rpc == rpc::DELETE_BUCKET {
                Error::new(
                    ErrorKind::BucketNotFound,
                    format!("bucket not found ({bucket:?})"),
                )
            } else {
                Error::new(ErrorKind::Protocol, message)
            }
        }
        RPC_ALREADY_EXISTS => Error::new(
            ErrorKind::BucketAlreadyExists,
            format!("bucket already exists ({bucket:?})"),
        ),
        RPC_PERMISSION_DENIED => Error::new(
            ErrorKind::PermissionDenied,
            format!("permission denied ({message})"),
        ),
        RPC_RESOURCE_EXHAUSTED => {
            if message.ends_with("Exceeded Usage Limit") {
                Error::new(ErrorKind::BandwidthLimitExceeded, message)
            } else if message.ends_with("Too Many Requests") {
                Error::new(ErrorKind::TooManyRequests, message)
            } else if message.contains("Exceeded Storage Limit") {
                Error::new(ErrorKind::StorageLimitExceeded, message)
            } else if message.contains("Exceeded Segments Limit") {
                Error::new(ErrorKind::SegmentsLimitExceeded, message)
            } else {
                Error::new(ErrorKind::Protocol, message)
            }
        }
        // Go: only DeleteBucket maps FailedPrecondition to ErrBucketNotEmpty.
        RPC_FAILED_PRECONDITION if rpc == rpc::DELETE_BUCKET || lower.contains("not empty") => {
            Error::new(
                ErrorKind::BucketNotEmpty,
                format!("bucket not empty ({bucket:?})"),
            )
        }
        RPC_UNAUTHENTICATED => Error::new(
            ErrorKind::PermissionDenied,
            format!("permission denied ({message})"),
        ),
        RPC_OBJECT_LOCK_ENDPOINTS_DISABLED => {
            Error::new(ErrorKind::Protocol, "object lock is not enabled")
        }
        RPC_OBJECT_LOCK_DISABLED_FOR_PROJECT => Error::new(
            ErrorKind::Protocol,
            "object lock is not enabled for this project",
        ),
        RPC_OBJECT_LOCK_INVALID_BUCKET_STATE => Error::new(
            ErrorKind::Protocol,
            "object lock requires bucket versioning to be enabled",
        ),
        RPC_OBJECT_LOCK_BUCKET_CONFIG_MISSING => Error::new(
            ErrorKind::Protocol,
            "object lock is not enabled for this bucket",
        ),
        RPC_OBJECT_LOCK_OBJECT_RETENTION_MISSING => {
            Error::new(ErrorKind::Protocol, RETENTION_NOT_FOUND_MSG)
        }
        RPC_OBJECT_LOCK_OBJECT_PROTECTED => Error::new(
            ErrorKind::Protocol,
            "object is protected by Object Lock settings",
        ),
        RPC_OBJECT_LOCK_INVALID_OBJECT_STATE => Error::new(
            ErrorKind::Protocol,
            "object state is invalid for Object Lock",
        ),
        RPC_OBJECT_LOCK_INVALID_BUCKET_CONFIG => Error::new(
            ErrorKind::Protocol,
            "bucket object lock configuration is invalid",
        ),
        RPC_OBJECT_LOCK_UPLOAD_WITH_TTL => Error::new(
            ErrorKind::Protocol,
            "cannot specify an object expiration time when uploading into an Object Lock enabled bucket",
        ),
        RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_API_KEY => Error::new(
            ErrorKind::Protocol,
            "cannot upload into an Object Lock enabled bucket using an API key that enforces an object expiration time",
        ),
        RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_AND_DEFAULT_RETENTION => Error::new(
            ErrorKind::Protocol,
            "cannot specify an object expiration time when uploading into a bucket with default retention settings",
        ),
        RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_API_KEY_AND_DEFAULT_RETENTION => Error::new(
            ErrorKind::Protocol,
            "cannot upload into a bucket with default retention settings using an API key that enforces an object expiration time",
        ),
        _ => Error::new(
            ErrorKind::Protocol,
            format!("DRPC remote error (code {code}): {message}"),
        ),
    }
}

fn is_retention_not_found(err: &Error) -> bool {
    err.kind() == ErrorKind::Protocol && err.to_string().ends_with(RETENTION_NOT_FOUND_MSG)
}

fn bucket_from_not_found(message: &str) -> Option<&str> {
    const PREFIX: &str = "bucket not found";
    message
        .strip_prefix(PREFIX)
        .map(|rest| rest.trim_start_matches([':', ' ']))
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_ipv4_and_name() {
        assert_eq!(host_from_address("127.0.0.1:7777"), "127.0.0.1");
        assert_eq!(host_from_address("us1.storj.io:7777"), "us1.storj.io");
        assert_eq!(host_from_address("[::1]:7777"), "::1");
    }

    #[test]
    fn remote_not_found_is_bucket() {
        let e = map_remote("", RPC_NOT_FOUND, "bucket not found: logs", "logs", "");
        assert_eq!(e.kind(), ErrorKind::BucketNotFound);
        assert!(e.to_string().contains("logs"));
    }

    #[test]
    fn remote_already_exists() {
        let e = map_remote("", RPC_ALREADY_EXISTS, "exists", "photos", "");
        assert_eq!(e.kind(), ErrorKind::BucketAlreadyExists);
        assert!(e.to_string().contains("photos"));
    }

    #[test]
    fn remote_failed_precondition_not_empty() {
        let e = map_remote("", RPC_FAILED_PRECONDITION, "not empty", "b", "");
        assert_eq!(e.kind(), ErrorKind::BucketNotEmpty);
    }

    #[test]
    fn remote_resource_exhausted_kinds() {
        assert_eq!(
            map_remote("", RPC_RESOURCE_EXHAUSTED, "Exceeded Usage Limit", "", "").kind(),
            ErrorKind::BandwidthLimitExceeded
        );
        assert_eq!(
            map_remote("", RPC_RESOURCE_EXHAUSTED, "Too Many Requests", "", "").kind(),
            ErrorKind::TooManyRequests
        );
        assert_eq!(
            map_remote(
                "",
                RPC_RESOURCE_EXHAUSTED,
                "project Exceeded Storage Limit",
                "",
                ""
            )
            .kind(),
            ErrorKind::StorageLimitExceeded
        );
        assert_eq!(
            map_remote(
                "",
                RPC_RESOURCE_EXHAUSTED,
                "project Exceeded Segments Limit",
                "",
                ""
            )
            .kind(),
            ErrorKind::SegmentsLimitExceeded
        );
    }

    #[test]
    fn node_id_required_is_invalid_grant() {
        let e = parse_satellite_url("us1.storj.io:7777").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidGrant);
        assert!(
            e.to_string()
                .contains("node id is required in satelliteNodeURL")
        );
    }

    #[test]
    fn known_tardigrade_fills_id() {
        let url = parse_satellite_url("us-central-1.tardigrade.io:7777").unwrap();
        assert_eq!(
            url.id.to_string(),
            "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S"
        );
    }

    #[test]
    fn object_lock_rpc_codes() {
        assert_eq!(
            map_remote("", RPC_OBJECT_LOCK_OBJECT_RETENTION_MISSING, "", "b", "k").kind(),
            ErrorKind::Protocol
        );
        let e = map_remote("", RPC_OBJECT_LOCK_OBJECT_RETENTION_MISSING, "", "b", "k");
        assert!(is_retention_not_found(&e), "{e}");
        assert_eq!(
            map_remote("", RPC_OBJECT_LOCK_BUCKET_CONFIG_MISSING, "", "b", "").to_string(),
            "protocol: object lock is not enabled for this bucket"
        );
        assert_eq!(
            map_remote("", RPC_OBJECT_LOCK_INVALID_BUCKET_CONFIG, "", "b", "").kind(),
            ErrorKind::Protocol
        );
        assert_eq!(
            map_remote("", RPC_OBJECT_LOCK_OBJECT_PROTECTED, "", "b", "k").kind(),
            ErrorKind::Protocol
        );
        assert_eq!(
            map_remote("", RPC_OBJECT_LOCK_UPLOAD_WITH_TTL, "", "b", "k").to_string(),
            "protocol: cannot specify an object expiration time when uploading into an Object Lock enabled bucket"
        );
        assert_eq!(
            map_remote("", RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_API_KEY, "", "b", "k").to_string(),
            "protocol: cannot upload into an Object Lock enabled bucket using an API key that enforces an object expiration time"
        );
        assert_eq!(
            map_remote(
                "",
                RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_AND_DEFAULT_RETENTION,
                "",
                "b",
                "k"
            )
            .to_string(),
            "protocol: cannot specify an object expiration time when uploading into a bucket with default retention settings"
        );
        assert_eq!(
            map_remote(
                "",
                RPC_OBJECT_LOCK_UPLOAD_WITH_TTL_API_KEY_AND_DEFAULT_RETENTION,
                "",
                "b",
                "k"
            )
            .to_string(),
            "protocol: cannot upload into a bucket with default retention settings using an API key that enforces an object expiration time"
        );
    }
}
