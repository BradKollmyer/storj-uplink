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
    self, BatchRequest, BatchRequestItem, BeginDeleteObjectRequest, BeginObjectRequest,
    BeginSegmentRequest, CommitObjectRequest, CommitSegmentRequest, CompressedBatchResponse,
    CreateBucketRequest, DeleteBucketRequest, FinishDeleteObjectRequest, GetBucketRequest,
    ListBucketsRequest, MakeInlineSegmentRequest, ProjectInfoRequest, ProjectInfoResponse,
    RequestHeader, RetryBeginSegmentPiecesRequest, SegmentPosition, batch_request_item,
    batch_response_item,
};
use storj_proto::rpc;
use storj_rpc::tls::client_config;
use storj_rpc::{Conn, Identity, NodeUrl, parse_node_url, write_tls_mux_prefix};

use crate::bucket::{bucket_from_list_item, bucket_from_proto, proto_timestamp};
use crate::error::{Error, ErrorKind, Result};
use crate::types::{Bucket, Config, CustomMetadata, Object, SystemMetadata};

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

const SATELLITE_ATTEMPTS: u32 = 3;
const LIST_BUCKETS_LIMIT: i32 = 1000;

type SatelliteStream = TlsStream<TcpStream>;

/// Long-lived satellite metainfo connection (one in-flight RPC at a time).
pub(crate) struct MetainfoClient {
    node: NodeUrl,
    api_key: Vec<u8>,
    user_agent: Vec<u8>,
    identity: Identity,
    dial_timeout: Duration,
    satellite_ca: Mutex<Vec<u8>>,
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
            satellite_ca: Mutex::new(Vec::new()),
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
            satellite_ca: Mutex::new(Vec::new()),
            conn: Mutex::new(None),
        }
    }

    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }

    pub(crate) async fn satellite_ca(&self) -> Vec<u8> {
        self.satellite_ca.lock().await.clone()
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
            if let Some(ca) = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.last())
                .map(|c| c.as_ref().to_vec())
            {
                *self.satellite_ca.lock().await = ca;
            }
            Ok::<_, Error>(Conn::new(tls))
        };
        tokio::time::timeout(self.dial_timeout, dial)
            .await
            .map_err(|_| Error::new(ErrorKind::Protocol, "satellite dial timed out"))?
    }

    async fn invoke(&self, rpc: &str, request: &[u8], bucket: &str, key: &str) -> Result<Vec<u8>> {
        let mut last_err = None;
        for attempt in 0..SATELLITE_ATTEMPTS {
            match self.invoke_once(rpc, request).await {
                Ok(body) => return Ok(body),
                Err(e) if attempt + 1 < SATELLITE_ATTEMPTS && is_retryable(&e) => {
                    last_err = Some(e);
                    let backoff = Duration::from_millis(200 * 2u64.pow(attempt));
                    tokio::time::sleep(backoff.min(Duration::from_secs(2))).await;
                }
                Err(e) => return Err(map_rpc_error(e, bucket, key)),
            }
        }
        Err(map_rpc_error(
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
        let wrapped = encode_batch_request(&batch);
        let body = self
            .invoke(rpc::COMPRESSED_BATCH, &wrapped.encode_to_vec(), bucket, key)
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

    pub(crate) async fn begin_delete_object(
        &self,
        bucket: &str,
        encrypted_object_key: Vec<u8>,
        stream_id: Vec<u8>,
    ) -> Result<metainfo::BeginDeleteObjectResponse> {
        let req = BeginDeleteObjectRequest {
            header: Some(self.header()),
            bucket: bucket.as_bytes().to_vec(),
            encrypted_object_key,
            stream_id,
            status: metainfo::object::Status::Uploading as i32,
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

    pub(crate) async fn finish_delete_object(
        &self,
        bucket: &str,
        stream_id: Vec<u8>,
    ) -> Result<()> {
        let req = FinishDeleteObjectRequest {
            header: Some(self.header()),
            stream_id,
        };
        let items = self
            .compressed_batch(
                vec![BatchRequestItem {
                    request: Some(batch_request_item::Request::ObjectFinishDelete(req)),
                }],
                bucket,
                "",
            )
            .await?;
        match Self::expect_one(items, "FinishDeleteObject")? {
            batch_response_item::Response::ObjectFinishDelete(_) => Ok(()),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unexpected FinishDeleteObject response",
            )),
        }
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
    let (created, expires, content_length) = match &pb {
        Some(o) => (
            Some(proto_timestamp(o.created_at)),
            o.expires_at.map(|t| proto_timestamp(Some(t))),
            o.plain_size,
        ),
        None => (None, None, 0),
    };
    Object {
        key: plaintext_key.to_owned(),
        is_prefix: false,
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
        storj_rpc::IdentityError::Certificate(_)
        | storj_rpc::IdentityError::NoCaKey
        | storj_rpc::IdentityError::Signature => {
            Error::new(ErrorKind::Protocol, e.to_string()).with_source(e)
        }
    }
}

pub(crate) fn parse_satellite_url(address: &str) -> Result<NodeUrl> {
    parse_node_url(address).map_err(map_identity_err)
}

pub(crate) fn map_rpc_error(err: storj_rpc::Error, bucket: &str, key: &str) -> Error {
    match err {
        storj_rpc::Error::Remote { code, message } => map_remote(code, &message, bucket, key),
        storj_rpc::Error::Io(e) => Error::from(e),
        other => Error::new(ErrorKind::Protocol, other.to_string()).with_source(other),
    }
}

fn map_remote(code: u64, message: &str, bucket: &str, key: &str) -> Error {
    match code {
        RPC_CANCELED => Error::new(ErrorKind::Canceled, message),
        RPC_INVALID_ARGUMENT if !key.is_empty() => Error::new(
            ErrorKind::ObjectKeyInvalid,
            format!("object key invalid ({key:?})"),
        ),
        RPC_INVALID_ARGUMENT => Error::new(
            ErrorKind::BucketNameInvalid,
            format!("bucket name invalid ({bucket:?})"),
        ),
        RPC_NOT_FOUND => {
            if message.starts_with("bucket not found") {
                let name = bucket_from_not_found(message).unwrap_or(bucket);
                Error::new(
                    ErrorKind::BucketNotFound,
                    format!("bucket not found ({name:?})"),
                )
            } else if message.starts_with("object not found") {
                Error::new(
                    ErrorKind::ObjectNotFound,
                    format!("object not found ({key:?})"),
                )
            } else if !bucket.is_empty() {
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
        RPC_FAILED_PRECONDITION if !bucket.is_empty() => Error::new(
            ErrorKind::BucketNotEmpty,
            format!("bucket not empty ({bucket:?})"),
        ),
        _ => Error::new(
            ErrorKind::Protocol,
            format!("DRPC remote error (code {code}): {message}"),
        ),
    }
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
        let e = map_remote(RPC_NOT_FOUND, "bucket not found: logs", "logs", "");
        assert_eq!(e.kind(), ErrorKind::BucketNotFound);
        assert!(e.to_string().contains("logs"));
    }

    #[test]
    fn remote_already_exists() {
        let e = map_remote(RPC_ALREADY_EXISTS, "exists", "photos", "");
        assert_eq!(e.kind(), ErrorKind::BucketAlreadyExists);
        assert!(e.to_string().contains("photos"));
    }

    #[test]
    fn remote_failed_precondition_not_empty() {
        let e = map_remote(RPC_FAILED_PRECONDITION, "not empty", "b", "");
        assert_eq!(e.kind(), ErrorKind::BucketNotEmpty);
    }

    #[test]
    fn remote_resource_exhausted_kinds() {
        assert_eq!(
            map_remote(RPC_RESOURCE_EXHAUSTED, "Exceeded Usage Limit", "", "").kind(),
            ErrorKind::BandwidthLimitExceeded
        );
        assert_eq!(
            map_remote(RPC_RESOURCE_EXHAUSTED, "Too Many Requests", "", "").kind(),
            ErrorKind::TooManyRequests
        );
        assert_eq!(
            map_remote(
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
}
