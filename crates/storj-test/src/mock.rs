//! In-process mock satellite: loopback TLS + DRPC unary for ProjectInfo and buckets.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use storj_proto::metainfo::{
    Bucket as ProtoBucket, BucketListItem, CreateBucketRequest, CreateBucketResponse,
    DeleteBucketRequest, DeleteBucketResponse, GetBucketRequest, GetBucketResponse,
    ListBucketsRequest, ListBucketsResponse, ListDirection, ProjectInfoRequest,
    ProjectInfoResponse, RequestHeader,
};
use storj_proto::rpc;
use storj_rpc::tls::server_config;
use storj_rpc::{Conn, Identity, Kind, Packet, marshal_error, read_tls_mux_prefix};
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

struct MockState {
    api_key: Vec<u8>,
    project_salt: Vec<u8>,
    buckets: BTreeMap<String, BucketRec>,
}

/// Loopback TLS satellite that speaks `ProjectInfo` and bucket RPCs.
pub struct MockSatellite {
    node_url: String,
    api_key: String,
    api_key_raw: Vec<u8>,
    project_salt: Vec<u8>,
    state: Arc<Mutex<MockState>>,
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

        let state = Arc::new(Mutex::new(MockState {
            api_key: api_key_raw.clone(),
            project_salt: project_salt.clone(),
            buckets: BTreeMap::new(),
        }));

        let server_cfg = server_config(&identity).expect("mock server tls");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let join_state = Arc::clone(&state);
        let join = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&join_state);
                tokio::spawn(async move {
                    let _ = serve_conn(tcp, acceptor, state).await;
                });
            }
        });

        Self {
            node_url,
            api_key,
            api_key_raw,
            project_salt,
            state,
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
) -> Result<(), storj_rpc::Error> {
    read_tls_mux_prefix(&mut tcp).await?;
    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(storj_rpc::Error::Io)?;
    let mut conn = Conn::new(tls);
    loop {
        match serve_one(&mut conn, &state).await {
            Ok(()) => {}
            Err(storj_rpc::Error::Closed | storj_rpc::Error::Truncated) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

async fn serve_one(
    conn: &mut Conn<tokio_rustls::server::TlsStream<TcpStream>>,
    state: &Mutex<MockState>,
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

    match handle_rpc(&rpc, &request, state) {
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

fn handle_rpc(rpc: &str, body: &[u8], state: &Mutex<MockState>) -> Result<Vec<u8>, (u64, String)> {
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
        _ => Err((RPC_UNIMPLEMENTED, format!("unknown rpc {rpc}"))),
    }
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
