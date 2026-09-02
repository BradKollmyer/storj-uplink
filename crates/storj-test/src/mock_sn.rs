//! In-process mock storage node (piecestore Upload / Download).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use storj_proto::piecestore::{
    PieceDownloadRequest, PieceDownloadResponse, PieceUploadRequest, PieceUploadResponse,
    piece_download_response,
};
use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
use storj_rpc::tls::server_config;
use storj_rpc::{Conn, Identity, Kind, Packet, read_tls_mux_prefix};
use storj_uplink::orders::{
    PieceHashAlgo, PieceHasher, PiecePublicKey, sign_piece_hash_node, verify_order_limit,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// Loopback TLS storage node speaking piecestore Upload.
pub struct MockStorageNode {
    identity: Identity,
    address: String,
    delay: Arc<Mutex<Duration>>,
    fail_next: Arc<Mutex<bool>>,
    fail_next_download: Arc<Mutex<bool>>,
    #[allow(dead_code)]
    store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    join: JoinHandle<()>,
}

impl MockStorageNode {
    /// Bind `127.0.0.1:0` and serve piecestore over TLS.
    pub async fn start(satellite_ca: Vec<u8>) -> Self {
        let identity = Identity::generate().expect("mock SN identity");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock SN");
        let addr = listener.local_addr().expect("sn local addr");
        let address = addr.to_string();
        let delay = Arc::new(Mutex::new(Duration::ZERO));
        let fail_next = Arc::new(Mutex::new(false));
        let fail_next_download = Arc::new(Mutex::new(false));
        let store = Arc::new(Mutex::new(HashMap::new()));
        let server_cfg = server_config(&identity).expect("mock SN tls");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let sn = identity.clone();
        let delay_c = Arc::clone(&delay);
        let fail_c = Arc::clone(&fail_next);
        let fail_dl_c = Arc::clone(&fail_next_download);
        let store_c = Arc::clone(&store);
        let join = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let sn = sn.clone();
                let sat_ca = satellite_ca.clone();
                let delay = Arc::clone(&delay_c);
                let fail_next = Arc::clone(&fail_c);
                let fail_next_download = Arc::clone(&fail_dl_c);
                let store = Arc::clone(&store_c);
                tokio::spawn(async move {
                    let _ = serve_conn(
                        tcp,
                        acceptor,
                        sn,
                        sat_ca,
                        delay,
                        fail_next,
                        fail_next_download,
                        store,
                    )
                    .await;
                });
            }
        });
        Self {
            identity,
            address,
            delay,
            fail_next,
            fail_next_download,
            store,
            join,
        }
    }

    /// `host:port` for addressed order limits.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Node identity (NodeID + CA for order limits / piece hashes).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Sleep this long before finishing Upload (long-tail tests).
    pub async fn set_delay(&self, d: Duration) {
        *self.delay.lock().await = d;
    }

    /// Next Upload closes without a piece-hash response.
    pub async fn fail_next_upload(&self) {
        *self.fail_next.lock().await = true;
    }

    /// Next Download closes without piece data.
    pub async fn fail_next_download(&self) {
        *self.fail_next_download.lock().await = true;
    }
}

impl Drop for MockStorageNode {
    fn drop(&mut self) {
        self.join.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_conn(
    mut tcp: TcpStream,
    acceptor: TlsAcceptor,
    sn: Identity,
    satellite_ca: Vec<u8>,
    delay: Arc<Mutex<Duration>>,
    fail_next: Arc<Mutex<bool>>,
    fail_next_download: Arc<Mutex<bool>>,
    store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
) -> Result<(), storj_rpc::Error> {
    read_tls_mux_prefix(&mut tcp).await?;
    let tls = acceptor.accept(tcp).await.map_err(storj_rpc::Error::Io)?;
    let mut conn = Conn::new(tls);
    loop {
        let invoke = loop {
            match conn.read_packet().await {
                Ok(pkt) if pkt.kind == Kind::INVOKE => break pkt,
                Ok(_) => continue,
                Err(storj_rpc::Error::Closed | storj_rpc::Error::Truncated) => return Ok(()),
                Err(e) => return Err(e),
            }
        };
        let rpc = String::from_utf8_lossy(&invoke.data).into_owned();
        let result = match rpc.as_str() {
            PIECESTORE_UPLOAD => {
                serve_upload(
                    &mut conn,
                    invoke.stream_id,
                    &sn,
                    &satellite_ca,
                    &delay,
                    &fail_next,
                    &store,
                )
                .await
            }
            PIECESTORE_DOWNLOAD => {
                serve_download(
                    &mut conn,
                    invoke.stream_id,
                    &satellite_ca,
                    &fail_next_download,
                    &store,
                )
                .await
            }
            _ => return Ok(()),
        };
        if result.is_err() {
            return Ok(());
        }
    }
}

async fn serve_upload(
    conn: &mut Conn<tokio_rustls::server::TlsStream<TcpStream>>,
    stream_id: u64,
    sn: &Identity,
    satellite_ca: &[u8],
    delay: &Mutex<Duration>,
    fail_next: &Mutex<bool>,
    store: &Mutex<HashMap<Vec<u8>, Vec<u8>>>,
) -> Result<(), storj_uplink::Error> {
    let mut limit = None;
    let mut algo = PieceHashAlgo::Blake3;
    let mut data = Vec::new();
    let mut done = None;
    loop {
        let pkt = conn.read_packet().await?;
        if pkt.stream_id != stream_id {
            continue;
        }
        match pkt.kind {
            Kind::MESSAGE => {
                let req = PieceUploadRequest::decode(pkt.data.as_slice())?;
                if let Some(l) = req.limit {
                    verify_order_limit(&l, satellite_ca)?;
                    algo = PieceHashAlgo::from_i32(req.hash_algorithm);
                    limit = Some(l);
                }
                if let Some(chunk) = req.chunk {
                    let off = usize::try_from(chunk.offset).unwrap_or(0);
                    if off == data.len() {
                        data.extend_from_slice(&chunk.data);
                    } else if off > data.len() {
                        data.resize(off, 0);
                        data.extend_from_slice(&chunk.data);
                    } else {
                        let end = off + chunk.data.len();
                        if end > data.len() {
                            data.resize(end, 0);
                        }
                        data[off..end].copy_from_slice(&chunk.data);
                    }
                }
                if let Some(d) = req.done {
                    done = Some(d);
                }
            }
            Kind::CLOSE_SEND | Kind::CLOSE => break,
            _ => {}
        }
    }
    let wait = *delay.lock().await;
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
    {
        let mut g = fail_next.lock().await;
        if *g {
            *g = false;
            return Err(storj_uplink::Error::protocol(
                "injected piece upload failure",
            ));
        }
    }
    let limit = limit.ok_or_else(|| storj_uplink::Error::protocol("missing order limit"))?;
    let uplink_done = done.ok_or_else(|| storj_uplink::Error::protocol("missing piece hash"))?;
    let mut hasher = PieceHasher::new(algo);
    hasher.update(&data);
    let digest = hasher.finalize();
    if let Ok(pk) = PiecePublicKey::from_bytes(&limit.uplink_public_key) {
        let _ = pk;
        let _ = digest;
    }
    store.lock().await.insert(limit.piece_id.clone(), data);
    let mut sn_hash = storj_proto::orders::PieceHash {
        piece_id: limit.piece_id,
        hash: uplink_done.hash.clone(),
        piece_size: uplink_done.piece_size,
        timestamp: uplink_done.timestamp.or(limit.order_creation),
        signature: Vec::new(),
        hash_algorithm: algo.to_i32(),
    };
    sign_piece_hash_node(&mut sn_hash, sn)?;
    let resp = PieceUploadResponse {
        done: Some(sn_hash),
        node_certchain: Vec::new(),
    };
    conn.write_packet(&Packet {
        stream_id,
        message_id: 1,
        kind: Kind::MESSAGE,
        control: false,
        data: resp.encode_to_vec(),
    })
    .await?;
    Ok(())
}

async fn serve_download(
    conn: &mut Conn<tokio_rustls::server::TlsStream<TcpStream>>,
    stream_id: u64,
    satellite_ca: &[u8],
    fail_next: &Mutex<bool>,
    store: &Mutex<HashMap<Vec<u8>, Vec<u8>>>,
) -> Result<(), storj_uplink::Error> {
    {
        let mut g = fail_next.lock().await;
        if *g {
            *g = false;
            return Err(storj_uplink::Error::protocol(
                "injected piece download failure",
            ));
        }
    }
    let mut limit = None;
    let mut chunk = None;
    loop {
        let pkt = conn.read_packet().await?;
        if pkt.stream_id != stream_id {
            continue;
        }
        match pkt.kind {
            Kind::MESSAGE => {
                let req = PieceDownloadRequest::decode(pkt.data.as_slice())?;
                if let Some(l) = req.limit {
                    verify_order_limit(&l, satellite_ca)?;
                    limit = Some(l);
                }
                if let Some(c) = req.chunk {
                    chunk = Some(c);
                }
                if limit.is_some() && chunk.is_some() {
                    break;
                }
            }
            Kind::CLOSE_SEND | Kind::CLOSE => break,
            _ => {}
        }
    }
    let limit = limit.ok_or_else(|| storj_uplink::Error::protocol("missing order limit"))?;
    let chunk = chunk.ok_or_else(|| storj_uplink::Error::protocol("missing chunk"))?;
    let data = store
        .lock()
        .await
        .get(&limit.piece_id)
        .cloned()
        .ok_or_else(|| storj_uplink::Error::protocol("piece not found"))?;
    let start = usize::try_from(chunk.offset).unwrap_or(0);
    let want = usize::try_from(chunk.chunk_size).unwrap_or(0);
    let slice = data.get(start..).unwrap_or(&[][..]);
    let slice = &slice[..want.min(slice.len())];
    const CHUNK: usize = 16 * 1024;
    let mut off = start as i64;
    let mut message_id = 0u64;
    for part in slice.chunks(CHUNK) {
        message_id += 1;
        let resp = PieceDownloadResponse {
            chunk: Some(piece_download_response::Chunk {
                offset: off,
                data: part.to_vec(),
            }),
            hash: None,
            limit: None,
            restored_from_trash: false,
        };
        conn.write_packet(&Packet {
            stream_id,
            message_id,
            kind: Kind::MESSAGE,
            control: false,
            data: resp.encode_to_vec(),
        })
        .await?;
        off += part.len() as i64;
    }
    message_id += 1;
    conn.write_packet(&Packet {
        stream_id,
        message_id,
        kind: Kind::CLOSE_SEND,
        control: false,
        data: Vec::new(),
    })
    .await?;
    Ok(())
}
