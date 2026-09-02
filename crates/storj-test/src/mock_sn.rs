//! In-process mock storage node (piecestore Upload).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use storj_proto::piecestore::{PieceUploadRequest, PieceUploadResponse};
use storj_proto::rpc::PIECESTORE_UPLOAD;
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
        let store = Arc::new(Mutex::new(HashMap::new()));
        let server_cfg = server_config(&identity).expect("mock SN tls");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let sn = identity.clone();
        let delay_c = Arc::clone(&delay);
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
                let store = Arc::clone(&store_c);
                tokio::spawn(async move {
                    let _ = serve_conn(tcp, acceptor, sn, sat_ca, delay, store).await;
                });
            }
        });
        Self {
            identity,
            address,
            delay,
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
}

impl Drop for MockStorageNode {
    fn drop(&mut self) {
        self.join.abort();
    }
}

async fn serve_conn(
    mut tcp: TcpStream,
    acceptor: TlsAcceptor,
    sn: Identity,
    satellite_ca: Vec<u8>,
    delay: Arc<Mutex<Duration>>,
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
        if rpc != PIECESTORE_UPLOAD {
            return Ok(());
        }
        if serve_upload(
            &mut conn,
            invoke.stream_id,
            &sn,
            &satellite_ca,
            &delay,
            &store,
        )
        .await
        .is_err()
        {
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
