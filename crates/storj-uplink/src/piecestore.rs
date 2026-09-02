//! Storage-node piecestore client (upload / download streams).
//!
//! Wire RPCs: `/piecestore.Piecestore/Upload` (client stream) and
//! `/piecestore.Piecestore/Download` (bidi). Hash algorithm is
//! [`crate::PieceHashAlgo`] from satellite negotiation (K18).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use storj_proto::orders::{Order, OrderLimit, PieceAction, PieceHash};
use storj_proto::piecestore::{
    PieceDownloadRequest, PieceDownloadResponse, PieceUploadRequest, PieceUploadResponse,
    piece_download_request, piece_upload_request,
};
use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
use storj_rpc::{Conn, RpcStream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::orders::{
    PieceHashAlgo, PiecePrivateKey, sign_order, sign_piece_hash_uplink, verify_order_limit,
    verify_piece_hash_node,
};
use crate::{Error, Result};

/// Go `piecestore.DefaultConfig` (subset used by this client).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Bytes read per upload `Chunk` (Go `UploadBufferSize`, 64 KiB).
    pub upload_buffer_size: usize,
    /// First signed order amount (Go `InitialStep`, 256 KiB).
    pub initial_step: i64,
    /// Cap on order-step growth (Go `MaximumStep`, 550 KiB).
    pub maximum_step: i64,
    /// Advisory download chunk size (Go `MaximumChunkSize`, 16 KiB).
    pub maximum_chunk_size: i32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            upload_buffer_size: 64 * 1024,
            initial_step: 256 * 1024,
            maximum_step: 550 * 1024,
            maximum_chunk_size: 16 * 1024,
        }
    }
}

/// Piecestore client over one DRPC connection (one RPC at a time).
pub struct Client<T> {
    conn: Conn<T>,
    satellite_ca_der: Vec<u8>,
    peer_ca_der: Vec<u8>,
    hash_algo: PieceHashAlgo,
    config: Config,
}

impl<T> Client<T> {
    /// Wrap an established SN connection.
    ///
    /// `satellite_ca_der` verifies order limits. `peer_ca_der` is the storage
    /// node's CA (from TLS) used to verify the signed piece hash it returns.
    #[must_use]
    pub fn new(conn: Conn<T>, satellite_ca_der: Vec<u8>, peer_ca_der: Vec<u8>) -> Self {
        Self {
            conn,
            satellite_ca_der,
            peer_ca_der,
            hash_algo: PieceHashAlgo::Blake3,
            config: Config::default(),
        }
    }

    /// Select SHA-256 or BLAKE3 (`WithPieceHashAlgo`).
    #[must_use]
    pub fn with_hash_algo(mut self, algo: PieceHashAlgo) -> Self {
        self.hash_algo = algo;
        self
    }

    /// Override buffer / order-step sizes.
    #[must_use]
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Negotiated piece-hash algorithm.
    #[must_use]
    pub fn hash_algo(&self) -> PieceHashAlgo {
        self.hash_algo
    }

    /// Inner DRPC connection.
    pub fn conn_mut(&mut self) -> &mut Conn<T> {
        &mut self.conn
    }

    /// Recover the transport after a piece RPC.
    #[must_use]
    pub fn into_conn(self) -> Conn<T> {
        self.conn
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Client<T> {
    /// Upload `data` as one piece. Verifies the satellite signature on `limit`
    /// before talking to the node, then the node's signed piece hash.
    pub async fn upload(
        &mut self,
        limit: &OrderLimit,
        piece_key: &PiecePrivateKey,
        data: &[u8],
    ) -> Result<PieceHash> {
        verify_order_limit(limit, &self.satellite_ca_der)?;
        if limit.action != PieceAction::Put as i32 && limit.action != PieceAction::PutRepair as i32
        {
            return Err(Error::protocol("order limit action is not PUT"));
        }
        if (data.len() as i64) > limit.limit {
            return Err(Error::protocol("piece exceeds order limit"));
        }

        let mut hasher = self.hash_algo.hasher();
        hasher.update(data);
        let digest = hasher.finalize();

        let mut stream = self.conn.open_stream(PIECESTORE_UPLOAD).await?;
        let result = self
            .upload_once(&mut stream, limit, piece_key, data, &digest)
            .await;
        let close_err = self.conn.close_stream(&mut stream).await;
        match result {
            Ok(hash) => {
                close_err?;
                Ok(hash)
            }
            Err(e) => Err(e),
        }
    }

    async fn upload_once(
        &mut self,
        stream: &mut RpcStream,
        limit: &OrderLimit,
        piece_key: &PiecePrivateKey,
        data: &[u8],
        digest: &[u8],
    ) -> Result<PieceHash> {
        let buf = self.config.upload_buffer_size.max(1);
        let mut offset: i64 = 0;
        let mut ordered_so_far: i64 = 0;
        let mut order_step = self.config.initial_step;
        let mut first = true;

        if data.is_empty() {
            let req = PieceUploadRequest {
                limit: Some(limit.clone()),
                hash_algorithm: self.hash_algo.to_i32(),
                order: None,
                chunk: None,
                done: Some(signed_uplink_hash(
                    limit,
                    piece_key,
                    digest,
                    0,
                    self.hash_algo,
                )?),
            };
            self.conn.send_msg(stream, &req.encode_to_vec()).await?;
        } else {
            let mut rest = data;
            while !rest.is_empty() {
                let n = rest.len().min(buf);
                let chunk = &rest[..n];
                rest = &rest[n..];
                let last = rest.is_empty();
                let end = offset + n as i64;

                let mut req = PieceUploadRequest {
                    limit: None,
                    hash_algorithm: 0,
                    order: None,
                    chunk: Some(piece_upload_request::Chunk {
                        offset,
                        data: chunk.to_vec(),
                    }),
                    done: None,
                };
                if first {
                    req.limit = Some(limit.clone());
                    req.hash_algorithm = self.hash_algo.to_i32();
                    first = false;
                }
                if end > ordered_so_far {
                    ordered_so_far = (offset + order_step).min(limit.limit);
                    req.order = Some(signed_order(limit, piece_key, ordered_so_far)?);
                    order_step = next_order_step(order_step, self.config.maximum_step);
                }
                if last {
                    req.done = Some(signed_uplink_hash(
                        limit,
                        piece_key,
                        digest,
                        end,
                        self.hash_algo,
                    )?);
                }
                self.conn.send_msg(stream, &req.encode_to_vec()).await?;
                offset = end;
            }
        }

        self.conn.close_send(stream).await?;
        let resp = PieceUploadResponse::decode(self.conn.recv_msg(stream).await?.as_slice())?;
        let sn_hash = resp
            .done
            .ok_or_else(|| Error::protocol("expected piece hash"))?;
        verify_sn_piece_hash(&sn_hash, limit, digest, self.hash_algo, &self.peer_ca_der)?;
        Ok(sn_hash)
    }

    /// Download `size` bytes from `offset`. Verifies the satellite signature
    /// on `limit` first.
    pub async fn download(
        &mut self,
        limit: &OrderLimit,
        piece_key: &PiecePrivateKey,
        offset: i64,
        size: i64,
    ) -> Result<Vec<u8>> {
        verify_order_limit(limit, &self.satellite_ca_der)?;
        if limit.action != PieceAction::Get as i32
            && limit.action != PieceAction::GetAudit as i32
            && limit.action != PieceAction::GetRepair as i32
        {
            return Err(Error::protocol("order limit action is not GET"));
        }
        if offset < 0 || size < 0 {
            return Err(Error::protocol("download offset/size must be >= 0"));
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut stream = self.conn.open_stream(PIECESTORE_DOWNLOAD).await?;
        let result = self
            .download_once(&mut stream, limit, piece_key, offset, size)
            .await;
        let _ = self.conn.close_stream(&mut stream).await;
        result
    }

    async fn download_once(
        &mut self,
        stream: &mut RpcStream,
        limit: &OrderLimit,
        piece_key: &PiecePrivateKey,
        offset: i64,
        size: i64,
    ) -> Result<Vec<u8>> {
        let req = PieceDownloadRequest {
            limit: Some(limit.clone()),
            order: Some(signed_order(limit, piece_key, size)?),
            chunk: Some(piece_download_request::Chunk {
                offset,
                chunk_size: size,
            }),
            maximum_chunk_size: self.config.maximum_chunk_size,
        };
        self.conn.send_msg(stream, &req.encode_to_vec()).await?;

        let mut out = Vec::new();
        while (out.len() as i64) < size {
            match self.conn.recv_msg_opt(stream).await? {
                Some(bytes) => {
                    let resp = PieceDownloadResponse::decode(bytes.as_slice())?;
                    if let Some(chunk) = resp.chunk {
                        out.extend_from_slice(&chunk.data);
                    }
                }
                None => break,
            }
        }
        let _ = self.conn.close_send(stream).await;
        if (out.len() as i64) > size {
            out.truncate(size as usize);
        }
        if (out.len() as i64) < size {
            return Err(Error::protocol("short piece download"));
        }
        Ok(out)
    }
}

fn signed_order(limit: &OrderLimit, key: &PiecePrivateKey, amount: i64) -> Result<Order> {
    let mut order = Order {
        serial_number: limit.serial_number.clone(),
        amount,
        uplink_signature: Vec::new(),
    };
    sign_order(&mut order, key)?;
    Ok(order)
}

fn signed_uplink_hash(
    limit: &OrderLimit,
    key: &PiecePrivateKey,
    digest: &[u8],
    size: i64,
    algo: PieceHashAlgo,
) -> Result<PieceHash> {
    let mut hash = PieceHash {
        piece_id: limit.piece_id.clone(),
        hash: digest.to_vec(),
        piece_size: size,
        timestamp: limit.order_creation,
        signature: Vec::new(),
        hash_algorithm: algo.to_i32(),
    };
    sign_piece_hash_uplink(&mut hash, key)?;
    Ok(hash)
}

fn next_order_step(previous: i64, maximum: i64) -> i64 {
    previous.saturating_mul(3).saturating_div(2).min(maximum)
}

const PIECE_HASH_EXPIRATION: Duration = Duration::from_secs(24 * 60 * 60);

fn verify_sn_piece_hash(
    hash: &PieceHash,
    limit: &OrderLimit,
    expected: &[u8],
    algo: PieceHashAlgo,
    peer_ca_der: &[u8],
) -> Result<()> {
    if hash.piece_id != limit.piece_id {
        return Err(Error::PieceIdMismatch);
    }
    if PieceHashAlgo::from_i32(hash.hash_algorithm) != algo {
        return Err(Error::HashAlgoMismatch);
    }
    if hash.hash != expected {
        return Err(Error::PieceHashMismatch);
    }
    verify_piece_hash_node(hash, peer_ca_der)?;
    if timestamp_too_old(hash.timestamp.as_ref()) {
        return Err(Error::PieceHashExpired);
    }
    Ok(())
}

fn timestamp_too_old(ts: Option<&prost_types::Timestamp>) -> bool {
    let Some(ts) = ts else {
        return true;
    };
    let Ok(secs) = u64::try_from(ts.seconds) else {
        return true;
    };
    // Unnormalized protobuf timestamps must not reach Duration::new (panics
    // when nanos >= 1e9). Treat them as invalid / expired.
    if !(0..1_000_000_000).contains(&ts.nanos) {
        return true;
    }
    let nanos = u64::from(u32::try_from(ts.nanos).unwrap_or(0));
    let Some(t) = UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .and_then(|t| t.checked_add(Duration::from_nanos(nanos)))
    else {
        return true;
    };
    let cutoff = SystemTime::now()
        .checked_sub(PIECE_HASH_EXPIRATION)
        .unwrap_or(UNIX_EPOCH);
    t < cutoff
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use prost::Message;
    use storj_proto::piecestore::piece_download_response;
    use storj_rpc::frame::{Kind, Packet};
    use storj_rpc::tls::{client_config, server_config};
    use storj_rpc::{Conn, Identity};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::sync::Mutex;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::PieceHasher;
    use crate::orders::{PiecePublicKey, sign_order_limit, sign_piece_hash_node, verify_order};

    fn proto_now() -> prost_types::Timestamp {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        prost_types::Timestamp {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        }
    }

    fn signed_limit(
        satellite: &Identity,
        sn: &Identity,
        piece_key: &PiecePrivateKey,
        piece_id: &[u8],
        action: PieceAction,
        limit: i64,
    ) -> OrderLimit {
        let now = proto_now();
        let mut ol = OrderLimit {
            serial_number: (0u8..16).collect(),
            satellite_id: satellite.node_id().as_bytes().to_vec(),
            deprecated_uplink_id: Vec::new(),
            uplink_public_key: piece_key.public().to_bytes().to_vec(),
            storage_node_id: sn.node_id().as_bytes().to_vec(),
            piece_id: piece_id.to_vec(),
            limit,
            action: action as i32,
            piece_expiration: Some(now),
            order_expiration: Some(now),
            order_creation: Some(now),
            encrypted_metadata_key_id: Vec::new(),
            encrypted_metadata: Vec::new(),
            satellite_signature: Vec::new(),
            deprecated_satellite_address: None,
        };
        sign_order_limit(&mut ol, satellite).unwrap();
        ol
    }

    type PieceStore = Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum UploadFault {
        None,
        WrongDigest,
        WrongSigner,
        ExpiredTimestamp,
    }

    async fn serve_mock<T: AsyncRead + AsyncWrite + Unpin>(
        conn: Conn<T>,
        sn: Identity,
        satellite_ca: Vec<u8>,
        store: PieceStore,
    ) {
        serve_mock_with_fault(
            conn,
            sn,
            satellite_ca,
            store,
            Arc::new(Mutex::new(UploadFault::None)),
        )
        .await;
    }

    async fn serve_mock_with_fault<T: AsyncRead + AsyncWrite + Unpin>(
        mut conn: Conn<T>,
        sn: Identity,
        satellite_ca: Vec<u8>,
        store: PieceStore,
        fault: Arc<Mutex<UploadFault>>,
    ) {
        loop {
            let invoke = match read_invoke(&mut conn).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let result = match invoke.1.as_str() {
                PIECESTORE_UPLOAD => {
                    let f = {
                        let mut g = fault.lock().await;
                        let f = *g;
                        *g = UploadFault::None;
                        f
                    };
                    serve_upload(&mut conn, invoke.0, &sn, &satellite_ca, &store, f).await
                }
                PIECESTORE_DOWNLOAD => {
                    serve_download(&mut conn, invoke.0, &satellite_ca, &store).await
                }
                _ => Err(Error::protocol("unknown rpc")),
            };
            if result.is_err() {
                return;
            }
        }
    }

    async fn read_invoke<T: AsyncRead + Unpin>(
        conn: &mut Conn<T>,
    ) -> Result<(u64, String), storj_rpc::Error> {
        loop {
            let pkt = conn.read_packet().await?;
            if pkt.kind == Kind::INVOKE {
                return Ok((
                    pkt.stream_id,
                    String::from_utf8_lossy(&pkt.data).into_owned(),
                ));
            }
        }
    }

    async fn serve_upload<T: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut Conn<T>,
        stream_id: u64,
        sn: &Identity,
        satellite_ca: &[u8],
        store: &PieceStore,
        fault: UploadFault,
    ) -> Result<()> {
        let mut limit = None;
        let mut algo = PieceHashAlgo::Sha256;
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
                    if let Some(order) = req.order.as_ref() {
                        if let Some(l) = limit.as_ref() {
                            let pk = PiecePublicKey::from_bytes(&l.uplink_public_key)?;
                            verify_order(order, &pk)?;
                        }
                    }
                    if let Some(chunk) = req.chunk {
                        let off = usize::try_from(chunk.offset).unwrap_or(0);
                        if off > data.len() {
                            data.resize(off, 0);
                        }
                        if off == data.len() {
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
        let limit = limit.ok_or_else(|| Error::protocol("missing order limit"))?;
        let uplink_done = done.ok_or_else(|| Error::protocol("missing piece hash"))?;
        let mut hasher = PieceHasher::new(algo);
        hasher.update(&data);
        let digest = hasher.finalize();
        if uplink_done.hash != digest {
            return Err(Error::PieceHashMismatch);
        }
        let pk = PiecePublicKey::from_bytes(&limit.uplink_public_key)?;
        crate::verify_piece_hash_uplink(&uplink_done, &pk)?;

        store.lock().await.insert(limit.piece_id.clone(), data);

        let mut sn_hash = PieceHash {
            piece_id: limit.piece_id,
            hash: digest,
            piece_size: uplink_done.piece_size,
            timestamp: uplink_done.timestamp.or(limit.order_creation),
            signature: Vec::new(),
            hash_algorithm: algo.to_i32(),
        };
        match fault {
            UploadFault::None => {}
            UploadFault::WrongDigest => sn_hash.hash = vec![0xab; 32],
            UploadFault::WrongSigner => {}
            UploadFault::ExpiredTimestamp => {
                sn_hash.timestamp = Some(prost_types::Timestamp {
                    seconds: 1,
                    nanos: 0,
                });
            }
        }
        let other;
        let signer = match fault {
            UploadFault::WrongSigner => {
                other = Identity::generate().unwrap();
                &other
            }
            _ => sn,
        };
        sign_piece_hash_node(&mut sn_hash, signer)?;
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

    async fn serve_download<T: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut Conn<T>,
        stream_id: u64,
        satellite_ca: &[u8],
        store: &PieceStore,
    ) -> Result<()> {
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
        let limit = limit.ok_or_else(|| Error::protocol("missing order limit"))?;
        let chunk = chunk.ok_or_else(|| Error::protocol("missing chunk"))?;
        let data = store
            .lock()
            .await
            .get(&limit.piece_id)
            .cloned()
            .ok_or_else(|| Error::protocol("piece not found"))?;
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

    async fn roundtrip(algo: PieceHashAlgo, payload: &[u8]) {
        let satellite = Identity::generate().unwrap();
        let sn = Identity::generate().unwrap();
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x11; 32];
        let sat_ca = satellite.ca_der().as_ref().to_vec();
        let sn_ca = sn.ca_der().as_ref().to_vec();
        let store: PieceStore = Arc::new(Mutex::new(HashMap::new()));
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(serve_mock(
            Conn::new(server_io),
            sn,
            sat_ca.clone(),
            Arc::clone(&store),
        ));

        let mut client = Client::new(Conn::new(client_io), sat_ca, sn_ca)
            .with_hash_algo(algo)
            .with_config(Config {
                upload_buffer_size: 32,
                initial_step: 64,
                maximum_step: 128,
                maximum_chunk_size: 32,
            });
        let dummy_sn = Identity::generate().unwrap();
        let put = signed_limit(
            &satellite,
            &dummy_sn,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            payload.len() as i64 + 1024,
        );
        let hash = client.upload(&put, &piece_key, payload).await.unwrap();
        assert_eq!(hash.hash_algorithm, algo.to_i32());
        assert_eq!(hash.piece_size, payload.len() as i64);

        let get = signed_limit(
            &satellite,
            &dummy_sn,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            payload.len() as i64 + 1024,
        );
        let got = client
            .download(&get, &piece_key, 0, payload.len() as i64)
            .await
            .unwrap();
        assert_eq!(got, payload);

        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn upload_download_blake3() {
        roundtrip(PieceHashAlgo::Blake3, b"hello blake3 piecestore").await;
    }

    #[tokio::test]
    async fn upload_download_sha256() {
        roundtrip(PieceHashAlgo::Sha256, &(0u8..=255).collect::<Vec<_>>()).await;
    }

    #[tokio::test]
    async fn upload_download_empty_piece() {
        roundtrip(PieceHashAlgo::Blake3, b"").await;
    }

    #[tokio::test]
    async fn rejects_tampered_order_limit() {
        let satellite = Identity::generate().unwrap();
        let sn = Identity::generate().unwrap();
        let piece_key = PiecePrivateKey::generate();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(serve_mock(
            Conn::new(server_io),
            sn,
            satellite.ca_der().as_ref().to_vec(),
            Arc::new(Mutex::new(HashMap::new())),
        ));
        // Client verifies against satellite CA; SN identity is a dummy CA.
        let dummy = Identity::generate().unwrap();
        let mut client = Client::new(
            Conn::new(client_io),
            satellite.ca_der().as_ref().to_vec(),
            dummy.ca_der().as_ref().to_vec(),
        );
        let mut limit = signed_limit(
            &satellite,
            &dummy,
            &piece_key,
            &[0x22; 32],
            PieceAction::Put,
            64,
        );
        limit.limit = 999_999;
        let err = client
            .upload(&limit, &piece_key, b"nope")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::OrderLimitSignature));
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn tls_loopback_upload_download() {
        let satellite = Identity::generate().unwrap();
        let sn = Identity::generate().unwrap();
        let client_ident = Identity::generate().unwrap();
        let piece_key = PiecePrivateKey::generate();
        let payload = b"tls piecestore";
        let piece_id = vec![0x33; 32];
        let store: PieceStore = Arc::new(Mutex::new(HashMap::new()));

        let client_cfg = client_config(&client_ident, sn.node_id()).unwrap();
        let server_cfg = server_config(&sn).unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let name = rustls::pki_types::ServerName::try_from("us1.storj.io").unwrap();

        let sat_ca = satellite.ca_der().as_ref().to_vec();
        let sn_ca = sn.ca_der().as_ref().to_vec();
        let server = tokio::spawn(async move {
            let tls = acceptor.accept(server_io).await.unwrap();
            serve_mock(Conn::new(tls), sn, sat_ca, store).await;
        });

        let tls = connector.connect(name, client_io).await.unwrap();
        let mut client = Client::new(Conn::new(tls), satellite.ca_der().as_ref().to_vec(), sn_ca)
            .with_hash_algo(PieceHashAlgo::Blake3)
            .with_config(Config {
                upload_buffer_size: 8,
                initial_step: 16,
                maximum_step: 32,
                maximum_chunk_size: 8,
            });
        let put = signed_limit(
            &satellite,
            &Identity::generate().unwrap(),
            &piece_key,
            &piece_id,
            PieceAction::Put,
            1024,
        );
        client.upload(&put, &piece_key, payload).await.unwrap();
        let get = signed_limit(
            &satellite,
            &Identity::generate().unwrap(),
            &piece_key,
            &piece_id,
            PieceAction::Get,
            1024,
        );
        let got = client
            .download(&get, &piece_key, 0, payload.len() as i64)
            .await
            .unwrap();
        assert_eq!(got, payload);
        drop(client);
        let _ = server.await;
    }

    #[test]
    fn unnormalized_timestamp_is_expired_not_panic() {
        assert!(timestamp_too_old(Some(&prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 1_000_000_000,
        })));
        assert!(timestamp_too_old(Some(&prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: i32::MAX,
        })));
        assert!(timestamp_too_old(Some(&prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: -1,
        })));
        assert!(timestamp_too_old(None));
        assert!(!timestamp_too_old(Some(&proto_now())));
    }

    async fn upload_with_fault(fault: UploadFault, want: fn(&Error) -> bool) {
        let satellite = Identity::generate().unwrap();
        let sn = Identity::generate().unwrap();
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x44; 32];
        let sat_ca = satellite.ca_der().as_ref().to_vec();
        let sn_ca = sn.ca_der().as_ref().to_vec();
        let store: PieceStore = Arc::new(Mutex::new(HashMap::new()));
        let faults = Arc::new(Mutex::new(fault));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_mock_with_fault(
            Conn::new(server_io),
            sn,
            sat_ca.clone(),
            Arc::clone(&store),
            Arc::clone(&faults),
        ));
        let mut client = Client::new(Conn::new(client_io), sat_ca, sn_ca);
        let dummy_sn = Identity::generate().unwrap();
        let put = signed_limit(
            &satellite,
            &dummy_sn,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            1024,
        );
        let err = client
            .upload(&put, &piece_key, b"fault-piece")
            .await
            .unwrap_err();
        assert!(want(&err), "unexpected error: {err}");

        // Stream was closed: a second upload on this conn (fault consumed) works.
        let put2 = signed_limit(
            &satellite,
            &dummy_sn,
            &piece_key,
            &[0x45; 32],
            PieceAction::Put,
            1024,
        );
        client
            .upload(&put2, &piece_key, b"after-fault")
            .await
            .expect("conn usable after failed upload");
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn upload_wrong_digest_is_mismatch() {
        upload_with_fault(UploadFault::WrongDigest, |e| {
            matches!(e, Error::PieceHashMismatch)
        })
        .await;
    }

    #[tokio::test]
    async fn upload_wrong_signer_is_bad_signature() {
        upload_with_fault(UploadFault::WrongSigner, |e| {
            matches!(e, Error::PieceHashSignature)
        })
        .await;
    }

    #[tokio::test]
    async fn upload_expired_timestamp_is_expired() {
        upload_with_fault(UploadFault::ExpiredTimestamp, |e| {
            matches!(e, Error::PieceHashExpired)
        })
        .await;
    }
}
