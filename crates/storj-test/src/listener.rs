//! Shared authenticated listeners for TCP and QUIC integration tests.
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use storj_rpc::Identity;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Stream = Box<dyn Io>;
pub(crate) type Incoming = Pin<Box<dyn Future<Output = io::Result<Stream>> + Send>>;

pub(crate) enum Listener {
    Tcp(tokio::net::TcpListener, tokio_rustls::TlsAcceptor),
    Quic(quinn::Endpoint),
    Noise(tokio::net::TcpListener, i32, Vec<u8>),
}
impl Listener {
    pub(crate) async fn bind_noise(protocol: i32) -> (Self, storj_proto::noise::NoiseInfo) {
        let name = match protocol {
            1 => "Noise_IK_25519_ChaChaPoly_BLAKE2b",
            2 => "Noise_IK_25519_AESGCM_BLAKE2b",
            _ => panic!("unsupported test protocol"),
        };
        let key = snow::Builder::new(name.parse().unwrap())
            .generate_keypair()
            .unwrap();
        (
            Self::Noise(
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                protocol,
                key.private,
            ),
            storj_proto::noise::NoiseInfo {
                proto: protocol,
                public_key: key.public,
            },
        )
    }
    pub(crate) async fn bind(identity: &Identity, quic: bool) -> Self {
        let mut tls = storj_rpc::server_config(identity).unwrap();
        if quic {
            tls.alpn_protocols = vec![b"storj".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
            let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            Self::Quic(quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap())
        } else {
            Self::Tcp(
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
            )
        }
    }
    pub(crate) fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            Self::Tcp(l, _) => l.local_addr(),
            Self::Quic(e) => e.local_addr(),
            Self::Noise(l, _, _) => l.local_addr(),
        }
    }
    // Handshake in the connection task so failed/slow peers cannot stop accepts.
    pub(crate) async fn accept(&self) -> io::Result<Incoming> {
        match self {
            Self::Noise(l, protocol, key) => {
                let (mut tcp, _) = l.accept().await?;
                let protocol = *protocol;
                let key = key.clone();
                Ok(Box::pin(async move {
                    use tokio::io::AsyncReadExt;
                    let mut prefix = [0; 8];
                    tcp.read_exact(&mut prefix).await?;
                    if &prefix != storj_rpc::noise::HEADER {
                        return Err(io::Error::other("expected Noise prefix"));
                    }
                    Ok(
                        Box::new(storj_rpc::noise::NoiseStream::accept(tcp, protocol, &key).await?)
                            as Stream,
                    )
                }))
            }
            Self::Tcp(l, a) => {
                let (mut tcp, _) = l.accept().await?;
                let a = a.clone();
                Ok(Box::pin(async move {
                    storj_rpc::read_tls_mux_prefix(&mut tcp)
                        .await
                        .map_err(io::Error::other)?;
                    Ok(Box::new(a.accept(tcp).await?) as Stream)
                }))
            }
            Self::Quic(e) => {
                let incoming = e.accept().await.ok_or_else(|| io::Error::other("closed"))?;
                Ok(Box::pin(async move {
                    let conn = incoming.await.map_err(io::Error::other)?;
                    let (send, recv) = conn.accept_bi().await.map_err(io::Error::other)?;
                    Ok(Box::new(QuicIo {
                        io: tokio::io::join(recv, send),
                        conn,
                    }) as Stream)
                }))
            }
        }
    }
}
struct QuicIo {
    io: tokio::io::Join<quinn::RecvStream, quinn::SendStream>,
    conn: quinn::Connection,
}
impl Drop for QuicIo {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"");
    }
}
impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
