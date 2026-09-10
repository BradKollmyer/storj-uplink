//! Authenticated TCP/TLS and QUIC byte streams carrying Storj DRPC.

use crate::telemetry::{Outcome, Telemetry, TelemetryEvent};
use crate::{Identity, NodeId, client_config, write_tls_mux_prefix};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

/// Connection selection. Auto starts TCP after a 250 ms QUIC head start,
/// or immediately if QUIC fails; the first authenticated connection wins.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportMode {
    /// TCP with NodeID-pinned TLS; no UDP traffic.
    #[default]
    Tcp,
    /// QUIC with NodeID-pinned TLS 1.3; no TCP fallback.
    Quic,
    /// Prefer QUIC, allowing TCP/TLS to race after 250 ms.
    Auto,
}

/// Actual wire transport selected for a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// TCP with TLS.
    Tcp,
    /// QUIC over UDP.
    Quic,
}

/// Shared transport selection and observer for satellite and storage-node dials.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionOptions {
    pub mode: TransportMode,
    pub telemetry: Option<Telemetry>,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Io for T {}

/// A connected stream and the authenticated peer's leaf certificate.
pub struct Transport {
    io: Box<dyn Io>,
    pub peer_cert: Vec<u8>,
    pub kind: TransportKind,
}
impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
}
impl Drop for QuicStream {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"");
    }
}
impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

fn host(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

async fn tcp(identity: &Identity, node: NodeId, address: &str) -> io::Result<Transport> {
    let mut tcp = TcpStream::connect(address).await?;
    tcp.set_nodelay(true)?;
    write_tls_mux_prefix(&mut tcp).await?;
    let config = client_config(identity, node).map_err(io::Error::other)?;
    let name = rustls::pki_types::ServerName::try_from(host(address).to_owned())
        .map_err(io::Error::other)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    let peer_cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| io::Error::other("missing peer certificate"))?
        .as_ref()
        .to_vec();
    Ok(Transport {
        io: Box::new(tls),
        peer_cert,
        kind: TransportKind::Tcp,
    })
}

async fn quic(identity: &Identity, node: NodeId, address: &str) -> io::Result<Transport> {
    use futures_util::{StreamExt, stream::FuturesUnordered};
    let mut tls = client_config(identity, node).map_err(io::Error::other)?;
    tls.alpn_protocols = vec![b"storj".to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(15 * 60)
            .try_into()
            .expect("valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    let mut last = io::Error::other("address resolved to no endpoints");
    let mut candidates = FuturesUnordered::new();
    for (index, addr) in tokio::net::lookup_host(address).await?.enumerate() {
        let config = config.clone();
        candidates.push(async move {
            // A blackholed IPv6 address must not prevent trying IPv4 (or another A/AAAA record).
            if index > 0 {
                tokio::time::sleep(Duration::from_millis(250).saturating_mul(index as u32)).await;
            }
            let bind = if addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let mut endpoint = quinn::Endpoint::client(bind.parse().expect("valid bind address"))?;
            endpoint.set_default_client_config(config.clone());
            let connection = endpoint
                .connect(addr, host(address))
                .map_err(io::Error::other)?
                .await
                .map_err(io::Error::other)?;
            let peer_cert = connection
                .peer_identity()
                .and_then(|v| {
                    v.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                        .ok()
                })
                .and_then(|c| c.first().map(|c| c.as_ref().to_vec()))
                .ok_or_else(|| io::Error::other("missing QUIC peer certificate"))?;
            let (send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
            // Go's QUIC listener reads DRPC directly, without the TCP mux prefix.
            Ok::<_, io::Error>(Transport {
                io: Box::new(QuicStream {
                    send,
                    recv,
                    connection,
                    _endpoint: endpoint,
                }),
                peer_cert,
                kind: TransportKind::Quic,
            })
        });
    }
    while let Some(result) = candidates.next().await {
        match result {
            Ok(transport) => return Ok(transport),
            Err(e) => last = e,
        }
    }
    Err(last)
}

struct Attempt<'a> {
    telemetry: Option<&'a Telemetry>,
    kind: TransportKind,
    start: Instant,
    outcome: Outcome,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.telemetry {
            t.emit(TelemetryEvent::Connection {
                transport: self.kind,
                elapsed: self.start.elapsed(),
                outcome: self.outcome,
            });
        }
    }
}
async fn attempt(
    identity: &Identity,
    node: NodeId,
    address: &str,
    kind: TransportKind,
    telemetry: Option<&Telemetry>,
    deadline: Option<tokio::time::Instant>,
) -> io::Result<Transport> {
    let mut event = Attempt {
        telemetry,
        kind,
        start: Instant::now(),
        outcome: Outcome::Cancelled,
    };
    let connect = async {
        match kind {
            TransportKind::Tcp => tcp(identity, node, address).await,
            TransportKind::Quic => quic(identity, node, address).await,
        }
    };
    let result = if let Some(deadline) = deadline {
        match tokio::time::timeout_at(deadline, connect).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection dial timed out",
            )),
        }
    } else {
        connect.await
    };
    event.outcome = if result.is_ok() {
        Outcome::Success
    } else {
        Outcome::Error
    };
    result
}

/// Dial within one deadline, including DNS, authentication and fallback.
pub async fn dial(
    identity: &Identity,
    node: NodeId,
    address: &str,
    mode: TransportMode,
    timeout: Duration,
    telemetry: Option<&Telemetry>,
) -> io::Result<Transport> {
    let deadline = tokio::time::Instant::now().checked_add(timeout);
    let connect = async {
        match mode {
            TransportMode::Tcp => {
                attempt(
                    identity,
                    node,
                    address,
                    TransportKind::Tcp,
                    telemetry,
                    deadline,
                )
                .await
            }
            TransportMode::Quic => {
                attempt(
                    identity,
                    node,
                    address,
                    TransportKind::Quic,
                    telemetry,
                    deadline,
                )
                .await
            }
            TransportMode::Auto => {
                let q = attempt(
                    identity,
                    node,
                    address,
                    TransportKind::Quic,
                    telemetry,
                    deadline,
                );
                tokio::pin!(q);
                tokio::select! {
                    result = &mut q => match result { Ok(c) => return Ok(c), Err(_) => return attempt(identity, node, address, TransportKind::Tcp, telemetry, deadline).await },
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                let t = attempt(
                    identity,
                    node,
                    address,
                    TransportKind::Tcp,
                    telemetry,
                    deadline,
                );
                tokio::pin!(t);
                tokio::select! {
                    result = &mut q => match result { Ok(c) => Ok(c), Err(_) => t.await },
                    result = &mut t => match result { Ok(c) => Ok(c), Err(_) => q.await },
                }
            }
        }
    };
    connect.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn quic_server(identity: &Identity) -> quinn::Endpoint {
        let mut tls = crate::server_config(identity).unwrap();
        tls.alpn_protocols = vec![b"storj".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn extracts_dns_ipv4_and_ipv6_hosts() {
        assert_eq!(host("127.0.0.1:7777"), "127.0.0.1");
        assert_eq!(host("us1.storj.io:7777"), "us1.storj.io");
        assert_eq!(host("[::1]:7777"), "::1");
    }

    #[tokio::test]
    async fn quic_pins_identity_and_preserves_leaf() {
        let peer = Identity::generate_signed().unwrap();
        let client = Identity::generate().unwrap();
        let server = quic_server(&peer);
        let address = server.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let bad = server.accept().await.unwrap().await;
            assert!(bad.is_err(), "wrong NodeID must reject the handshake");
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut bytes = [0; 4];
            recv.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping"); // No TCP mux header over QUIC.
            send.write_all(b"pong").await.unwrap();
            connection.closed().await;
        });
        assert!(
            dial(
                &client,
                NodeId::ZERO,
                &address,
                TransportMode::Quic,
                Duration::from_secs(3),
                None
            )
            .await
            .is_err()
        );
        let mut io = dial(
            &client,
            peer.node_id(),
            &address,
            TransportMode::Quic,
            Duration::from_secs(3),
            None,
        )
        .await
        .unwrap();
        assert_eq!(io.peer_cert, peer.leaf_der().as_ref());
        io.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"pong");
        drop(io);
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn blackholed_quic_times_out_and_emits_error() {
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = Identity::generate().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let telemetry = Telemetry::new(move |event| sink.lock().unwrap().push(event));
        let error = dial(
            &client,
            NodeId::ZERO,
            &blackhole.local_addr().unwrap().to_string(),
            TransportMode::Quic,
            Duration::from_millis(50),
            Some(&telemetry),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(matches!(
            events.lock().unwrap().as_slice(),
            [TelemetryEvent::Connection {
                transport: TransportKind::Quic,
                outcome: Outcome::Error,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn auto_does_not_wait_for_udp_timeout() {
        let peer = Identity::generate_signed().unwrap();
        let client = Identity::generate().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _blackhole = tokio::net::UdpSocket::bind(addr).await.unwrap();
        let acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::new(crate::server_config(&peer).unwrap()));
        let task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            crate::read_tls_mux_prefix(&mut tcp).await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut bytes = [0; 4];
            tls.read_exact(&mut bytes).await.unwrap();
            tls.write_all(&bytes).await.unwrap();
        });
        let start = Instant::now();
        let mut io = dial(
            &client,
            peer.node_id(),
            &addr.to_string(),
            TransportMode::Auto,
            Duration::from_secs(10),
            None,
        )
        .await
        .unwrap();
        assert_eq!(io.kind, TransportKind::Tcp);
        assert!(start.elapsed() < Duration::from_secs(3));
        io.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        task.await.unwrap();
    }
}
