//! Authenticated TCP/TLS, QUIC and Noise byte streams carrying Storj DRPC.

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
    Tcp,
    /// QUIC with NodeID-pinned TLS 1.3; no TCP fallback.
    Quic,
    /// Prefer QUIC, allowing TCP/TLS to race after 250 ms.
    Auto,
    /// Noise for replay-safe storage-node RPCs with a satellite-advertised key.
    /// Uses TCP/TLS for metadata and nodes without Noise support. An advertised
    /// key that fails authentication is an error, with no TLS downgrade.
    #[default]
    Noise,
}

/// Actual wire transport selected for a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// TCP with TLS.
    Tcp,
    /// QUIC over UDP.
    Quic,
    /// TCP with Noise IK, authenticated by a satellite-advertised public key.
    Noise,
}

/// Shared transport selection and observer for satellite and storage-node dials.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionOptions {
    pub mode: TransportMode,
    pub telemetry: Option<Telemetry>,
    pub network: NetworkOptions,
}

/// TCP performance controls. Unsupported platform/kernel options are ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkOptions {
    /// Put the first transport write in the Noise IK handshake. The current
    /// piece RPC path flushes after DRPC INVOKE, so the order limit and first
    /// piece request are sent after the handshake, not as early data.
    pub noise_early_data: bool,
    /// Race Fast Open against ordinary TCP only for nodes advertising support
    /// and capacity to suppress at least two identical handshakes.
    pub tcp_fast_open: bool,
    /// Request Lower Effort DSCP on Linux TCP sockets, matching Go.
    pub background_qos: bool,
    /// Optional Linux TCP congestion controller; unavailable controllers are ignored.
    pub congestion_control: Option<String>,
}
impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            noise_early_data: true,
            tcp_fast_open: true,
            background_qos: true,
            congestion_control: None,
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Io for T {}

/// A connected stream and the peer's TLS leaf certificate (empty for Noise).
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

async fn tcp(
    identity: &Identity,
    node: NodeId,
    address: &str,
    network: &NetworkOptions,
) -> io::Result<Transport> {
    let mut tcp = crate::socket::connect(address, network).await?;
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

struct Attempt {
    telemetry: Option<Telemetry>,
    kind: TransportKind,
    start: Instant,
    outcome: Outcome,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(t) = self.telemetry.as_ref() {
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
    network: &NetworkOptions,
) -> io::Result<Transport> {
    let mut event = Attempt {
        telemetry: telemetry.cloned(),
        kind,
        start: Instant::now(),
        outcome: Outcome::Cancelled,
    };
    let connect = async {
        match kind {
            TransportKind::Tcp => tcp(identity, node, address, network).await,
            TransportKind::Quic => quic(identity, node, address).await,
            TransportKind::Noise => unreachable!("Noise uses dial_noise with an advertised key"),
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
    dial_with_options(
        identity,
        node,
        address,
        timeout,
        &ConnectionOptions {
            mode,
            telemetry: telemetry.cloned(),
            ..Default::default()
        },
    )
    .await
}

/// Dial a metadata/TLS endpoint with TCP socket policy.
pub async fn dial_with_options(
    identity: &Identity,
    node: NodeId,
    address: &str,
    timeout: Duration,
    options: &ConnectionOptions,
) -> io::Result<Transport> {
    let mode = options.mode;
    let telemetry = options.telemetry.as_ref();
    let network = &options.network;
    let deadline = tokio::time::Instant::now().checked_add(timeout);
    let connect = async {
        match mode {
            TransportMode::Tcp | TransportMode::Noise => {
                attempt(
                    identity,
                    node,
                    address,
                    TransportKind::Tcp,
                    telemetry,
                    deadline,
                    network,
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
                    network,
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
                    network,
                );
                tokio::pin!(q);
                tokio::select! {
                    result = &mut q => match result { Ok(c) => return Ok(c), Err(_) => return attempt(identity, node, address, TransportKind::Tcp, telemetry, deadline, network).await },
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                let t = attempt(
                    identity,
                    node,
                    address,
                    TransportKind::Tcp,
                    telemetry,
                    deadline,
                    network,
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

/// Dial a replay-safe endpoint using a key obtained over an authenticated
/// satellite connection. Noise authenticates this key; it supplies no TLS leaf.
pub async fn dial_noise(
    address: &str,
    protocol: i32,
    public_key: &[u8],
    timeout: Duration,
    telemetry: Option<&Telemetry>,
) -> io::Result<Transport> {
    let mut event = Attempt {
        telemetry: telemetry.cloned(),
        kind: TransportKind::Noise,
        start: Instant::now(),
        outcome: Outcome::Cancelled,
    };
    let connect = async {
        let tcp = TcpStream::connect(address).await?;
        tcp.set_nodelay(true)?;
        let io = crate::noise::NoiseStream::connect(tcp, protocol, public_key).await?;
        Ok(Transport {
            io: Box::new(io),
            peer_cert: Vec::new(),
            kind: TransportKind::Noise,
        })
    };
    let result = if let Some(deadline) = tokio::time::Instant::now().checked_add(timeout) {
        tokio::time::timeout_at(deadline, connect)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Noise connection dial timed out",
                ))
            })
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

type NoiseFuture = Pin<Box<dyn Future<Output = io::Result<Transport>> + Send + Sync>>;
type NoiseStart = Box<dyn FnOnce(Vec<u8>) -> NoiseFuture + Send + Sync>;

// The first write becomes IK payload. Subsequent I/O completes authentication;
// only replay-safe Upload/Download connections are wrapped this way.
// Conn::open_stream flushes INVOKE before sending the first piece request, so
// this does not cork INVOKE and the request together as Go's piece path does.
struct DeferredNoise {
    start: Option<NoiseStart>,
    pending: Option<NoiseFuture>,
    connected: Option<Transport>,
    failed: bool,
}
impl DeferredNoise {
    fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::other("Noise connection failed")));
        }
        if let Some(start) = self.start.take() {
            self.pending = Some(start(Vec::new()));
        }
        if let Some(pending) = &mut self.pending {
            match std::task::ready!(pending.as_mut().poll(cx)) {
                Ok(io) => self.connected = Some(io),
                Err(error) => {
                    self.failed = true;
                    self.pending = None;
                    return Poll::Ready(Err(error));
                }
            }
            self.pending = None;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for DeferredNoise {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(start) = self.start.take() {
            let n = data.len().min(crate::noise::MAX_EARLY_DATA);
            self.pending = Some(start(data[..n].to_vec()));
            return Poll::Ready(Ok(n));
        }
        std::task::ready!(self.poll_connect(cx))?;
        Pin::new(self.connected.as_mut().expect("connected")).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_connect(cx))?;
        Pin::new(self.connected.as_mut().expect("connected")).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_connect(cx))?;
        Pin::new(self.connected.as_mut().expect("connected")).poll_shutdown(cx)
    }
}
impl AsyncRead for DeferredNoise {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.poll_connect(cx))?;
        Pin::new(self.connected.as_mut().expect("connected")).poll_read(cx, out)
    }
}

/// Dial a replay-safe piece endpoint. When early data is enabled, authentication
/// is deferred to the first I/O; connection telemetry records its actual outcome.
pub async fn dial_noise_with_options(
    address: &str,
    protocol: i32,
    public_key: &[u8],
    timeout: Duration,
    options: &ConnectionOptions,
    fast_open_advertised: bool,
) -> io::Result<Transport> {
    let mut event = Attempt {
        telemetry: options.telemetry.clone(),
        kind: TransportKind::Noise,
        start: Instant::now(),
        outcome: Outcome::Error,
    };
    let initiator = crate::noise::Initiator::new(protocol, public_key)?;
    let public_key = public_key.to_vec();
    event.outcome = Outcome::Cancelled;
    let address = address.to_owned();
    let network = options.network.clone();
    let early = network.noise_early_data;
    let start: NoiseStart = Box::new(move |payload| {
        Box::pin(async move {
            // Start the deadline when first I/O triggers the actual dial, not while
            // an unused connection is held. It covers DNS, address candidates and IK.
            let connect = async {
                let mut first = Some(initiator);
                let stream = noise_exchange(
                    &address,
                    || {
                        let mut initiator = match first.take() {
                            Some(initiator) => initiator,
                            None => crate::noise::Initiator::new(protocol, &public_key)?,
                        };
                        initiator.set_payload(&payload)?;
                        Ok(initiator)
                    },
                    &network,
                    fast_open_advertised && network.tcp_fast_open,
                )
                .await?;
                Ok(Transport {
                    io: stream,
                    peer_cert: Vec::new(),
                    kind: TransportKind::Noise,
                })
            };
            let result = if let Some(deadline) = tokio::time::Instant::now().checked_add(timeout) {
                tokio::time::timeout_at(deadline, connect)
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Noise dial timed out",
                        ))
                    })
            } else {
                connect.await
            };
            event.outcome = if result.is_ok() {
                Outcome::Success
            } else {
                Outcome::Error
            };
            drop(event);
            result
        })
    });
    if !early {
        return start(Vec::new()).await;
    }
    Ok(Transport {
        io: Box::new(DeferredNoise {
            start: Some(start),
            pending: None,
            connected: None,
            failed: false,
        }),
        peer_cert: Vec::new(),
        kind: TransportKind::Noise,
    })
}

async fn noise_exchange(
    address: &str,
    make_initiator: impl FnMut() -> io::Result<crate::noise::Initiator>,
    network: &NetworkOptions,
    fast_open: bool,
) -> io::Result<Box<dyn Io>> {
    let addresses: Vec<_> = tokio::net::lookup_host(address).await?.collect();
    noise_exchange_with(
        &addresses,
        make_initiator,
        fast_open,
        |addr, fast| async move {
            let socket = crate::socket::socket(addr, network)?;
            #[cfg(any(
                windows,
                target_os = "linux",
                target_os = "android",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly",
                target_os = "macos",
                target_os = "ios",
                target_os = "watchos",
                target_os = "tvos"
            ))]
            if fast {
                return Ok(
                    Box::new(tokio_tfo::TfoStream::connect_with_socket(socket, addr).await?)
                        as Box<dyn Io>,
                );
            }
            // On other platforms the Fast Open attempt fails before sending bytes;
            // the race immediately uses ordinary TCP, without a tokio-tfo dependency.
            if fast {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TCP Fast Open unavailable",
                ));
            }
            Ok(Box::new(socket.connect(addr).await?) as Box<dyn Io>)
        },
    )
    .await
}

// The connector is injectable so tests control unavailable/stalled TFO without
// depending on the host kernel, resolver order, or socket settings.
async fn noise_exchange_with<C, F>(
    addresses: &[std::net::SocketAddr],
    mut make_initiator: impl FnMut() -> io::Result<crate::noise::Initiator>,
    fast_open: bool,
    connect: C,
) -> io::Result<Box<dyn Io>>
where
    C: Fn(std::net::SocketAddr, bool) -> F,
    F: Future<Output = io::Result<Box<dyn Io>>>,
{
    use futures_util::{StreamExt, stream::FuturesUnordered};
    let mut candidates = FuturesUnordered::new();
    for (i, &addr) in addresses.iter().enumerate() {
        // Each address has a fresh IK exchange. Only the two legs for this
        // address reuse a message, staying within the advertised debounce limit
        // without denying other addresses a handshake when this one stalls.
        let initiator = make_initiator()?;
        let connect = &connect;
        candidates.push(async move {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(250).saturating_mul(i as u32)).await;
            }
            let exchange = async {
                let attempt = |fast| {
                    let message = &initiator.message;
                    async move {
                        let stream = connect(addr, fast).await?;
                        crate::noise::exchange(stream, message).await
                    }
                };
                let normal = attempt(false);
                if !fast_open { return normal.await; }
                let fast = attempt(true);
                tokio::pin!(fast);
                tokio::select! {
                    result = &mut fast => return match result { Ok(v) => Ok(v), Err(_) => normal.await },
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                tokio::pin!(normal);
                tokio::select! {
                    result = &mut fast => match result { Ok(v) => Ok(v), Err(_) => normal.await },
                    result = &mut normal => match result { Ok(v) => Ok(v), Err(_) => fast.await },
                }
            };
            let (stream, response) = exchange.await?;
            // An unauthenticated response cannot win the address race.
            Ok(Box::new(initiator.finish(stream, &response)?) as Box<dyn Io>)
        });
    }
    let mut last = io::Error::other("address resolved to no endpoints");
    while let Some(result) = candidates.next().await {
        match result {
            Ok(v) => return Ok(v),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn initiator(protocol: i32, key: &[u8], payload: &[u8]) -> io::Result<crate::noise::Initiator> {
        let mut initiator = crate::noise::Initiator::new(protocol, key)?;
        initiator.set_payload(payload)?;
        Ok(initiator)
    }

    #[tokio::test]
    async fn stalled_fast_open_fallback_reuses_identical_early_handshake() {
        let key = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            async fn first(tcp: &mut TcpStream) -> Vec<u8> {
                let mut prefix = [0; 8];
                tcp.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, crate::noise::HEADER);
                let mut h = [0; 4];
                tcp.read_exact(&mut h).await.unwrap();
                let n = ((h[1] as usize) << 16) | ((h[2] as usize) << 8) | h[3] as usize;
                let mut record = h.to_vec();
                record.resize(n + 4, 0);
                tcp.read_exact(&mut record[4..]).await.unwrap();
                record
            }
            let (mut stalled, _) = listener.accept().await.unwrap();
            let a = first(&mut stalled).await;
            let (mut tcp, _) = listener.accept().await.unwrap();
            let b = first(&mut tcp).await;
            assert_eq!(a, b, "duplicate suppression requires identical handshakes");
            let (read, write) = tcp.into_split();
            let io = tokio::io::join(std::io::Cursor::new(b).chain(read), write);
            let mut noise = crate::noise::NoiseStream::accept(io, 1, &key.private)
                .await
                .unwrap();
            let mut payload = [0; 4];
            noise.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            noise.write_all(b"pong").await.unwrap();
            noise.flush().await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(4), async {
            // Simulate a connected TFO leg over ordinary TCP. The first server
            // stalls its response; the second wins. No kernel TFO is required.
            let mut stream = noise_exchange_with(
                &[address.parse().unwrap()],
                || initiator(1, &key.public, b"ping"),
                true,
                |addr, _fast| async move {
                    Ok(Box::new(TcpStream::connect(addr).await?) as Box<dyn Io>)
                },
            )
            .await
            .unwrap();
            stream.flush().await.unwrap();
            let mut got = [0; 4];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"pong");
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unavailable_fast_open_falls_back_before_sending_handshake() {
        let key = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let seen = attempts.clone();
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = noise_exchange_with(
                &["127.0.0.1:1".parse().unwrap()],
                || initiator(1, &key.public, b"ping"),
                true,
                |_, fast| {
                    seen.lock().unwrap().push(fast);
                    let private = key.private.clone();
                    async move {
                        if fast {
                            return Err(io::Error::new(io::ErrorKind::Unsupported, "TFO disabled"));
                        }
                        let (client, mut server) = tokio::io::duplex(4096);
                        tokio::spawn(async move {
                            let mut prefix = [0; 8];
                            server.read_exact(&mut prefix).await.unwrap();
                            assert_eq!(&prefix, crate::noise::HEADER);
                            let mut stream = crate::noise::NoiseStream::accept(server, 1, &private)
                                .await
                                .unwrap();
                            let mut payload = [0; 4];
                            stream.read_exact(&mut payload).await.unwrap();
                            assert_eq!(&payload, b"ping");
                            stream.write_all(b"pong").await.unwrap();
                            stream.flush().await.unwrap();
                        });
                        Ok(Box::new(client) as Box<dyn Io>)
                    }
                },
            )
            .await
            .unwrap();
            let mut response = [0; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
        })
        .await
        .unwrap();
        assert_eq!(*attempts.lock().unwrap(), [true, false]);
    }

    #[tokio::test(start_paused = true)]
    async fn noise_address_race_survives_stalled_or_unauthenticated_first_address() {
        let addresses = ["[::1]:1", "127.0.0.1:1"].map(|addr| addr.parse().unwrap());
        for protocol in [1, 2] {
            for fast in [false, true] {
                for reject in [false, true] {
                    let key =
                        snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap())
                            .generate_keypair()
                            .unwrap();
                    let servers = Mutex::new(Vec::new());
                    let mut stream = tokio::time::timeout(
                        Duration::from_secs(2),
                        noise_exchange_with(
                            &addresses,
                            || initiator(protocol, &key.public, b"ping"),
                            fast,
                            |addr, _| {
                                let private = key.private.clone();
                                let (client, mut server) = tokio::io::duplex(4096);
                                servers.lock().unwrap().push(tokio::spawn(async move {
                                    let mut prefix = [0; 8];
                                    server.read_exact(&mut prefix).await.unwrap();
                                    assert_eq!(&prefix, crate::noise::HEADER);
                                    if addr.is_ipv6() {
                                        let mut header = [0; 4];
                                        server.read_exact(&mut header).await.unwrap();
                                        let len = ((header[1] as usize) << 16)
                                            | ((header[2] as usize) << 8)
                                            | header[3] as usize;
                                        server.read_exact(&mut vec![0; len]).await.unwrap();
                                        if reject {
                                            // A correctly framed but unauthenticated IK response.
                                            server.write_all(&[0x80, 0, 0, 48]).await.unwrap();
                                            server.write_all(&[0; 48]).await.unwrap();
                                            return;
                                        }
                                        std::future::pending::<()>().await;
                                    }
                                    let mut stream = crate::noise::NoiseStream::accept(
                                        server, protocol, &private,
                                    )
                                    .await
                                    .unwrap();
                                    let mut payload = [0; 4];
                                    stream.read_exact(&mut payload).await.unwrap();
                                    assert_eq!(&payload, b"ping");
                                    stream.write_all(b"pong").await.unwrap();
                                    stream.flush().await.unwrap();
                                }));
                                async move { Ok(Box::new(client) as Box<dyn Io>) }
                            },
                        ),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    let mut response = [0; 4];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"pong");
                    for server in servers.into_inner().unwrap() {
                        server.abort();
                        match server.await {
                            Ok(()) => {}
                            Err(error) => assert!(error.is_cancelled()),
                        }
                    }
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn noise_handshake_copies_are_bounded_per_address() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Both address families, multiple addresses, and a response slower than
        // every stagger. Every address must get its own handshake.
        let addresses = ["[::1]:1", "127.0.0.1:1", "127.0.0.2:1"].map(|addr| addr.parse().unwrap());
        for (fast, reject, expected) in [
            (true, false, 6),
            (false, false, 3),
            (true, true, 6),
            (false, true, 3),
        ] {
            let copies = Arc::new(Mutex::new(Vec::new()));
            let attempts = Arc::new(AtomicUsize::new(0));
            let mut servers = Vec::new();
            let key = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2b".parse().unwrap())
                .generate_keypair()
                .unwrap();
            let server_handles = Mutex::new(&mut servers);
            let result = tokio::time::timeout(
                Duration::from_millis(1100),
                noise_exchange_with(
                    &addresses,
                    || initiator(1, &key.public, b"early request"),
                    fast,
                    |addr, _| {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        let copies = copies.clone();
                        let (client, mut server) = tokio::io::duplex(4096);
                        server_handles
                            .lock()
                            .unwrap()
                            .push(tokio::spawn(async move {
                                let mut prefix = [0; 12];
                                if server.read_exact(&mut prefix).await.is_err() {
                                    return;
                                }
                                assert_eq!(&prefix[..8], crate::noise::HEADER);
                                let len = ((prefix[9] as usize) << 16)
                                    | ((prefix[10] as usize) << 8)
                                    | prefix[11] as usize;
                                let mut message = vec![0; len];
                                server.read_exact(&mut message).await.unwrap();
                                copies
                                    .lock()
                                    .unwrap()
                                    .push((addr, [prefix.as_slice(), message.as_slice()].concat()));
                                if reject {
                                    // A rejected handshake must not cause more than
                                    // two identical copies for this address.
                                    server.write_all(&[0; 4]).await.unwrap();
                                    return;
                                }
                                std::future::pending::<()>().await;
                            }));
                        async move { Ok(Box::new(client) as Box<dyn Io>) }
                    },
                ),
            )
            .await;
            if reject {
                assert!(result.unwrap().is_err());
            } else {
                assert!(result.is_err(), "all responders deliberately stall");
            }
            assert_eq!(attempts.load(Ordering::Relaxed), if fast { 6 } else { 3 });
            let copies = copies.lock().unwrap();
            assert_eq!(copies.len(), expected);
            let mut messages = Vec::new();
            for addr in addresses {
                let sent: Vec<_> = copies
                    .iter()
                    .filter(|(a, _)| *a == addr)
                    .map(|(_, m)| m)
                    .collect();
                assert_eq!(sent.len(), if fast { 2 } else { 1 });
                assert!(sent.iter().all(|m| *m == sent[0]));
                assert!(
                    !messages.contains(&sent[0]),
                    "addresses must use fresh IK messages"
                );
                messages.push(sent[0]);
            }
            for server in servers {
                server.abort();
            }
        }
    }

    #[tokio::test]
    async fn deferred_handshake_timeout_and_unused_drop_report_actual_outcomes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let options = ConnectionOptions {
            telemetry: Some(Telemetry::new(move |e| sink.lock().unwrap().push(e))),
            ..Default::default()
        };
        let address = listener.local_addr().unwrap().to_string();
        let unused = dial_noise_with_options(
            &address,
            1,
            &[9; 32],
            Duration::from_millis(30),
            &options,
            false,
        )
        .await
        .unwrap();
        assert!(events.lock().unwrap().is_empty());
        drop(unused);
        let mut stream = dial_noise_with_options(
            &address,
            1,
            &[9; 32],
            Duration::from_millis(30),
            &options,
            false,
        )
        .await
        .unwrap();
        stream.write_all(b"request").await.unwrap();
        assert_eq!(
            stream.flush().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(stream.write_all(b"cannot reuse").await.is_err());
        let outcomes: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .map(|e| match e {
                TelemetryEvent::Connection { outcome, .. } => *outcome,
            })
            .collect();
        assert_eq!(outcomes, [Outcome::Cancelled, Outcome::Error]);
    }

    #[tokio::test]
    async fn stalled_noise_handshake_obeys_deadline_and_reports_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let telemetry = Telemetry::new(move |event| sink.lock().unwrap().push(event));
        let error = dial_noise(
            &listener.local_addr().unwrap().to_string(),
            1,
            &[9; 32],
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
                transport: TransportKind::Noise,
                outcome: Outcome::Error,
                ..
            }]
        ));
    }

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
