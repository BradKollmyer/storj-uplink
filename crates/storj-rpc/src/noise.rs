//! Storj's `noiseconn` framing over TCP. Only replay-safe RPCs may use this stream.
//! The responder key must come from a trusted source (the authenticated satellite).
//! We complete IK with empty payloads before sending any application data.

use snow::{
    HandshakeState,
    params::{CipherChoice, DHChoice, HashChoice, NoiseParams},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;

/// Storj TCP protocol multiplexer prefix.
pub const HEADER: &[u8; 8] = b"DRPC!N!1";
const MAX_PLAIN: usize = 65535;
const TAG: usize = 16;
const MAX_RECORD: usize = MAX_PLAIN + TAG;

// Snow's default X25519 resolver accepts all-zero DH outputs. Go's X25519
// rejects these: preserve that behavior for both static and ephemeral keys.
struct Resolver;
impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        DefaultResolver.resolve_rng()
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver
            .resolve_dh(choice)
            .map(|dh| Box::new(CheckedDh(dh)) as Box<dyn Dh>)
    }
}
struct CheckedDh(Box<dyn Dh>);
impl Dh for CheckedDh {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn pub_len(&self) -> usize {
        self.0.pub_len()
    }
    fn priv_len(&self) -> usize {
        self.0.priv_len()
    }
    fn set(&mut self, key: &[u8]) {
        self.0.set(key);
    }
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        self.0.generate(rng)
    }
    fn pubkey(&self) -> &[u8] {
        self.0.pubkey()
    }
    fn privkey(&self) -> &[u8] {
        self.0.privkey()
    }
    fn dh(&self, key: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        self.0.dh(key, out)?;
        // A fixed-length reduction avoids branching on individual secret bytes.
        if out[..self.0.dh_len()].iter().fold(0u8, |a, b| a | b) == 0 {
            return Err(snow::Error::Dh);
        }
        Ok(())
    }
}

fn builder<'a>(params: NoiseParams) -> snow::Builder<'a> {
    snow::Builder::with_resolver(params, Box::new(Resolver))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn noise_error(error: snow::Error) -> io::Error {
    invalid(error.to_string())
}

fn params(protocol: i32) -> io::Result<NoiseParams> {
    let name = match protocol {
        1 => "Noise_IK_25519_ChaChaPoly_BLAKE2b",
        2 => "Noise_IK_25519_AESGCM_BLAKE2b",
        _ => return Err(invalid("unsupported Noise protocol")),
    };
    name.parse().map_err(noise_error)
}

fn header(len: usize) -> [u8; 4] {
    [0x80, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}
fn record_len(header: &[u8]) -> io::Result<usize> {
    let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    if header[0] != 0x80 || !(TAG..=MAX_RECORD).contains(&len) {
        return Err(invalid("invalid Noise record header or length"));
    }
    Ok(len)
}
async fn read_record<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    io.read_exact(&mut h).await?;
    let mut body = vec![0; record_len(&h)?];
    io.read_exact(&mut body).await?;
    Ok(body)
}
async fn write_handshake<S: AsyncWrite + Unpin>(
    io: &mut S,
    hs: &mut HandshakeState,
) -> io::Result<()> {
    let mut body = [0; 256];
    let n = hs.write_message(&[], &mut body).map_err(noise_error)?;
    io.write_all(&header(n)).await?;
    io.write_all(&body[..n]).await?;
    io.flush().await
}

/// Encrypted, ordered Noise records with bounded buffering and implicit nonces.
pub struct NoiseStream<S> {
    io: S,
    send: Box<dyn Cipher>,
    recv: Box<dyn Cipher>,
    send_nonce: u64,
    recv_nonce: u64,
    write: Vec<u8>,
    written: usize,
    read: Vec<u8>,
    read_pos: usize,
    read_target: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    failed: bool,
    eof: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseStream<S> {
    /// Authenticate the responder against its advertised X25519 key.
    /// Writes the TCP mux prefix, then completes IK without early application data.
    pub async fn connect(mut io: S, protocol: i32, public_key: &[u8]) -> io::Result<Self> {
        if public_key.len() != 32 || public_key.iter().all(|b| *b == 0) {
            return Err(invalid("invalid Noise public key"));
        }
        let params = params(protocol)?;
        let cipher = params.cipher;
        let builder = builder(params);
        let key = Zeroizing::new(builder.generate_keypair().map_err(noise_error)?.private);
        let mut hs = builder
            .local_private_key(&key)
            .map_err(noise_error)?
            .remote_public_key(public_key)
            .map_err(noise_error)?
            .build_initiator()
            .map_err(noise_error)?;
        io.write_all(HEADER).await?;
        write_handshake(&mut io, &mut hs).await?;
        let record = read_record(&mut io).await?;
        let mut payload = vec![0; MAX_RECORD];
        if hs
            .read_message(&record, &mut payload)
            .map_err(noise_error)?
            != 0
        {
            return Err(invalid("unexpected Noise handshake payload"));
        }
        Self::established(io, &mut hs, cipher, true)
    }

    /// Accept an IK connection after the caller has consumed [`HEADER`].
    /// Intended for local protocol test servers; early application data is rejected.
    pub async fn accept(mut io: S, protocol: i32, private_key: &[u8]) -> io::Result<Self> {
        let params = params(protocol)?;
        let cipher = params.cipher;
        let mut hs = builder(params)
            .local_private_key(private_key)
            .map_err(noise_error)?
            .build_responder()
            .map_err(noise_error)?;
        let record = read_record(&mut io).await?;
        let mut payload = vec![0; MAX_RECORD];
        if hs
            .read_message(&record, &mut payload)
            .map_err(noise_error)?
            != 0
        {
            return Err(invalid("early Noise application data is unsupported"));
        }
        write_handshake(&mut io, &mut hs).await?;
        Self::established(io, &mut hs, cipher, false)
    }

    fn established(
        io: S,
        hs: &mut HandshakeState,
        cipher: CipherChoice,
        initiator: bool,
    ) -> io::Result<Self> {
        if !hs.is_handshake_finished() {
            return Err(invalid("incomplete Noise handshake"));
        }
        // Go noiseconn permits 65535 *plaintext* bytes (65551 with the tag).
        // Snow TransportState caps ciphertext at 65535, so use its ciphers with
        // the completed handshake's split keys. Preserve Noise's nonce rules:
        // independent directions, start at zero, never use 2^64-1 or reuse after error.
        let (first, second) = hs.dangerously_get_raw_split();
        let first = Zeroizing::new(first);
        let second = Zeroizing::new(second);
        let mut send = DefaultResolver
            .resolve_cipher(&cipher)
            .ok_or_else(|| invalid("missing Noise cipher"))?;
        let mut recv = DefaultResolver
            .resolve_cipher(&cipher)
            .ok_or_else(|| invalid("missing Noise cipher"))?;
        if initiator {
            send.set(&first);
            recv.set(&second);
        } else {
            send.set(&second);
            recv.set(&first);
        }
        Ok(Self {
            io,
            send,
            recv,
            send_nonce: 0,
            recv_nonce: 0,
            write: Vec::new(),
            written: 0,
            read: vec![0; MAX_RECORD],
            read_pos: 0,
            read_target: 4,
            plain: Vec::new(),
            plain_pos: 0,
            failed: false,
            eof: false,
        })
    }

    fn drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid("Noise connection failed")));
        }
        while self.written < self.write.len() {
            match ready!(Pin::new(&mut self.io).poll_write(cx, &self.write[self.written..])) {
                Ok(0) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(n) => self.written += n,
                Err(e) => {
                    self.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        self.write.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.send_nonce == u64::MAX {
            this.failed = true;
            return Poll::Ready(Err(invalid("Noise nonce exhausted")));
        }
        let n = buf.len().min(MAX_PLAIN);
        this.write.resize(4 + n + TAG, 0);
        this.write[..4].copy_from_slice(&header(n + TAG));
        this.send
            .encrypt(this.send_nonce, &[], &buf[..n], &mut this.write[4..]);
        this.send_nonce += 1;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        let result = ready!(Pin::new(&mut this.io).poll_flush(cx));
        if result.is_err() {
            this.failed = true;
        }
        Poll::Ready(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        let result = ready!(Pin::new(&mut self.io).poll_shutdown(cx));
        if result.is_err() {
            self.failed = true;
        }
        Poll::Ready(result)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("Noise connection failed")));
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.plain_pos < this.plain.len() {
                let n = out.remaining().min(this.plain.len() - this.plain_pos);
                out.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut buf = ReadBuf::new(&mut this.read[this.read_pos..this.read_target]);
            if let Err(e) = ready!(Pin::new(&mut this.io).poll_read(cx, &mut buf)) {
                this.failed = true;
                return Poll::Ready(Err(e));
            }
            let n = buf.filled().len();
            if n == 0 {
                if this.read_pos == 0 && this.read_target == 4 {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.failed = true;
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.read_pos += n;
            if this.read_pos < this.read_target {
                continue;
            }
            if this.read_target == 4 {
                match record_len(&this.read[..4]) {
                    Ok(n) => {
                        this.read_target = n;
                        this.read_pos = 0;
                        continue;
                    }
                    Err(e) => {
                        this.failed = true;
                        return Poll::Ready(Err(e));
                    }
                }
            }
            if this.recv_nonce == u64::MAX {
                this.failed = true;
                return Poll::Ready(Err(invalid("Noise nonce exhausted")));
            }
            this.plain.resize(this.read_target - TAG, 0);
            if let Err(e) = this.recv.decrypt(
                this.recv_nonce,
                &[],
                &this.read[..this.read_target],
                &mut this.plain,
            ) {
                this.failed = true;
                return Poll::Ready(Err(noise_error(e)));
            }
            this.recv_nonce += 1;
            this.plain_pos = 0;
            this.read_pos = 0;
            this.read_target = 4;
            // Empty authenticated records must not be exposed as EOF or starve the executor.
            if this.plain.is_empty() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{DuplexStream, duplex},
        time::{Duration, timeout},
    };

    async fn pair(
        protocol: i32,
        capacity: usize,
    ) -> (NoiseStream<DuplexStream>, NoiseStream<DuplexStream>) {
        let key = snow::Builder::new(params(protocol).unwrap())
            .generate_keypair()
            .unwrap();
        let (client, mut server) = duplex(capacity);
        let (client, server) =
            tokio::join!(NoiseStream::connect(client, protocol, &key.public), async {
                let mut prefix = [0; 8];
                server.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, HEADER);
                NoiseStream::accept(server, protocol, &key.private).await
            });
        (client.unwrap(), server.unwrap())
    }

    #[tokio::test]
    async fn both_ciphers_handle_partial_io_large_records_and_shutdown() {
        timeout(Duration::from_secs(10), async {
            for protocol in [1, 2] {
                let (mut client, mut server) = pair(protocol, 31).await;
                let task = tokio::spawn(async move {
                    for len in [1, MAX_PLAIN, MAX_PLAIN + 1, 180_000] {
                        let mut payload = vec![0; len];
                        server.read_exact(&mut payload).await.unwrap();
                        server.write_all(&payload).await.unwrap();
                        server.flush().await.unwrap();
                    }
                    server.shutdown().await.unwrap();
                });
                for len in [1, MAX_PLAIN, MAX_PLAIN + 1, 180_000] {
                    let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
                    client.write_all(&payload).await.unwrap();
                    client.flush().await.unwrap();
                    let mut got = vec![0; len];
                    client.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, payload);
                }
                assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
                task.await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn invalid_keys_protocols_and_wrong_responder_are_rejected() {
        for (protocol, key) in [
            (0, vec![1; 32]),
            (3, vec![1; 32]),
            (1, vec![1; 31]),
            (2, vec![0; 32]),
        ] {
            let (client, _) = duplex(1024);
            assert!(NoiseStream::connect(client, protocol, &key).await.is_err());
        }
        // Nonzero small-order public key: rejects before writing a handshake.
        let mut low_order = [0; 32];
        low_order[0] = 1;
        let (client, _server) = duplex(1024);
        assert!(NoiseStream::connect(client, 1, &low_order).await.is_err());
        for protocol in [1, 2] {
            let builder = snow::Builder::new(params(protocol).unwrap());
            let actual = builder.generate_keypair().unwrap();
            let wrong = builder.generate_keypair().unwrap();
            let (client, mut server) = duplex(1024);
            let (client, server) = tokio::join!(
                NoiseStream::connect(client, protocol, &wrong.public),
                async {
                    server.read_exact(&mut [0; 8]).await.unwrap();
                    NoiseStream::accept(server, protocol, &actual.private).await
                }
            );
            assert!(client.is_err());
            assert!(server.is_err());
        }
    }

    #[test]
    fn low_order_ephemeral_keys_fail_dh() {
        let mut dh = Resolver.resolve_dh(&DHChoice::Curve25519).unwrap();
        dh.set(&[42; 32]);
        let mut out = [0; 32];
        assert!(dh.dh(&[0; 32], &mut out).is_err());
        let mut low_order = [0; 32];
        low_order[0] = 1;
        assert!(dh.dh(&low_order, &mut out).is_err());
    }

    #[tokio::test]
    async fn malformed_truncated_and_corrupt_records_poison_the_stream() {
        for raw in [
            vec![0, 0, 0, 16],
            vec![0x80, 1, 0, 16],
            vec![0x80, 0, 0, 15],
            vec![0x80, 0],
            vec![0x80, 0, 0, 20, 0],
            vec![
                0x80, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ] {
            let (mut client, mut server) = pair(1, 1024).await;
            server.io.write_all(&raw).await.unwrap();
            server.io.shutdown().await.unwrap();
            assert!(client.read(&mut [0]).await.is_err());
            assert!(client.read(&mut [0]).await.is_err());
            assert!(client.write_all(b"no nonce reuse").await.is_err());
        }
    }

    #[tokio::test]
    async fn tampering_replay_and_nonce_exhaustion_are_rejected() {
        for protocol in [1, 2] {
            let (mut client, mut server) = pair(protocol, 1024).await;
            server.write_all(b"data").await.unwrap();
            let record = server.write.clone();
            server.flush().await.unwrap();
            let mut payload = [0; 4];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"data");
            server.io.write_all(&record).await.unwrap();
            assert!(client.read(&mut payload).await.is_err());

            let (mut client, mut server) = pair(protocol, 1024).await;
            server.write_all(b"data").await.unwrap();
            server.write[4] ^= 1;
            server.flush().await.unwrap();
            assert!(client.read(&mut payload).await.is_err());

            let (mut client, mut server) = pair(protocol, 1024).await;
            client.send_nonce = u64::MAX;
            assert!(client.write_all(b"exhausted").await.is_err());
            server.recv_nonce = u64::MAX;
            // Send a correctly framed record; exhaustion must fail before decrypting.
            client.io.write_all(&record).await.unwrap();
            assert!(server.read(&mut payload).await.is_err());
        }
    }

    #[tokio::test]
    async fn cancellation_preserves_partial_read_and_write_state() {
        let (mut client, mut server) = pair(1, 31).await;
        let payload = vec![42; 1000];
        server.write_all(&payload).await.unwrap();
        // The tiny underlying pipe fills mid-record. Resume the cancelled flush.
        assert!(
            timeout(Duration::from_millis(5), server.flush())
                .await
                .is_err()
        );
        let mut got = vec![0; payload.len()];
        assert!(
            timeout(Duration::from_millis(5), client.read_exact(&mut got))
                .await
                .is_err()
        );
        let (sent, read) = tokio::join!(server.flush(), client.read_exact(&mut got));
        sent.unwrap();
        read.unwrap();
        assert_eq!(got, payload);
    }
}
