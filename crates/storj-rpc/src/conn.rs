//! Unary DRPC invoke over generic `AsyncRead + AsyncWrite`.
//!
//! No TLS here (PR 9b). One in-flight RPC per connection is a **pool**
//! invariant, not a wire rule: frames still carry `stream_id`.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::{
    DEFAULT_SPLIT_SIZE, DRPC_TLS_MUX_PREFIX, FrameError, Kind, MAX_PACKET_SIZE, Packet,
    PacketAssembler, append_packet_data, parse_frame, unmarshal_error,
};

/// Client-side DRPC errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed frame or packet reassembly failure.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// EOF in the middle of a frame.
    #[error("unexpected end of stream while reading a DRPC frame")]
    Truncated,
    /// Peer closed before sending a response message.
    #[error("rpc closed without a response message")]
    Closed,
    /// Remote `Kind::ERROR` packet.
    #[error("DRPC remote error (code {code}): {message}")]
    Remote {
        /// `drpcerr` code (0 if absent).
        code: u64,
        /// Error text after the 8-byte code prefix.
        message: String,
    },
    /// Packet kind was not a message, error, or close.
    #[error("unexpected DRPC packet kind {0}")]
    UnexpectedKind(Kind),
    /// Packet arrived for a stream other than the in-flight RPC.
    #[error("unexpected DRPC stream id {got} (expected {expected})")]
    UnexpectedStream {
        /// Stream id on the packet.
        got: u64,
        /// Stream id of the in-flight invoke.
        expected: u64,
    },
    /// First 8 bytes were not [`DRPC_TLS_MUX_PREFIX`].
    #[error("DRPC mux prefix mismatch (want DRPC!!!1, got {got:?})")]
    MuxPrefix {
        /// Bytes actually read.
        got: [u8; 8],
    },
    /// Transport I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Write `DRPC!!!1` (`drpcmigrate.DRPCHeader`) to `w` and flush.
pub async fn write_tls_mux_prefix<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    w.write_all(DRPC_TLS_MUX_PREFIX).await?;
    w.flush().await
}

/// Read 8 bytes and require them to equal [`DRPC_TLS_MUX_PREFIX`].
pub async fn read_tls_mux_prefix<R: AsyncRead + Unpin>(r: &mut R) -> Result<[u8; 8], Error> {
    let mut got = [0u8; 8];
    r.read_exact(&mut got).await?;
    if got.as_slice() != DRPC_TLS_MUX_PREFIX {
        return Err(Error::MuxPrefix { got });
    }
    Ok(got)
}

/// Client DRPC connection over a raw byte stream (no TLS).
pub struct Conn<T> {
    io: T,
    buf: Vec<u8>,
    pos: usize,
    next_stream_id: u64,
    assembler: PacketAssembler,
    split_size: usize,
}

impl<T> Conn<T> {
    /// Wrap an already-connected transport. Does not write a mux prefix.
    pub fn new(io: T) -> Self {
        Self {
            io,
            buf: Vec::new(),
            pos: 0,
            next_stream_id: 1,
            assembler: PacketAssembler::default(),
            split_size: DEFAULT_SPLIT_SIZE,
        }
    }

    /// Consume the connection and return the inner transport.
    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T: AsyncWrite + Unpin> Conn<T> {
    /// Write the TLS mux prefix. Call before any invoke when talking to a
    /// muxed listener; on real Storj this happens *before* TLS, not here.
    pub async fn write_tls_mux_prefix(&mut self) -> io::Result<()> {
        write_tls_mux_prefix(&mut self.io).await
    }

    /// Write a single DRPC packet (split into frames if larger than split size).
    pub async fn write_packet(&mut self, packet: &Packet) -> Result<(), Error> {
        self.write_packet_data(
            packet.stream_id,
            packet.message_id,
            packet.kind,
            packet.control,
            &packet.data,
        )
        .await?;
        self.flush().await
    }

    async fn flush(&mut self) -> Result<(), Error> {
        self.io.flush().await?;
        Ok(())
    }

    async fn write_packet_data(
        &mut self,
        stream_id: u64,
        message_id: u64,
        kind: Kind,
        control: bool,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut buf = Vec::with_capacity(32 + data.len());
        append_packet_data(
            &mut buf,
            stream_id,
            message_id,
            kind,
            control,
            data,
            self.split_size,
        );
        self.io.write_all(&buf).await?;
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> Conn<T> {
    /// Read and check the TLS mux prefix. Call before reading frames.
    pub async fn read_tls_mux_prefix(&mut self) -> Result<[u8; 8], Error> {
        read_tls_mux_prefix(&mut self.io).await
    }

    /// Read the next reassembled packet, including `stream_id`.
    pub async fn read_packet(&mut self) -> Result<Packet, Error> {
        loop {
            match parse_frame(self.unparsed())? {
                Some((frame, consumed)) => {
                    self.consume(consumed);
                    if let Some(pkt) = self.assembler.push(frame)? {
                        return Ok(pkt);
                    }
                }
                None => self.fill().await?,
            }
        }
    }

    fn unparsed(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }

    async fn fill(&mut self) -> Result<(), Error> {
        if self.pos > 0 {
            self.buf.copy_within(self.pos.., 0);
            self.buf.truncate(self.buf.len() - self.pos);
            self.pos = 0;
        }
        if self.buf.len() > MAX_PACKET_SIZE + 32 {
            return Err(FrameError::Overflow.into());
        }
        let mut tmp = [0u8; 4096];
        let n = self.io.read(&mut tmp).await?;
        if n == 0 {
            // Partial frame bytes, or a not-done packet still in the assembler.
            if self.buf.is_empty() && !self.assembler.in_progress() {
                return Err(Error::Closed);
            }
            return Err(Error::Truncated);
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Conn<T> {
    /// Unary RPC: `Invoke` + `Message` + `CloseSend`, then wait for a `Message`.
    ///
    /// `rpc` is the invoke path (e.g. `/metainfo.Metainfo/ProjectInfo`).
    /// `request` is already-encoded protobuf (encoding is out of scope here).
    pub async fn invoke(&mut self, rpc: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 1;
        let mut message_id = 0u64;

        message_id += 1;
        self.write_packet_data(stream_id, message_id, Kind::INVOKE, false, rpc.as_bytes())
            .await?;
        message_id += 1;
        self.write_packet_data(stream_id, message_id, Kind::MESSAGE, false, request)
            .await?;
        message_id += 1;
        self.write_packet_data(stream_id, message_id, Kind::CLOSE_SEND, false, &[])
            .await?;
        // One flush for the corked Invoke+Message+CloseSend burst (Go flushes on
        // CloseSend / MsgRecv; TlsStream will not emit records without this).
        self.flush().await?;

        loop {
            let pkt = self.read_packet().await?;
            if pkt.stream_id != stream_id {
                if pkt.stream_id < stream_id {
                    continue;
                }
                return Err(Error::UnexpectedStream {
                    got: pkt.stream_id,
                    expected: stream_id,
                });
            }
            match pkt.kind {
                Kind::MESSAGE => {
                    // Go `defer stream.Close()` after MsgRecv.
                    message_id += 1;
                    self.write_packet_data(stream_id, message_id, Kind::CLOSE, false, &[])
                        .await?;
                    self.flush().await?;
                    return Ok(pkt.data);
                }
                Kind::ERROR => {
                    let (code, message) = unmarshal_error(&pkt.data);
                    return Err(Error::Remote { code, message });
                }
                Kind::CLOSE | Kind::CLOSE_SEND => return Err(Error::Closed),
                Kind::CANCEL => {
                    return Err(Error::Remote {
                        code: 0,
                        message: "canceled".into(),
                    });
                }
                _ if pkt.control => continue,
                other => return Err(Error::UnexpectedKind(other)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, append_frame};

    impl<T> Conn<T> {
        fn with_split_size(mut self, n: usize) -> Self {
            self.split_size = n;
            self
        }
    }

    async fn echo_one<T: AsyncRead + AsyncWrite + Unpin>(
        server: &mut Conn<T>,
    ) -> Result<(), Error> {
        let (stream_id, body) = loop {
            let pkt = server.read_packet().await?;
            if pkt.kind == Kind::MESSAGE {
                break (pkt.stream_id, pkt.data);
            }
            // Skip Invoke and leftover Close/CloseSend from a previous stream.
        };
        server
            .write_packet(&Packet {
                stream_id,
                message_id: 1,
                kind: Kind::MESSAGE,
                control: false,
                data: body,
            })
            .await?;
        server
            .write_packet(&Packet {
                stream_id,
                message_id: 2,
                kind: Kind::CLOSE_SEND,
                control: false,
                data: Vec::new(),
            })
            .await?;
        Ok(())
    }

    async fn drain_until_closed<T: AsyncRead + Unpin>(server: &mut Conn<T>) -> Result<(), Error> {
        loop {
            match server.read_packet().await {
                Ok(_) => {}
                Err(Error::Closed | Error::Truncated) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    async fn echo_unary<T: AsyncRead + AsyncWrite + Unpin>(
        mut server: Conn<T>,
    ) -> Result<(), Error> {
        echo_one(&mut server).await?;
        // Stay up so the client can write Kind::CLOSE (Go defer stream.Close).
        drain_until_closed(&mut server).await
    }

    #[tokio::test]
    async fn invoke_writes_invoke_message_closesend() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let mut client = Conn::new(client_io);
            client.invoke("/echo.Echo/Ping", b"hello").await
        });

        let mut server = Conn::new(server_io);
        let invoke = server.read_packet().await.unwrap();
        assert_eq!(invoke.kind, Kind::INVOKE);
        assert_eq!(invoke.stream_id, 1);
        assert_eq!(invoke.message_id, 1);
        assert_eq!(invoke.data, b"/echo.Echo/Ping");

        let msg = server.read_packet().await.unwrap();
        assert_eq!(msg.kind, Kind::MESSAGE);
        assert_eq!(msg.stream_id, 1);
        assert_eq!(msg.message_id, 2);
        assert_eq!(msg.data, b"hello");

        let close_send = server.read_packet().await.unwrap();
        assert_eq!(close_send.kind, Kind::CLOSE_SEND);
        assert_eq!(close_send.stream_id, 1);
        assert_eq!(close_send.message_id, 3);
        assert!(close_send.data.is_empty());

        server
            .write_packet(&Packet {
                stream_id: 1,
                message_id: 1,
                kind: Kind::MESSAGE,
                control: false,
                data: b"hello".to_vec(),
            })
            .await
            .unwrap();

        let out = client.await.unwrap().unwrap();
        assert_eq!(out, b"hello");

        let close = server.read_packet().await.unwrap();
        assert_eq!(close.kind, Kind::CLOSE);
        assert_eq!(close.stream_id, 1);
        assert_eq!(close.message_id, 4);
        assert!(close.data.is_empty());
    }

    #[tokio::test]
    async fn sequential_invoke_skips_previous_stream_close() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut server = Conn::new(server_io);
            echo_one(&mut server).await?;
            echo_one(&mut server).await?;
            drain_until_closed(&mut server).await
        });

        let mut client = Conn::new(client_io);
        assert_eq!(client.invoke("/echo/A", b"one").await.unwrap(), b"one");
        assert_eq!(client.invoke("/echo/B", b"two").await.unwrap(), b"two");
        drop(client);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn loopback_unary_echo() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { echo_unary(Conn::new(server_io)).await });

        let mut client = Conn::new(client_io);
        let out = client
            .invoke("/echo.Echo/Ping", b"hello")
            .await
            .expect("invoke");
        assert_eq!(out, b"hello");

        drop(client);
        server.await.expect("join").expect("echo");
    }

    #[tokio::test]
    async fn loopback_unary_echo_split_frames() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server =
            tokio::spawn(async move { echo_unary(Conn::new(server_io).with_split_size(8)).await });

        let mut client = Conn::new(client_io).with_split_size(8);
        let payload = vec![b'x'; 40];
        let out = client
            .invoke("/echo.Echo/Ping", &payload)
            .await
            .expect("invoke");
        assert_eq!(out, payload);

        drop(client);
        server.await.expect("join").expect("echo");
    }

    #[tokio::test]
    async fn loopback_with_mux_prefix() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut server = Conn::new(server_io);
            server.read_tls_mux_prefix().await?;
            echo_unary(server).await
        });

        let mut client = Conn::new(client_io);
        client.write_tls_mux_prefix().await.unwrap();
        let out = client.invoke("/svc/M", b"z").await.unwrap();
        assert_eq!(out, b"z");
        drop(client);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mux_prefix_mismatch() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"XXXXXXXX").await.unwrap();
        drop(a);
        let err = read_tls_mux_prefix(&mut Conn::new(b).into_inner())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MuxPrefix { .. }));
    }

    #[tokio::test]
    async fn mux_prefix_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_tls_mux_prefix(&mut a).await.unwrap();
        let got = read_tls_mux_prefix(&mut b).await.unwrap();
        assert_eq!(&got, DRPC_TLS_MUX_PREFIX);
    }

    #[tokio::test]
    async fn truncated_frame_is_error() {
        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(&[0x03, 0x01]).await.unwrap();
        drop(a);
        let err = Conn::new(b).read_packet().await.unwrap_err();
        assert!(matches!(err, Error::Truncated));
    }

    #[tokio::test]
    async fn eof_before_packet_is_closed() {
        let (a, b) = tokio::io::duplex(1024);
        drop(a);
        let err = Conn::new(b).read_packet().await.unwrap_err();
        assert!(matches!(err, Error::Closed));
    }

    #[tokio::test]
    async fn truncated_mid_packet_is_error() {
        let (mut a, b) = tokio::io::duplex(1024);
        let mut wire = Vec::new();
        append_frame(
            &mut wire,
            &Frame {
                stream_id: 1,
                message_id: 1,
                kind: Kind::MESSAGE,
                done: false,
                control: false,
                data: b"ab".to_vec(),
            },
        );
        a.write_all(&wire).await.unwrap();
        drop(a);
        let err = Conn::new(b).read_packet().await.unwrap_err();
        assert!(matches!(err, Error::Truncated));
    }

    #[tokio::test]
    async fn unexpected_stream_id_is_not_unexpected_kind() {
        let (mut a, b) = tokio::io::duplex(1024);
        let mut wire = Vec::new();
        append_frame(
            &mut wire,
            &Frame {
                stream_id: 9,
                message_id: 1,
                kind: Kind::MESSAGE,
                done: true,
                control: false,
                data: b"x".to_vec(),
            },
        );
        a.write_all(&wire).await.unwrap();

        let client = tokio::spawn(async move {
            let mut client = Conn::new(b);
            client.invoke("/x/Y", b"").await
        });
        let err = client.await.unwrap().unwrap_err();
        match err {
            Error::UnexpectedStream { got, expected } => {
                assert_eq!(got, 9);
                assert_eq!(expected, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn leftover_second_packet() {
        let (mut a, b) = tokio::io::duplex(1024);
        let mut wire = Vec::new();
        append_frame(
            &mut wire,
            &Frame {
                stream_id: 1,
                message_id: 1,
                kind: Kind::INVOKE,
                done: true,
                control: false,
                data: b"rpc".to_vec(),
            },
        );
        append_frame(
            &mut wire,
            &Frame {
                stream_id: 1,
                message_id: 2,
                kind: Kind::MESSAGE,
                done: true,
                control: false,
                data: b"body".to_vec(),
            },
        );
        a.write_all(&wire).await.unwrap();
        drop(a);

        let mut conn = Conn::new(b);
        let first = conn.read_packet().await.unwrap();
        assert_eq!(first.kind, Kind::INVOKE);
        assert_eq!(first.data, b"rpc");
        let second = conn.read_packet().await.unwrap();
        assert_eq!(second.kind, Kind::MESSAGE);
        assert_eq!(second.data, b"body");
        assert_eq!(second.stream_id, 1);
        assert_eq!(second.message_id, 2);
    }

    #[tokio::test]
    async fn remote_error_packet() {
        let (client_io, mut server_io) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            // Drain client frames then send Kind::ERROR.
            let mut tmp = [0u8; 4096];
            let _ = server_io.read(&mut tmp).await;
            let mut body = 7u64.to_be_bytes().to_vec();
            body.extend_from_slice(b"nope");
            let mut wire = Vec::new();
            append_frame(
                &mut wire,
                &Frame {
                    stream_id: 1,
                    message_id: 1,
                    kind: Kind::ERROR,
                    done: true,
                    control: false,
                    data: body,
                },
            );
            server_io.write_all(&wire).await.unwrap();
        });

        let mut client = Conn::new(client_io);
        let err = client.invoke("/x/Y", b"").await.unwrap_err();
        match err {
            Error::Remote { code, message } => {
                assert_eq!(code, 7);
                assert_eq!(message, "nope");
            }
            other => panic!("unexpected {other:?}"),
        }
        server.await.unwrap();
    }
}
