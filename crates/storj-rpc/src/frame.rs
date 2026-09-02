//! DRPC frame parse/serialize.
//!
//! Wire layout from <https://github.com/storj/drpc/wiki/Docs:-Wire-protocol>
//! and `storj.io/drpc/drpcwire`:
//!
//! ```text
//! header (1) | stream_id (varint) | message_id (varint) | length (varint) | data
//! header: control (MSB) | kind (6 bits) | done (LSB)
//! ```
//!
//! IDs and length are protobuf unsigned varints (7-bit groups, LSB first,
//! high bit = continue) so the bytes match Go `drpcwire.AppendVarint`.

use std::fmt;

/// First 8 bytes on a TLS-muxed TCP conn, before the TLS handshake
/// (`storj.io/drpc/drpcmigrate.DRPCHeader`).
pub const DRPC_TLS_MUX_PREFIX: &[u8] = b"DRPC!!!1";

/// Default max assembled packet (Go `ReaderOptions.MaximumBufferSize`).
pub const MAX_PACKET_SIZE: usize = 4 << 20;

/// Default frame split size (Go `SplitData` when `n == 0`).
pub const DEFAULT_SPLIT_SIZE: usize = 64 * 1024;

/// Frame header: control bit, 6-bit kind, done bit.
pub const HEADER_CONTROL: u8 = 0b1000_0000;
pub const HEADER_KIND_MASK: u8 = 0b0111_1110;
pub const HEADER_DONE: u8 = 0b0000_0001;

/// DRPC packet/frame kind (6 bits in the header). Unknown values are kept
/// so control frames stay forwards-compatible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Kind(pub u8);

impl Kind {
    /// Invoke an RPC; body is the RPC name.
    pub const INVOKE: Self = Self(1);
    /// Encoded message body.
    pub const MESSAGE: Self = Self(2);
    /// Error with a 8-byte big-endian code prefix.
    pub const ERROR: Self = Self(3);
    /// Soft cancel.
    pub const CANCEL: Self = Self(4);
    /// Stream is dead.
    pub const CLOSE: Self = Self(5);
    /// No more messages will be sent.
    pub const CLOSE_SEND: Self = Self(6);
    /// Metadata for the next Invoke on this stream.
    pub const INVOKE_METADATA: Self = Self(7);

    /// Kind field from a header byte.
    pub const fn from_header(header: u8) -> Self {
        Self((header & HEADER_KIND_MASK) >> 1)
    }

    /// Kind bits in the header byte (done/control not set).
    pub const fn to_header_bits(self) -> u8 {
        (self.0 & 0b0011_1111) << 1
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::INVOKE => "invoke",
            Self::MESSAGE => "message",
            Self::ERROR => "error",
            Self::CANCEL => "cancel",
            Self::CLOSE => "close",
            Self::CLOSE_SEND => "close_send",
            Self::INVOKE_METADATA => "invoke_metadata",
            Kind(n) => return write!(f, "{n}"),
        };
        f.write_str(name)
    }
}

/// One DRPC frame on the wire. Packets may span multiple frames; `stream_id`
/// is always present even when the client pool allows only one in-flight RPC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// Stream identifier (connection-scoped, monotonically increasing).
    pub stream_id: u64,
    /// Message identifier within the stream.
    pub message_id: u64,
    /// Payload kind.
    pub kind: Kind,
    /// Last frame of this packet.
    pub done: bool,
    /// Forwards-compatible control frame.
    pub control: bool,
    /// Frame payload (`length` bytes).
    pub data: Vec<u8>,
}

/// Reassembled DRPC packet (one or more frames with the same id).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    /// Stream identifier.
    pub stream_id: u64,
    /// Message identifier within the stream.
    pub message_id: u64,
    /// Payload kind.
    pub kind: Kind,
    /// Set if any frame of the packet had the control bit.
    pub control: bool,
    /// Concatenated frame payloads.
    pub data: Vec<u8>,
}

/// Codec failure (malformed varint, id regression, oversize).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameError {
    /// More than 10 bytes in a varint (protobuf uint64 limit).
    #[error("DRPC varint too long")]
    VarintTooLong,
    /// Frame id was less than the last processed id.
    #[error("DRPC id monotonicity violation")]
    Monotonicity,
    /// Kind changed across frames of the same packet.
    #[error("DRPC packet kind changed between frames")]
    KindChange,
    /// Declared or assembled size exceeds [`MAX_PACKET_SIZE`].
    #[error("DRPC packet exceeds maximum size")]
    Overflow,
}

/// Parse one frame at the front of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet hold a complete frame (truncated
/// header, varint, or payload). On success, the `usize` is the number of bytes
/// consumed; leftover bytes (the next frame, if any) start at that offset.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let header = buf[0];
    let mut offset = 1;

    let Some((stream_id, n)) = read_varint(&buf[offset..])? else {
        return Ok(None);
    };
    offset += n;

    let Some((message_id, n)) = read_varint(&buf[offset..])? else {
        return Ok(None);
    };
    offset += n;

    let Some((length, n)) = read_varint(&buf[offset..])? else {
        return Ok(None);
    };
    offset += n;

    let len = usize::try_from(length).map_err(|_| FrameError::Overflow)?;
    if len > MAX_PACKET_SIZE {
        return Err(FrameError::Overflow);
    }
    if buf.len() - offset < len {
        return Ok(None);
    }

    let data = buf[offset..offset + len].to_vec();
    let consumed = offset + len;
    Ok(Some((
        Frame {
            stream_id,
            message_id,
            kind: Kind::from_header(header),
            done: header & HEADER_DONE != 0,
            control: header & HEADER_CONTROL != 0,
            data,
        },
        consumed,
    )))
}

/// Append a marshaled frame (Go `AppendFrame`).
pub fn append_frame(buf: &mut Vec<u8>, frame: &Frame) {
    append_frame_parts(
        buf,
        frame.stream_id,
        frame.message_id,
        frame.kind,
        frame.done,
        frame.control,
        &frame.data,
    );
}

fn append_frame_parts(
    buf: &mut Vec<u8>,
    stream_id: u64,
    message_id: u64,
    kind: Kind,
    done: bool,
    control: bool,
    data: &[u8],
) {
    let mut header = kind.to_header_bits();
    if done {
        header |= HEADER_DONE;
    }
    if control {
        header |= HEADER_CONTROL;
    }
    buf.push(header);
    append_varint(buf, stream_id);
    append_varint(buf, message_id);
    append_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Append `pkt` as one or more frames. `split == 0` uses [`DEFAULT_SPLIT_SIZE`].
pub fn append_packet(buf: &mut Vec<u8>, pkt: &Packet, split: usize) {
    append_packet_data(
        buf,
        pkt.stream_id,
        pkt.message_id,
        pkt.kind,
        pkt.control,
        &pkt.data,
        split,
    );
}

pub(crate) fn append_packet_data(
    buf: &mut Vec<u8>,
    stream_id: u64,
    message_id: u64,
    kind: Kind,
    control: bool,
    mut data: &[u8],
    split: usize,
) {
    let n = if split == 0 {
        DEFAULT_SPLIT_SIZE
    } else {
        split
    };
    loop {
        let (chunk, rest) = if data.len() > n {
            (&data[..n], &data[n..])
        } else {
            (data, &[][..])
        };
        append_frame_parts(
            buf,
            stream_id,
            message_id,
            kind,
            rest.is_empty(),
            control,
            chunk,
        );
        if rest.is_empty() {
            return;
        }
        data = rest;
    }
}

/// Protobuf unsigned varint (Go `ReadVarint`). `None` means truncated.
pub(crate) fn read_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, FrameError> {
    let mut out = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(FrameError::VarintTooLong);
        }
        let val = u64::from(b);
        out |= (val & 127).wrapping_shl(shift);
        if val < 128 {
            return Ok(Some((out, i + 1)));
        }
        shift += 7;
        if shift >= 64 {
            return Err(FrameError::VarintTooLong);
        }
    }
    Ok(None)
}

/// Protobuf unsigned varint (Go `AppendVarint`).
pub(crate) fn append_varint(buf: &mut Vec<u8>, mut x: u64) {
    while x >= 128 {
        buf.push((x as u8) & 127 | 128);
        x >>= 7;
    }
    buf.push(x as u8);
}

fn id_less(a_stream: u64, a_message: u64, b_stream: u64, b_message: u64) -> bool {
    a_stream < b_stream || (a_stream == b_stream && a_message < b_message)
}

/// Reconstructs packets from frames. IDs must be monotonically increasing
/// (Go `Reader.ReadPacketUsing`).
#[derive(Debug)]
pub(crate) struct PacketAssembler {
    last_stream: u64,
    last_message: u64,
    current: Option<Packet>,
    max_data: usize,
}

impl Default for PacketAssembler {
    fn default() -> Self {
        Self {
            // Go `NewReader` starts at Stream:1 Message:1 so the first
            // client frame (stream 1, message 1) is accepted, not "less".
            last_stream: 1,
            last_message: 1,
            current: None,
            max_data: MAX_PACKET_SIZE,
        }
    }
}

impl PacketAssembler {
    pub(crate) fn push(&mut self, fr: Frame) -> Result<Option<Packet>, FrameError> {
        if id_less(
            fr.stream_id,
            fr.message_id,
            self.last_stream,
            self.last_message,
        ) {
            return Err(FrameError::Monotonicity);
        }

        let same_id = fr.stream_id == self.last_stream && fr.message_id == self.last_message;
        if self.current.is_none() || !same_id {
            self.last_stream = fr.stream_id;
            self.last_message = fr.message_id;
            self.current = Some(Packet {
                stream_id: fr.stream_id,
                message_id: fr.message_id,
                kind: fr.kind,
                control: fr.control,
                data: fr.data,
            });
        } else if let Some(pkt) = self.current.as_mut() {
            if pkt.kind != fr.kind {
                return Err(FrameError::KindChange);
            }
            pkt.control |= fr.control;
            pkt.data.extend_from_slice(&fr.data);
        }

        let len = self.current.as_ref().map_or(0, |pkt| pkt.data.len());
        if len > self.max_data {
            return Err(FrameError::Overflow);
        }

        if fr.done {
            self.last_message = self.last_message.saturating_add(1);
            return Ok(self.current.take());
        }
        Ok(None)
    }
}

/// Decode a remote `Kind::ERROR` payload (8-byte BE code + message).
pub(crate) fn unmarshal_error(data: &[u8]) -> (u64, String) {
    if data.len() < 8 {
        return (0, String::from_utf8_lossy(data).into_owned());
    }
    let code = u64::from_be_bytes(data[..8].try_into().expect("8 bytes"));
    let message = String::from_utf8_lossy(&data[8..]).into_owned();
    (code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(stream_id: u64, message_id: u64, kind: Kind, done: bool, data: &[u8]) -> Frame {
        Frame {
            stream_id,
            message_id,
            kind,
            done,
            control: false,
            data: data.to_vec(),
        }
    }

    #[test]
    fn round_trip_small() {
        let original = frame(1, 1, Kind::INVOKE, true, b"/echo.Echo/Ping");
        let mut buf = Vec::new();
        append_frame(&mut buf, &original);
        let (parsed, consumed) = parse_frame(&buf).unwrap().expect("complete");
        assert_eq!(consumed, buf.len());
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_go_message_golden() {
        // drpcstream.TestStream_CorkUntilFirstRead: header=0x05 (Message|done),
        // stream=0, message=1, length=5, "write".
        let wire = b"\x05\x00\x01\x05write";
        let (fr, n) = parse_frame(wire).unwrap().expect("complete");
        assert_eq!(n, wire.len());
        assert_eq!(fr.stream_id, 0);
        assert_eq!(fr.message_id, 1);
        assert_eq!(fr.kind, Kind::MESSAGE);
        assert!(fr.done);
        assert!(!fr.control);
        assert_eq!(fr.data, b"write");

        let mut out = Vec::new();
        append_frame(&mut out, &fr);
        assert_eq!(out, wire);
    }

    #[test]
    fn round_trip_large_varints() {
        let original = frame(300, 1 << 21, Kind::MESSAGE, true, b"x");
        let mut buf = Vec::new();
        append_frame(&mut buf, &original);
        // 300 = 0xAC 0x02 (two-byte varint); proves we do not use fixed-width IDs.
        assert_eq!(buf[1], 0xAC);
        assert_eq!(buf[2], 0x02);
        let (parsed, consumed) = parse_frame(&buf).unwrap().expect("complete");
        assert_eq!(consumed, buf.len());
        assert_eq!(parsed, original);
    }

    #[test]
    fn header_bits() {
        let mut fr = frame(1, 1, Kind::CANCEL, true, &[]);
        fr.control = true;
        let mut buf = Vec::new();
        append_frame(&mut buf, &fr);
        // kind=4 << 1 | done | control = 8 | 1 | 0x80 = 0x89
        assert_eq!(buf[0], 0x89);
        let (parsed, _) = parse_frame(&buf).unwrap().unwrap();
        assert!(parsed.control);
        assert!(parsed.done);
        assert_eq!(parsed.kind, Kind::CANCEL);
    }

    #[test]
    fn truncated_frames() {
        let original = frame(1, 2, Kind::MESSAGE, true, b"hello");
        let mut full = Vec::new();
        append_frame(&mut full, &original);

        for n in 0..full.len() {
            let got = parse_frame(&full[..n]).unwrap();
            assert!(got.is_none(), "prefix of {n} bytes should be incomplete");
        }
        assert!(parse_frame(&full).unwrap().is_some());
    }

    #[test]
    fn leftover_bytes() {
        let a = frame(1, 1, Kind::INVOKE, true, b"rpc");
        let b = frame(1, 2, Kind::MESSAGE, true, b"body");
        let mut buf = Vec::new();
        append_frame(&mut buf, &a);
        let first_len = buf.len();
        append_frame(&mut buf, &b);

        let (parsed, consumed) = parse_frame(&buf).unwrap().expect("complete");
        assert_eq!(consumed, first_len);
        assert_eq!(parsed, a);
        assert_eq!(&buf[consumed..], {
            let mut second = Vec::new();
            append_frame(&mut second, &b);
            second
        });

        let (parsed_b, consumed_b) = parse_frame(&buf[consumed..]).unwrap().unwrap();
        assert_eq!(consumed_b, buf.len() - consumed);
        assert_eq!(parsed_b, b);
    }

    #[test]
    fn varint_too_long() {
        let mut buf = vec![0x03]; // invoke|done
        buf.extend(std::iter::repeat_n(0x80, 10)); // never-terminating stream_id
        assert_eq!(parse_frame(&buf).unwrap_err(), FrameError::VarintTooLong);
    }

    #[test]
    fn empty_payload_round_trip() {
        let original = frame(1, 3, Kind::CLOSE_SEND, true, &[]);
        let mut buf = Vec::new();
        append_frame(&mut buf, &original);
        assert_eq!(buf, [0x0D, 0x01, 0x03, 0x00]); // kind 6 << 1 | done
        let (parsed, n) = parse_frame(&buf).unwrap().unwrap();
        assert_eq!(n, 4);
        assert_eq!(parsed, original);
    }

    #[test]
    fn split_packet_round_trip() {
        let pkt = Packet {
            stream_id: 2,
            message_id: 4,
            kind: Kind::MESSAGE,
            control: false,
            data: b"abcdefghij".to_vec(),
        };
        let mut buf = Vec::new();
        append_packet(&mut buf, &pkt, 4);

        let mut asm = PacketAssembler::default();
        let mut rest = buf.as_slice();
        let mut out = None;
        while !rest.is_empty() {
            let (fr, n) = parse_frame(rest).unwrap().expect("complete frame");
            rest = &rest[n..];
            if let Some(p) = asm.push(fr).unwrap() {
                out = Some(p);
            }
        }
        assert!(rest.is_empty());
        assert_eq!(out.unwrap(), pkt);
    }

    #[test]
    fn assembler_kind_change() {
        let mut asm = PacketAssembler::default();
        let mut first = frame(1, 1, Kind::MESSAGE, false, b"ab");
        assert!(asm.push(first.clone()).unwrap().is_none());
        first.kind = Kind::ERROR;
        first.data = b"cd".to_vec();
        assert_eq!(asm.push(first).unwrap_err(), FrameError::KindChange);
    }

    #[test]
    fn assembler_monotonicity() {
        let mut asm = PacketAssembler::default();
        let done = frame(1, 1, Kind::MESSAGE, true, b"a");
        assert!(asm.push(done).unwrap().is_some());
        let replay = frame(1, 1, Kind::MESSAGE, true, b"b");
        assert_eq!(asm.push(replay).unwrap_err(), FrameError::Monotonicity);
    }

    #[test]
    fn mux_prefix_bytes() {
        assert_eq!(DRPC_TLS_MUX_PREFIX, b"DRPC!!!1");
        assert_eq!(DRPC_TLS_MUX_PREFIX.len(), 8);
    }
}
