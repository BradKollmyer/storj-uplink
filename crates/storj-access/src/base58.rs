//! Bitcoin-style Base58Check matching `storj.io/common/base58`.
//!
//! Wire format: `version || payload || checksum[4]`, where checksum is the
//! first 4 bytes of SHA256(SHA256(version || payload)). Alphabet is Bitcoin's
//! (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).

use sha2::{Digest, Sha256};

/// Version byte used for access grants and standalone API keys.
pub const GRANT_VERSION: u8 = 0;

/// Failure to decode a Base58Check string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Alphabet, length, or missing version/checksum bytes.
    InvalidFormat,
    /// Double-SHA256 checksum did not match.
    Checksum,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => {
                f.write_str("invalid format: version and/or checksum bytes missing")
            }
            Self::Checksum => f.write_str("checksum error"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode `payload` with a version byte and 4-byte checksum (Go `CheckEncode`).
pub fn check_encode(payload: &[u8], version: u8) -> String {
    let mut buf = Vec::with_capacity(1 + payload.len() + 4);
    buf.push(version);
    buf.extend_from_slice(payload);
    let sum = checksum(&buf);
    buf.extend_from_slice(&sum);
    bs58::encode(buf).into_string()
}

/// Decode a CheckEncode string. Returns `(payload, version)`.
pub fn check_decode(input: &str) -> Result<(Vec<u8>, u8), DecodeError> {
    let decoded = bs58::decode(input)
        .into_vec()
        .map_err(|_| DecodeError::InvalidFormat)?;
    if decoded.len() < 5 {
        return Err(DecodeError::InvalidFormat);
    }
    let version = decoded[0];
    let (body, cksum) = decoded.split_at(decoded.len() - 4);
    if checksum(body).as_slice() != cksum {
        return Err(DecodeError::Checksum);
    }
    Ok((body[1..].to_vec(), version))
}

fn checksum(input: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(input);
    let second = Sha256::digest(first);
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by `storj.io/common/base58.CheckEncode` (one-off Go program).
    #[test]
    fn check_encode_matches_go() {
        assert_eq!(check_encode(&[], 0), "1Wh4bh");
        assert_eq!(check_encode(b"Hello World", 0), "132UWxgjUJDXeRwy8XYYVQ");
        assert_eq!(check_encode(b"Hello World", 1), "ABsn8bcafMZENwm1nSs3C");
        assert_eq!(check_encode(&[0, 0, 1, 2], 0), "111W9ycZ2q");
        assert_eq!(
            check_encode(&[0xab; 32], 0),
            "12Jc6VooH5wxteNEnVgqR8hNw3Pb58bphqk1myKZpXwrCf9uxJC"
        );
    }

    #[test]
    fn check_roundtrip() {
        for (payload, version) in [
            (&b""[..], 0u8),
            (b"Hello World", 0),
            (b"Hello World", 1),
            (&[0, 0, 1, 2], 0),
            (&[0xab; 32], 0),
        ] {
            let encoded = check_encode(payload, version);
            let (got, got_ver) = check_decode(&encoded).expect("decode");
            assert_eq!(got_ver, version);
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn check_decode_rejects_garbage() {
        assert_eq!(check_decode(""), Err(DecodeError::InvalidFormat));
        assert_eq!(
            check_decode("!!!not-base58!!!"),
            Err(DecodeError::InvalidFormat)
        );
        let mut bad = check_encode(b"hello", 0);
        // Flip a payload character so the checksum fails while staying in alphabet.
        let last = bad.pop().unwrap();
        bad.push(if last == 'z' { 'y' } else { 'z' });
        assert_eq!(check_decode(&bad), Err(DecodeError::Checksum));
    }
}
