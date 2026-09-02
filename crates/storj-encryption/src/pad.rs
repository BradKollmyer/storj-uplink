//! Encryption-block padding (Go `encryption.Pad` / `makePadding` / `UnpadSlow`).
//!
//! Trailer is a big-endian u32 of the padding length (at least 4 bytes). Zeros
//! fill the rest so `len(data) + padding` is a multiple of the plaintext block
//! size. Stripe-size zero padding is a later RS step, not this module.

use crate::error::{Error, ErrorKind, Result};

/// Size of the padding-length trailer (`uint32Size`).
pub const UINT32_SIZE: usize = 4;

/// Padding bytes to append so `data_len + padding` is a multiple of `block_size`.
pub fn make_padding(data_len: i64, block_size: usize) -> Result<Vec<u8>> {
    if block_size == 0 {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "block size must be positive",
        ));
    }
    if data_len < 0 {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "data length was negative",
        ));
    }
    let block_size_i = i64::try_from(block_size)
        .map_err(|_| Error::new(ErrorKind::InvalidConfig, "block size too large"))?;
    let amount = data_len + i64::try_from(UINT32_SIZE).expect("4 fits i64");
    let r = amount % block_size_i;
    let mut padding = UINT32_SIZE;
    if r > 0 {
        padding += usize::try_from(block_size_i - r).expect("r < block_size");
    }
    let mut padding_bytes = vec![0u8; padding];
    let padding_u32 = u32::try_from(padding)
        .map_err(|_| Error::new(ErrorKind::InvalidConfig, "padding too large"))?;
    let n = padding_bytes.len();
    padding_bytes[n - UINT32_SIZE..].copy_from_slice(&padding_u32.to_be_bytes());
    Ok(padding_bytes)
}

/// Append padding so the result length is a multiple of `block_size`.
pub fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    let data_len = i64::try_from(data.len())
        .map_err(|_| Error::new(ErrorKind::InvalidConfig, "data too large"))?;
    let padding = make_padding(data_len, block_size)?;
    let mut out = Vec::with_capacity(data.len() + padding.len());
    out.extend_from_slice(data);
    out.extend_from_slice(&padding);
    Ok(out)
}

/// Strip a known padding length (Go `Unpad`).
pub fn unpad_len(data: &[u8], padding: usize) -> Result<&[u8]> {
    if padding > data.len() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "padding longer than data",
        ));
    }
    Ok(&data[..data.len() - padding])
}

/// Read the 4-byte trailer and strip padding (Go `UnpadSlow`).
pub fn unpad(data: &[u8]) -> Result<&[u8]> {
    if data.len() < UINT32_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "padded data too short",
        ));
    }
    let mut trailer = [0u8; UINT32_SIZE];
    trailer.copy_from_slice(&data[data.len() - UINT32_SIZE..]);
    let padding = usize::try_from(u32::from_be_bytes(trailer)).expect("u32 fits usize");
    unpad_len(data, padding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_padding_matches_go_block8() {
        let cases: &[(i64, usize, &str)] = &[
            (0, 8, "0000000000000008"),
            (1, 8, "00000000000007"),
            (4, 8, "00000004"),
            (5, 8, "000000000000000000000b"),
            (8, 8, "0000000000000008"),
            (12, 8, "00000004"),
            (100, 8, "00000004"),
        ];
        for &(data_len, block, hex_pad) in cases {
            let p = make_padding(data_len, block).unwrap();
            assert_eq!(hex::encode(&p), hex_pad, "data_len={data_len}");
            let last4 = u32::from_be_bytes(p[p.len() - 4..].try_into().unwrap());
            assert_eq!(last4 as usize, p.len());
            assert_eq!((data_len as usize + p.len()) % block, 0);
        }
    }

    #[test]
    fn make_padding_default_in_block() {
        // AES-GCM in-block at uplink default encrypted size 7424.
        let in_block = 7424 - 16;
        let cases: &[(i64, usize)] = &[(0, 7408), (1, 7407), (7404, 4), (7408, 7408), (7409, 7407)];
        for &(data_len, pad_len) in cases {
            let p = make_padding(data_len, in_block).unwrap();
            assert_eq!(p.len(), pad_len, "data_len={data_len}");
            let last4 = u32::from_be_bytes(p[p.len() - 4..].try_into().unwrap());
            assert_eq!(last4 as usize, pad_len);
        }
    }

    #[test]
    fn pad_unpad_roundtrip() {
        for data in [b"".as_slice(), b"h", b"hi", b"hello world", &[0u8; 100]] {
            let padded = pad(data, 8).unwrap();
            assert_eq!(padded.len() % 8, 0);
            assert_eq!(unpad(&padded).unwrap(), data);
        }
        let padded = pad(b"hi", 8).unwrap();
        assert_eq!(hex::encode(&padded), "6869000000000006");
        assert_eq!(unpad_len(&padded, 6).unwrap(), b"hi");
    }

    #[test]
    fn unpad_rejects_short_and_overlong() {
        assert_eq!(
            unpad(&[0, 0, 0]).unwrap_err().kind(),
            ErrorKind::InvalidConfig
        );
        let mut buf = vec![0u8; 8];
        buf[4..].copy_from_slice(&9u32.to_be_bytes());
        assert_eq!(unpad(&buf).unwrap_err().kind(), ErrorKind::InvalidConfig);
    }

    #[test]
    fn zero_block_size_fails() {
        assert_eq!(
            make_padding(1, 0).unwrap_err().kind(),
            ErrorKind::InvalidConfig
        );
    }
}
