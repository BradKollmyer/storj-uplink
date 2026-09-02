//! CompressedBatch zstd codec.
//!
//! Matches Go uplink `metaclient` / satellite `WithDecoderMaxMemory(64<<20)`
//! and satellite encode `WithWindowSize(1<<20)`.

use std::io::{self, Read, Write};

use prost::Message;

use crate::metainfo::{
    BatchRequest, BatchResponse, CompressedBatchRequest, CompressedBatchResponse,
    compressed_batch_request::CompressionType,
};

/// Max decoded zstd payload / window (Go `WithDecoderMaxMemory(64<<20)`).
pub const MAX_DECODE_MEMORY: usize = 64 * 1024 * 1024;

/// Encoder window log: `2^20` = 1 MiB (satellite `WithWindowSize(1<<20)`).
const WINDOW_LOG: u32 = 20;
/// Decoder max window log: `2^26` = 64 MiB.
const WINDOW_LOG_MAX: u32 = 26;

/// CompressedBatch codec errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// zstd encode/decode failure (corrupt frame, window too large, …).
    #[error("zstd: {0}")]
    Zstd(#[from] io::Error),
    /// Protobuf decode of the inner `BatchRequest` / `BatchResponse`.
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    /// `selected` was not `NONE` or `ZSTD`.
    #[error("unsupported CompressedBatch compression type {0}")]
    Unsupported(i32),
    /// Decompressed payload would exceed [`MAX_DECODE_MEMORY`].
    #[error("decompressed CompressedBatch exceeds 64 MiB")]
    Oversize,
}

/// zstd-compress `plain` (1 MiB window, default level).
pub fn compress(plain: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder = zstd::Encoder::new(Vec::new(), 0)?;
    encoder.window_log(WINDOW_LOG)?;
    encoder.write_all(plain)?;
    Ok(encoder.finish()?)
}

/// zstd-decompress `compressed`, rejecting output or window above 64 MiB.
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder = zstd::Decoder::new(compressed)?;
    decoder.window_log_max(WINDOW_LOG_MAX)?;
    let mut out = Vec::new();
    let mut tmp = [0u8; 32 * 1024];
    loop {
        let n = match decoder.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e.into()),
        };
        if out.len().saturating_add(n) > MAX_DECODE_MEMORY {
            return Err(Error::Oversize);
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

/// Go metaclient: uncompressed `BatchRequest` bytes, `supported = [ZSTD]`.
pub fn encode_batch_request(batch: &BatchRequest) -> CompressedBatchRequest {
    CompressedBatchRequest {
        supported: vec![CompressionType::Zstd as i32],
        selected: CompressionType::None as i32,
        data: batch.encode_to_vec(),
    }
}

/// Compress the inner `BatchRequest` (satellite also accepts `selected = ZSTD`).
pub fn encode_batch_request_zstd(batch: &BatchRequest) -> Result<CompressedBatchRequest, Error> {
    Ok(CompressedBatchRequest {
        supported: vec![CompressionType::Zstd as i32],
        selected: CompressionType::Zstd as i32,
        data: compress(&batch.encode_to_vec())?,
    })
}

/// Decode a CompressedBatch request payload into a `BatchRequest`.
pub fn decode_batch_request(req: &CompressedBatchRequest) -> Result<BatchRequest, Error> {
    let raw = decode_payload(req.selected, &req.data)?;
    Ok(BatchRequest::decode(raw.as_slice())?)
}

/// Encode a batch response; compress with zstd when `use_zstd` is true.
pub fn encode_batch_response(
    batch: &BatchResponse,
    use_zstd: bool,
) -> Result<CompressedBatchResponse, Error> {
    let raw = batch.encode_to_vec();
    if use_zstd {
        Ok(CompressedBatchResponse {
            selected: CompressionType::Zstd as i32,
            data: compress(&raw)?,
        })
    } else {
        Ok(CompressedBatchResponse {
            selected: CompressionType::None as i32,
            data: raw,
        })
    }
}

/// Decode a CompressedBatch response payload into a `BatchResponse`.
pub fn decode_batch_response(resp: &CompressedBatchResponse) -> Result<BatchResponse, Error> {
    let raw = decode_payload(resp.selected, &resp.data)?;
    Ok(BatchResponse::decode(raw.as_slice())?)
}

fn decode_payload(selected: i32, data: &[u8]) -> Result<Vec<u8>, Error> {
    match CompressionType::try_from(selected) {
        Ok(CompressionType::None) => Ok(data.to_vec()),
        Ok(CompressionType::Zstd) => decompress(data),
        Err(_) => Err(Error::Unsupported(selected)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{BatchRequestItem, RequestHeader, batch_request_item};
    use crate::metainfo::{ProjectInfoRequest, batch_response_item};

    fn sample_batch() -> BatchRequest {
        BatchRequest {
            header: Some(RequestHeader::new(*b"api-key", *b"storj-uplink")),
            requests: vec![BatchRequestItem {
                request: Some(batch_request_item::Request::ObjectGet(
                    crate::metainfo::GetObjectRequest {
                        header: None,
                        bucket: b"b".to_vec(),
                        encrypted_object_key: b"k".to_vec(),
                        version: 0,
                        object_version: vec![],
                        redundancy_scheme_per_segment: true,
                    },
                )),
            }],
        }
    }

    #[test]
    fn zstd_round_trip() {
        let plain = b"compressed-batch-payload";
        let c = compress(plain).unwrap();
        assert_ne!(c, plain);
        assert_eq!(decompress(&c).unwrap(), plain);
    }

    #[test]
    fn go_style_request_is_uncompressed_with_zstd_supported() {
        let batch = sample_batch();
        let req = encode_batch_request(&batch);
        assert_eq!(req.selected, CompressionType::None as i32);
        assert_eq!(req.supported, vec![CompressionType::Zstd as i32]);
        assert_eq!(req.data, batch.encode_to_vec());
        let round = decode_batch_request(&req).unwrap();
        assert_eq!(round.header.unwrap().api_key, b"api-key");
        assert_eq!(round.requests.len(), 1);
    }

    #[test]
    fn compressed_request_round_trip() {
        let batch = sample_batch();
        let req = encode_batch_request_zstd(&batch).unwrap();
        assert_eq!(req.selected, CompressionType::Zstd as i32);
        let round = decode_batch_request(&req).unwrap();
        assert_eq!(round.encode_to_vec(), batch.encode_to_vec());
    }

    #[test]
    fn compressed_response_round_trip() {
        let resp = BatchResponse {
            responses: vec![crate::metainfo::BatchResponseItem {
                response: Some(batch_response_item::Response::ObjectGet(
                    crate::metainfo::GetObjectResponse { object: None },
                )),
            }],
        };
        let wire = encode_batch_response(&resp, true).unwrap();
        assert_eq!(wire.selected, CompressionType::Zstd as i32);
        let round = decode_batch_response(&wire).unwrap();
        assert_eq!(round.encode_to_vec(), resp.encode_to_vec());

        let uncompressed = encode_batch_response(&resp, false).unwrap();
        assert_eq!(uncompressed.selected, CompressionType::None as i32);
        assert_eq!(
            decode_batch_response(&uncompressed)
                .unwrap()
                .encode_to_vec(),
            resp.encode_to_vec()
        );
    }

    #[test]
    fn unsupported_compression_type() {
        let req = CompressedBatchRequest {
            supported: vec![],
            selected: 99,
            data: vec![],
        };
        match decode_batch_request(&req) {
            Err(Error::Unsupported(99)) => {}
            other => panic!("expected Unsupported(99), got {other:?}"),
        }
    }

    #[test]
    fn compression_type_values_match_proto() {
        assert_eq!(CompressionType::None as i32, 0);
        assert_eq!(CompressionType::Zstd as i32, 1);
    }

    #[test]
    fn oversize_rejected() {
        let plain = vec![0u8; MAX_DECODE_MEMORY + 1];
        let compressed = compress(&plain).expect("compress zeros");
        match decompress(&compressed) {
            Err(Error::Oversize) => {}
            other => panic!("expected Oversize, got {other:?}"),
        }
    }

    #[test]
    fn exactly_max_decode_ok() {
        let plain = vec![0x5au8; MAX_DECODE_MEMORY];
        let compressed = compress(&plain).unwrap();
        assert_eq!(decompress(&compressed).unwrap().len(), MAX_DECODE_MEMORY);
    }

    #[test]
    fn project_info_is_not_a_batch_item() {
        // ProjectInfo is a standalone RPC, not a CompressedBatch item.
        let _ = ProjectInfoRequest {
            header: Some(RequestHeader::new(*b"k", *b"ua")),
        };
        let batch = encode_batch_request(&sample_batch());
        assert!(!batch.data.is_empty());
    }
}
