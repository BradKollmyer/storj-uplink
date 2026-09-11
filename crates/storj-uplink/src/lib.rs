//! Piecestore client, order-limit verify, SN pool, and segment upload/download.
//!
//! Implementation detail of the `storj` crate; not a stable public API.
//! Depend on `storj` instead.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod download;
pub mod multipart;
pub mod orders;
pub mod piecestore;
pub mod pipeline;
pub mod pool;
pub mod segment;
pub mod upload;

pub use orders::{
    PieceHashAlgo, PieceHasher, PiecePrivateKey, PiecePublicKey, encode_order, encode_order_limit,
    encode_piece_hash, sign_order, sign_order_limit, sign_piece_hash_node, sign_piece_hash_uplink,
    verify_order, verify_order_limit, verify_piece_hash_node, verify_piece_hash_uplink,
};
pub use piecestore::{Client, Config as PieceConfig};
pub use pool::{ConnectionPool, DEFAULT_SCHEME_N, PoolConfig, Pooled};

/// Piecestore / order-limit errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// DRPC transport or framing.
    #[error(transparent)]
    Rpc(#[from] storj_rpc::Error),
    /// Identity / ECDSA (satellite or storage-node CA).
    #[error(transparent)]
    Identity(#[from] storj_rpc::IdentityError),
    /// Satellite signature on an [`storj_proto::orders::OrderLimit`] is invalid.
    #[error("invalid order-limit signature")]
    OrderLimitSignature,
    /// Uplink Ed25519 signature on an order is invalid.
    #[error("invalid order signature")]
    OrderSignature,
    /// Piece-hash signature (uplink Ed25519 or node ECDSA) is invalid.
    #[error("invalid piece-hash signature")]
    PieceHashSignature,
    /// Storage-node hash does not match the bytes we sent.
    #[error("piece hashes do not match")]
    PieceHashMismatch,
    /// Hash algorithm on the response did not match the negotiated algo.
    #[error("piece hash algorithm mismatch")]
    HashAlgoMismatch,
    /// Piece id on the hash does not match the order limit.
    #[error("piece id mismatch")]
    PieceIdMismatch,
    /// Piece public/private key is the wrong length or malformed.
    #[error("invalid piece key")]
    PieceKey,
    /// Order limit timestamp is older than the allowed window.
    #[error("piece hash timestamp is too old")]
    PieceHashExpired,
    /// Protocol sequence or protobuf decode failure.
    #[error("protocol: {0}")]
    Protocol(String),
    /// Invalid local range arithmetic; retrying cannot change the request.
    #[error("invalid download range {offset}+{size}: {reason}")]
    InvalidDownloadRange {
        offset: i64,
        size: i64,
        reason: &'static str,
    },
    /// Requested byte count exceeds the signed transfer allowance.
    #[error("download size {size} exceeds order byte limit {limit} (offset {offset})")]
    DownloadLimit { offset: i64, size: i64, limit: i64 },
    /// Connection establishment and authentication exceeded the dial deadline.
    #[error("storage-node dial timed out")]
    DialTimeout,
    /// Too few pieces were downloaded; retains all node failures.
    #[error(transparent)]
    PieceDownload(#[from] Box<download::PieceDownloadError>),
    /// Underlying I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Reed-Solomon encode/decode.
    #[error(transparent)]
    Ec(#[from] storj_ec::Error),
    /// Content encryption.
    #[error(transparent)]
    Encryption(#[from] storj_encryption::Error),
}

// gRPC / rpcstatus codes carried in DRPC error payloads.
const RPC_UNKNOWN: u64 = 2;
const RPC_DEADLINE_EXCEEDED: u64 = 4;
const RPC_RESOURCE_EXHAUSTED: u64 = 8;
const RPC_INTERNAL: u64 = 13;
const RPC_UNAVAILABLE: u64 = 14;

impl Error {
    /// Whether repeating the operation can recover from this failure.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::DialTimeout | Self::Io(_) => true,
            Self::Rpc(
                storj_rpc::Error::Io(_) | storj_rpc::Error::Closed | storj_rpc::Error::Truncated,
            ) => true,
            Self::Rpc(storj_rpc::Error::Remote { code, message }) => {
                matches!(
                    *code,
                    RPC_UNKNOWN | RPC_DEADLINE_EXCEEDED | RPC_INTERNAL | RPC_UNAVAILABLE
                ) || (*code == RPC_RESOURCE_EXHAUSTED && message.contains("Too Many Requests"))
            }
            Self::PieceDownload(error) => error.is_retryable(),
            _ => false,
        }
    }

    /// Protocol / sequence failure.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
}

impl From<prost::DecodeError> for Error {
    fn from(e: prost::DecodeError) -> Self {
        Self::Protocol(e.to_string())
    }
}

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_retry_policy_distinguishes_throttling_from_exhausted_resources() {
        for (code, message, retryable) in [
            (RPC_UNKNOWN, "unknown", true),
            (RPC_DEADLINE_EXCEEDED, "deadline", true),
            (RPC_INTERNAL, "internal", true),
            (RPC_UNAVAILABLE, "unavailable", true),
            (RPC_RESOURCE_EXHAUSTED, "Too Many Requests", true),
            (RPC_RESOURCE_EXHAUSTED, "bandwidth quota exceeded", false),
            (RPC_RESOURCE_EXHAUSTED, "storage quota exceeded", false),
            (RPC_RESOURCE_EXHAUSTED, "", false),
            (3, "invalid argument", false),
            (7, "permission denied", false),
            (999, "unrecognized status", false),
        ] {
            let err = Error::Rpc(storj_rpc::Error::Remote {
                code,
                message: message.into(),
            });
            assert_eq!(err.is_retryable(), retryable, "{err}");
        }
    }
}
