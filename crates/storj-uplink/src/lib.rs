//! Piecestore client, order-limit verify, SN pool, and single-segment upload/download.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod download;
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

impl Error {
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
