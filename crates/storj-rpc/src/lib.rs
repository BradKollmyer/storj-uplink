//! Client-only DRPC codec for Storj (not gRPC).
//!
//! Workspace-internal (`publish = false`). Identity is ephemeral
//! ECDSA P-256; rustls pins the peer NodeID (no WebPKI).

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod conn;
pub mod frame;
pub mod identity;
pub mod known_ids;
pub mod tls;

pub use conn::{Conn, Error, RpcStream, read_tls_mux_prefix, write_tls_mux_prefix};
pub use frame::{
    DRPC_TLS_MUX_PREFIX, Frame, FrameError, Kind, Packet, append_frame, append_packet,
    marshal_error, parse_frame,
};
pub use identity::{Identity, IdentityError, NodeId, NodeUrl, hash_and_verify};
pub use known_ids::{known_node_id, parse_node_url};
pub use tls::{NodeIdVerifier, client_config, server_config};
