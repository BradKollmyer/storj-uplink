//! Client-only DRPC codec for Storj (not gRPC).
//!
//! Workspace-internal (`publish = false`) until 1.0. Identity is ephemeral
//! ECDSA P-256; rustls pins the peer NodeID (no WebPKI).

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod conn;
pub mod frame;
pub mod identity;
pub mod known_ids;
pub mod tls;

pub use conn::{Conn, Error, read_tls_mux_prefix, write_tls_mux_prefix};
pub use frame::{
    DRPC_TLS_MUX_PREFIX, Frame, FrameError, Kind, Packet, append_frame, append_packet, parse_frame,
};
pub use identity::{Identity, IdentityError, NodeId, NodeUrl};
pub use known_ids::{known_node_id, parse_node_url};
pub use tls::{NodeIdVerifier, client_config};
