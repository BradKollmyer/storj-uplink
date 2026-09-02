//! Client-only DRPC codec for Storj (not gRPC).
//!
//! Workspace-internal (`publish = false`) until 1.0. TLS and NodeID pinning
//! land in a later PR.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod conn;
pub mod frame;

pub use conn::{Conn, Error, read_tls_mux_prefix, write_tls_mux_prefix};
pub use frame::{
    DRPC_TLS_MUX_PREFIX, Frame, FrameError, Kind, Packet, append_frame, append_packet, parse_frame,
};
