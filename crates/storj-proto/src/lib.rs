//! Vendored Storj protobuf types and CompressedBatch zstd codec.
//!
//! Implementation detail of the `storj` crate; not a stable public API.
//! Depend on `storj` instead. Types are generated from `proto/*.proto` (pin in
//! `proto/README.md`) and checked in under `gen/`.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod compressed;
pub mod rpc;

#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/encryption.rs"]
pub mod encryption;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/encryption_access.rs"]
pub mod encryption_access;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/metainfo.rs"]
pub mod metainfo;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/node.rs"]
pub mod node;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/noise.rs"]
pub mod noise;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/orders.rs"]
pub mod orders;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/piecestore.rs"]
pub mod piecestore;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/pointerdb.rs"]
pub mod pointerdb;
#[allow(clippy::all, dead_code, unused_imports)]
#[path = "gen/scope.rs"]
pub mod scope;

pub use compressed::{
    Error as CompressedError, MAX_DECODE_MEMORY, compress, decode_batch_request,
    decode_batch_response, decompress, encode_batch_request, encode_batch_request_zstd,
    encode_batch_response,
};
pub use metainfo::RequestHeader;

impl RequestHeader {
    /// Metainfo auth header (Go `metaclient.Client.header()`).
    pub fn new(api_key: impl Into<Vec<u8>>, user_agent: impl Into<Vec<u8>>) -> Self {
        Self {
            api_key: api_key.into(),
            user_agent: user_agent.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn request_header_wire_tags() {
        let h = RequestHeader::new(vec![0xaa], vec![0xbb]);
        assert_eq!(h.api_key, [0xaa]);
        assert_eq!(h.user_agent, [0xbb]);
        // field 1 (api_key) = 0x0a, field 2 (user_agent) = 0x12
        assert_eq!(h.encode_to_vec(), [0x0a, 0x01, 0xaa, 0x12, 0x01, 0xbb]);
    }

    #[test]
    fn project_info_header_is_field_15() {
        let req = metainfo::ProjectInfoRequest {
            header: Some(RequestHeader::new(*b"key", *b"storj-uplink")),
        };
        let buf = req.encode_to_vec();
        // field 15, wire type 2 (len) => (15 << 3) | 2 = 0x7a
        assert_eq!(buf[0], 0x7a);
        let round = metainfo::ProjectInfoRequest::decode(buf.as_slice()).unwrap();
        let h = round.header.expect("header");
        assert_eq!(h.api_key, b"key");
        assert_eq!(h.user_agent, b"storj-uplink");
    }

    #[test]
    fn rpc_name_is_project_info_not_get_project_info() {
        assert_eq!(rpc::PROJECT_INFO, "/metainfo.Metainfo/ProjectInfo");
        assert!(
            !rpc::PROJECT_INFO.contains("GetProjectInfo"),
            "satellite RPC is ProjectInfo (K15)"
        );
        assert_eq!(rpc::COMPRESSED_BATCH, "/metainfo.Metainfo/CompressedBatch");
        assert_eq!(
            rpc::GET_OBJECT_RETENTION,
            "/metainfo.Metainfo/GetObjectRetention"
        );
        assert_eq!(
            rpc::SET_BUCKET_OBJECT_LOCK_CONFIGURATION,
            "/metainfo.Metainfo/SetBucketObjectLockConfiguration"
        );
    }
}
