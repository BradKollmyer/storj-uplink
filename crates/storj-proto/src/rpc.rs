//! DRPC invoke paths (`/package.Service/Method`).

/// Satellite metainfo `ProjectInfo` (not `GetProjectInfo`).
pub const PROJECT_INFO: &str = "/metainfo.Metainfo/ProjectInfo";
/// Default data-path RPC (zstd `CompressedBatch`).
pub const COMPRESSED_BATCH: &str = "/metainfo.Metainfo/CompressedBatch";
/// Uncompressed batch fallback.
pub const BATCH: &str = "/metainfo.Metainfo/Batch";
/// Create a bucket.
pub const CREATE_BUCKET: &str = "/metainfo.Metainfo/CreateBucket";
/// Stat a bucket.
pub const GET_BUCKET: &str = "/metainfo.Metainfo/GetBucket";
/// Delete a bucket.
pub const DELETE_BUCKET: &str = "/metainfo.Metainfo/DeleteBucket";
/// List buckets.
pub const LIST_BUCKETS: &str = "/metainfo.Metainfo/ListBuckets";
/// Revoke an API key (`Project::revoke_access`).
pub const REVOKE_API_KEY: &str = "/metainfo.Metainfo/RevokeAPIKey";

/// Storage-node piece upload (client stream).
pub const PIECESTORE_UPLOAD: &str = "/piecestore.Piecestore/Upload";
/// Storage-node piece download (bidi stream).
pub const PIECESTORE_DOWNLOAD: &str = "/piecestore.Piecestore/Download";
