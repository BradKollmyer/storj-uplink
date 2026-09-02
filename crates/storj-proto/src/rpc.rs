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
/// Begin an object upload (`BeginObject`).
pub const BEGIN_OBJECT: &str = "/metainfo.Metainfo/BeginObject";
/// Commit an object (`CommitObject`).
pub const COMMIT_OBJECT: &str = "/metainfo.Metainfo/CommitObject";
/// Begin a segment (`BeginSegment`).
pub const BEGIN_SEGMENT: &str = "/metainfo.Metainfo/BeginSegment";
/// Commit a remote segment (`CommitSegment`).
pub const COMMIT_SEGMENT: &str = "/metainfo.Metainfo/CommitSegment";
/// Store an inline segment on the satellite (`MakeInlineSegment`).
pub const MAKE_INLINE_SEGMENT: &str = "/metainfo.Metainfo/MakeInlineSegment";
/// Replace failed piece order limits (`RetryBeginSegmentPieces`).
pub const RETRY_BEGIN_SEGMENT_PIECES: &str = "/metainfo.Metainfo/RetryBeginSegmentPieces";
/// Abort / delete a pending object (`BeginDeleteObject`).
pub const BEGIN_DELETE_OBJECT: &str = "/metainfo.Metainfo/BeginDeleteObject";
/// Finish object delete (`FinishDeleteObject`).
pub const FINISH_DELETE_OBJECT: &str = "/metainfo.Metainfo/FinishDeleteObject";

/// Storage-node piece upload (client stream).
pub const PIECESTORE_UPLOAD: &str = "/piecestore.Piecestore/Upload";
/// Storage-node piece download (bidi stream).
pub const PIECESTORE_DOWNLOAD: &str = "/piecestore.Piecestore/Download";
