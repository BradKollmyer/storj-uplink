//! Multipart upload API (PR 24). Min part 5 MiB except last; max 10_000 parts.

use storj::constants::{MAX_MULTIPART_PARTS, MIN_MULTIPART_PART_SIZE};
use storj::{CommitUploadOptions, ErrorKind, ListUploadsOptions, UploadOptions};

#[test]
fn multipart_limits_match_satellite_defaults() {
    assert_eq!(MIN_MULTIPART_PART_SIZE, 5 * 1024 * 1024);
    assert_eq!(MAX_MULTIPART_PARTS, 10_000);
}

#[tokio::test]
#[ignore = "PR 24: BeginUpload / UploadPart / CommitUpload"]
async fn begin_part_commit() {
    panic!("needs multipart implementation");
}

#[tokio::test]
#[ignore = "PR 24: abort"]
async fn abort_multipart() {
    panic!("needs abort_upload");
}

#[tokio::test]
async fn list_uploads_prefix_slash_rule() {
    let bad = ListUploadsOptions {
        prefix: "p".into(),
        ..Default::default()
    };
    assert_eq!(
        bad.validate().unwrap_err().kind(),
        ErrorKind::ObjectKeyInvalid
    );
    let _ = (UploadOptions::default(), CommitUploadOptions::default());
}
