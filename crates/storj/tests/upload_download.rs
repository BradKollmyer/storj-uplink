//! Upload/download pipeline tests (PR 13–14, 22).
//!
//! Sizes from the design exit criterion: empty, 1B, inline±1, 64MiB, 64MiB+1.

use storj::{DownloadOptions, ErrorKind};
use storj_test::{INTEROP_SIZES, size_label};

#[test]
fn interop_sizes_are_the_exit_criterion() {
    let labels: Vec<_> = INTEROP_SIZES.iter().copied().map(size_label).collect();
    assert_eq!(
        labels,
        ["empty", "1B", "inline-1", "inline+1", "1seg", "64MiB+1"]
    );
}

#[tokio::test]
#[ignore = "PR 13: single-segment upload"]
async fn upload_commit_then_download() {
    panic!("needs Project::upload_object implementation");
}

#[tokio::test]
#[ignore = "PR 13: Drop without commit aborts"]
async fn drop_upload_aborts() {
    panic!("needs Upload Drop → abort");
}

#[tokio::test]
#[ignore = "PR 14: ranged download"]
async fn ranged_download() {
    let opts = DownloadOptions {
        offset: 10,
        length: 100,
    };
    assert!(opts.validate().is_ok());
    panic!("needs download pipeline");
}

#[tokio::test]
async fn ranged_download_rejects_go_unsupported_combo() {
    let opts = DownloadOptions {
        offset: -10,
        length: 100,
    };
    assert_eq!(
        opts.validate().unwrap_err().kind(),
        ErrorKind::ObjectKeyInvalid
    );
}

#[tokio::test]
#[ignore = "PR 14: poll_shutdown does not commit"]
async fn shutdown_does_not_commit() {
    panic!("AsyncWrite::poll_shutdown must not call CommitObject");
}

#[tokio::test]
#[ignore = "PR 22: multi-segment 64MiB+1"]
async fn multi_segment_round_trip() {
    let size = INTEROP_SIZES[5];
    assert_eq!(size_label(size), "64MiB+1");
    panic!("needs multi-segment pipeline");
}

#[tokio::test]
#[ignore = "PR 13: inline segment threshold"]
async fn inline_vs_remote_threshold() {
    panic!("encrypted size ≤ 4KiB → MakeInlineSegment");
}
