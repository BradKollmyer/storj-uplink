//! Upload/download pipeline tests (PR 13–14, 22).
//!
//! Sizes from the design exit criterion: empty, 1B, inline±1, 64MiB, 64MiB+1.

use std::time::Duration;

use storj::constants::MAX_SEGMENT_SIZE;
use storj::{DownloadOptions, ErrorKind, Project};
use storj_test::{INTEROP_SIZES, MockSatellite, size_label};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn interop_sizes_are_the_exit_criterion() {
    let labels: Vec<_> = INTEROP_SIZES.iter().copied().map(size_label).collect();
    assert_eq!(
        labels,
        ["empty", "1B", "inline-1", "inline+1", "1seg", "64MiB+1"]
    );
}

async fn open_project(mock: &MockSatellite) -> Project {
    Project::open(&mock.access()).await.expect("open")
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[tokio::test]
async fn upload_commit_then_info() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("up");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(&bucket, "hello.txt", Default::default())
        .await
        .expect("upload_object");
    upload.write_all(b"hello storj").await.expect("write");
    let obj = upload.commit().await.expect("commit");
    assert_eq!(obj.key, "hello.txt");
    assert_eq!(obj.system.content_length, 11);
    assert_eq!(mock.committed_count(), 1);
    assert_eq!(mock.inline_segment_count(), 1);
    assert_eq!(mock.remote_segment_count(), 0);

    let mut download = project
        .download_object(&bucket, "hello.txt", Default::default())
        .await
        .expect("download_object");
    assert_eq!(download.info().key, "hello.txt");
    assert_eq!(download.info().system.content_length, 11);
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.expect("read");
    assert_eq!(got, b"hello storj");
    download.close().await.expect("close");
}

#[tokio::test]
async fn drop_upload_aborts() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("drop");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(&bucket, "gone.bin", Default::default())
        .await
        .unwrap();
    upload.write_all(b"not committed").await.unwrap();
    drop(upload);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(mock.committed_count(), 0);
    assert!(mock.aborted_count() >= 1);
}

#[tokio::test]
async fn ranged_download() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("range");
    project.ensure_bucket(&bucket).await.unwrap();

    let payload: Vec<u8> = (0u8..=255).collect();
    let mut upload = project
        .upload_object(&bucket, "bytes.bin", Default::default())
        .await
        .unwrap();
    upload.write_all(&payload).await.unwrap();
    upload.commit().await.unwrap();

    let opts = DownloadOptions {
        offset: 10,
        length: 20,
    };
    assert!(opts.validate().is_ok());
    let mut download = project
        .download_object(&bucket, "bytes.bin", opts)
        .await
        .expect("ranged download");
    assert_eq!(download.info().system.content_length, payload.len() as i64);
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, &payload[10..30]);

    let mut suffix = project
        .download_object(
            &bucket,
            "bytes.bin",
            DownloadOptions {
                offset: -8,
                length: -1,
            },
        )
        .await
        .expect("suffix download");
    let mut tail = Vec::new();
    suffix.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, &payload[payload.len() - 8..]);
}

#[tokio::test]
async fn remote_segment_round_trip() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("remote");
    project.ensure_bucket(&bucket).await.unwrap();

    let payload = vec![0x5Au8; 5000];
    let mut upload = project
        .upload_object(&bucket, "big.bin", Default::default())
        .await
        .unwrap();
    upload.write_all(&payload).await.unwrap();
    upload.commit().await.unwrap();
    assert_eq!(mock.remote_segment_count(), 1);

    let mut download = project
        .download_object(&bucket, "big.bin", Default::default())
        .await
        .expect("remote download");
    assert_eq!(download.info().system.content_length, 5000);
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, payload);

    let mut ranged = project
        .download_object(
            &bucket,
            "big.bin",
            DownloadOptions {
                offset: 100,
                length: 50,
            },
        )
        .await
        .unwrap();
    let mut slice = Vec::new();
    ranged.read_to_end(&mut slice).await.unwrap();
    assert_eq!(slice, &payload[100..150]);
}

#[tokio::test]
async fn download_missing_object() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("miss");
    project.ensure_bucket(&bucket).await.unwrap();
    let err = match project
        .download_object(&bucket, "nope", Default::default())
        .await
    {
        Ok(_) => panic!("missing object must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), ErrorKind::ObjectNotFound);
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
async fn shutdown_does_not_commit() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("shut");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(&bucket, "pending.txt", Default::default())
        .await
        .unwrap();
    upload.write_all(b"still pending").await.unwrap();
    AsyncWriteExt::shutdown(&mut upload).await.unwrap();
    assert_eq!(mock.committed_count(), 0);
    let obj = upload.commit().await.expect("commit after shutdown");
    assert_eq!(obj.system.content_length, 13);
    assert_eq!(mock.committed_count(), 1);
}

#[tokio::test]
#[ignore = "PR 22: multi-segment 64MiB+1"]
async fn multi_segment_round_trip() {
    let size = INTEROP_SIZES[5];
    assert_eq!(size_label(size), "64MiB+1");
    panic!("needs multi-segment pipeline");
}

#[tokio::test]
async fn inline_vs_remote_threshold() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("thr");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut small = project
        .upload_object(&bucket, "small", Default::default())
        .await
        .unwrap();
    small.write_all(&[0u8; 100]).await.unwrap();
    small.commit().await.unwrap();
    assert_eq!(mock.inline_segment_count(), 1);
    assert_eq!(mock.remote_segment_count(), 0);

    let mut large = project
        .upload_object(&bucket, "large", Default::default())
        .await
        .unwrap();
    large.write_all(&vec![1u8; 5000]).await.unwrap();
    large.commit().await.unwrap();
    assert_eq!(mock.inline_segment_count(), 1);
    assert_eq!(mock.remote_segment_count(), 1);
}

#[tokio::test]
async fn empty_object_is_inline() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("empty");
    project.ensure_bucket(&bucket).await.unwrap();
    let upload = project
        .upload_object(&bucket, "zero", Default::default())
        .await
        .unwrap();
    let obj = upload.commit().await.unwrap();
    assert_eq!(obj.system.content_length, 0);
    assert_eq!(mock.inline_segment_count(), 1);
    let mut download = project
        .download_object(&bucket, "zero", Default::default())
        .await
        .unwrap();
    assert_eq!(download.info().system.content_length, 0);
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.unwrap();
    assert!(got.is_empty());
}

#[tokio::test]
async fn empty_key_is_invalid() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("ek");
    project.ensure_bucket(&bucket).await.unwrap();
    let err = match project.upload_object(&bucket, "", Default::default()).await {
        Ok(_) => panic!("empty key must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);
}

#[tokio::test]
async fn set_custom_metadata_at_commit() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("meta");
    project.ensure_bucket(&bucket).await.unwrap();
    let mut upload = project
        .upload_object(&bucket, "m", Default::default())
        .await
        .unwrap();
    let mut meta = storj::CustomMetadata::new();
    meta.insert("app:title".into(), "hi".into());
    upload.set_custom_metadata(meta.clone()).await.unwrap();
    upload.write_all(b"x").await.unwrap();
    let obj = upload.commit().await.unwrap();
    assert_eq!(obj.custom.get("app:title").map(String::as_str), Some("hi"));

    let download = project
        .download_object(&bucket, "m", Default::default())
        .await
        .unwrap();
    assert_eq!(
        download.info().custom.get("app:title").map(String::as_str),
        Some("hi")
    );
}

#[tokio::test]
async fn abort_uncommitted() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("ab");
    project.ensure_bucket(&bucket).await.unwrap();
    let mut upload = project
        .upload_object(&bucket, "y", Default::default())
        .await
        .unwrap();
    upload.write_all(b"nope").await.unwrap();
    upload.abort().await.unwrap();
    assert_eq!(mock.committed_count(), 0);
    assert!(mock.aborted_count() >= 1);
}

#[tokio::test]
async fn write_beyond_one_segment_fails() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("big");
    project.ensure_bucket(&bucket).await.unwrap();
    let mut upload = project
        .upload_object(&bucket, "too-big", Default::default())
        .await
        .unwrap();
    let data = vec![0u8; MAX_SEGMENT_SIZE as usize + 1];
    let err = upload.write_all(&data).await.unwrap_err();
    assert!(err.to_string().contains("64MiB") || err.to_string().contains("single-segment"));
    drop(upload);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(mock.committed_count(), 0);
}

#[tokio::test]
async fn failed_commit_object_aborts() {
    let mock = MockSatellite::start().await;
    mock.fail_next_commit_object();
    let project = open_project(&mock).await;
    let bucket = unique("failc");
    project.ensure_bucket(&bucket).await.unwrap();
    let mut upload = project
        .upload_object(&bucket, "x", Default::default())
        .await
        .unwrap();
    upload.write_all(b"hello").await.unwrap();
    assert!(upload.commit().await.is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(mock.committed_count(), 0);
    assert!(mock.aborted_count() >= 1);
}
