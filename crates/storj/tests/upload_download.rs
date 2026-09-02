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

    let mut at_eof = project
        .download_object(
            &bucket,
            "bytes.bin",
            DownloadOptions {
                offset: payload.len() as i64,
                length: -1,
            },
        )
        .await
        .expect("offset at EOF is empty, not an error");
    assert_eq!(at_eof.info().system.content_length, payload.len() as i64);
    let mut empty = Vec::new();
    at_eof.read_to_end(&mut empty).await.unwrap();
    assert!(empty.is_empty());

    let mut past_eof = project
        .download_object(
            &bucket,
            "bytes.bin",
            DownloadOptions {
                offset: payload.len() as i64 + 50,
                length: 10,
            },
        )
        .await
        .expect("offset past EOF is empty, not an error");
    empty.clear();
    past_eof.read_to_end(&mut empty).await.unwrap();
    assert!(empty.is_empty());
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
    let zero = DownloadOptions {
        offset: -10,
        length: 0,
    };
    assert_eq!(
        zero.validate().unwrap_err().kind(),
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

fn pattern_byte(i: usize) -> u8 {
    (i % 251) as u8
}

async fn write_pattern(upload: &mut storj::Upload, size: usize) {
    let mut pos = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    while pos < size {
        let n = (size - pos).min(buf.len());
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern_byte(pos + i);
        }
        upload.write_all(&buf[..n]).await.unwrap();
        pos += n;
    }
}

fn assert_pattern(got: &[u8], offset: usize) {
    assert!(
        got.iter()
            .enumerate()
            .all(|(i, b)| *b == pattern_byte(offset + i)),
        "pattern mismatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_segment_round_trip() {
    let size = INTEROP_SIZES[5] as usize;
    assert_eq!(size_label(size as u64), "64MiB+1");

    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("ms");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(&bucket, "big.bin", Default::default())
        .await
        .unwrap();
    write_pattern(&mut upload, size).await;
    let obj = upload.commit().await.expect("commit 64MiB+1");
    assert_eq!(obj.system.content_length, size as i64);
    assert!(mock.remote_segment_count() >= 1);
    assert_eq!(mock.inline_segment_count() + mock.remote_segment_count(), 2);

    let mut download = project
        .download_object(&bucket, "big.bin", Default::default())
        .await
        .expect("full download");
    assert_eq!(download.info().system.content_length, size as i64);
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), size);
    assert_pattern(&got, 0);
    drop(got);

    let span_off = MAX_SEGMENT_SIZE as i64 - 16;
    let mut spanned = project
        .download_object(
            &bucket,
            "big.bin",
            DownloadOptions {
                offset: span_off,
                length: 17,
            },
        )
        .await
        .expect("spanning range");
    let mut slice = Vec::new();
    spanned.read_to_end(&mut slice).await.unwrap();
    assert_eq!(slice.len(), 17);
    assert_pattern(&slice, span_off as usize);

    let mut suffix = project
        .download_object(
            &bucket,
            "big.bin",
            DownloadOptions {
                offset: -8,
                length: -1,
            },
        )
        .await
        .expect("suffix range");
    let mut tail = Vec::new();
    suffix.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail.len(), 8);
    assert_pattern(&tail, size - 8);
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
async fn corrupt_metadata_fails_download() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("badmeta");
    project.ensure_bucket(&bucket).await.unwrap();
    let mut upload = project
        .upload_object(&bucket, "m", Default::default())
        .await
        .unwrap();
    upload.write_all(b"x").await.unwrap();
    upload.commit().await.unwrap();
    mock.corrupt_encrypted_metadata();
    let err = match project
        .download_object(&bucket, "m", Default::default())
        .await
    {
        Ok(_) => panic!("corrupt metadata must fail the download"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), ErrorKind::DecryptionFailed);
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

#[tokio::test(flavor = "multi_thread")]
async fn write_beyond_one_segment_is_two_segments() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("big");
    project.ensure_bucket(&bucket).await.unwrap();
    let mut upload = project
        .upload_object(&bucket, "two-seg", Default::default())
        .await
        .unwrap();
    write_pattern(&mut upload, MAX_SEGMENT_SIZE as usize + 1).await;
    let obj = upload.commit().await.expect("64MiB+1 commit");
    assert_eq!(obj.system.content_length, MAX_SEGMENT_SIZE as i64 + 1);
    assert!(mock.remote_segment_count() >= 1);
    assert_eq!(mock.inline_segment_count() + mock.remote_segment_count(), 2);
    assert_eq!(mock.committed_count(), 1);
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

#[tokio::test]
async fn upload_from_download_to_round_trip() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("fromto");
    project.ensure_bucket(&bucket).await.unwrap();

    let payload = b"upload_from then download_to";
    let obj = project
        .upload_from(&bucket, "rt.txt", payload.as_slice(), Default::default())
        .await
        .expect("upload_from");
    assert_eq!(obj.key, "rt.txt");
    assert_eq!(obj.system.content_length, payload.len() as i64);
    assert_eq!(mock.committed_count(), 1);

    let mut got = Vec::new();
    let info = project
        .download_to(&bucket, "rt.txt", &mut got, Default::default())
        .await
        .expect("download_to");
    assert_eq!(info.key, "rt.txt");
    assert_eq!(got, payload);
}

#[tokio::test]
async fn upload_from_aborts_on_reader_error() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("fromerr");
    project.ensure_bucket(&bucket).await.unwrap();

    let err = project
        .upload_from(
            &bucket,
            "boom.bin",
            FailAfter { left: 4 },
            Default::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Io);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(mock.committed_count(), 0);
    assert!(mock.aborted_count() >= 1);
}

#[tokio::test]
async fn upload_from_empty_key_is_invalid() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("fromek");
    project.ensure_bucket(&bucket).await.unwrap();
    let err = project
        .upload_from(&bucket, "", tokio::io::empty(), Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);
}

#[tokio::test]
async fn download_to_empty_key_is_invalid() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let err = project
        .download_to("b", "", tokio::io::sink(), Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);
}

struct FailAfter {
    left: usize,
}

impl tokio::io::AsyncRead for FailAfter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.left == 0 {
            return std::task::Poll::Ready(Err(std::io::Error::other("reader failed")));
        }
        if buf.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        buf.put_slice(b"x");
        self.left -= 1;
        std::task::Poll::Ready(Ok(()))
    }
}
