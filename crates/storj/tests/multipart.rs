//! Multipart upload API (PR 24). Min part 5 MiB except last; max 10_000 parts.

use futures_util::StreamExt;
use storj::constants::{
    MAX_MULTIPART_PARTS, MAX_SEGMENT_SIZE, MIN_MULTIPART_PART_SIZE, STREAM_ID_BASE58_VERSION,
};
use storj::{
    CommitUploadOptions, CustomMetadata, ErrorKind, ListUploadsOptions, Project, UploadOptions,
};
use storj_test::MockSatellite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn multipart_limits_match_satellite_defaults() {
    assert_eq!(MIN_MULTIPART_PART_SIZE, 5 * 1024 * 1024);
    assert_eq!(MAX_MULTIPART_PARTS, 10_000);
}

#[test]
fn upload_id_roundtrip_version_1() {
    let stream_id = b"unit-test-stream-id";
    let encoded = storj_access::check_encode(stream_id, STREAM_ID_BASE58_VERSION);
    let (payload, version) = storj_access::check_decode(&encoded).expect("check_decode");
    assert_eq!(version, STREAM_ID_BASE58_VERSION);
    assert_eq!(version, 1);
    assert_eq!(payload, stream_id);
    let grant = storj_access::check_encode(stream_id, 0);
    assert_ne!(encoded, grant);
    let (_payload, grant_ver) = storj_access::check_decode(&grant).expect("grant decode");
    assert_eq!(grant_ver, 0);
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
async fn begin_part_commit() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("mp");
    project.ensure_bucket(&bucket).await.unwrap();
    let key = "multi.bin";

    let info = project
        .begin_upload(&bucket, key, UploadOptions::default())
        .await
        .expect("begin_upload");
    assert_eq!(info.key, key);
    assert!(!info.upload_id.is_empty());
    let (_payload, version) = storj_access::check_decode(&info.upload_id).expect("upload_id");
    assert_eq!(version, 1);

    let too_small = vec![7u8; 1024];
    let mut p1 = project
        .upload_part(&bucket, key, &info.upload_id, 1)
        .await
        .expect("upload_part 1 small");
    p1.write_all(&too_small).await.unwrap();
    p1.commit().await.unwrap();
    let mut p2 = project
        .upload_part(&bucket, key, &info.upload_id, 2)
        .await
        .expect("upload_part 2");
    p2.write_all(b"tail").await.unwrap();
    p2.commit().await.unwrap();
    let err = project
        .commit_upload(
            &bucket,
            key,
            &info.upload_id,
            CommitUploadOptions::default(),
        )
        .await
        .expect_err("non-last part below 5 MiB must fail");
    assert_ne!(err.kind(), ErrorKind::UploadDone);
    project
        .abort_upload(&bucket, key, &info.upload_id)
        .await
        .expect("abort undersized upload");

    let empty = project
        .begin_upload(&bucket, "", UploadOptions::default())
        .await
        .expect_err("empty key");
    assert_eq!(empty.kind(), ErrorKind::ObjectKeyInvalid);

    let info = project
        .begin_upload(&bucket, key, UploadOptions::default())
        .await
        .expect("begin_upload 2");
    let first = vec![0xA5u8; MIN_MULTIPART_PART_SIZE as usize];
    let mut part1 = project
        .upload_part(&bucket, key, &info.upload_id, 1)
        .await
        .expect("upload_part 1");
    part1.set_etag(b"etag-one").await.unwrap();
    part1.write_all(&first).await.unwrap();
    part1.commit().await.unwrap();

    let last = b"last-part-bytes";
    let mut part2 = project
        .upload_part(&bucket, key, &info.upload_id, 2)
        .await
        .expect("upload_part 2");
    part2.write_all(last).await.unwrap();
    part2.commit().await.unwrap();

    let parts: Vec<_> = project
        .list_upload_parts(&bucket, key, &info.upload_id, Default::default())
        .collect()
        .await;
    let parts: Vec<_> = parts.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].part_number, 1);
    assert_eq!(parts[0].size, first.len() as i64);
    assert_eq!(parts[0].etag, b"etag-one");
    assert_eq!(parts[1].part_number, 2);
    assert_eq!(parts[1].size, last.len() as i64);

    let mut custom = CustomMetadata::new();
    custom.insert("app:kind".into(), "multipart".into());
    let obj = project
        .commit_upload(
            &bucket,
            key,
            &info.upload_id,
            CommitUploadOptions {
                custom_metadata: custom.clone(),
            },
        )
        .await
        .expect("commit_upload");
    assert_eq!(obj.key, key);
    assert_eq!(obj.system.content_length, (first.len() + last.len()) as i64);
    assert_eq!(
        obj.custom.get("app:kind").map(String::as_str),
        Some("multipart")
    );

    let mut download = project
        .download_object(&bucket, key, Default::default())
        .await
        .expect("download");
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), first.len() + last.len());
    assert_eq!(&got[..first.len()], first.as_slice());
    assert_eq!(&got[first.len()..], last);
}

#[tokio::test]
async fn abort_multipart() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("abort");
    project.ensure_bucket(&bucket).await.unwrap();
    let key = "gone.bin";

    let info = project
        .begin_upload(&bucket, key, UploadOptions::default())
        .await
        .unwrap();
    let mut part = project
        .upload_part(&bucket, key, &info.upload_id, 1)
        .await
        .unwrap();
    part.write_all(b"will abort").await.unwrap();
    part.commit().await.unwrap();

    project
        .abort_upload(&bucket, key, &info.upload_id)
        .await
        .expect("abort_upload");
    assert!(mock.aborted_count() >= 1);

    let err = project
        .commit_upload(
            &bucket,
            key,
            &info.upload_id,
            CommitUploadOptions::default(),
        )
        .await
        .expect_err("commit after abort");
    assert!(
        err.kind() == ErrorKind::ObjectNotFound || err.kind() == ErrorKind::UploadIdInvalid,
        "commit after abort: {}",
        err.kind()
    );

    let bad = project
        .upload_part(&bucket, key, "not-an-upload-id", 1)
        .await
        .err()
        .expect("invalid upload id");
    assert_eq!(bad.kind(), ErrorKind::UploadIdInvalid);
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

    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("list");
    project.ensure_bucket(&bucket).await.unwrap();
    let info = project
        .begin_upload(&bucket, "pending/obj", Default::default())
        .await
        .unwrap();
    let mut part = project
        .upload_part(&bucket, "pending/obj", &info.upload_id, 1)
        .await
        .unwrap();
    part.write_all(b"listed-part").await.unwrap();
    part.commit().await.unwrap();

    let listed: Vec<_> = project
        .list_uploads(
            &bucket,
            ListUploadsOptions {
                prefix: "pending/".into(),
                recursive: true,
                system: true,
                ..Default::default()
            },
        )
        .collect()
        .await;
    let listed: Vec<_> = listed.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(
        listed.iter().any(|u| u.upload_id == info.upload_id),
        "pending upload should be listed"
    );

    let nested = project
        .begin_upload(&bucket, "pending/nested/x", Default::default())
        .await
        .unwrap();
    let collapsed: Vec<_> = project
        .list_uploads(
            &bucket,
            ListUploadsOptions {
                prefix: "pending/".into(),
                recursive: false,
                system: true,
                ..Default::default()
            },
        )
        .collect()
        .await;
    let collapsed: Vec<_> = collapsed
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        collapsed.iter().any(|u| u.upload_id == info.upload_id),
        "object under prefix should be listed"
    );
    assert!(
        collapsed.iter().all(|u| !u.upload_id.is_empty()),
        "prefix entries must not be returned as uploads"
    );
    assert!(
        !collapsed
            .iter()
            .any(|u| u.upload_id == storj_access::check_encode(b"", STREAM_ID_BASE58_VERSION)),
        "empty stream_id must not be encoded as an upload id"
    );
    let _ = nested;
}

#[tokio::test]
async fn part_etag_survives_exact_segment_size() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("etag64");
    project.ensure_bucket(&bucket).await.unwrap();
    let key = "exact.bin";
    let info = project
        .begin_upload(&bucket, key, Default::default())
        .await
        .unwrap();
    let payload = vec![0x5Au8; MAX_SEGMENT_SIZE as usize];
    let mut part = project
        .upload_part(&bucket, key, &info.upload_id, 1)
        .await
        .unwrap();
    part.set_etag(b"exact-seg-etag").await.unwrap();
    part.write_all(&payload).await.unwrap();
    part.commit().await.unwrap();

    let parts: Vec<_> = project
        .list_upload_parts(&bucket, key, &info.upload_id, Default::default())
        .collect()
        .await;
    let parts: Vec<_> = parts.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].part_number, 1);
    assert_eq!(parts[0].size, MAX_SEGMENT_SIZE as i64);
    assert_eq!(parts[0].etag, b"exact-seg-etag");
}
