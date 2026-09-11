//! Object checksums on BeginObject / CommitObject.

use storj::{
    CommitUploadOptions, ErrorKind, ObjectChecksum, ObjectChecksumAlgorithm, Project, UploadOptions,
};
use storj_test::MockSatellite;
use tokio::io::AsyncWriteExt;

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

fn sha256_checksum(encrypted_value: Vec<u8>) -> ObjectChecksum {
    ObjectChecksum {
        algorithm: ObjectChecksumAlgorithm::Sha256,
        composite: false,
        encrypted_value,
    }
}

#[tokio::test]
async fn upload_commit_without_checksum() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-none");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(&bucket, "plain.txt", UploadOptions::default())
        .await
        .expect("upload_object");
    upload.write_all(b"no checksum").await.unwrap();
    let obj = upload.commit().await.expect("commit without checksum");
    assert_eq!(obj.key, "plain.txt");
    assert_eq!(obj.system.content_length, 11);
}

#[tokio::test]
async fn upload_commit_with_checksum() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-up");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(
            &bucket,
            "sum.txt",
            UploadOptions {
                checksum: Some(sha256_checksum(vec![1, 2, 3])),
                ..Default::default()
            },
        )
        .await
        .expect("upload_object");
    upload.write_all(b"checksummed").await.unwrap();
    let obj = upload.commit().await.expect("commit with checksum");
    assert_eq!(obj.system.content_length, 11);
}

#[tokio::test]
async fn multipart_begin_and_commit_checksum() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-mp");
    project.ensure_bucket(&bucket).await.unwrap();
    let key = "multi.bin";
    let checksum = sha256_checksum(vec![1, 2, 3]);

    let info = project
        .begin_upload(
            &bucket,
            key,
            UploadOptions {
                checksum: Some(checksum.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("begin_upload");
    let mut part = project
        .upload_part(&bucket, key, &info.upload_id, 1)
        .await
        .expect("upload_part");
    part.write_all(b"multipart checksum").await.unwrap();
    part.commit().await.unwrap();
    let obj = project
        .commit_upload(
            &bucket,
            key,
            &info.upload_id,
            CommitUploadOptions {
                checksum: Some(checksum),
                ..Default::default()
            },
        )
        .await
        .expect("commit_upload with checksum");
    assert_eq!(obj.key, key);
    assert_eq!(obj.system.content_length, 18);
}

#[tokio::test]
async fn commit_checksum_requires_encrypted_value() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-empty");
    project.ensure_bucket(&bucket).await.unwrap();
    let key = "empty-sum.bin";

    let info = project
        .begin_upload(
            &bucket,
            key,
            UploadOptions {
                checksum: Some(sha256_checksum(Vec::new())),
                ..Default::default()
            },
        )
        .await
        .expect("begin may omit encrypted checksum");
    let mut part = project
        .upload_part(&bucket, key, &info.upload_id, 1)
        .await
        .expect("upload_part");
    part.write_all(b"body").await.unwrap();
    part.commit().await.unwrap();
    let err = project
        .commit_upload(
            &bucket,
            key,
            &info.upload_id,
            CommitUploadOptions {
                checksum: Some(sha256_checksum(Vec::new())),
                ..Default::default()
            },
        )
        .await
        .expect_err("commit requires encrypted checksum when algorithm is set");
    assert_eq!(err.kind(), ErrorKind::Protocol);
}

#[tokio::test]
async fn regular_commit_checksum_requires_encrypted_value() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-up-empty");
    project.ensure_bucket(&bucket).await.unwrap();

    let mut upload = project
        .upload_object(
            &bucket,
            "empty.txt",
            UploadOptions {
                checksum: Some(sha256_checksum(Vec::new())),
                ..Default::default()
            },
        )
        .await
        .expect("begin may omit encrypted checksum");
    upload.write_all(b"body").await.unwrap();
    let err = upload
        .commit()
        .await
        .expect_err("commit requires encrypted checksum when algorithm is set");
    assert_eq!(err.kind(), ErrorKind::Protocol);
}
