//! Object checksums on BeginObject / CommitObject.
//!
//! The caller supplies the plaintext checksum; the library encrypts it under
//! the object's metadata key at commit (like the ETag). The mock decrypts it
//! the way a reader using `include_checksum` would, so these tests assert the
//! value round-trips and never reaches the satellite in the clear.

use storj::{
    CommitUploadOptions, ErrorKind, ObjectChecksum, ObjectChecksumAlgorithm, Project, UploadOptions,
};
use storj_test::MockSatellite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SHA256_PROTO: i32 = storj_proto::metainfo::ObjectChecksumAlgorithm::Sha256 as i32;

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

fn sha256_checksum(value: Vec<u8>) -> ObjectChecksum {
    ObjectChecksum {
        algorithm: ObjectChecksumAlgorithm::Sha256,
        composite: false,
        value,
    }
}

/// Assert the stored checksum is ciphertext that decrypts back to `plain`.
fn assert_round_trip(mock: &MockSatellite, bucket: &str, key: &str, plain: &[u8], composite: bool) {
    let stored = mock
        .committed_checksum(bucket, key)
        .expect("committed object");
    assert_eq!(stored.algorithm, SHA256_PROTO);
    assert_eq!(stored.composite, composite);
    assert_ne!(
        stored.encrypted_value, plain,
        "checksum must not reach the satellite in plaintext"
    );
    assert!(
        stored.encrypted_value.len() > plain.len(),
        "ciphertext carries an authentication tag"
    );
    assert_eq!(
        stored.value.as_deref(),
        Ok(plain),
        "decrypts under the metadata key"
    );
}

#[tokio::test]
async fn metadata_updates_preserve_regular_and_multipart_checksums() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-metadata");
    project.ensure_bucket(&bucket).await.unwrap();
    let plain = vec![0x5a; 32];
    let body = b"checksummed body";
    for multipart in [false, true] {
        let key = if multipart { "multipart" } else { "regular" };
        let checksum = ObjectChecksum {
            algorithm: ObjectChecksumAlgorithm::Sha256,
            composite: multipart,
            value: plain.clone(),
        };
        if multipart {
            let pending = project
                .begin_upload(&bucket, key, Default::default())
                .await
                .unwrap();
            let mut part = project
                .upload_part(&bucket, key, &pending.upload_id, 1)
                .await
                .unwrap();
            part.write_all(body).await.unwrap();
            part.commit().await.unwrap();
            project
                .commit_upload(
                    &bucket,
                    key,
                    &pending.upload_id,
                    CommitUploadOptions {
                        checksum: Some(checksum),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        } else {
            let mut upload = project
                .upload_object(
                    &bucket,
                    key,
                    UploadOptions {
                        checksum: Some(checksum),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            upload.write_all(body).await.unwrap();
            upload.commit().await.unwrap();
        }
        assert_round_trip(&mock, &bucket, key, &plain, multipart);
        for value in ["first update", "second update"] {
            let before = mock.committed_checksum(&bucket, key).unwrap();
            let metadata = [("label".to_owned(), value.to_owned())]
                .into_iter()
                .collect();
            project
                .update_object_metadata(&bucket, key, metadata)
                .await
                .unwrap();
            assert_round_trip(&mock, &bucket, key, &plain, multipart);
            let after = mock.committed_checksum(&bucket, key).unwrap();
            assert_ne!(
                before.encrypted_value, after.encrypted_value,
                "checksum must be encrypted under the new metadata key"
            );
            let mut download = project
                .download_object(&bucket, key, Default::default())
                .await
                .unwrap();
            assert_eq!(
                download.info().custom.get("label").map(String::as_str),
                Some(value)
            );
            assert_eq!(download.info().system.content_length, body.len() as i64);
            let mut got = Vec::new();
            download.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, body);
        }
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
    let stored = mock.committed_checksum(&bucket, "plain.txt").unwrap();
    assert_eq!(stored.algorithm, 0);
    assert!(!stored.composite);
    assert!(stored.encrypted_value.is_empty());
}

#[tokio::test]
async fn upload_commit_with_checksum() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-up");
    project.ensure_bucket(&bucket).await.unwrap();
    let plain = vec![0xABu8; 32];

    let mut upload = project
        .upload_object(
            &bucket,
            "sum.txt",
            UploadOptions {
                checksum: Some(sha256_checksum(plain.clone())),
                ..Default::default()
            },
        )
        .await
        .expect("upload_object");
    upload.write_all(b"checksummed").await.unwrap();
    let obj = upload.commit().await.expect("commit with checksum");
    assert_eq!(obj.system.content_length, 11);
    assert_round_trip(&mock, &bucket, "sum.txt", &plain, false);
}

#[tokio::test]
async fn multipart_begin_and_commit_checksum() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-mp");
    project.ensure_bucket(&bucket).await.unwrap();
    let key = "multi.bin";
    let plain = vec![0x5Au8; 32];

    // Begin announces the algorithm only; the composite value is not known
    // until the parts are done, so it may be empty here.
    let info = project
        .begin_upload(
            &bucket,
            key,
            UploadOptions {
                checksum: Some(ObjectChecksum {
                    algorithm: ObjectChecksumAlgorithm::Sha256,
                    composite: true,
                    value: Vec::new(),
                }),
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
                checksum: Some(ObjectChecksum {
                    algorithm: ObjectChecksumAlgorithm::Sha256,
                    composite: true,
                    value: plain.clone(),
                }),
                ..Default::default()
            },
        )
        .await
        .expect("commit_upload with checksum");
    assert_eq!(obj.key, key);
    assert_eq!(obj.system.content_length, 18);
    assert_round_trip(&mock, &bucket, key, &plain, true);
}

#[tokio::test]
async fn copy_and_move_preserve_checksums() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-copy");
    project.ensure_bucket(&bucket).await.unwrap();
    let plain = vec![0xCDu8; 32];

    let mut upload = project
        .upload_object(
            &bucket,
            "src.bin",
            UploadOptions {
                checksum: Some(sha256_checksum(plain.clone())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    upload.write_all(b"checksummed copy").await.unwrap();
    upload.commit().await.unwrap();

    project
        .copy_object(&bucket, "src.bin", &bucket, "dst.bin")
        .await
        .expect("copy");
    assert_round_trip(&mock, &bucket, "dst.bin", &plain, false);

    project
        .move_object(&bucket, "dst.bin", &bucket, "moved.bin")
        .await
        .expect("move");
    assert_round_trip(&mock, &bucket, "moved.bin", &plain, false);
}

#[tokio::test]
async fn each_commit_uses_its_own_metadata_key() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-keys");
    project.ensure_bucket(&bucket).await.unwrap();
    let plain = vec![0x11u8; 32];

    for key in ["a.bin", "b.bin"] {
        let mut upload = project
            .upload_object(
                &bucket,
                key,
                UploadOptions {
                    checksum: Some(sha256_checksum(plain.clone())),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        upload.write_all(b"same checksum").await.unwrap();
        upload.commit().await.unwrap();
    }
    let a = mock.committed_checksum(&bucket, "a.bin").unwrap();
    let b = mock.committed_checksum(&bucket, "b.bin").unwrap();
    assert_eq!(a.value.as_deref(), Ok(plain.as_slice()));
    assert_eq!(b.value.as_deref(), Ok(plain.as_slice()));
    assert_ne!(
        a.encrypted_value, b.encrypted_value,
        "a fresh random metadata key per commit yields distinct ciphertexts"
    );
}

#[tokio::test]
async fn commit_checksum_requires_value() {
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
        .expect("begin may omit the checksum value");
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
        .expect_err("commit requires the checksum value when algorithm is set");
    assert_eq!(err.kind(), ErrorKind::MetadataInvalid);
}

#[tokio::test]
async fn upload_object_checksum_requires_value_before_begin() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-up-empty");
    project.ensure_bucket(&bucket).await.unwrap();

    // `Upload::commit` sends the value, so it is required up front; no
    // pending object is created.
    let Err(err) = project
        .upload_object(
            &bucket,
            "empty.txt",
            UploadOptions {
                checksum: Some(sha256_checksum(Vec::new())),
                ..Default::default()
            },
        )
        .await
    else {
        panic!("upload_object requires the checksum value");
    };
    assert_eq!(err.kind(), ErrorKind::MetadataInvalid);
    assert_eq!(mock.committed_count(), 0);
}

#[tokio::test]
async fn checksum_value_requires_algorithm() {
    let mock = MockSatellite::start().await;
    let project = open_project(&mock).await;
    let bucket = unique("cksum-noalgo");
    project.ensure_bucket(&bucket).await.unwrap();

    let Err(err) = project
        .upload_object(
            &bucket,
            "noalgo.txt",
            UploadOptions {
                checksum: Some(ObjectChecksum {
                    algorithm: ObjectChecksumAlgorithm::None,
                    composite: false,
                    value: vec![1, 2, 3],
                }),
                ..Default::default()
            },
        )
        .await
    else {
        panic!("value without algorithm");
    };
    assert_eq!(err.kind(), ErrorKind::MetadataInvalid);

    let err = project
        .begin_upload(
            &bucket,
            "noalgo.bin",
            UploadOptions {
                checksum: Some(ObjectChecksum {
                    algorithm: ObjectChecksumAlgorithm::None,
                    composite: true,
                    value: Vec::new(),
                }),
                ..Default::default()
            },
        )
        .await
        .expect_err("composite without algorithm");
    assert_eq!(err.kind(), ErrorKind::MetadataInvalid);
}
