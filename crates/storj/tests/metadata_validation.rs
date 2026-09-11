use storj::{CommitUploadOptions, CustomMetadata, ErrorKind, Project, verify_custom_metadata};
use storj_test::MockSatellite;
use tokio::io::AsyncWriteExt;

fn invalid() -> Vec<CustomMetadata> {
    [("", "value"), ("bad\0key", "value"), ("key", "bad\0value")]
        .into_iter()
        .map(|(k, v)| [(k.to_owned(), v.to_owned())].into_iter().collect())
        .collect()
}

#[test]
fn metadata_preflight_matches_go_constraints() {
    verify_custom_metadata(&CustomMetadata::new()).unwrap();
    verify_custom_metadata(
        &[
            ("日本語".into(), "".into()),
            ("app:key".into(), "café 🐈".into()),
        ]
        .into_iter()
        .collect(),
    )
    .unwrap();
    for meta in invalid() {
        let err = verify_custom_metadata(&meta).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MetadataInvalid);
        assert!(!err.is_retryable());
    }
}

#[tokio::test]
async fn invalid_setter_preserves_previous_metadata_and_upload() {
    let mock = MockSatellite::start().await;
    let project = Project::open(&mock.access()).await.unwrap();
    project.ensure_bucket("metadata").await.unwrap();
    let mut upload = project
        .upload_object("metadata", "object", Default::default())
        .await
        .unwrap();
    upload.write_all(b"payload").await.unwrap();
    let good: CustomMetadata = [("app:key".into(), "value".into())].into_iter().collect();
    upload.set_custom_metadata(good.clone()).await.unwrap();
    for meta in invalid() {
        assert_eq!(
            upload.set_custom_metadata(meta).await.unwrap_err().kind(),
            ErrorKind::MetadataInvalid
        );
    }
    upload.commit().await.unwrap();
    assert_eq!(
        project
            .stat_object("metadata", "object")
            .await
            .unwrap()
            .custom,
        good
    );
}

#[tokio::test]
async fn update_rejects_invalid_metadata_before_fetching_missing_object() {
    let mock = MockSatellite::start().await;
    let project = Project::open(&mock.access()).await.unwrap();
    // Neither bucket nor object exists: an RPC would produce a different error.
    for meta in invalid() {
        assert_eq!(
            project
                .update_object_metadata("missing", "object", meta)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::MetadataInvalid
        );
    }
}

#[tokio::test]
async fn multipart_validation_leaves_upload_available_for_valid_commit() {
    let mock = MockSatellite::start().await;
    let project = Project::open(&mock.access()).await.unwrap();
    project.ensure_bucket("metadata").await.unwrap();
    let pending = project
        .begin_upload("metadata", "multipart", Default::default())
        .await
        .unwrap();
    let mut part = project
        .upload_part("metadata", "multipart", &pending.upload_id, 1)
        .await
        .unwrap();
    part.write_all(b"part").await.unwrap();
    part.commit().await.unwrap();
    for meta in invalid() {
        assert_eq!(
            project
                .commit_upload(
                    "metadata",
                    "multipart",
                    &pending.upload_id,
                    CommitUploadOptions {
                        custom_metadata: meta,
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::MetadataInvalid
        );
    }
    project
        .commit_upload(
            "metadata",
            "multipart",
            &pending.upload_id,
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        project
            .stat_object("metadata", "multipart")
            .await
            .unwrap()
            .system
            .content_length,
        4
    );
}
