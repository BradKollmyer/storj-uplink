//! Bucket operations against the in-process mock satellite.

use futures_util::StreamExt;
use storj::{ErrorKind, ListBucketsOptions, Project};
use storj_test::MockSatellite;

#[tokio::test]
async fn create_stat_ensure_delete_bucket() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let name = unique_bucket();

    let created = project.create_bucket(&name).await.expect("create");
    assert_eq!(created.name, name);

    let already = project.create_bucket(&name).await.unwrap_err();
    assert_eq!(already.kind(), ErrorKind::BucketAlreadyExists);
    assert_eq!(
        already.bucket().map(|b| b.name.as_str()),
        Some(name.as_str())
    );

    let ensured = project.ensure_bucket(&name).await.expect("ensure");
    assert_eq!(ensured.name, name);

    let st = project.stat_bucket(&name).await.expect("stat");
    assert_eq!(st.name, name);

    let missing = project
        .stat_bucket("does-not-exist-zzzz")
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::BucketNotFound);

    project.delete_bucket(&name).await.expect("delete");
}

#[tokio::test]
async fn delete_nonempty_bucket_fails_without_with_objects() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let name = unique_bucket();
    project.ensure_bucket(&name).await.unwrap();
    mock.put_object(&name);
    let err = project.delete_bucket(&name).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BucketNotEmpty);
    project.delete_bucket_with_objects(&name).await.unwrap();
}

#[tokio::test]
async fn list_buckets_cursor() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let a = format!("a-{}", unique_bucket());
    let b = format!("b-{}", unique_bucket());
    project.ensure_bucket(&a).await.unwrap();
    project.ensure_bucket(&b).await.unwrap();

    let mut names = Vec::new();
    let mut stream = project.list_buckets(ListBucketsOptions { cursor: None });
    while let Some(item) = stream.next().await {
        names.push(item.unwrap().name);
    }
    assert!(names.contains(&a), "{names:?}");
    assert!(names.contains(&b), "{names:?}");

    let mut after_a = Vec::new();
    let mut stream = project.list_buckets(ListBucketsOptions {
        cursor: Some(a.clone()),
    });
    while let Some(item) = stream.next().await {
        after_a.push(item.unwrap().name);
    }
    assert!(!after_a.contains(&a), "cursor is exclusive: {after_a:?}");
    assert!(after_a.contains(&b), "{after_a:?}");
}

#[tokio::test]
async fn create_bucket_stat_failure_does_not_invent_bucket() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let name = unique_bucket();
    project.create_bucket(&name).await.unwrap();
    mock.deny_get_bucket(&name);

    let err = project.create_bucket(&name).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BucketAlreadyExists);
    assert!(
        err.bucket().is_none(),
        "failed GetBucket must not attach a UNIX_EPOCH placeholder"
    );
    assert!(
        std::error::Error::source(&err).is_some(),
        "stat failure should be chained"
    );

    let err = project.ensure_bucket(&name).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert!(err.bucket().is_none());
}

#[tokio::test]
async fn empty_bucket_name_is_invalid() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let err = project.create_bucket("").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BucketNameInvalid);
}

async fn open_test_project(mock: &MockSatellite) -> Project {
    Project::open(&mock.access())
        .await
        .expect("open mock project")
}

fn unique_bucket() -> String {
    format!(
        "t-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}
