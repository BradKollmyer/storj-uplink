//! Bucket operations against a mock satellite (PR 11) or `storj-sim`.

use futures_util::StreamExt;
use storj::{ErrorKind, ListBucketsOptions, Project};

#[tokio::test]
#[ignore = "PR 11: metainfo client"]
async fn create_stat_ensure_delete_bucket() {
    let project = open_test_project().await;
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
#[ignore = "PR 11: metainfo client"]
async fn delete_nonempty_bucket_fails_without_with_objects() {
    let project = open_test_project().await;
    let name = unique_bucket();
    project.ensure_bucket(&name).await.unwrap();
    // upload one object then:
    let err = project.delete_bucket(&name).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BucketNotEmpty);
    project.delete_bucket_with_objects(&name).await.unwrap();
}

#[tokio::test]
#[ignore = "PR 11: metainfo client"]
async fn list_buckets_cursor() {
    let project = open_test_project().await;
    let mut stream = project.list_buckets(ListBucketsOptions { cursor: None });
    while let Some(item) = stream.next().await {
        item.unwrap();
    }
}

async fn open_test_project() -> Project {
    panic!("needs mock satellite or STORJ_SIM_ACCESS");
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
