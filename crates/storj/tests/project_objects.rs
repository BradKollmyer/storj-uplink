//! Object metadata operations (PR 23) and list prefix rules.

use futures_util::StreamExt;
use storj::{ErrorKind, ListObjectsOptions, Project};
use storj_test::MockSatellite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn stat_delete_copy_move() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique("obj");
    project.ensure_bucket(&bucket).await.unwrap();
    upload(&project, &bucket, "k", b"hello").await;
    upload(&project, &bucket, "src", b"payload").await;

    let st = project.stat_object(&bucket, "k").await.expect("stat");
    assert_eq!(st.key, "k");
    assert!(!st.is_prefix);
    assert_eq!(st.system.content_length, 5);

    let copied = project
        .copy_object(&bucket, "src", &bucket, "k2")
        .await
        .expect("copy");
    assert_eq!(copied.key, "k2");
    let mut dl = project
        .download_object(&bucket, "k2", Default::default())
        .await
        .expect("download copy");
    let mut got = Vec::new();
    dl.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"payload");

    project
        .move_object(&bucket, "k2", &bucket, "k3")
        .await
        .expect("move");
    let moved = project
        .stat_object(&bucket, "k3")
        .await
        .expect("stat moved");
    assert_eq!(moved.key, "k3");
    let missing = project.stat_object(&bucket, "k2").await.unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::ObjectNotFound);

    let deleted = project.delete_object(&bucket, "k").await.expect("delete");
    assert!(deleted.is_some(), "full-permission grant returns Some");
    assert_eq!(deleted.unwrap().key, "k");
    let gone = project.stat_object(&bucket, "k").await.unwrap_err();
    assert_eq!(gone.kind(), ErrorKind::ObjectNotFound);

    let empty = project.delete_object(&bucket, "").await.unwrap_err();
    assert_eq!(empty.kind(), ErrorKind::ObjectKeyInvalid);
    let missing_del = project
        .delete_object(&bucket, "does-not-exist")
        .await
        .unwrap_err();
    assert_eq!(missing_del.kind(), ErrorKind::ObjectNotFound);
}

#[tokio::test]
async fn delete_object_returns_none_without_read() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique("noread");
    project.ensure_bucket(&bucket).await.unwrap();
    upload(&project, &bucket, "secret", b"x").await;
    mock.omit_delete_object_metadata();

    let deleted = project
        .delete_object(&bucket, "secret")
        .await
        .expect("delete without metadata");
    assert!(deleted.is_none());
    let gone = project.stat_object(&bucket, "secret").await.unwrap_err();
    assert_eq!(gone.kind(), ErrorKind::ObjectNotFound);
}

#[tokio::test]
async fn list_objects_rejects_prefix_without_slash() {
    let opts = ListObjectsOptions {
        prefix: "no-slash".into(),
        ..Default::default()
    };
    assert_eq!(
        opts.validate().unwrap_err().kind(),
        ErrorKind::ObjectKeyInvalid
    );

    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let mut s = project.list_objects(
        "b",
        ListObjectsOptions {
            prefix: "no-slash".into(),
            ..Default::default()
        },
    );
    let err = s.next().await.unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);
}

#[tokio::test]
async fn list_objects_stream() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique("list");
    project.ensure_bucket(&bucket).await.unwrap();
    upload(&project, &bucket, "p/a", b"a").await;
    upload(&project, &bucket, "p/b", b"b").await;
    upload(&project, &bucket, "p/dir/c", b"c").await;
    upload(&project, &bucket, "other/x", b"x").await;

    let rec = collect(
        &project,
        &bucket,
        ListObjectsOptions {
            prefix: "p/".into(),
            recursive: true,
            system: true,
            custom: true,
            cursor: String::new(),
        },
    )
    .await;
    let rec_keys: Vec<_> = rec.iter().map(|o| o.key.as_str()).collect();
    assert!(rec_keys.contains(&"p/a"), "{rec_keys:?}");
    assert!(rec_keys.contains(&"p/b"), "{rec_keys:?}");
    assert!(rec_keys.contains(&"p/dir/c"), "{rec_keys:?}");
    assert!(!rec_keys.contains(&"other/x"), "{rec_keys:?}");
    assert!(rec.iter().all(|o| !o.is_prefix));
    assert!(rec.iter().all(|o| o.system.content_length > 0));

    let non_rec = collect(
        &project,
        &bucket,
        ListObjectsOptions {
            prefix: "p/".into(),
            recursive: false,
            system: true,
            custom: false,
            cursor: String::new(),
        },
    )
    .await;
    let prefixes: Vec<_> = non_rec
        .iter()
        .filter(|o| o.is_prefix)
        .map(|o| o.key.as_str())
        .collect();
    let objects: Vec<_> = non_rec
        .iter()
        .filter(|o| !o.is_prefix)
        .map(|o| o.key.as_str())
        .collect();
    assert!(prefixes.contains(&"p/dir/"), "{prefixes:?}");
    assert!(objects.contains(&"p/a"), "{objects:?}");
    assert!(objects.contains(&"p/b"), "{objects:?}");
    assert!(!objects.contains(&"p/dir/c"), "{objects:?}");

    let first = rec[0].key.strip_prefix("p/").unwrap().to_owned();
    let after = collect(
        &project,
        &bucket,
        ListObjectsOptions {
            prefix: "p/".into(),
            recursive: true,
            system: true,
            custom: true,
            cursor: first.clone(),
        },
    )
    .await;
    let after_keys: Vec<_> = after.iter().map(|o| o.key.as_str()).collect();
    assert!(
        !after_keys.contains(&rec[0].key.as_str()),
        "cursor is exclusive: {after_keys:?}"
    );
    for key in rec.iter().skip(1).map(|o| o.key.as_str()) {
        assert!(after_keys.contains(&key), "missing {key} in {after_keys:?}");
    }
}

async fn collect(project: &Project, bucket: &str, opts: ListObjectsOptions) -> Vec<storj::Object> {
    let mut s = project.list_objects(bucket, opts);
    let mut out = Vec::new();
    while let Some(item) = s.next().await {
        out.push(item.unwrap());
    }
    out
}

async fn upload(project: &Project, bucket: &str, key: &str, data: &[u8]) {
    let mut u = project
        .upload_object(bucket, key, Default::default())
        .await
        .unwrap();
    u.write_all(data).await.unwrap();
    u.commit().await.unwrap();
}

async fn open_test_project(mock: &MockSatellite) -> Project {
    Project::open(&mock.access())
        .await
        .expect("open mock project")
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
