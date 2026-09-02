//! Object metadata operations (PR 23) and list prefix rules.

use futures_util::StreamExt;
use storj::encryption::{CipherSuite, Store, encrypt_path};
use storj::{EncryptionKey, ErrorKind, ListObjectsOptions, Project};
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
    for p in non_rec.iter().filter(|o| o.is_prefix) {
        assert!(
            p.system.created.is_none() && p.system.expires.is_none(),
            "omitted prefix timestamps must stay None: {p:?}"
        );
    }

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

#[tokio::test]
async fn list_skips_undecryptable_sibling() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique("skip");
    project.ensure_bucket(&bucket).await.unwrap();
    upload(&project, &bucket, "p/a", b"a").await;
    upload(&project, &bucket, "p/b", b"b").await;

    let store = mock_aes_store();
    let junk_path = encrypt_path(&bucket, "p/junk", &store).unwrap();
    mock.put_encrypted_object(&bucket, junk_path);

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
    let keys: Vec<_> = rec.iter().map(|o| o.key.as_str()).collect();
    assert!(keys.contains(&"p/a"), "{keys:?}");
    assert!(keys.contains(&"p/b"), "{keys:?}");
    assert!(!keys.contains(&"p/junk"), "{keys:?}");
}

#[tokio::test]
async fn list_honors_override_encryption_key_remainder() {
    let mock = MockSatellite::start().await;
    let bucket = unique("ov");
    let root = open_test_project(&mock).await;
    root.ensure_bucket(&bucket).await.unwrap();

    let mut access = mock.access();
    access
        .override_encryption_key(&bucket, "p/", &EncryptionKey::from_bytes([9u8; 32]))
        .unwrap();
    let project = Project::open(&access).await.expect("open overridden");
    upload(&project, &bucket, "p/a", b"a").await;
    upload(&project, &bucket, "p/dir/c", b"c").await;
    upload(&project, &bucket, "z/x", b"x").await;

    let rec = collect(
        &project,
        &bucket,
        ListObjectsOptions {
            prefix: "p/".into(),
            recursive: true,
            system: true,
            custom: false,
            cursor: String::new(),
        },
    )
    .await;
    let keys: Vec<_> = rec.iter().map(|o| o.key.as_str()).collect();
    assert!(keys.contains(&"p/a"), "{keys:?}");
    assert!(keys.contains(&"p/dir/c"), "{keys:?}");
    assert!(!keys.contains(&"z/x"), "{keys:?}");
}

#[tokio::test]
async fn list_encnull_prefix_is_raw_byte_prefix() {
    let mock = MockSatellite::start().await;
    let project = Project::open(&mock.access_with_path_cipher(storj_access::CipherSuite::NULL))
        .await
        .expect("open EncNull");
    let bucket = unique("null");
    project.ensure_bucket(&bucket).await.unwrap();
    upload(&project, &bucket, "p/a", b"a").await;
    upload(&project, &bucket, "p/dir/c", b"c").await;
    upload(&project, &bucket, "p2", b"no").await;
    upload(&project, &bucket, "prefix", b"no").await;

    let rec = collect(
        &project,
        &bucket,
        ListObjectsOptions {
            prefix: "p/".into(),
            recursive: true,
            system: true,
            custom: false,
            cursor: String::new(),
        },
    )
    .await;
    let keys: Vec<_> = rec.iter().map(|o| o.key.as_str()).collect();
    assert!(keys.contains(&"p/a"), "{keys:?}");
    assert!(keys.contains(&"p/dir/c"), "{keys:?}");
    assert!(
        !keys.contains(&"p2"),
        "EncNull prefix p/ must not match p2: {keys:?}"
    );
    assert!(
        !keys.contains(&"prefix"),
        "EncNull prefix p/ must not match prefix: {keys:?}"
    );
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

fn mock_aes_store() -> Store {
    let mut store = Store::new();
    store.set_default_key(EncryptionKey::from_bytes([1u8; 32]).inner().clone());
    store.set_default_path_cipher(CipherSuite::AES_GCM);
    store
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
