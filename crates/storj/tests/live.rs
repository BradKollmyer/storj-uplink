//! Live satellite tests. Opt-in: `STORJ_LIVE=1` plus `#[ignore]`.
//! Loads `STORJ_ACCESS` from the environment or a `.env` file in the workspace
//! or a parent directory. A `.env` file does not enable the tests by itself.
//!
//! `upload_download_inline_and_remote` is a short smoke check. `satellite_walkthrough`
//! covers prefix listing, ranged download, copy, move, abort, small multipart,
//! custom metadata, cross-bucket copy, restricted grants, and TCP vs default
//! Noise. Uses `STORJ_BUCKET` when set; otherwise creates a unique bucket and
//! deletes it afterwards.
//!
//! ```text
//! STORJ_LIVE=1 cargo test -p storj --test live -- --ignored --nocapture
//! ```

use std::time::Duration;

use futures_util::StreamExt;
use storj::{
    Access, CommitUploadOptions, Config, CustomMetadata, DownloadOptions, ErrorKind,
    ListObjectsOptions, ListUploadsOptions, Permission, SharePrefix, TransportMode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

async fn round_trip(project: &storj::Project, bucket: &str, key: &str, payload: &[u8]) {
    let mut upload = project
        .upload_object(bucket, key, Default::default())
        .await
        .unwrap_or_else(|e| panic!("upload_object {key}: {e}"));
    upload
        .write_all(payload)
        .await
        .unwrap_or_else(|e| panic!("write {key}: {e}"));
    upload
        .commit()
        .await
        .unwrap_or_else(|e| panic!("commit {key}: {e}"));

    let st = project
        .stat_object(bucket, key)
        .await
        .unwrap_or_else(|e| panic!("stat {key}: {e}"));
    assert_eq!(st.key, key);
    assert_eq!(st.system.content_length, payload.len() as i64);

    let mut download = project
        .download_object(bucket, key, Default::default())
        .await
        .unwrap_or_else(|e| panic!("download_object {key}: {e}"));
    let mut got = Vec::new();
    download
        .read_to_end(&mut got)
        .await
        .unwrap_or_else(|e| panic!("read {key}: {e}"));
    download
        .close()
        .await
        .unwrap_or_else(|e| panic!("close {key}: {e}"));
    assert_eq!(got, payload, "{key} contents");
}

async fn upload(project: &storj::Project, bucket: &str, key: &str, payload: &[u8]) {
    let mut upload = project
        .upload_object(bucket, key, Default::default())
        .await
        .unwrap_or_else(|e| panic!("upload_object {key}: {e}"));
    upload
        .write_all(payload)
        .await
        .unwrap_or_else(|e| panic!("write {key}: {e}"));
    upload
        .commit()
        .await
        .unwrap_or_else(|e| panic!("commit {key}: {e}"));
}

async fn download(project: &storj::Project, bucket: &str, key: &str) -> Vec<u8> {
    let mut download = project
        .download_object(bucket, key, Default::default())
        .await
        .unwrap_or_else(|e| panic!("download_object {key}: {e}"));
    let mut got = Vec::new();
    download
        .read_to_end(&mut got)
        .await
        .unwrap_or_else(|e| panic!("read {key}: {e}"));
    download
        .close()
        .await
        .unwrap_or_else(|e| panic!("close {key}: {e}"));
    got
}

async fn download_range(
    project: &storj::Project,
    bucket: &str,
    key: &str,
    offset: i64,
    length: i64,
) -> Vec<u8> {
    let mut download = project
        .download_object(
            bucket,
            key,
            DownloadOptions {
                offset,
                length,
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("download_object {key} offset={offset} length={length}: {e}"));
    let mut got = Vec::new();
    download
        .read_to_end(&mut got)
        .await
        .unwrap_or_else(|e| panic!("read range {key}: {e}"));
    download
        .close()
        .await
        .unwrap_or_else(|e| panic!("close range {key}: {e}"));
    got
}

async fn list_keys(
    project: &storj::Project,
    bucket: &str,
    prefix: &str,
    recursive: bool,
) -> (Vec<String>, Vec<String>) {
    let mut objects = Vec::new();
    let mut prefixes = Vec::new();
    let mut stream = project.list_objects(
        bucket,
        ListObjectsOptions {
            prefix: prefix.to_string(),
            recursive,
            ..Default::default()
        },
    );
    while let Some(item) = stream.next().await {
        let obj = item.unwrap_or_else(|e| panic!("list {prefix}: {e}"));
        if obj.is_prefix {
            prefixes.push(obj.key);
        } else {
            objects.push(obj.key);
        }
    }
    (objects, prefixes)
}

#[test]
fn live_env_is_opt_in() {
    if !storj_test::live_enabled() {
        return;
    }
    assert!(
        storj_test::live_access().is_some(),
        "STORJ_LIVE=1 requires STORJ_ACCESS (env or .env)"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs STORJ_LIVE=1 and STORJ_ACCESS (live satellite or .env)"]
async fn upload_download_inline_and_remote() {
    if !storj_test::live_enabled() {
        eprintln!("skip: set STORJ_LIVE=1 to run live satellite tests");
        return;
    }
    let target = storj_test::LiveTarget::from_env("live");
    let access = Access::parse(&target.grant).expect("parse grant");
    eprintln!(
        "live smoke: satellite={} bucket={} prefix={:?}",
        access.satellite_address(),
        target.bucket,
        target.prefix
    );
    let project = storj::Project::open(&access).await.expect("open project");
    project
        .ensure_bucket(&target.bucket)
        .await
        .expect("ensure_bucket");

    let body = {
        let project = project.clone();
        let bucket = target.bucket.clone();
        let inline_key = target.key("hello.txt");
        let remote_key = target.key("remote.bin");
        let prefix = target.prefix.clone();
        async move {
            timeout(
                Duration::from_secs(60),
                round_trip(&project, &bucket, &inline_key, b"hello storj"),
            )
            .await
            .expect("inline round trip timed out");
            eprintln!("inline ok: {inline_key}");

            let remote = vec![0x5a_u8; 64 * 1024];
            timeout(
                Duration::from_secs(120),
                round_trip(&project, &bucket, &remote_key, &remote),
            )
            .await
            .expect("remote 64 KiB round trip timed out");
            eprintln!("remote ok: {remote_key}");

            let mut listed = Vec::new();
            let mut stream = project.list_objects(
                &bucket,
                ListObjectsOptions {
                    prefix,
                    recursive: true,
                    ..Default::default()
                },
            );
            while let Some(item) = stream.next().await {
                let obj = item.expect("list");
                if !obj.is_prefix {
                    listed.push(obj.key);
                }
            }
            assert!(
                listed.iter().any(|k| k == &inline_key),
                "list missing {inline_key}: {listed:?}"
            );
            assert!(
                listed.iter().any(|k| k == &remote_key),
                "list missing {remote_key}: {listed:?}"
            );
        }
    };
    storj_test::with_live_cleanup(&project, &target, body).await;
    project.close().await.ok();
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

/// Wire paths that passed mocks and failed a real satellite: prefix-relative
/// listing keys, SN ranged reads, copy RPCs, abort = BeginDeleteObject only,
/// live `share()` enforcement, and TLS piece transfers vs default Noise.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs STORJ_LIVE=1 and STORJ_ACCESS (live satellite or .env)"]
async fn satellite_walkthrough() {
    if !storj_test::live_enabled() {
        eprintln!("skip: set STORJ_LIVE=1 to run live satellite tests");
        return;
    }
    let target = storj_test::LiveTarget::from_env("walk");
    let access = Access::parse(&target.grant).expect("parse grant");
    eprintln!(
        "live walkthrough: satellite={} bucket={} prefix={:?}",
        access.satellite_address(),
        target.bucket,
        target.prefix
    );
    let project = storj::Project::open(&access).await.expect("open project");
    project
        .ensure_bucket(&target.bucket)
        .await
        .expect("ensure_bucket");

    let body = {
        let project = project.clone();
        let access = access.clone();
        let bucket = target.bucket.clone();
        let prefix = target.prefix.clone();
        async move {
            let nested_a = format!("{prefix}a/b/one.txt");
            let nested_b = format!("{prefix}a/b/two.txt");
            let nested_c = format!("{prefix}a/c/three.txt");
            let sibling = format!("{prefix}other/x.txt");
            timeout(Duration::from_secs(60), async {
                upload(&project, &bucket, &nested_a, b"one").await;
                upload(&project, &bucket, &nested_b, b"two").await;
                upload(&project, &bucket, &nested_c, b"three").await;
                upload(&project, &bucket, &sibling, b"other").await;
            })
            .await
            .expect("nested uploads timed out");

            let list_prefix = format!("{prefix}a/");
            timeout(Duration::from_secs(30), async {
                let (objects, prefixes) = list_keys(&project, &bucket, &list_prefix, true).await;
                assert!(
                    objects.contains(&nested_a),
                    "recursive missing {nested_a}: {objects:?}"
                );
                assert!(objects.contains(&nested_b), "{objects:?}");
                assert!(objects.contains(&nested_c), "{objects:?}");
                assert!(
                    !objects.contains(&sibling),
                    "sibling leaked into {list_prefix}: {objects:?}"
                );
                assert!(
                    prefixes.is_empty(),
                    "recursive list should not collapse prefixes: {prefixes:?}"
                );

                let (objects, prefixes) = list_keys(&project, &bucket, &list_prefix, false).await;
                assert!(
                    prefixes.contains(&format!("{prefix}a/b/")),
                    "non-recursive missing a/b/: {prefixes:?}"
                );
                assert!(
                    prefixes.contains(&format!("{prefix}a/c/")),
                    "non-recursive missing a/c/: {prefixes:?}"
                );
                assert!(
                    !objects.contains(&nested_a) && !objects.contains(&nested_c),
                    "non-recursive should not return nested objects: {objects:?}"
                );
            })
            .await
            .expect("prefix listing timed out");
            eprintln!("prefix listing ok");

            let remote_key = format!("{prefix}pattern.bin");
            let remote: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
            timeout(Duration::from_secs(120), async {
                upload(&project, &bucket, &remote_key, &remote).await;
                let mid = download_range(&project, &bucket, &remote_key, 100, 50).await;
                assert_eq!(mid, &remote[100..150], "ranged [100,150)");
                let tail = download_range(&project, &bucket, &remote_key, -8, -1).await;
                assert_eq!(tail, &remote[remote.len() - 8..], "suffix 8");
            })
            .await
            .expect("ranged download timed out");
            eprintln!("ranged download ok: {remote_key}");

            let copy_key = format!("{prefix}pattern.copy");
            timeout(Duration::from_secs(60), async {
                let copied = project
                    .copy_object(&bucket, &remote_key, &bucket, &copy_key)
                    .await
                    .unwrap_or_else(|e| panic!("copy_object: {e}"));
                assert_eq!(copied.key, copy_key);
                assert_eq!(copied.system.content_length, remote.len() as i64);
                let got = download(&project, &bucket, &copy_key).await;
                assert_eq!(got, remote, "copy contents");
            })
            .await
            .expect("copy timed out");
            eprintln!("copy ok: {copy_key}");

            let moved_src = format!("{prefix}move-src.bin");
            let moved_dst = format!("{prefix}move-dst.bin");
            timeout(Duration::from_secs(60), async {
                upload(&project, &bucket, &moved_src, b"move-me").await;
                project
                    .move_object(&bucket, &moved_src, &bucket, &moved_dst)
                    .await
                    .unwrap_or_else(|e| panic!("move_object: {e}"));
                let err = project
                    .stat_object(&bucket, &moved_src)
                    .await
                    .expect_err("moved source must be gone");
                assert_eq!(err.kind(), ErrorKind::ObjectNotFound, "{err}");
                let got = download(&project, &bucket, &moved_dst).await;
                assert_eq!(got, b"move-me");
            })
            .await
            .expect("move timed out");
            eprintln!("move ok: {moved_dst}");

            let mp_key = format!("{prefix}mp/small.bin");
            timeout(Duration::from_secs(90), async {
                let info = project
                    .begin_upload(&bucket, &mp_key, Default::default())
                    .await
                    .expect("begin_upload");
                let mut part = project
                    .upload_part(&bucket, &mp_key, &info.upload_id, 1)
                    .await
                    .expect("upload_part");
                part.write_all(b"tiny-part").await.expect("write part");
                part.commit().await.expect("commit part");
                project
                    .commit_upload(
                        &bucket,
                        &mp_key,
                        &info.upload_id,
                        CommitUploadOptions::default(),
                    )
                    .await
                    .expect("commit_upload");
                let got = download(&project, &bucket, &mp_key).await;
                assert_eq!(got, b"tiny-part");

                let aborted_mp = format!("{prefix}mp/aborted.bin");
                let info = project
                    .begin_upload(&bucket, &aborted_mp, Default::default())
                    .await
                    .expect("begin_upload abort");
                let mut part = project
                    .upload_part(&bucket, &aborted_mp, &info.upload_id, 1)
                    .await
                    .expect("upload_part abort");
                part.write_all(b"nope").await.expect("write abort part");
                part.commit().await.expect("commit abort part");
                project
                    .abort_upload(&bucket, &aborted_mp, &info.upload_id)
                    .await
                    .expect("abort_upload");
                let mut pending = Vec::new();
                let mut stream = project.list_uploads(
                    &bucket,
                    ListUploadsOptions {
                        prefix: format!("{prefix}mp/"),
                        ..Default::default()
                    },
                );
                while let Some(item) = stream.next().await {
                    pending.push(item.unwrap_or_else(|e| panic!("list_uploads: {e}")));
                }
                assert!(
                    pending.iter().all(|u| u.key != aborted_mp),
                    "aborted multipart still listed: {pending:?}"
                );
            })
            .await
            .expect("multipart timed out");
            eprintln!("multipart ok: {mp_key}");

            let meta_key = format!("{prefix}meta.txt");
            timeout(Duration::from_secs(60), async {
                let mut upload = project
                    .upload_object(&bucket, &meta_key, Default::default())
                    .await
                    .expect("upload_object meta");
                let mut custom = CustomMetadata::new();
                custom.insert("app:title".into(), "one".into());
                upload
                    .set_custom_metadata(custom)
                    .await
                    .expect("set_custom_metadata");
                upload.write_all(b"meta-body").await.expect("write meta");
                upload.commit().await.expect("commit meta");
                let st = project
                    .stat_object(&bucket, &meta_key)
                    .await
                    .expect("stat meta");
                assert_eq!(st.custom.get("app:title").map(String::as_str), Some("one"));

                let mut updated = CustomMetadata::new();
                updated.insert("app:title".into(), "two".into());
                project
                    .update_object_metadata(&bucket, &meta_key, updated)
                    .await
                    .expect("update_object_metadata");
                let st = project
                    .stat_object(&bucket, &meta_key)
                    .await
                    .expect("stat meta after update");
                assert_eq!(st.custom.get("app:title").map(String::as_str), Some("two"));
                let got = download(&project, &bucket, &meta_key).await;
                assert_eq!(got, b"meta-body");
            })
            .await
            .expect("custom metadata timed out");
            eprintln!("custom metadata ok: {meta_key}");

            let xcopy_src = format!("{prefix}xcopy.bin");
            let extra_bucket = unique("walk-xcopy");
            timeout(Duration::from_secs(90), async {
                project
                    .ensure_bucket(&extra_bucket)
                    .await
                    .unwrap_or_else(|e| panic!("ensure extra bucket {extra_bucket}: {e}"));
                upload(&project, &bucket, &xcopy_src, b"cross-bucket").await;
                let copied = project
                    .copy_object(&bucket, &xcopy_src, &extra_bucket, "dest.bin")
                    .await;
                let got = match &copied {
                    Ok(_) => Some(download(&project, &extra_bucket, "dest.bin").await),
                    Err(_) => None,
                };
                let deleted = project.delete_bucket_with_objects(&extra_bucket).await;
                copied.unwrap_or_else(|e| panic!("cross-bucket copy: {e}"));
                assert_eq!(got.as_deref(), Some(b"cross-bucket".as_slice()));
                deleted.unwrap_or_else(|e| panic!("delete extra bucket {extra_bucket}: {e}"));
            })
            .await
            .expect("cross-bucket copy timed out");
            eprintln!("cross-bucket copy ok: {extra_bucket}");

            let aborted_key = format!("{prefix}aborted.bin");
            timeout(Duration::from_secs(60), async {
                let mut upload = project
                    .upload_object(&bucket, &aborted_key, Default::default())
                    .await
                    .expect("upload_object abort");
                upload
                    .write_all(b"should not commit")
                    .await
                    .expect("write abort");
                upload.abort().await.expect("abort");
                let err = project
                    .stat_object(&bucket, &aborted_key)
                    .await
                    .expect_err("aborted object must not stat");
                assert_eq!(err.kind(), ErrorKind::ObjectNotFound, "{err}");
            })
            .await
            .expect("abort timed out");
            eprintln!("abort ok: {aborted_key}");

            let allowed_prefix = format!("{prefix}allowed/");
            let allowed_key = format!("{allowed_prefix}nested/ok.txt");
            let denied_key = format!("{prefix}denied/secret.txt");
            timeout(Duration::from_secs(90), async {
                upload(&project, &bucket, &allowed_key, b"visible").await;
                upload(&project, &bucket, &denied_key, b"hidden").await;
                let share_prefix = SharePrefix::new(&bucket, &allowed_prefix)
                    .unwrap_or_else(|e| panic!("SharePrefix: {e}"));
                let restricted = access
                    .share(Permission::read_only(), &[share_prefix])
                    .expect("share");
                let restricted = storj::Project::open(&restricted)
                    .await
                    .expect("open restricted");
                let got = download(&restricted, &bucket, &allowed_key).await;
                assert_eq!(got, b"visible");
                match restricted
                    .download_object(&bucket, &denied_key, Default::default())
                    .await
                {
                    Ok(_) => panic!("out-of-prefix download must fail"),
                    Err(err) => assert!(
                        matches!(
                            err.kind(),
                            ErrorKind::PermissionDenied
                                | ErrorKind::ObjectNotFound
                                | ErrorKind::InvalidGrant
                        ),
                        "expected PermissionDenied, ObjectNotFound, or InvalidGrant, got {}: {err}",
                        err.kind()
                    ),
                }
                restricted.close().await.ok();
            })
            .await
            .expect("restricted grant timed out");
            eprintln!("restricted grant ok");

            timeout(Duration::from_secs(120), async {
                let tcp = storj::Project::open_with_config(
                    &access,
                    Config {
                        transport: TransportMode::Tcp,
                        ..Default::default()
                    },
                )
                .await
                .expect("open TCP project");
                let got = download(&tcp, &bucket, &remote_key).await;
                assert_eq!(got, remote, "TCP download of Noise-uploaded object");
                tcp.close().await.ok();
            })
            .await
            .expect("TCP transport timed out");
            eprintln!("TCP transport ok");
        }
    };
    storj_test::with_live_cleanup(&project, &target, body).await;
    project.close().await.ok();
}
