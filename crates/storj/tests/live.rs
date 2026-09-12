//! Live satellite smoke test. Opt-in: `STORJ_LIVE=1` plus `#[ignore]`.
//! Loads `STORJ_ACCESS` from the environment or a `.env` file in the workspace
//! or a parent directory. A `.env` file does not enable the tests by itself.
//!
//! Writes a small inline object and a remote (64 KiB) object, then reads them
//! back. Uses `STORJ_BUCKET` when set; otherwise creates a unique bucket and
//! deletes it afterwards.
//!
//! ```text
//! STORJ_LIVE=1 cargo test -p storj --test live -- --ignored --nocapture
//! ```

use std::time::Duration;

use futures_util::StreamExt;
use storj::{Access, ListObjectsOptions};
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
