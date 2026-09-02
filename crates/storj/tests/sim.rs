//! `storj-sim` integration. Nightly CI, not every PR (design Testing Strategy).
//!
//! ```text
//! export STORJ_SIM=1
//! export STORJ_SIM_ACCESS="$(storj-sim network env GATEWAY_0_ACCESS)"
//! cargo test -p storj --test sim -- --ignored
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use storj::Access;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn sim_env_is_opt_in() {
    if !storj_test::sim_enabled() {
        return;
    }
    assert!(
        storj_test::sim_access().is_some(),
        "STORJ_SIM=1 requires STORJ_SIM_ACCESS"
    );
}

#[tokio::test]
#[ignore = "nightly: storj-sim"]
async fn sim_walkthrough_empty_and_inline() {
    if !storj_test::sim_enabled() {
        return;
    }
    let grant = storj_test::sim_access().expect("STORJ_SIM=1 requires STORJ_SIM_ACCESS");
    let access = Access::parse(&grant).expect("parse sim grant");
    let project = storj::Project::open(&access).await.expect("open");

    let bucket = format!(
        "sim-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    project.ensure_bucket(&bucket).await.expect("ensure_bucket");

    for (key, payload) in [("empty", &b""[..]), ("inline", &b"hello storj-sim"[..])] {
        let mut upload = project
            .upload_object(&bucket, key, Default::default())
            .await
            .expect("upload_object");
        upload.write_all(payload).await.expect("write");
        upload.commit().await.expect("commit");

        let mut download = project
            .download_object(&bucket, key, Default::default())
            .await
            .expect("download_object");
        let mut got = Vec::new();
        download.read_to_end(&mut got).await.expect("read");
        download.close().await.expect("close");
        assert_eq!(got, payload, "mismatch for {key}");
    }

    project.close().await.ok();
}
