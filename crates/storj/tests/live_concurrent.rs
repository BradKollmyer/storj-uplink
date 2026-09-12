//! Live satellite probe for concurrent object uploads.
//!
//! Reproduces the rustic `--backup-connections 10` pattern: N remote
//! segments sharing one SN connection pool (default cap = `n` × 10).
//! Opt-in: `STORJ_LIVE=1` plus `#[ignore]`. Loads `STORJ_ACCESS` from the
//! environment or a `.env` file. A `.env` file does not enable the tests.
//!
//! ```text
//! STORJ_LIVE=1 cargo test -p storj --test live_concurrent -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use storj::Access;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

async fn upload_one(project: &storj::Project, bucket: &str, key: &str, size: usize) {
    let payload = vec![0x5a_u8; size];
    let mut upload = project
        .upload_object(bucket, key, Default::default())
        .await
        .unwrap_or_else(|e| panic!("upload_object {key}: {e}"));
    upload
        .write_all(&payload)
        .await
        .unwrap_or_else(|e| panic!("write {key}: {e}"));
    upload
        .commit()
        .await
        .unwrap_or_else(|e| panic!("commit {key}: {e}"));
}

async fn download_one(project: &storj::Project, bucket: &str, key: &str, size: usize) {
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
    assert_eq!(got.len(), size, "{key} length");
    assert!(got.iter().all(|&b| b == 0x5a), "{key} contents");
}

async fn run_concurrent_uploads(
    project: &storj::Project,
    bucket: &str,
    prefix: &str,
    n: usize,
    size: usize,
) -> Vec<String> {
    let start = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..n {
        let project = project.clone();
        let bucket = bucket.to_string();
        let key = format!("{prefix}c{i:02}.bin");
        set.spawn(async move {
            upload_one(&project, &bucket, &key, size).await;
            eprintln!("  uploaded {key} at +{:.1}s", start.elapsed().as_secs_f64());
            key
        });
    }
    let mut keys = Vec::new();
    while let Some(joined) = set.join_next().await {
        keys.push(joined.expect("upload task panicked"));
    }
    eprintln!(
        "concurrent {n} x {size} bytes upload: {:.1}s",
        start.elapsed().as_secs_f64()
    );
    keys
}

async fn run_serial_downloads(
    project: &storj::Project,
    bucket: &str,
    keys: &[String],
    size: usize,
) {
    let start = Instant::now();
    for key in keys {
        let one = Instant::now();
        download_one(project, bucket, key, size).await;
        eprintln!("  downloaded {key} in {:.1}s", one.elapsed().as_secs_f64());
    }
    eprintln!(
        "serial download of {} objects: {:.1}s",
        keys.len(),
        start.elapsed().as_secs_f64()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs STORJ_LIVE=1 and STORJ_ACCESS (live satellite or .env)"]
async fn concurrent_remote_uploads_do_not_hang() {
    if !storj_test::live_enabled() {
        eprintln!("skip: set STORJ_LIVE=1 to run live satellite tests");
        return;
    }
    let target = storj_test::LiveTarget::from_env("conc");
    let access = Access::parse(&target.grant).expect("parse grant");
    let project = storj::Project::open(&access).await.expect("open project");
    project
        .ensure_bucket(&target.bucket)
        .await
        .expect("ensure_bucket");

    let eight_mib = 8 * 1024 * 1024;
    let body = {
        let project = project.clone();
        let bucket = target.bucket.clone();
        let prefix = target.prefix.clone();
        async move {
            let serial_key = format!("{prefix}serial.bin");
            eprintln!("phase serial 8 MiB");
            let serial_start = Instant::now();
            timeout(Duration::from_secs(120), async {
                upload_one(&project, &bucket, &serial_key, eight_mib).await;
                download_one(&project, &bucket, &serial_key, eight_mib).await;
            })
            .await
            .expect("serial 8 MiB timed out");
            eprintln!(
                "serial {eight_mib} bytes: {:.1}s",
                serial_start.elapsed().as_secs_f64()
            );

            eprintln!("phase 2 x 8 MiB upload");
            let keys2 = timeout(
                Duration::from_secs(120),
                run_concurrent_uploads(&project, &bucket, &prefix, 2, eight_mib),
            )
            .await
            .expect("2 concurrent 8 MiB upload timed out");

            eprintln!("phase 2 x 8 MiB download");
            timeout(
                Duration::from_secs(90),
                run_serial_downloads(&project, &bucket, &keys2, eight_mib),
            )
            .await
            .expect("2-object download timed out");

            eprintln!("phase 10 x 8 MiB upload");
            let keys10 = timeout(
                Duration::from_secs(180),
                run_concurrent_uploads(&project, &bucket, &prefix, 10, eight_mib),
            )
            .await
            .expect("10 concurrent 8 MiB upload timed out");

            eprintln!("phase 10 x 8 MiB download");
            timeout(
                Duration::from_secs(120),
                run_serial_downloads(&project, &bucket, &keys10, eight_mib),
            )
            .await
            .expect("10-object download timed out");
        }
    };
    storj_test::with_live_cleanup(&project, &target, body).await;
    project.close().await.ok();
}

/// Same 10-way upload, but from OS threads calling `Handle::block_on` —
/// rustic's pack-upload worker pattern.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs STORJ_LIVE=1 and STORJ_ACCESS (live satellite or .env)"]
async fn concurrent_block_on_uploads_do_not_hang() {
    if !storj_test::live_enabled() {
        eprintln!("skip: set STORJ_LIVE=1 to run live satellite tests");
        return;
    }
    let target = storj_test::LiveTarget::from_env("conc-thr");
    let access = Access::parse(&target.grant).expect("parse grant");
    let project = storj::Project::open(&access).await.expect("open project");
    project
        .ensure_bucket(&target.bucket)
        .await
        .expect("ensure_bucket");

    let size = 32 * 1024 * 1024;
    let body = {
        let project = project.clone();
        let bucket = target.bucket.clone();
        let prefix = target.prefix.clone();
        async move {
            let handle = tokio::runtime::Handle::current();
            let start = Instant::now();
            let n = 10;
            let threads: Vec<_> = (0..n)
                .map(|i| {
                    let project = project.clone();
                    let bucket = bucket.clone();
                    let prefix = prefix.clone();
                    let handle = handle.clone();
                    std::thread::Builder::new()
                        .name(format!("pack-upload-{i}"))
                        .spawn(move || {
                            handle.block_on(async move {
                                let key = format!("{prefix}t{i:02}.bin");
                                upload_one(&project, &bucket, &key, size).await;
                                eprintln!(
                                    "  thread uploaded {key} at +{:.1}s",
                                    start.elapsed().as_secs_f64()
                                );
                            });
                        })
                        .expect("spawn")
                })
                .collect();
            for t in threads {
                t.join().expect("thread panicked");
            }
            eprintln!(
                "10 OS-thread block_on x 32 MiB upload: {:.1}s",
                start.elapsed().as_secs_f64()
            );
        }
    };
    timeout(Duration::from_secs(300), async {
        storj_test::with_live_cleanup(&project, &target, body).await;
    })
    .await
    .expect("10 OS-thread 32 MiB uploads timed out");
    project.close().await.ok();
}
