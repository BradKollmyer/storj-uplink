//! Go ↔ Rust writer/reader matrix (design interop requirements).
//!
//! Enable with `STORJ_INTEROP=1` and a Go toolchain. Never required of crate
//! consumers. Go is a CI-only test helper (`go run -C scripts/interop .`).
//!
//! Grant parse/serialize/share run without a satellite. Object I/O also needs
//! `STORJ_INTEROP_ACCESS` or `STORJ_SIM_ACCESS`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use storj::constants::MAX_SEGMENT_SIZE;
use storj::{Access, Permission, Project, SharePrefix};
use storj_test::{INTEROP_SIDES, INTEROP_SIZES, Side, size_label};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const GO_SAT: &str = "12edKaxTestSatelliteId@127.0.0.1:7777";

#[test]
fn matrix_is_complete() {
    assert_eq!(INTEROP_SIDES.len(), 4);
    assert!(INTEROP_SIDES.contains(&(Side::Go, Side::Rust)));
    assert!(INTEROP_SIDES.contains(&(Side::Rust, Side::Go)));
    for &n in INTEROP_SIZES {
        let _ = size_label(n);
    }
    assert_eq!(
        INTEROP_SIZES[INTEROP_SIZES.len() - 1],
        MAX_SEGMENT_SIZE + 1,
        "64MiB+1 stays in INTEROP_SIZES for PR 26; this job skips it"
    );
}

#[test]
#[ignore = "STORJ_INTEROP=1 + Go helper"]
fn rust_parse_go_grant_and_go_parse_rust_grant() {
    if !storj_test::interop_enabled() {
        return;
    }
    let fixture = load_go_grant();
    let rust = Access::parse(&fixture).expect("Rust Access::parse of grant_go.txt");
    assert_eq!(rust.satellite_address(), GO_SAT);
    let rust_serialized = rust.serialize().expect("Rust serialize");

    let parsed = go_ok(&["parse", &rust_serialized]);
    assert!(
        parsed.contains("ok"),
        "Go ParseAccess of Rust serialize: {parsed}"
    );
    assert!(
        parsed.contains(rust.satellite_address()),
        "Go ParseAccess satellite mismatch: {parsed}"
    );

    let go_serialized = go_ok(&["serialize", &fixture]);
    let round = Access::parse(&go_serialized).expect("Rust parse of Go serialize");
    assert_eq!(round.satellite_address(), GO_SAT);
    assert_eq!(round.serialize().unwrap(), fixture);
}

#[test]
#[ignore = "STORJ_INTEROP=1 + Go helper"]
fn rust_share_then_go_open() {
    if !storj_test::interop_enabled() {
        return;
    }
    let fixture = load_go_grant();
    let root = Access::parse(&fixture).unwrap();
    let prefix = SharePrefix::new("app", "user1/").unwrap();
    let shared = root
        .share(Permission::read_only(), &[prefix])
        .expect("Rust share");
    let shared_ser = shared.serialize().unwrap();

    let parsed = go_ok(&["parse", &shared_ser]);
    assert!(
        parsed.contains("ok"),
        "Go ParseAccess of Rust share(): {parsed}"
    );
    assert!(parsed.contains(GO_SAT), "shared grant satellite: {parsed}");

    let go_restricted = go_ok(&["restrict", "-bucket", "app", "-prefix", "user1/", &fixture]);
    let from_go = Access::parse(&go_restricted).expect("Rust parse of Go restrict");
    assert_eq!(from_go.satellite_address(), GO_SAT);
}

#[tokio::test]
#[ignore = "STORJ_INTEROP=1 + live satellite; 64MiB+1 is PR 26"]
async fn writer_reader_size_matrix() {
    if !storj_test::interop_enabled() {
        return;
    }
    let Some(grant) = storj_test::interop_access() else {
        eprintln!(
            "skip object matrix: set STORJ_INTEROP_ACCESS or STORJ_SIM_ACCESS (needs a satellite)"
        );
        return;
    };

    let access = Access::parse(&grant).expect("parse live grant");
    let project = match Project::open(&access).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skip object matrix: satellite unreachable ({e})");
            return;
        }
    };
    let bucket = unique("interop");
    project.ensure_bucket(&bucket).await.expect("ensure_bucket");

    for &(writer, reader) in INTEROP_SIDES {
        for &size in INTEROP_SIZES {
            if size > MAX_SEGMENT_SIZE {
                eprintln!(
                    "skip {}->{} / {} until PR 26 (multi-segment)",
                    writer.as_str(),
                    reader.as_str(),
                    size_label(size)
                );
                continue;
            }
            let name = format!(
                "{}->{}/{}",
                writer.as_str(),
                reader.as_str(),
                size_label(size)
            );
            let key = format!("{}/{}", writer.as_str(), size_label(size));
            let want = payload(size);
            round_trip(writer, reader, &project, &grant, &bucket, &key, &want)
                .await
                .unwrap_or_else(|CellSkip(msg)| {
                    panic!("go helper skipped despite live satellite ({name}): {msg}");
                });
        }
    }

    project.close().await.ok();
}

struct CellSkip(String);

async fn round_trip(
    writer: Side,
    reader: Side,
    project: &Project,
    grant: &str,
    bucket: &str,
    key: &str,
    want: &[u8],
) -> Result<(), CellSkip> {
    match writer {
        Side::Rust => rust_upload(project, bucket, key, want).await,
        Side::Go => go_upload(grant, bucket, key, want)?,
    }
    let got = match reader {
        Side::Rust => rust_download(project, bucket, key).await,
        Side::Go => go_download(grant, bucket, key)?,
    };
    assert_eq!(
        got,
        want,
        "{}->{} {} bytes",
        writer.as_str(),
        reader.as_str(),
        want.len()
    );
    Ok(())
}

async fn rust_upload(project: &Project, bucket: &str, key: &str, data: &[u8]) {
    let mut upload = project
        .upload_object(bucket, key, Default::default())
        .await
        .expect("rust upload_object");
    upload.write_all(data).await.expect("rust write");
    upload.commit().await.expect("rust commit");
}

async fn rust_download(project: &Project, bucket: &str, key: &str) -> Vec<u8> {
    let mut download = project
        .download_object(bucket, key, Default::default())
        .await
        .expect("rust download_object");
    let mut got = Vec::new();
    download.read_to_end(&mut got).await.expect("rust read");
    download.close().await.expect("rust close");
    got
}

fn go_upload(grant: &str, bucket: &str, key: &str, data: &[u8]) -> Result<(), CellSkip> {
    let path = tmp_path("ul");
    std::fs::write(&path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    let file = path.to_str().unwrap().to_owned();
    let out = go(&[
        "upload", "-grant", grant, "-bucket", bucket, "-key", key, "-file", &file,
    ]);
    let _ = std::fs::remove_file(&path);
    if is_skip(&out) {
        return Err(CellSkip(stderr(&out)));
    }
    assert_status(&out, &["upload"]);
    Ok(())
}

fn go_download(grant: &str, bucket: &str, key: &str) -> Result<Vec<u8>, CellSkip> {
    let path = tmp_path("dl");
    let out = go(&[
        "download",
        "-grant",
        grant,
        "-bucket",
        bucket,
        "-key",
        key,
        "-file",
        path.to_str().unwrap(),
    ]);
    if is_skip(&out) {
        let _ = std::fs::remove_file(&path);
        return Err(CellSkip(stderr(&out)));
    }
    assert_status(&out, &["download"]);
    let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let _ = std::fs::remove_file(&path);
    Ok(got)
}

fn load_go_grant() -> String {
    storj_test::read_fixture_str("grant_go.txt")
        .trim()
        .to_owned()
}

fn helper_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/interop")
}

fn go(args: &[&str]) -> std::process::Output {
    let dir = helper_dir();
    assert!(
        dir.join("main.go").exists(),
        "missing {} — expected scripts/interop helper",
        dir.display()
    );
    Command::new("go")
        .arg("run")
        .arg("-C")
        .arg(&dir)
        .arg(".")
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!("STORJ_INTEROP=1 requires Go on PATH to run scripts/interop ({e})")
        })
}

fn go_ok(args: &[&str]) -> String {
    let out = go(args);
    assert_status(&out, args);
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn assert_status(out: &std::process::Output, args: &[&str]) {
    if out.status.success() {
        return;
    }
    panic!(
        "go run -C scripts/interop . {args:?}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn is_skip(out: &std::process::Output) -> bool {
    out.status.success() && stderr(out).contains("skip:")
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn payload(size: u64) -> Vec<u8> {
    let mut buf = vec![0u8; size as usize];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    buf
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn tmp_path(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "storj-interop-{}-{}-{label}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}
