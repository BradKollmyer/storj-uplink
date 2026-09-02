//! In-process mock satellite / storage-node fault injection (PR 11–14).
//!
//! ProjectInfo and bucket RPCs run against the mock. Piece long-tail, `k-1`,
//! and commit-timeout faults land in later PRs.

#[tokio::test]
async fn mock_satellite_project_info_and_buckets() {
    let mock = storj_test::MockSatellite::start().await;
    let access = storj::Access::request_with_passphrase(mock.node_url(), mock.api_key(), "pw")
        .await
        .expect("ProjectInfo + Argon2 p=8");
    assert_eq!(access.satellite_address(), mock.node_url());

    let serialized = access.serialize().unwrap();
    let grant = storj_access::Grant::parse(&serialized).unwrap();
    let expected = storj::encryption::derive_root_key(
        b"pw",
        mock.project_salt(),
        b"",
        storj::constants::ARGON2_PARALLELISM_REQUEST,
    )
    .unwrap();
    assert_eq!(
        grant
            .enc_access()
            .default_key
            .as_ref()
            .map(|k| k.as_slice()),
        Some(expected.as_bytes().as_slice())
    );

    let project = storj::Project::open(&access).await.expect("open");
    let name = "info-buckets";
    project.create_bucket(name).await.expect("create");
    assert_eq!(project.stat_bucket(name).await.unwrap().name, name);
    project.delete_bucket(name).await.unwrap();
}

#[tokio::test]
async fn open_rejects_wrong_node_id_pin() {
    let mock = storj_test::MockSatellite::start().await;
    let host = mock
        .node_url()
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap();
    let wrong = format!("12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@{host}");
    let grant = storj_access::Grant::from_parts(
        wrong,
        storj_access::ApiKey::parse(mock.api_key())
            .unwrap()
            .serialize_raw(),
        storj_access::EncryptionAccess {
            default_key: Some([1u8; 32]),
            default_path_cipher: storj_access::CipherSuite::AES_GCM,
            store_entries: Vec::new(),
            default_encryption_parameters: None,
        },
    );
    let access = storj::Access::parse(&grant.serialize().unwrap()).unwrap();
    let err = match storj::Project::open(&access).await {
        Ok(_) => panic!("wrong NodeID pin must fail open"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err.kind(),
            storj::ErrorKind::Protocol | storj::ErrorKind::Io
        ),
        "{err}"
    );
}

#[tokio::test]
async fn long_tail_cancels_slow_pieces() {
    use tokio::io::AsyncWriteExt;
    let mock = storj_test::MockSatellite::start().await;
    mock.set_sn_delay(3, std::time::Duration::from_secs(30))
        .await;
    let access = mock.access();
    let project = storj::Project::open(&access).await.expect("open");
    let name = format!(
        "lt-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    project.ensure_bucket(&name).await.unwrap();
    let mut upload = project
        .upload_object(&name, "slow", Default::default())
        .await
        .unwrap();
    upload.write_all(&vec![7u8; 5000]).await.unwrap();
    let obj = tokio::time::timeout(std::time::Duration::from_secs(15), upload.commit())
        .await
        .expect("long-tail should not wait for the delayed node")
        .expect("commit");
    assert_eq!(obj.system.content_length, 5000);
    assert!(mock.remote_segment_count() >= 1);

    mock.set_sn_delay(3, std::time::Duration::ZERO).await;
    let mut upload = project
        .upload_object(&name, "again", Default::default())
        .await
        .unwrap();
    upload.write_all(&vec![8u8; 5000]).await.unwrap();
    let obj = tokio::time::timeout(std::time::Duration::from_secs(15), upload.commit())
        .await
        .expect("second remote upload must redial cancelled SN")
        .expect("second commit");
    assert_eq!(obj.system.content_length, 5000);
}

#[tokio::test]
async fn retry_rotates_segment_id_for_commit() {
    use tokio::io::AsyncWriteExt;
    let mock = storj_test::MockSatellite::start().await;
    mock.storage_nodes()[0].fail_next_upload().await;
    mock.storage_nodes()[1].fail_next_upload().await;
    let project = storj::Project::open(&mock.access()).await.expect("open");
    let name = format!(
        "retry-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    project.ensure_bucket(&name).await.unwrap();
    let mut upload = project
        .upload_object(&name, "r", Default::default())
        .await
        .unwrap();
    upload.write_all(&vec![9u8; 5000]).await.unwrap();
    upload.commit().await.expect("commit after retry");
    assert!(mock.retry_begin_count() >= 1);
    assert_eq!(
        mock.last_commit_segment_id(),
        mock.last_retry_segment_id(),
        "CommitSegment must use the rotated segment id"
    );
}

#[tokio::test]
async fn k_minus_one_pieces_fails_download() {
    use tokio::io::AsyncWriteExt;

    let mock = storj_test::MockSatellite::start().await;
    let project = storj::Project::open(&mock.access()).await.expect("open");
    let name = unique("k1");
    project.ensure_bucket(&name).await.unwrap();
    let mut upload = project
        .upload_object(&name, "r", Default::default())
        .await
        .unwrap();
    upload.write_all(&vec![9u8; 5000]).await.unwrap();
    upload.commit().await.expect("commit");

    // Mock RS is k=2, n=4. Fail 3 SNs so at most 1 piece remains.
    for i in 1..4 {
        mock.fail_sn_download(i).await;
    }
    // Downloads are lazy (segments are fetched on read, as in Go), so the
    // piece shortage surfaces when the body is read, not when it is opened.
    let mut download = project
        .download_object(&name, "r", Default::default())
        .await
        .expect("open is lazy");
    let mut body = Vec::new();
    let err = match tokio::io::copy(&mut download, &mut body).await {
        Ok(_) => panic!("k-1 pieces must fail"),
        Err(e) => e,
    };
    let err = storj::Error::from(err);
    assert_eq!(err.kind(), storj::ErrorKind::Protocol);
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

#[test]
#[ignore = "later: CommitSegment hang → Canceled or Protocol"]
fn commit_segment_timeout() {
    panic!("mock metainfo CommitSegment hang → Canceled or Protocol");
}

#[test]
fn compressed_batch_max_decode_matches_proto() {
    assert_eq!(
        storj::constants::COMPRESSED_BATCH_MAX_DECODE,
        storj_proto::MAX_DECODE_MEMORY
    );
}

/// A storage node that accepts the piece and then never answers must not hang
/// the upload: the per-message timeout fails the piece, the long tail retries
/// on other nodes, and the object commits.
#[tokio::test]
async fn stalled_storage_node_times_out_and_upload_completes() {
    use std::time::Duration;
    use storj::Project;
    use storj_test::MockSatellite;
    use tokio::io::AsyncWriteExt;

    let mock = MockSatellite::start().await;
    let config = storj::Config {
        message_timeout: Some(Duration::from_secs(1)),
        ..Default::default()
    };
    let project = Project::open_with_config(&mock.access(), config)
        .await
        .expect("open");
    let name = unique("stall");
    project.ensure_bucket(&name).await.unwrap();
    // Mock RS is k=2, n=4, o=3: stall two nodes so the threshold cannot be met
    // without the timeout kicking in and the retry round replacing them.
    mock.set_sn_delay(2, Duration::from_secs(60)).await;
    mock.set_sn_delay(3, Duration::from_secs(60)).await;

    let started = std::time::Instant::now();
    let mut upload = project
        .upload_object(&name, "s", Default::default())
        .await
        .unwrap();
    upload.write_all(&vec![7u8; 5000]).await.unwrap();
    upload.commit().await.expect("commit despite stalled nodes");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "upload took {:?}; the stalled nodes were not timed out",
        started.elapsed()
    );
    assert!(
        mock.retry_begin_count() >= 1,
        "stalled pieces must be retried"
    );
    assert_eq!(mock.committed_count(), 1);
}
