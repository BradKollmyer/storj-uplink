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

#[test]
#[ignore = "PR 13: long-tail cancels slow pieces after o successes"]
fn long_tail_cancels_slow_pieces() {
    panic!("inject delayed piecestore Upload");
}

#[test]
#[ignore = "PR 13: reconstruction fails with k-1 pieces"]
fn k_minus_one_pieces_fails_download() {
    panic!("mock SN set of size k-1");
}

#[test]
#[ignore = "PR 13: commit timeout"]
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
