//! In-process mock satellite / storage-node fault injection (PR 11–14).
//!
//! The mock is not implemented yet. These tests document the required faults
//! from the design: long-tail slow pieces, `k-1` available pieces, commit timeout.

#[test]
#[ignore = "PR 11: in-process DRPC mock server"]
fn mock_satellite_project_info_and_buckets() {
    panic!("implement storj-test mock DRPC server");
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
fn compressed_batch_rejects_oversize() {
    assert_eq!(
        storj::constants::COMPRESSED_BATCH_MAX_DECODE,
        storj_proto::MAX_DECODE_MEMORY
    );
    let plain = vec![0u8; storj_proto::MAX_DECODE_MEMORY + 1];
    let compressed = storj_proto::compress(&plain).expect("compress zeros");
    match storj_proto::decompress(&compressed) {
        Err(storj_proto::CompressedError::Oversize) => {}
        other => panic!("expected Oversize, got {other:?}"),
    }
}
