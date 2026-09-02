//! Reed-Solomon goldens vs Go `infectious` / `eestream` (K16).
//!
//! Default scheme for tests only: `29/35/80/110-256B`. Production uses BeginSegment.

use storj::constants::{DEFAULT_SHARE_SIZE, TEST_RS_K, TEST_RS_M, TEST_RS_N, TEST_RS_O};

#[test]
fn test_scheme_matches_satellite_release_default() {
    assert_eq!(TEST_RS_K, 29);
    assert_eq!(TEST_RS_M, 35);
    assert_eq!(TEST_RS_O, 80);
    assert_eq!(TEST_RS_N, 110);
    assert_eq!(DEFAULT_SHARE_SIZE, 256);
    const { assert!(TEST_RS_K <= TEST_RS_M && TEST_RS_M <= TEST_RS_O && TEST_RS_O <= TEST_RS_N) };
}

#[test]
#[ignore = "PR 8: reed-solomon-erasure vs infectious vectors"]
fn encode_decode_known_stripe() {
    let path = storj_test::fixture("rs_shares.jsonl");
    assert!(
        path.exists(),
        "run go run -C scripts . to emit infectious shares"
    );
    // Implementation: encode stripe, drop n-k shares, decode, compare plaintext.
}

#[test]
#[ignore = "PR 8: k-1 shares must fail reconstruction"]
fn decode_fails_with_k_minus_one() {
    panic!("storj-ec not implemented");
}

#[test]
#[ignore = "PR 8: corrupted share recovered via Berlekamp-Welch if m allows"]
fn decode_with_corrupted_share() {
    panic!("storj-ec not implemented");
}
