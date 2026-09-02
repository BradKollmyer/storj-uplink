//! Reed-Solomon goldens vs Go `infectious` / `eestream` (K16).
//!
//! Default scheme for tests only: `29/35/80/110-256B`. Production uses BeginSegment.

use storj::constants::{DEFAULT_SHARE_SIZE, TEST_RS_K, TEST_RS_M, TEST_RS_N, TEST_RS_O};
use storj_ec::{Error, ReedSolomon};

#[test]
fn test_scheme_matches_satellite_release_default() {
    assert_eq!(TEST_RS_K, 29);
    assert_eq!(TEST_RS_M, 35);
    assert_eq!(TEST_RS_O, 80);
    assert_eq!(TEST_RS_N, 110);
    assert_eq!(DEFAULT_SHARE_SIZE, 256);
    const { assert!(TEST_RS_K <= TEST_RS_M && TEST_RS_M <= TEST_RS_O && TEST_RS_O <= TEST_RS_N) };
}

fn parse_num(line: &str, key: &str) -> usize {
    let pat = format!("\"{key}\":");
    let i = line.find(&pat).expect(key);
    line[i + pat.len()..]
        .split([',', '}'])
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn parse_hex_field(line: &str, key: &str) -> Vec<u8> {
    let pat = format!("\"{key}\":\"");
    let i = line.find(&pat).expect(key);
    hex::decode(line[i + pat.len()..].split('"').next().unwrap()).unwrap()
}

fn parse_hex_array(line: &str, key: &str) -> Vec<Vec<u8>> {
    let pat = format!("\"{key}\":[");
    let i = line.find(&pat).expect(key);
    let rest = &line[i + pat.len()..];
    let end = rest.find(']').unwrap();
    rest[..end]
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| hex::decode(s.trim().trim_matches('"')).unwrap())
        .collect()
}

fn load_prod_vector() -> (Vec<u8>, Vec<Vec<u8>>) {
    let path = storj_test::fixture("rs_shares.jsonl");
    assert!(
        path.exists(),
        "run go run -C scripts . to emit infectious shares"
    );
    let text = std::fs::read_to_string(&path).unwrap();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if parse_num(line, "k") == TEST_RS_K && parse_num(line, "n") == TEST_RS_N {
            return (
                parse_hex_field(line, "stripe_hex"),
                parse_hex_array(line, "shares_hex"),
            );
        }
    }
    panic!("no 29/110 vector in {}", path.display());
}

#[test]
fn encode_decode_known_stripe() {
    let (stripe, expected) = load_prod_vector();
    assert_eq!(stripe.len(), TEST_RS_K * DEFAULT_SHARE_SIZE);
    let rs = ReedSolomon::new(TEST_RS_K, TEST_RS_N, DEFAULT_SHARE_SIZE).unwrap();
    let shares = rs.encode_stripe(&stripe).unwrap();
    assert_eq!(shares, expected, "encode must match infectious goldens");

    // Drop n-k shares (keep last k, all parity).
    let mut slots: Vec<Option<&[u8]>> = vec![None; TEST_RS_N];
    for (slot, share) in slots
        .iter_mut()
        .skip(TEST_RS_N - TEST_RS_K)
        .zip(shares.iter().skip(TEST_RS_N - TEST_RS_K))
    {
        *slot = Some(share.as_slice());
    }
    assert_eq!(rs.decode_stripe(&slots).unwrap(), stripe);
}

#[test]
fn decode_fails_with_k_minus_one() {
    let (stripe, _) = load_prod_vector();
    let rs = ReedSolomon::new(TEST_RS_K, TEST_RS_N, DEFAULT_SHARE_SIZE).unwrap();
    let shares = rs.encode_stripe(&stripe).unwrap();
    let mut slots: Vec<Option<&[u8]>> = vec![None; TEST_RS_N];
    for (i, s) in shares.iter().take(TEST_RS_K - 1).enumerate() {
        slots[i] = Some(s.as_slice());
    }
    let err = rs.decode_stripe(&slots).unwrap_err();
    assert_eq!(
        err,
        Error::TooFewShares {
            have: TEST_RS_K - 1,
            need: TEST_RS_K
        }
    );
}

#[test]
#[ignore = "PR 8: corrupted share recovered via Berlekamp-Welch if m allows"]
fn decode_with_corrupted_share() {
    // Infectious Decode uses Berlekamp-Welch when extra shares are present.
    // The Uplink data path treats corruption as erasures via piece hashes;
    // BW is not required to ship encode/decode. Keep ignored until a BW port.
    panic!("berlekamp-welch not implemented");
}
