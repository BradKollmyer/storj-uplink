//! Infectious / eestream goldens from `go run -C scripts .`.

use std::fs;
use std::path::PathBuf;

use storj_ec::ReedSolomon;

struct Vector {
    k: usize,
    n: usize,
    share_size: usize,
    stripe: Vec<u8>,
    shares: Vec<Vec<u8>>,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../storj/tests/fixtures")
}

fn parse_num(line: &str, key: &str) -> usize {
    let pat = format!("\"{key}\":");
    let i = line
        .find(&pat)
        .unwrap_or_else(|| panic!("key {key} in {line}"));
    let rest = &line[i + pat.len()..];
    rest.split([',', '}'])
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn parse_hex_field(line: &str, key: &str) -> Vec<u8> {
    let pat = format!("\"{key}\":\"");
    let i = line.find(&pat).unwrap_or_else(|| panic!("key {key}"));
    let rest = &line[i + pat.len()..];
    let hex = rest.split('"').next().unwrap();
    hex::decode(hex).unwrap_or_else(|e| panic!("{key} hex: {e}"))
}

fn parse_hex_array(line: &str, key: &str) -> Vec<Vec<u8>> {
    let pat = format!("\"{key}\":[");
    let i = line.find(&pat).unwrap_or_else(|| panic!("key {key}"));
    let rest = &line[i + pat.len()..];
    let end = rest.find(']').expect("array close");
    rest[..end]
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let h = s.trim().trim_matches('"');
            hex::decode(h).unwrap_or_else(|e| panic!("share hex: {e}"))
        })
        .collect()
}

fn load_vectors() -> Vec<Vector> {
    let path = fixtures_dir().join("rs_shares.jsonl");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing {} ({e}). Run: go run -C scripts .", path.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| Vector {
            k: parse_num(line, "k"),
            n: parse_num(line, "n"),
            share_size: parse_num(line, "share_size"),
            stripe: parse_hex_field(line, "stripe_hex"),
            shares: parse_hex_array(line, "shares_hex"),
        })
        .collect()
}

#[test]
fn encode_matches_infectious_goldens() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 3,
        "expected small + hello + 29/110 goldens"
    );
    for v in &vectors {
        let rs = ReedSolomon::new(v.k, v.n, v.share_size).unwrap();
        let got = rs.encode_stripe(&v.stripe).unwrap();
        assert_eq!(got.len(), v.shares.len(), "k={} n={}", v.k, v.n);
        for (i, (a, b)) in got.iter().zip(v.shares.iter()).enumerate() {
            assert_eq!(a, b, "share {i} k={} n={}", v.k, v.n);
        }
    }
}

#[test]
fn decode_infectious_shares_any_k() {
    for v in load_vectors() {
        let rs = ReedSolomon::new(v.k, v.n, v.share_size).unwrap();
        // Drop n-k highest shares.
        let mut slots: Vec<Option<&[u8]>> = v.shares.iter().map(|s| Some(s.as_slice())).collect();
        for s in slots.iter_mut().skip(v.k) {
            *s = None;
        }
        assert_eq!(rs.decode_stripe(&slots).unwrap(), v.stripe);

        // Drop first n-k (keep last k, typically parity).
        let mut slots: Vec<Option<&[u8]>> = vec![None; v.n];
        for (slot, share) in slots
            .iter_mut()
            .skip(v.n - v.k)
            .zip(v.shares.iter().skip(v.n - v.k))
        {
            *slot = Some(share.as_slice());
        }
        assert_eq!(rs.decode_stripe(&slots).unwrap(), v.stripe);
    }
}

#[test]
fn production_stripe_bin_matches_jsonl() {
    let bin = fs::read(fixtures_dir().join("rs_stripe.bin")).expect("rs_stripe.bin");
    let prod = load_vectors()
        .into_iter()
        .find(|v| v.k == 29 && v.n == 110)
        .expect("29/110 vector");
    assert_eq!(bin, prod.stripe);
    assert_eq!(bin.len(), 29 * 256);
}

#[test]
fn hello_world_infectious_example() {
    let hello = load_vectors()
        .into_iter()
        .find(|v| v.k == 8 && v.n == 14)
        .expect("8/14 vector");
    assert_eq!(hello.stripe, b"hello, world! __");
    let rs = ReedSolomon::new(8, 14, 2).unwrap();
    assert_eq!(rs.encode_stripe(&hello.stripe).unwrap(), hello.shares);
}
