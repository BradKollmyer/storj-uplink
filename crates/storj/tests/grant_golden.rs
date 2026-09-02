//! Grant parse/serialize goldens vs Go `grant.ParseAccess` / `Serialize`.
//!
//! `grant_go.txt` is a synthetic Scope from `go run -C scripts .`
//! (`storj.io/common/grant`). CI regenerates it and fails on drift.
//! Must not contain production secrets.

use storj::{Access, ErrorKind};
use storj_access::{CipherSuite, Grant};

const GO_SAT: &str = "12edKaxTestSatelliteId@127.0.0.1:7777";
const GO_API_KEY_HEX: &str = "0202201111111111111111111111111111111111111111111111111111111111111111000006203da4552191fbdcc8c196a729816b881dca3a4cc0799bfe65b3f0a2e1f307cf49";

fn load_grant(name: &str) -> String {
    let path = storj_test::require_fixture(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing {name} ({e}). Run: go run -C scripts ."))
}

#[test]
fn parse_go_serialized_grant() {
    let serialized = load_grant("grant_go.txt");
    let body = serialized.trim();

    let mut g = Grant::parse(body).expect("parse Go grant");
    assert_eq!(g.satellite_addr(), GO_SAT);
    assert!(
        !g.satellite_addr().to_ascii_lowercase().contains("storj.io"),
        "fixture must not be a production satellite"
    );
    assert_eq!(g.enc_access().default_key, Some([0x33; 32]));
    assert_eq!(g.enc_access().default_path_cipher, CipherSuite::AES_GCM);
    assert_eq!(hex::encode(g.api_key()), GO_API_KEY_HEX);
    assert_eq!(g.enc_access().store_entries.len(), 1);
    let entry = &g.enc_access().store_entries[0];
    assert_eq!(entry.bucket, b"app");
    assert_eq!(entry.unencrypted_path, b"user1");
    assert_eq!(entry.encrypted_path, b"enc-user1");
    assert_eq!(entry.key, [0x44; 32]);

    assert_eq!(g.serialize().unwrap(), body);
    g.mark_mutated();
    assert_eq!(
        g.serialize().unwrap(),
        body,
        "Rust re-encode must match Go grant.Serialize"
    );

    let access = Access::parse(body).expect("facade parse");
    assert_eq!(access.satellite_address(), GO_SAT);
}

#[test]
fn parse_rejects_empty_and_garbage() {
    assert_eq!(
        Access::parse("").unwrap_err().kind(),
        ErrorKind::InvalidGrant
    );
    assert_eq!(
        Access::parse("!!!not-base58!!!").unwrap_err().kind(),
        ErrorKind::InvalidGrant
    );
    // Go `base58.CheckEncode([]byte("Hello World"), 1)` — version != 0.
    assert_eq!(
        Access::parse("ABsn8bcafMZENwm1nSs3C").unwrap_err().kind(),
        ErrorKind::InvalidGrant
    );
}

#[test]
fn unmodified_serialize_is_identity() {
    let serialized = load_grant("grant_go.txt");
    let access = Access::parse(serialized.trim()).unwrap();
    assert_eq!(access.serialize().unwrap(), serialized.trim());
}
