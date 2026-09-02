//! Grant parse/serialize goldens vs Go `uplink.ParseAccess` / `Serialize`.
//!
//! `grant_go.txt` is a synthetic Scope from `go run ./scripts/gen-vectors.go`
//! (deterministic test macaroon + keys). CI regenerates it and fails on drift.
//! Must not contain production secrets.

use storj::{Access, ErrorKind};

fn load_grant(name: &str) -> String {
    let path = storj_test::require_fixture(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("missing {name} ({e}). Run: go run ./scripts/gen-vectors.go (from repo root)")
    })
}

#[test]
fn parse_go_serialized_grant() {
    let serialized = load_grant("grant_go.txt");
    let access = Access::parse(serialized.trim()).expect("parse Go grant");
    assert_eq!(
        access.satellite_address(),
        "12edKaxTestSatelliteId@127.0.0.1:7777"
    );
    assert!(
        access.satellite_address().contains("127.0.0.1"),
        "fixture must be a local synthetic grant, not production"
    );
    let round = access.serialize().expect("serialize");
    let reparsed = Access::parse(&round).expect("reparse own serialize");
    assert_eq!(reparsed.satellite_address(), access.satellite_address());
    assert_eq!(round, serialized.trim());
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
