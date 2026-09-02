//! Grant parse/serialize goldens vs Go `uplink.ParseAccess` / `Serialize`.
//!
//! Fixtures are produced by `go run -C scripts .` and must not
//! contain production secrets.

use storj::{Access, ErrorKind};

fn load_grant(name: &str) -> String {
    let path = storj_test::fixture(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("missing {name} ({e}). Run: go run -C scripts . (from repo root)")
    })
}

#[test]
#[ignore = "PR 3: Access::parse / Base58Check Scope"]
fn parse_go_serialized_grant() {
    let serialized = load_grant("grant_go.txt");
    let access = Access::parse(serialized.trim()).expect("parse Go grant");
    assert!(
        !access.satellite_address().is_empty(),
        "satellite address required after parse"
    );
    let round = access.serialize().expect("serialize");
    let reparsed = Access::parse(&round).expect("reparse own serialize");
    assert_eq!(reparsed.satellite_address(), access.satellite_address());
}

#[test]
#[ignore = "PR 3: Access::parse rejects version != 0"]
fn parse_rejects_empty_and_garbage() {
    assert_eq!(
        Access::parse("").unwrap_err().kind(),
        ErrorKind::InvalidGrant
    );
    assert_eq!(
        Access::parse("!!!not-base58!!!").unwrap_err().kind(),
        ErrorKind::InvalidGrant
    );
}

#[test]
#[ignore = "PR 3: unknown protobuf fields preserved until share()"]
fn unmodified_serialize_is_identity() {
    let serialized = load_grant("grant_go.txt");
    let access = Access::parse(serialized.trim()).unwrap();
    assert_eq!(access.serialize().unwrap(), serialized.trim());
}
