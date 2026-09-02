//! Go ↔ Rust writer/reader matrix (design interop requirements).
//!
//! Enable with `STORJ_INTEROP=1` and a Go toolchain. Never required of crate
//! consumers. Go is a CI-only test helper.

use storj_test::{INTEROP_SIDES, INTEROP_SIZES, Side, size_label};

#[test]
fn matrix_is_complete() {
    assert_eq!(INTEROP_SIDES.len(), 4);
    assert!(INTEROP_SIDES.contains(&(Side::Go, Side::Rust)));
    assert!(INTEROP_SIDES.contains(&(Side::Rust, Side::Go)));
    for &n in INTEROP_SIZES {
        let _ = size_label(n);
    }
}

#[test]
#[ignore = "PR 20: Go uplink helper binary"]
fn rust_parse_go_grant_and_go_parse_rust_grant() {
    assert!(
        storj_test::interop_enabled() || true,
        "set STORJ_INTEROP=1 in the interop CI job"
    );
    panic!("needs Access::parse + Go helper");
}

#[test]
#[ignore = "PR 20 / PR 26: object round-trip matrix"]
fn writer_reader_size_matrix() {
    for &(w, r) in INTEROP_SIDES {
        for &size in INTEROP_SIZES {
            let _name = format!("{}->{}/{}", w.as_str(), r.as_str(), size_label(size));
            // Each cell: writer uploads `size` bytes, reader downloads and compares.
        }
    }
    panic!("needs upload/download + Go helper");
}

#[test]
#[ignore = "PR 6 + PR 20: share() then Go OpenProject"]
fn rust_share_then_go_open() {
    panic!("needs Access::share + Go helper");
}
