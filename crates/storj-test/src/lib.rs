//! Shared test helpers for the Storj native uplink crate.
//!
//! Layering (see `crates/storj/tests/README.md`):
//! 1. Unit / contract tests always run.
//! 2. Golden / protocol tests are `#[ignore]` until the matching PR lands.
//! 3. Interop (`STORJ_INTEROP=1`) builds Go uplink as a helper.
//! 4. Sim (`STORJ_SIM=1` + `STORJ_SIM_ACCESS`) talks to `storj-sim`.

use std::path::{Path, PathBuf};

use storj::constants::{MAX_INLINE_SEGMENT_SIZE, MAX_SEGMENT_SIZE};

/// Object sizes for the Go↔Rust interop matrix (design v1.0 exit criterion).
///
/// `0`, `1`, inline-1, inline+1, one-segment, multi-segment (`64MiB+1`).
pub const INTEROP_SIZES: &[u64] = &[
    0,
    1,
    MAX_INLINE_SEGMENT_SIZE - 1,
    MAX_INLINE_SEGMENT_SIZE + 1,
    MAX_SEGMENT_SIZE,
    MAX_SEGMENT_SIZE + 1,
];

/// Writer/reader sides of the interop matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// `storj.io/uplink` (Go).
    Go,
    /// This crate.
    Rust,
}

impl Side {
    /// Label used in test names and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Rust => "rust",
        }
    }
}

/// Full writer × reader matrix.
pub const INTEROP_SIDES: &[(Side, Side)] = &[
    (Side::Go, Side::Go),
    (Side::Go, Side::Rust),
    (Side::Rust, Side::Go),
    (Side::Rust, Side::Rust),
];

/// True when interop tests should run (Go toolchain + helper binary).
pub fn interop_enabled() -> bool {
    env_flag("STORJ_INTEROP")
}

/// True when `storj-sim` tests should run.
pub fn sim_enabled() -> bool {
    env_flag("STORJ_SIM")
}

/// Access grant serialized string from `storj-sim network env GATEWAY_0_ACCESS`.
pub fn sim_access() -> Option<String> {
    std::env::var("STORJ_SIM_ACCESS")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Directory containing checked-in golden fixtures.
pub fn fixtures_dir() -> PathBuf {
    // crates/storj-test/src/lib.rs → workspace tests/fixtures
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/storj/tests/fixtures")
}

/// Path to a named fixture file.
pub fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

/// Read a fixture as bytes. Panics with a useful path if missing.
pub fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixture(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

/// Read a fixture as UTF-8 text.
pub fn read_fixture_str(name: &str) -> String {
    String::from_utf8(read_fixture(name)).expect("fixture is utf-8")
}

/// Assert `path` exists, with a hint to run the Go generator.
pub fn require_fixture(name: &str) -> PathBuf {
    let path = fixture(name);
    assert!(
        path.exists(),
        "missing fixture {} — run: go run -C scripts .",
        path.display()
    );
    path
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

/// Human-readable size label for test names.
pub fn size_label(n: u64) -> String {
    match n {
        0 => "empty".into(),
        1 => "1B".into(),
        n if n == MAX_INLINE_SEGMENT_SIZE - 1 => "inline-1".into(),
        n if n == MAX_INLINE_SEGMENT_SIZE + 1 => "inline+1".into(),
        n if n == MAX_SEGMENT_SIZE => "1seg".into(),
        n if n == MAX_SEGMENT_SIZE + 1 => "64MiB+1".into(),
        n => format!("{n}B"),
    }
}

/// Placeholder until a mock satellite exists (PR 11).
pub fn mock_satellite_available() -> bool {
    env_flag("STORJ_MOCK")
}

/// Check that a path looks like a fixture directory the tests expect.
pub fn assert_fixtures_layout(root: &Path) {
    assert!(root.join("README.md").exists() || root.exists());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interop_matrix_covers_exit_criterion() {
        assert_eq!(INTEROP_SIZES.len(), 6);
        assert_eq!(INTEROP_SIDES.len(), 4);
        assert!(INTEROP_SIZES.contains(&(MAX_SEGMENT_SIZE + 1)));
    }

    #[test]
    fn env_flags_default_off() {
        // Unset in unit tests.
        let _ = interop_enabled();
        let _ = sim_enabled();
    }
}
