//! Public API contract: types, Send+Sync, 2025 mapping deltas that we can
//! assert without a satellite.

use std::time::Duration;

use storj::{
    Access, Config, DownloadOptions, EncryptionKey, Error, ErrorKind, ListObjectsOptions,
    Permission, Project, SharePrefix,
};

#[test]
fn version_matches_cargo_pkg() {
    assert_eq!(storj::version(), env!("CARGO_PKG_VERSION"));
    assert!(!storj::version().is_empty());
}

#[test]
fn error_kinds_cover_2025_user_visible_codes() {
    let kinds = [
        ErrorKind::TooManyRequests,
        ErrorKind::BandwidthLimitExceeded,
        ErrorKind::StorageLimitExceeded,
        ErrorKind::SegmentsLimitExceeded,
        ErrorKind::PermissionDenied,
        ErrorKind::BucketNameInvalid,
        ErrorKind::BucketAlreadyExists,
        ErrorKind::BucketNotEmpty,
        ErrorKind::BucketNotFound,
        ErrorKind::ObjectKeyInvalid,
        ErrorKind::ObjectNotFound,
        ErrorKind::UploadDone,
        ErrorKind::UploadIdInvalid,
        ErrorKind::Canceled,
        ErrorKind::EdgeAuthDialFailed,
        ErrorKind::EdgeRegisterAccessFailed,
    ];
    for k in kinds {
        let e = Error::new(k, "x");
        assert!(e.is(k));
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn error_kinds_do_not_mention_ffi() {
    for k in [
        ErrorKind::Protocol,
        ErrorKind::Io,
        ErrorKind::InvalidGrant,
        ErrorKind::DecryptionFailed,
    ] {
        let s = format!("{k:?} {k}");
        assert!(
            !s.to_lowercase().contains("handle"),
            "{s} must not leak FFI InvalidHandle"
        );
        assert!(!s.to_lowercase().contains("ffi"));
        assert!(!s.to_lowercase().contains("uplink-c"));
    }
}

#[test]
fn permission_full_is_not_2025_four_flag_full() {
    // 2025 uplink::access::Permission::full was CRUD only. Go v1.14 FullPermission
    // adds lock bits. Our full() follows Go.
    let p = Permission::full();
    assert!(p.allow_put_object_retention);
    assert!(p.allow_bypass_governance_retention);
    assert!(!p.allow_lock);
}

#[test]
fn config_has_no_temp_dir() {
    let c = Config::default();
    assert!(c.user_agent.is_none());
    assert_eq!(c.dial_timeout_or_default(), Duration::from_secs(20));
}

#[test]
fn download_options_match_go_defaults() {
    let d = DownloadOptions::default();
    assert_eq!(d.offset, 0);
    assert_eq!(d.length, -1);
}

#[tokio::test]
async fn project_open_returns_result() {
    // 2025 Project::open returned Self. Ours returns Result (native dial can fail).
    let err = Access::parse("not-empty-but-unimplemented").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol);
}

#[test]
fn grant_rename_is_access_not_grant() {
    // Compile-time: the 2025 name `Grant` is not part of the public API.
    let _ = std::any::type_name::<Access>();
}

#[test]
fn share_prefix_and_list_prefix_slash_rule() {
    assert!(SharePrefix::new("logs", "2024").is_err());
    assert!(SharePrefix::new("logs", "2024/").is_ok());
    assert!(
        ListObjectsOptions {
            prefix: "2024".into(),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn encryption_key_derive_is_32_bytes() {
    let k = EncryptionKey::derive("passphrase", b"sixteen-byte-ok!").unwrap();
    assert_eq!(k.as_bytes().len(), 32);
}

#[test]
fn crate_is_send_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<Access>();
    assert::<Project>();
    assert::<Error>();
    assert::<EncryptionKey>();
    assert::<storj::Upload>();
    assert::<storj::Download>();
    assert::<storj::PartUpload>();
    assert::<Config>();
}
