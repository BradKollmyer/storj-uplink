//! Object Lock RPCs (PR 25a / K19). Permission bits are tested in-crate.

use std::time::{Duration, SystemTime};
use storj::{
    BucketObjectLockConfiguration, Permission, Retention, RetentionMode, SetObjectRetentionOptions,
};

#[test]
fn permission_full_includes_lock_bits_for_share() {
    let p = Permission::full();
    assert!(p.allow_put_object_retention);
    assert!(p.allow_get_object_retention);
    assert!(p.allow_put_object_legal_hold);
    assert!(p.allow_get_object_legal_hold);
    assert!(p.allow_bypass_governance_retention);
    assert!(p.allow_put_bucket_object_lock_configuration);
    assert!(p.allow_get_bucket_object_lock_configuration);
    assert!(!p.allow_lock);
}

#[test]
fn retention_modes() {
    let r = Retention {
        mode: RetentionMode::Compliance,
        retain_until: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
    };
    assert_eq!(r.mode, RetentionMode::Compliance);
    let opts = SetObjectRetentionOptions {
        bypass_governance_retention: true,
    };
    assert!(opts.bypass_governance_retention);
    let cfg = BucketObjectLockConfiguration {
        enabled: true,
        default_retention: None,
    };
    assert!(cfg.enabled);
}

#[tokio::test]
#[ignore = "PR 25a: Object Lock RPCs"]
async fn put_get_retention_and_legal_hold() {
    panic!("needs metainfo Object Lock RPCs");
}

#[tokio::test]
#[ignore = "PR 25a: bucket lock configuration"]
async fn bucket_object_lock_configuration() {
    panic!("needs Get/SetBucketObjectLockConfiguration");
}
