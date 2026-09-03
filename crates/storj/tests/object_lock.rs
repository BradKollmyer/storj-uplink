//! Object Lock RPCs (PR 25a / K19). Permission bits are tested in-crate.

use std::time::{Duration, SystemTime};
use storj::{
    BucketObjectLockConfiguration, DefaultRetention, ErrorKind, Permission, Project, Retention,
    RetentionMode, SetObjectRetentionOptions, UploadOptions,
};
use storj_test::MockSatellite;
use tokio::io::AsyncWriteExt;

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
async fn put_get_retention_and_legal_hold() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique_bucket();
    project.create_bucket(&bucket).await.expect("create bucket");
    project
        .set_bucket_object_lock_configuration(
            &bucket,
            BucketObjectLockConfiguration {
                enabled: true,
                default_retention: None,
            },
        )
        .await
        .expect("enable lock");

    let key = "dir/obj";
    put_object(&project, &bucket, key).await;
    let none = project
        .get_object_retention(&bucket, key, None)
        .await
        .expect("unlocked object has no retention");
    assert_eq!(none, None);
    assert!(
        !project
            .get_object_legal_hold(&bucket, key, None)
            .await
            .expect("unlocked object has no legal hold")
    );

    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let retention = Retention {
        mode: RetentionMode::Compliance,
        retain_until: until,
    };
    project
        .set_object_retention(
            &bucket,
            key,
            None,
            retention.clone(),
            SetObjectRetentionOptions::default(),
        )
        .await
        .expect("set retention");
    let got = project
        .get_object_retention(&bucket, key, None)
        .await
        .expect("get retention");
    assert_eq!(got, Some(retention));

    assert!(
        !project
            .get_object_legal_hold(&bucket, key, None)
            .await
            .expect("get legal hold")
    );
    project
        .set_object_legal_hold(&bucket, key, None, true)
        .await
        .expect("set legal hold");
    assert!(
        project
            .get_object_legal_hold(&bucket, key, None)
            .await
            .expect("get legal hold enabled")
    );

    let gov = Retention {
        mode: RetentionMode::Governance,
        retain_until: until + Duration::from_secs(3600),
    };
    project
        .set_object_retention(
            &bucket,
            key,
            None,
            gov.clone(),
            SetObjectRetentionOptions {
                bypass_governance_retention: true,
            },
        )
        .await
        .expect("set governance with bypass");
    assert_eq!(
        project
            .get_object_retention(&bucket, key, None)
            .await
            .expect("get governance"),
        Some(gov.clone())
    );

    let missing = project
        .get_object_retention(&bucket, "no-such", None)
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::ObjectNotFound);

    let set_missing = project
        .set_object_retention(
            &bucket,
            "no-such",
            None,
            gov.clone(),
            SetObjectRetentionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(set_missing.kind(), ErrorKind::ObjectNotFound);

    let hold_missing = project
        .set_object_legal_hold(&bucket, "no-such", None, true)
        .await
        .unwrap_err();
    assert_eq!(hold_missing.kind(), ErrorKind::ObjectNotFound);

    let no_bucket = project
        .get_object_retention("does-not-exist-zzzz", key, None)
        .await
        .unwrap_err();
    assert_eq!(no_bucket.kind(), ErrorKind::BucketNotFound);
}

#[tokio::test]
async fn begin_object_retention_and_legal_hold_applied_at_commit() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique_bucket();
    project.create_bucket(&bucket).await.expect("create bucket");
    project
        .set_bucket_object_lock_configuration(
            &bucket,
            BucketObjectLockConfiguration {
                enabled: true,
                default_retention: None,
            },
        )
        .await
        .expect("enable lock");

    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let retention = Retention {
        mode: RetentionMode::Governance,
        retain_until: until,
    };
    let key = "locked-at-create";
    let mut upload = project
        .upload_object(
            &bucket,
            key,
            UploadOptions {
                retention: Some(retention.clone()),
                legal_hold: true,
                ..Default::default()
            },
        )
        .await
        .expect("upload_object");
    upload.write_all(b"lock-at-create").await.expect("write");
    upload.commit().await.expect("commit");

    assert_eq!(
        project
            .get_object_retention(&bucket, key, None)
            .await
            .expect("get retention"),
        Some(retention)
    );
    assert!(
        project
            .get_object_legal_hold(&bucket, key, None)
            .await
            .expect("get legal hold")
    );
}

#[tokio::test]
async fn begin_object_retention_rejected_without_bucket_lock() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique_bucket();
    project.create_bucket(&bucket).await.expect("create bucket");

    let err = match project
        .upload_object(
            &bucket,
            "k",
            UploadOptions {
                retention: Some(Retention {
                    mode: RetentionMode::Compliance,
                    retain_until: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
                }),
                ..Default::default()
            },
        )
        .await
    {
        Ok(_) => panic!("expected BeginObject retention rejection"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), ErrorKind::Protocol);
    assert!(
        err.to_string()
            .contains("object lock is not enabled for this bucket"),
        "{err}"
    );

    let err = match project
        .upload_object(
            &bucket,
            "k",
            UploadOptions {
                legal_hold: true,
                ..Default::default()
            },
        )
        .await
    {
        Ok(_) => panic!("expected BeginObject legal-hold rejection"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), ErrorKind::Protocol);
    assert!(
        err.to_string()
            .contains("object lock is not enabled for this bucket"),
        "{err}"
    );
}

#[tokio::test]
async fn bucket_object_lock_configuration() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique_bucket();
    project.create_bucket(&bucket).await.expect("create bucket");

    let unset = project
        .get_bucket_object_lock_configuration(&bucket)
        .await
        .unwrap_err();
    assert_eq!(unset.kind(), ErrorKind::Protocol);
    assert!(
        unset
            .to_string()
            .contains("object lock is not enabled for this bucket"),
        "{unset}"
    );

    let cfg = BucketObjectLockConfiguration {
        enabled: true,
        default_retention: Some(DefaultRetention {
            mode: RetentionMode::Governance,
            days: 7,
            years: 0,
        }),
    };
    project
        .set_bucket_object_lock_configuration(&bucket, cfg.clone())
        .await
        .expect("set lock config");
    let got = project
        .get_bucket_object_lock_configuration(&bucket)
        .await
        .expect("get lock config");
    assert_eq!(got, cfg);

    let years = BucketObjectLockConfiguration {
        enabled: true,
        default_retention: Some(DefaultRetention {
            mode: RetentionMode::Compliance,
            days: 0,
            years: 2,
        }),
    };
    project
        .set_bucket_object_lock_configuration(&bucket, years.clone())
        .await
        .expect("set years");
    assert_eq!(
        project
            .get_bucket_object_lock_configuration(&bucket)
            .await
            .expect("get years"),
        years
    );

    let both = project
        .set_bucket_object_lock_configuration(
            &bucket,
            BucketObjectLockConfiguration {
                enabled: true,
                default_retention: Some(DefaultRetention {
                    mode: RetentionMode::Compliance,
                    days: 1,
                    years: 1,
                }),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(both.kind(), ErrorKind::Protocol);
    assert!(
        both.to_string()
            .contains("bucket object lock configuration is invalid"),
        "{both}"
    );

    let missing = project
        .get_bucket_object_lock_configuration("does-not-exist-zzzz")
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::BucketNotFound);

    let empty = project
        .set_bucket_object_lock_configuration("", cfg)
        .await
        .unwrap_err();
    assert_eq!(empty.kind(), ErrorKind::BucketNameInvalid);
}

#[tokio::test]
async fn get_retention_none_when_only_legal_hold_set() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique_bucket();
    project.create_bucket(&bucket).await.unwrap();
    put_object(&project, &bucket, "k").await;
    project
        .set_object_legal_hold(&bucket, "k", None, true)
        .await
        .unwrap();
    let got = project
        .get_object_retention(&bucket, "k", None)
        .await
        .expect("no retention");
    assert_eq!(got, None);
}

#[tokio::test]
async fn empty_object_key_is_invalid_before_rpc() {
    let mock = MockSatellite::start().await;
    let project = open_test_project(&mock).await;
    let bucket = unique_bucket();
    project.create_bucket(&bucket).await.unwrap();

    let err = project
        .get_object_retention(&bucket, "", None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);

    let err = project
        .set_object_retention(
            &bucket,
            "",
            None,
            Retention {
                mode: RetentionMode::Compliance,
                retain_until: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
            },
            SetObjectRetentionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);

    let err = project
        .get_object_legal_hold(&bucket, "", None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);

    let err = project
        .set_object_legal_hold(&bucket, "", None, true)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ObjectKeyInvalid);
}

async fn open_test_project(mock: &MockSatellite) -> Project {
    Project::open(&mock.access())
        .await
        .expect("open mock project")
}

async fn put_object(project: &Project, bucket: &str, key: &str) {
    let mut upload = project
        .upload_object(bucket, key, Default::default())
        .await
        .expect("upload_object");
    upload.write_all(b"lock").await.expect("write");
    upload.commit().await.expect("commit");
}

fn unique_bucket() -> String {
    format!(
        "t-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}
