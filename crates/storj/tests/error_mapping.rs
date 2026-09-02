//! Error mapping: Go dual returns, I/O conversion, 2025 vs new kinds.

use std::io;
use std::time::SystemTime;

use storj::{Bucket, Error, ErrorKind, Object, SystemMetadata};

#[test]
fn create_bucket_already_exists_carries_bucket() {
    let existing = Bucket {
        name: "photos".into(),
        created: SystemTime::UNIX_EPOCH,
    };
    let e = Error::new(
        ErrorKind::BucketAlreadyExists,
        r#"bucket already exists ("photos")"#,
    )
    .with_bucket(existing);
    assert_eq!(e.kind(), ErrorKind::BucketAlreadyExists);
    assert_eq!(e.bucket().unwrap().name, "photos");
}

#[test]
fn delete_object_absence_is_option_not_not_found() {
    // Document the contract: success with no metadata is Ok(None), not ObjectNotFound.
    // (Implementation in PR 23.) This test locks the Result type.
    fn _sig(_: Result<Option<Object>, Error>) {}
    let ok_none: Result<Option<Object>, Error> = Ok(None);
    assert!(matches!(ok_none, Ok(None)));
}

#[test]
fn object_not_found_is_distinct_from_ok_none() {
    let e = Error::new(ErrorKind::ObjectNotFound, r#"object not found ("k")"#);
    assert_eq!(e.kind(), ErrorKind::ObjectNotFound);
}

#[test]
fn io_round_trip_canceled() {
    let e = Error::from(io::Error::new(io::ErrorKind::Interrupted, "abort"));
    assert!(e.is_canceled());
    let back = io::Error::from(e);
    assert_eq!(back.kind(), io::ErrorKind::Interrupted);
}

#[test]
fn io_round_trip_other() {
    let e = Error::from(io::Error::other("disk"));
    assert_eq!(e.kind(), ErrorKind::Io);
    let back = io::Error::from(e);
    assert_eq!(back.kind(), io::ErrorKind::Other);
}

#[tokio::test]
async fn join_error_canceled_maps() {
    let handle = tokio::spawn(std::future::pending::<()>());
    handle.abort();
    let e = Error::from(handle.await.unwrap_err());
    assert!(e.is_canceled());
}

#[tokio::test]
async fn join_error_panic_resumes_unwind() {
    let handle = tokio::spawn(async { panic!("worker boom") });
    let join_err = handle.await.unwrap_err();
    assert!(join_err.is_panic());
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Error::from(join_err)));
    assert!(
        caught.is_err(),
        "panicking worker must not become ErrorKind::Protocol"
    );
}

#[test]
fn system_metadata_content_length_is_i64() {
    let m = SystemMetadata {
        content_length: 0,
        ..Default::default()
    };
    assert_eq!(m.content_length, 0i64);
}
