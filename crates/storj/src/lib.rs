//! Native Rust Uplink client for the Storj decentralized object store.
//!
//! This crate is **not** a wrapper around `uplink-c`. It is also **not** a
//! drop-in replacement for crates.io `uplink` 0.11.0 (May 2025): that crate is
//! blocking FFI and `!Send`. See `docs/design-native-uplink.md`.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod access;
pub mod constants;
pub mod encryption;
pub mod error;
pub mod project;
pub mod types;
pub mod upload;

pub use access::{Access, Permission, SharePrefix};
pub use encryption::EncryptionKey;
pub use error::{Error, ErrorKind, Result};
pub use project::{BucketStream, ObjectStream, PartStream, Project, UploadStream};
pub use types::{
    Bucket, BucketObjectLockConfiguration, CommitUploadOptions, Config, CustomMetadata,
    DefaultRetention, DownloadOptions, ListBucketsOptions, ListObjectsOptions,
    ListUploadPartsOptions, ListUploadsOptions, Object, Part, Retention, RetentionMode,
    SetObjectRetentionOptions, SystemMetadata, UploadInfo, UploadOptions,
};
pub use upload::{Download, PartUpload, Upload};

#[allow(dead_code)]
fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Access>();
    check::<Project>();
    check::<Config>();
    check::<Upload>();
    check::<Download>();
    check::<Error>();
    check::<EncryptionKey>();
    check::<PartUpload>();
    check::<Permission>();
    check::<Object>();
    check::<Bucket>();
}
