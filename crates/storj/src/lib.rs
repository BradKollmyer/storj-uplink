//! Native Rust Uplink client for the Storj decentralized object store.
//!
//! This crate is **not** a wrapper around `uplink-c`. It is also **not** a
//! drop-in replacement for crates.io `uplink` 0.11.0 (May 2025): that crate is
//! blocking FFI and `!Send`. See `docs/design-native-uplink.md`.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod access;
pub mod config;
pub mod constants;
pub mod encryption;
pub mod error;
pub mod project;
pub mod types;
pub mod upload;

pub use access::{Access, Permission, SharePrefix};
pub use config::Config;
pub use encryption::EncryptionKey;
pub use error::{Error, ErrorKind, Result};
pub use project::{BucketStream, ObjectStream, PartStream, Project, UploadStream};
pub use types::{
    Bucket, BucketObjectLockConfiguration, CommitUploadOptions, CustomMetadata, DefaultRetention,
    DownloadOptions, ListBucketsOptions, ListObjectsOptions, ListUploadPartsOptions,
    ListUploadsOptions, Object, Part, Retention, RetentionMode, SetObjectRetentionOptions,
    SystemMetadata, UploadInfo, UploadOptions,
};
pub use upload::{Download, PartUpload, Upload};

/// Crate version from `Cargo.toml`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn _assert() {
        assert_send_sync::<Access>();
        assert_send_sync::<Project>();
        assert_send_sync::<Config>();
        assert_send_sync::<Upload>();
        assert_send_sync::<Download>();
        assert_send_sync::<Error>();
        assert_send_sync::<EncryptionKey>();
        assert_send_sync::<PartUpload>();
        assert_send_sync::<Permission>();
        assert_send_sync::<Object>();
        assert_send_sync::<Bucket>();
    }
};
