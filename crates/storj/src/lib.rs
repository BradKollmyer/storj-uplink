//! Native Rust Uplink client for the Storj decentralized object store.
//!
//! **1.0.0** freezes the public `storj::*` API: access grants, buckets,
//! objects, multi-segment upload/download, listing, copy/move, multipart,
//! revoke, and Object Lock. Edge / GatewayMT is an optional 1.x feature and is
//! not required for this freeze.
//!
//! This crate is **not** a wrapper around `uplink-c`. It is also **not** a
//! drop-in replacement for crates.io `uplink` 0.11.0 (May 2025): that crate is
//! blocking FFI and `!Send`. See `docs/design-native-uplink.md`.
//!
//! MSRV is 1.85 (edition 2024). Dual-licensed MIT OR Apache-2.0.
//!
//! # Walkthrough
//!
//! ```no_run
//! use storj::{Access, Project};
//! use tokio::io::AsyncWriteExt;
//!
//! # async fn run() -> storj::Result<()> {
//! let access = Access::parse(&std::env::args().nth(1).expect("grant"))?;
//! let project = Project::open(&access).await?;
//! project.ensure_bucket("logs").await?;
//!
//! let mut upload = project
//!     .upload_object("logs", "2026-09-01/app.log", Default::default())
//!     .await?;
//! upload.write_all(b"hello storj").await?;
//! let _obj = upload.commit().await?;
//! # Ok(())
//! # }
//! ```

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod access;
mod bucket;
pub mod config;
pub mod constants;
pub mod encryption;
pub mod error;
pub(crate) mod metainfo;
mod object_lock;
mod objects;
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
