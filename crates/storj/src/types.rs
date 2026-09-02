//! Public metadata types (bucket, object, options, Object Lock).

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use crate::error::{Error, ErrorKind, Result};

/// Bucket metadata. Bucket names are **not** encrypted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bucket {
    /// Unencrypted bucket name.
    pub name: String,
    /// Creation time from the satellite.
    pub created: SystemTime,
}

/// Object metadata. Keys are encrypted on the wire; this struct holds plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    /// Plaintext object key (`/`-delimited).
    pub key: String,
    /// True when this list entry is a common prefix, not an object.
    pub is_prefix: bool,
    /// System timestamps and length.
    pub system: SystemMetadata,
    /// User custom metadata.
    pub custom: CustomMetadata,
}

/// Satellite-maintained object metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SystemMetadata {
    /// Object creation time.
    pub created: Option<SystemTime>,
    /// Optional expiry.
    pub expires: Option<SystemTime>,
    /// Go `SystemMetadata.ContentLength` is `int64`. Negative unused.
    pub content_length: i64,
}

/// Custom user metadata. Keys and values must be valid UTF-8.
/// App convention: `app:key` (e.g. `image-board:title`).
pub type CustomMetadata = BTreeMap<String, String>;

/// Options for `Project::list_buckets`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListBucketsOptions {
    /// First returned bucket is the one after this cursor.
    pub cursor: Option<String>,
}

/// Options for `Project::list_objects`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListObjectsOptions {
    /// If non-empty, must end with `/`.
    pub prefix: String,
    /// Relative to `prefix`. First returned item is *after* cursor.
    pub cursor: String,
    /// Do not collapse prefixes.
    pub recursive: bool,
    /// Include `SystemMetadata`.
    pub system: bool,
    /// Include `CustomMetadata`.
    pub custom: bool,
}

impl ListObjectsOptions {
    /// Validate prefix slash rule (Go `ListObjectsOptions.Prefix`).
    pub fn validate(&self) -> Result<()> {
        require_trailing_slash_if_nonempty("prefix", &self.prefix)
    }
}

/// Options for `Project::upload_object` / `begin_upload`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UploadOptions {
    /// Optional object expiry.
    pub expires: Option<SystemTime>,
}

/// Options for `Project::download_object`.
///
/// Negative `offset` reads a suffix. Combining negative offset and positive
/// length is not supported (Go rule).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadOptions {
    /// Byte offset. Negative → suffix of the object.
    pub offset: i64,
    /// Length. Negative → until EOF. Default: -1.
    pub length: i64,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            length: -1,
        }
    }
}

impl DownloadOptions {
    /// Reject the unsupported Go combination: negative offset + positive length.
    pub fn validate(&self) -> Result<()> {
        if self.offset < 0 && self.length > 0 {
            return Err(Error::new(
                ErrorKind::ObjectKeyInvalid,
                "combining negative offset and positive length is not supported",
            ));
        }
        Ok(())
    }
}

/// Go `storj.RetentionMode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionMode {
    /// Governance mode (bypassable with the bypass permission).
    Governance,
    /// Compliance mode (not bypassable).
    Compliance,
}

/// Object Lock retention on an object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retention {
    /// Retention mode.
    pub mode: RetentionMode,
    /// Retain until this time.
    pub retain_until: SystemTime,
}

/// Options for `set_object_retention`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SetObjectRetentionOptions {
    /// Requires `allow_bypass_governance_retention` on the grant.
    pub bypass_governance_retention: bool,
}

/// Default retention for a bucket Object Lock configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultRetention {
    /// Retention mode.
    pub mode: RetentionMode,
    /// Days (mutually exclusive with years in S3 semantics).
    pub days: i32,
    /// Years.
    pub years: i32,
}

/// Bucket-level Object Lock configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BucketObjectLockConfiguration {
    /// Whether Object Lock is enabled on the bucket.
    pub enabled: bool,
    /// Optional default retention.
    pub default_retention: Option<DefaultRetention>,
}

/// 2025: `object::upload::Info`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadInfo {
    /// Object key.
    pub key: String,
    /// Multipart upload id (Base58Check version 1).
    pub upload_id: String,
    /// System metadata.
    pub system: SystemMetadata,
}

/// Options for `commit_upload`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitUploadOptions {
    /// Custom metadata applied at commit.
    pub custom_metadata: CustomMetadata,
}

/// Options for listing uncommitted uploads.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListUploadsOptions {
    /// If non-empty, must end with `/`.
    pub prefix: String,
    /// Relative to `prefix`.
    pub cursor: String,
    /// Do not collapse prefixes.
    pub recursive: bool,
    /// Include system metadata.
    pub system: bool,
    /// Include custom metadata.
    pub custom: bool,
}

impl ListUploadsOptions {
    /// Validate prefix slash rule.
    pub fn validate(&self) -> Result<()> {
        require_trailing_slash_if_nonempty("prefix", &self.prefix)
    }
}

/// Options for listing parts of a multipart upload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListUploadPartsOptions {
    /// First returned part is after this part number.
    pub cursor: u32,
}

/// 2025: `object::upload::Part`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Part {
    /// Part number (1-indexed in S3; Storj follows Go uplink).
    pub part_number: u32,
    /// Plain size of the part.
    pub size: i64,
    /// Last modified.
    pub modified: SystemTime,
    /// Optional ETag bytes.
    pub etag: Vec<u8>,
}

/// Client configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Config {
    /// Partner User-Agent (RFC 7231 §5.5.3). Sent as `RequestHeader.user_agent`.
    pub user_agent: Option<String>,
    /// Dial timeout. `None` or zero → 20s (Go default). Rust `Duration` cannot
    /// be negative; omit a timeout by using `Duration::MAX`.
    pub dial_timeout: Option<Duration>,
}

impl Config {
    /// Effective dial timeout after applying Go's zero-means-default rule.
    pub fn dial_timeout_or_default(&self) -> Duration {
        match self.dial_timeout {
            None | Some(Duration::ZERO) => {
                Duration::from_secs(crate::constants::DEFAULT_DIAL_TIMEOUT_SECS)
            }
            Some(d) => d,
        }
    }
}

/// Require a trailing `/` when `value` is non-empty (share prefix, list prefix,
/// `override_encryption_key`).
pub(crate) fn require_trailing_slash_if_nonempty(label: &str, value: &str) -> Result<()> {
    if !value.is_empty() && !value.ends_with('/') {
        return Err(Error::new(
            ErrorKind::ObjectKeyInvalid,
            format!("{label} must end with '/'"),
        ));
    }
    Ok(())
}

/// `override_encryption_key` requires a non-empty prefix that ends with `/`.
pub(crate) fn require_encryption_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() || !prefix.ends_with('/') {
        return Err(Error::new(
            ErrorKind::ObjectKeyInvalid,
            "prefix must end with '/'",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_options_default_is_whole_object() {
        let d = DownloadOptions::default();
        assert_eq!(d.offset, 0);
        assert_eq!(d.length, -1);
        assert!(d.validate().is_ok());
    }

    #[test]
    fn download_suffix_ok() {
        let d = DownloadOptions {
            offset: -100,
            length: -1,
        };
        assert!(d.validate().is_ok());
    }

    #[test]
    fn download_negative_offset_positive_length_rejected() {
        let d = DownloadOptions {
            offset: -10,
            length: 100,
        };
        let e = d.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);
    }

    #[test]
    fn list_prefix_must_end_with_slash() {
        let bad = ListObjectsOptions {
            prefix: "logs".into(),
            ..Default::default()
        };
        assert_eq!(
            bad.validate().unwrap_err().kind(),
            ErrorKind::ObjectKeyInvalid
        );

        let ok = ListObjectsOptions {
            prefix: "logs/".into(),
            ..Default::default()
        };
        assert!(ok.validate().is_ok());

        let empty = ListObjectsOptions::default();
        assert!(empty.validate().is_ok());
    }

    #[test]
    fn dial_timeout_zero_is_twenty_seconds() {
        let c = Config {
            dial_timeout: Some(Duration::ZERO),
            ..Default::default()
        };
        assert_eq!(c.dial_timeout_or_default(), Duration::from_secs(20));
        assert_eq!(
            Config::default().dial_timeout_or_default(),
            Duration::from_secs(20)
        );
    }
}
