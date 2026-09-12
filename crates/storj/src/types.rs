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
///
/// Produced by the satellite; `#[non_exhaustive]` so fields can be added in
/// 1.x without breaking callers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Object {
    /// Plaintext object key (`/`-delimited).
    pub key: String,
    /// True when this list entry is a common prefix, not an object.
    pub is_prefix: bool,
    /// Object version bytes as returned by the satellite (empty when unknown,
    /// e.g. for list entries without version info). Pass to the Object Lock
    /// methods' `version` argument to address this exact version.
    pub version: Vec<u8>,
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

/// Validate custom metadata before making a request, like Go's `CustomMetadata.Verify`.
/// Keys must be nonempty; neither keys nor values may contain NUL bytes.
/// Empty values and Unicode are allowed. Rust strings already guarantee UTF-8.
pub fn verify_custom_metadata(metadata: &CustomMetadata) -> Result<()> {
    for (key, value) in metadata {
        if key.is_empty() {
            return Err(Error::new(
                ErrorKind::MetadataInvalid,
                "custom metadata contains an empty key",
            ));
        }
        if key.contains('\0') || value.contains('\0') {
            return Err(Error::new(
                ErrorKind::MetadataInvalid,
                "custom metadata contains a NUL byte",
            ));
        }
    }
    Ok(())
}

/// Options for `Project::list_buckets`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListBucketsOptions {
    /// First returned bucket is the one after this cursor.
    pub cursor: Option<String>,
}

/// Options for `Project::create_bucket_with`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateBucketOptions {
    /// Enable Object Lock at creation (satellite also enables versioning).
    pub object_lock_enabled: bool,
    /// Self-serve placement constraint name (empty = satellite project default).
    pub placement: Vec<u8>,
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
    /// Object Lock retention to apply at creation (Go `UploadOptions.Retention`).
    /// Requires Object Lock enabled on the bucket.
    pub retention: Option<Retention>,
    /// Place a legal hold at creation (Go `UploadOptions.LegalHold`).
    pub legal_hold: bool,
    /// Object checksum. `BeginObject` announces the algorithm and composite
    /// flag only; the plaintext `value` is encrypted under the object's
    /// metadata key and sent on `CommitObject`. For `upload_object` the value
    /// is therefore required up front; for `begin_upload` it is ignored and
    /// the commit-time value comes from `CommitUploadOptions::checksum`.
    /// `None` leaves the proto fields at their defaults (`NONE`).
    pub checksum: Option<ObjectChecksum>,
}

/// Options for `Project::download_object`.
///
/// Negative `offset` reads a suffix. Combining negative offset and
/// non-negative length is not supported (Go `NewStreamRange`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadOptions {
    /// Byte offset. Negative → suffix of the object.
    pub offset: i64,
    /// Length. Negative → until EOF. Default: -1.
    pub length: i64,
    /// Empty downloads the latest object. Nonempty is sent as
    /// `DownloadObject.object_version` (typically `Object.version`).
    pub version: Vec<u8>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            length: -1,
            version: Vec::new(),
        }
    }
}

impl DownloadOptions {
    /// Reject the unsupported Go combination: negative offset + non-negative length.
    pub fn validate(&self) -> Result<()> {
        if self.offset < 0 && self.length >= 0 {
            return Err(Error::new(
                ErrorKind::ObjectKeyInvalid,
                "suffix requires length to be negative",
            ));
        }
        Ok(())
    }
}

/// Go `storj.RetentionMode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
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

/// 2025: `object::upload::Info`. Satellite-produced; `#[non_exhaustive]`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct UploadInfo {
    /// Object key.
    pub key: String,
    /// Multipart upload id (Base58Check version 1).
    pub upload_id: String,
    /// System metadata.
    pub system: SystemMetadata,
}

/// Checksum algorithm on `BeginObject` / `CommitObject`.
///
/// Values match `storj_proto::metainfo::ObjectChecksumAlgorithm`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectChecksumAlgorithm {
    /// No checksum (`NONE` = 0).
    #[default]
    None,
    /// CRC-32 (`CRC32` = 1).
    Crc32,
    /// CRC-32C (`CRC32C` = 2).
    Crc32c,
    /// CRC-64/NVME (`CRC64NVME` = 3).
    Crc64Nvme,
    /// SHA-1 (`SHA1` = 4).
    Sha1,
    /// SHA-256 (`SHA256` = 5).
    Sha256,
}

impl ObjectChecksumAlgorithm {
    pub(crate) fn to_proto(self) -> i32 {
        use storj_proto::metainfo::ObjectChecksumAlgorithm as Proto;
        match self {
            Self::None => Proto::None as i32,
            Self::Crc32 => Proto::Crc32 as i32,
            Self::Crc32c => Proto::Crc32c as i32,
            Self::Crc64Nvme => Proto::Crc64nvme as i32,
            Self::Sha1 => Proto::Sha1 as i32,
            Self::Sha256 => Proto::Sha256 as i32,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_proto(value: i32) -> Self {
        use storj_proto::metainfo::ObjectChecksumAlgorithm as Proto;
        match Proto::try_from(value) {
            Ok(Proto::None) => Self::None,
            Ok(Proto::Crc32) => Self::Crc32,
            Ok(Proto::Crc32c) => Self::Crc32c,
            Ok(Proto::Crc64nvme) => Self::Crc64Nvme,
            Ok(Proto::Sha1) => Self::Sha1,
            Ok(Proto::Sha256) => Self::Sha256,
            Err(_) => Self::None,
        }
    }
}

/// Object checksum supplied by the caller in plaintext.
///
/// The library encrypts `value` for the satellite: on commit it is encrypted
/// under the object's random metadata key, exactly like the ETag, so it is
/// never visible to the satellite and can be decrypted by any reader that
/// can decrypt the object's metadata. `BeginObject` announces only
/// `algorithm` and `composite`; the encrypted value is sent on
/// `CommitObject`, the first point at which the metadata key exists.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObjectChecksum {
    /// Algorithm; `None` is proto `NONE`.
    pub algorithm: ObjectChecksumAlgorithm,
    /// Whether the checksum is a composite of part checksums.
    pub composite: bool,
    /// Plaintext checksum bytes (for example the 32 raw bytes of a SHA-256).
    /// Required at commit when `algorithm` is not
    /// [`ObjectChecksumAlgorithm::None`]; must be empty when it is.
    pub value: Vec<u8>,
}

impl ObjectChecksum {
    /// Satellite `validateChecksumOptions`, applied before any RPC.
    /// `require_value` is true at commit, where the value must be present.
    pub(crate) fn validate(&self, require_value: bool) -> Result<()> {
        if self.algorithm == ObjectChecksumAlgorithm::None {
            if self.composite {
                return Err(Error::new(
                    ErrorKind::MetadataInvalid,
                    "checksum composite flag requires a checksum algorithm",
                ));
            }
            if !self.value.is_empty() {
                return Err(Error::new(
                    ErrorKind::MetadataInvalid,
                    "checksum value requires a checksum algorithm",
                ));
            }
        } else if require_value && self.value.is_empty() {
            return Err(Error::new(
                ErrorKind::MetadataInvalid,
                "checksum value is required when a checksum algorithm is set",
            ));
        }
        Ok(())
    }
}

/// Options for `commit_upload`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitUploadOptions {
    /// Custom metadata applied at commit.
    pub custom_metadata: CustomMetadata,
    /// Object checksum for `CommitObject`; the plaintext `value` is
    /// encrypted under the object's metadata key before it is sent. `None`
    /// leaves the proto fields at their defaults (`NONE`).
    pub checksum: Option<ObjectChecksum>,
}

/// Options for listing uncommitted uploads.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListUploadsOptions {
    /// Empty lists the bucket. A nonempty value ending with `/` is a listing
    /// prefix. A nonempty value without `/` lists pending streams for that
    /// exact object key via `ListPendingObjectStreams`.
    pub prefix: String,
    /// Relative to `prefix`. For an exact-key listing, a valid multipart
    /// upload id is used as the exclusive `stream_id` cursor. An invalid nonempty
    /// upload id yields `ErrorKind::UploadIdInvalid`.
    pub cursor: String,
    /// Do not collapse prefixes.
    pub recursive: bool,
    /// Include system metadata.
    pub system: bool,
    /// Include custom metadata.
    pub custom: bool,
}

impl ListUploadsOptions {
    /// Empty prefix, trailing-slash listing prefix, and exact object key are valid.
    pub fn validate(&self) -> Result<()> {
        let _ = &self.prefix;
        Ok(())
    }
}

/// Options for listing parts of a multipart upload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListUploadPartsOptions {
    /// First returned part is after this part number.
    pub cursor: u32,
}

/// 2025: `object::upload::Part`. Satellite-produced; `#[non_exhaustive]`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
    /// Optional caller-supplied TLS identity, reused for all satellite and
    /// storage-node TLS/QUIC connections. `None` generates an ephemeral identity.
    /// Noise uses its own ephemeral X25519 initiator key.
    pub tls_identity: Option<crate::config::TlsIdentity>,
    /// Transport policy. Defaults to advertised Noise for pieces and TLS otherwise.
    /// `Noise` uses advertised keys for piece transfers and TCP/TLS for metadata.
    pub transport: crate::TransportMode,
    /// Early data, Fast Open, and best-effort TCP QoS controls.
    pub network: crate::NetworkOptions,
    /// Optional local observer for connection and transfer events.
    pub telemetry: Option<crate::Telemetry>,
    /// Partner User-Agent (RFC 7231 §5.5.3). Sent as `RequestHeader.user_agent`.
    pub user_agent: Option<String>,
    /// Dial timeout. `None` or zero → 20s (Go default). Rust `Duration` cannot
    /// be negative; omit a timeout by using `Duration::MAX`.
    pub dial_timeout: Option<Duration>,
    /// Deadline for each individual read/write on a satellite or storage-node
    /// connection (Go `piecestore.Config.MessageTimeout`). `None` or zero →
    /// 10 minutes. A slow-but-progressing transfer never trips it; a peer that
    /// stops responding fails within this bound instead of hanging forever.
    pub message_timeout: Option<Duration>,
    /// How many remote segments may upload or download at once. The storage-node
    /// pool cap is this times RS `n` (production 110). `None` or 0 → 8.
    pub concurrent_segments: Option<usize>,
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

    /// Effective per-message timeout (`None`/zero → 10 minutes).
    pub fn message_timeout_or_default(&self) -> Duration {
        match self.message_timeout {
            None | Some(Duration::ZERO) => storj_rpc::conn::DEFAULT_TIMEOUT,
            Some(d) => d,
        }
    }

    /// Effective remote-segment concurrency (`None`/zero → 8).
    #[must_use]
    pub fn concurrent_segments_or_default(&self) -> usize {
        match self.concurrent_segments {
            None | Some(0) => crate::constants::DEFAULT_CONCURRENT_SEGMENTS,
            Some(n) => n,
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
        assert!(d.version.is_empty());
        assert!(d.validate().is_ok());
    }

    #[test]
    fn download_suffix_ok() {
        let d = DownloadOptions {
            offset: -100,
            length: -1,
            version: Vec::new(),
        };
        assert!(d.validate().is_ok());
    }

    #[test]
    fn download_negative_offset_positive_length_rejected() {
        let d = DownloadOptions {
            offset: -10,
            length: 100,
            version: Vec::new(),
        };
        let e = d.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);
        let zero = DownloadOptions {
            offset: -10,
            length: 0,
            version: Vec::new(),
        };
        assert_eq!(
            zero.validate().unwrap_err().kind(),
            ErrorKind::ObjectKeyInvalid
        );
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
        assert_eq!(Config::default().concurrent_segments_or_default(), 8);
        assert_eq!(
            Config {
                concurrent_segments: Some(0),
                ..Default::default()
            }
            .concurrent_segments_or_default(),
            8
        );
        assert_eq!(
            Config {
                concurrent_segments: Some(10),
                ..Default::default()
            }
            .concurrent_segments_or_default(),
            10
        );
    }

    #[test]
    fn checksum_algorithm_proto_round_trip() {
        for algo in [
            ObjectChecksumAlgorithm::None,
            ObjectChecksumAlgorithm::Crc32,
            ObjectChecksumAlgorithm::Crc32c,
            ObjectChecksumAlgorithm::Crc64Nvme,
            ObjectChecksumAlgorithm::Sha1,
            ObjectChecksumAlgorithm::Sha256,
        ] {
            assert_eq!(ObjectChecksumAlgorithm::from_proto(algo.to_proto()), algo);
        }
        assert_eq!(
            ObjectChecksumAlgorithm::default(),
            ObjectChecksumAlgorithm::None
        );
        assert_eq!(
            ObjectChecksumAlgorithm::from_proto(99),
            ObjectChecksumAlgorithm::None
        );
        assert_eq!(UploadOptions::default().checksum, None);
        assert_eq!(CommitUploadOptions::default().checksum, None);
    }
}
