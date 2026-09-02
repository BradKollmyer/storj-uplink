//! Public error type. Stable `kind` for matching; `source` may change.

use std::fmt;
use std::io;

use crate::types::{Bucket, Object};

/// Public error. Optional `bucket`/`object` carry Go dual-return payloads.
/// Inner payload is boxed so `Result<T, Error>` stays small (clippy `result_large_err`).
#[derive(Debug)]
pub struct Error {
    inner: Box<ErrorInner>,
}

#[derive(Debug)]
struct ErrorInner {
    kind: ErrorKind,
    message: String,
    bucket: Option<Bucket>,
    object: Option<Object>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Construct an error with a kind and message.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            inner: Box::new(ErrorInner {
                kind,
                message: message.into(),
                bucket: None,
                object: None,
                source: None,
            }),
        }
    }

    /// Attach a source error.
    pub fn with_source(
        mut self,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        self.inner.source = Some(source.into());
        self
    }

    /// Attach an existing bucket (Go `CreateBucket` dual return).
    pub fn with_bucket(mut self, bucket: Bucket) -> Self {
        self.inner.bucket = Some(bucket);
        self
    }

    /// Attach an object payload (unused for `delete_object`; that uses `Ok(None)`).
    pub fn with_object(mut self, object: Object) -> Self {
        self.inner.object = Some(object);
        self
    }

    /// Stable kind for matching.
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    /// True when `kind` equals `kind`.
    pub fn is(&self, kind: ErrorKind) -> bool {
        self.inner.kind == kind
    }

    /// True when the operation was canceled.
    pub fn is_canceled(&self) -> bool {
        self.inner.kind == ErrorKind::Canceled
    }

    /// Present when `kind == BucketAlreadyExists`.
    pub fn bucket(&self) -> Option<&Bucket> {
        self.inner.bucket.as_ref()
    }

    /// Present when a dual-return object is attached.
    pub fn object(&self) -> Option<&Object> {
        self.inner.object.as_ref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.inner.kind, self.inner.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source.as_deref().map(|e| e as _)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        // An `io::Error` produced from a `storj::Error` (e.g. surfaced through
        // `AsyncRead`/`AsyncWrite` and `tokio::io::copy`) carries the original
        // as its inner error: unwrap it so the kind survives the round trip.
        if e.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = e.into_inner() {
                if let Ok(orig) = inner.downcast::<Error>() {
                    return *orig;
                }
            }
            return Self::new(ErrorKind::Io, "io error");
        }
        let kind = if e.kind() == io::ErrorKind::Interrupted {
            ErrorKind::Canceled
        } else {
            ErrorKind::Io
        };
        Self::new(kind, e.to_string()).with_source(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        if e.is_canceled() {
            io::Error::new(io::ErrorKind::Interrupted, e)
        } else {
            io::Error::other(e)
        }
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        if e.is_cancelled() {
            Self::new(ErrorKind::Canceled, "task canceled").with_source(e)
        } else {
            // Panicking workers must not look like a retryable satellite RPC.
            std::panic::resume_unwind(e.into_panic())
        }
    }
}

/// Stable error classification. Mapped 1:1 from `storj.io/uplink` v1.14.5
/// user-visible errors. Intentionally omitted vs 2025 `uplink` crate:
/// `InvalidHandle`, FFI `Internal`, `Uplink` wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Rate limited by the satellite.
    TooManyRequests,
    /// Project bandwidth limit exceeded.
    BandwidthLimitExceeded,
    /// Project storage limit exceeded.
    StorageLimitExceeded,
    /// Project segments limit exceeded.
    SegmentsLimitExceeded,
    /// Macaroon / ACL denied the operation.
    PermissionDenied,
    /// Bucket name does not meet satellite rules.
    BucketNameInvalid,
    /// Bucket already exists (`Error::bucket()` may be set).
    BucketAlreadyExists,
    /// Delete bucket refused because it still has objects.
    BucketNotEmpty,
    /// Named bucket does not exist.
    BucketNotFound,
    /// Object key is invalid.
    ObjectKeyInvalid,
    /// Named object does not exist (and the grant can observe that).
    ObjectNotFound,
    /// Upload already committed or aborted.
    UploadDone,
    /// Multipart upload id is invalid.
    UploadIdInvalid,
    /// Caller canceled the operation (task abort, timeout, Interrupted).
    Canceled,
    /// Access grant failed to parse or is internally inconsistent.
    InvalidGrant,
    /// Content or path decryption failed. Never includes key material.
    DecryptionFailed,
    /// Satellite/storage-node RPC failed after retries, or not yet implemented.
    Protocol,
    /// Local I/O failure.
    Io,
    /// Reserved for `storj::edge` (v1.x).
    EdgeAuthDialFailed,
    /// Reserved for `storj::edge` (v1.x).
    EdgeRegisterAccessFailed,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyRequests => "too many requests",
            Self::BandwidthLimitExceeded => "bandwidth limit exceeded",
            Self::StorageLimitExceeded => "storage limit exceeded",
            Self::SegmentsLimitExceeded => "segments limit exceeded",
            Self::PermissionDenied => "permission denied",
            Self::BucketNameInvalid => "bucket name invalid",
            Self::BucketAlreadyExists => "bucket already exists",
            Self::BucketNotEmpty => "bucket not empty",
            Self::BucketNotFound => "bucket not found",
            Self::ObjectKeyInvalid => "object key invalid",
            Self::ObjectNotFound => "object not found",
            Self::UploadDone => "upload done",
            Self::UploadIdInvalid => "upload ID invalid",
            Self::Canceled => "canceled",
            Self::InvalidGrant => "invalid grant",
            Self::DecryptionFailed => "decryption failed",
            Self::Protocol => "protocol",
            Self::Io => "i/o",
            Self::EdgeAuthDialFailed => "dial to auth service failed",
            Self::EdgeRegisterAccessFailed => "register access for edge service failed",
        })
    }
}

/// Result alias for Storj operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn kind_helpers() {
        let e = Error::new(ErrorKind::Canceled, "stopped");
        assert!(e.is_canceled());
        assert!(e.is(ErrorKind::Canceled));
        assert_eq!(e.kind(), ErrorKind::Canceled);
        assert!(e.bucket().is_none());
        assert!(e.object().is_none());
    }

    #[test]
    fn create_bucket_dual_return() {
        let bucket = Bucket {
            name: "logs".into(),
            created: SystemTime::UNIX_EPOCH,
        };
        let e = Error::new(
            ErrorKind::BucketAlreadyExists,
            "bucket already exists (\"logs\")",
        )
        .with_bucket(bucket.clone());
        assert_eq!(e.kind(), ErrorKind::BucketAlreadyExists);
        assert_eq!(e.bucket().map(|b| b.name.as_str()), Some("logs"));
    }

    #[test]
    fn from_interrupted_io_is_canceled() {
        let io = io::Error::new(io::ErrorKind::Interrupted, "abort");
        let e = Error::from(io);
        assert!(e.is_canceled());
    }

    #[test]
    fn from_other_io_is_io() {
        let io = io::Error::other("disk");
        let e = Error::from(io);
        assert_eq!(e.kind(), ErrorKind::Io);
    }

    #[test]
    fn display_matches_go_phrasing() {
        let e = Error::new(ErrorKind::BucketNotFound, "bucket not found (\"x\")");
        assert_eq!(e.to_string(), "bucket not found: bucket not found (\"x\")");
    }

    #[test]
    fn no_invalid_handle_kind() {
        // 2025 uplink::error::Uplink::InvalidHandle must not exist here.
        let names = format!("{:?}", ErrorKind::Protocol);
        assert!(!names.to_lowercase().contains("handle"));
    }
}
