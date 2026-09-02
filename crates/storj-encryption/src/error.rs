//! Encryption errors. Mapped to `storj::ErrorKind` by the facade.

use std::fmt;

/// Encryption/decryption failure.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

/// Stable classification for encryption failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// No store entry (or default key) to encrypt from.
    MissingEncryptionBase,
    /// No store entry (or default key) to decrypt from.
    MissingDecryptionBase,
    /// Path or content decryption failed. Never includes key material.
    DecryptionFailed,
    /// Unsupported cipher or invalid parameters.
    InvalidConfig,
    /// Conflicting encrypted/unencrypted path parts in the store.
    Conflict,
    /// KDF / primitive failure (argon2 params, etc.).
    Protocol,
}

impl Error {
    /// Construct an error with a kind and message.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Stable kind for matching.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Human-readable message without the kind prefix.
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn missing_encryption_base(bucket: &str, path: &[u8]) -> Self {
        Self::new(
            ErrorKind::MissingEncryptionBase,
            format!("{bucket:?}/{}", path_debug(path)),
        )
    }

    pub(crate) fn missing_decryption_base(bucket: &str, path: &[u8]) -> Self {
        Self::new(
            ErrorKind::MissingDecryptionBase,
            format!("{bucket:?}/{}", path_debug(path)),
        )
    }
}

fn path_debug(path: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(path))
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingEncryptionBase => "missing encryption base",
            Self::MissingDecryptionBase => "missing decryption base",
            Self::DecryptionFailed => "decryption failed, check encryption key",
            Self::InvalidConfig => "invalid encryption configuration",
            Self::Conflict => "conflicting encrypted parts for unencrypted path",
            Self::Protocol => "encryption",
        })
    }
}

/// Result alias for encryption operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;
