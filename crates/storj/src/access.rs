//! Access grants. Parse/serialize/share of the protobuf Scope land in later PRs.

use crate::encryption::EncryptionKey;
use crate::error::{Error, ErrorKind, Result};
use crate::types::{Config, require_encryption_prefix};

/// Parsed access grant. Cheap to clone (will be `Arc` internally).
/// 2025 name: `uplink::access::Grant`.
#[derive(Clone)]
pub struct Access {
    satellite_address: String,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access")
            .field("satellite_address", &self.satellite_address)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl Access {
    /// Parse a serialized grant (`base58check` protobuf Scope).
    /// 2025: `Grant::new`.
    pub fn parse(serialized: &str) -> Result<Self> {
        if serialized.is_empty() {
            return Err(Error::new(ErrorKind::InvalidGrant, "empty access grant"));
        }
        Err(Error::not_implemented("Access::parse"))
    }

    /// Serialize for storage or `Share` distribution.
    pub fn serialize(&self) -> Result<String> {
        Err(Error::not_implemented("Access::serialize"))
    }

    /// Satellite NodeURL, e.g. `12EayRS2…@us1.storj.io:7777`.
    pub fn satellite_address(&self) -> &str {
        &self.satellite_address
    }

    /// Restrict permissions and (optionally) path prefixes.
    /// Intersection with existing caveats; cannot widen.
    pub fn share(&self, permission: Permission, prefixes: &[SharePrefix]) -> Result<Self> {
        let _ = (permission, prefixes);
        Err(Error::not_implemented("Access::share"))
    }

    /// Multitenancy: replace the encryption key for `bucket/prefix/`.
    /// `prefix` must end with `/` (same as 2025 and Go).
    pub fn override_encryption_key(
        &mut self,
        bucket: &str,
        prefix: &str,
        key: &EncryptionKey,
    ) -> Result<()> {
        let _ = (bucket, key);
        require_encryption_prefix(prefix)?;
        Err(Error::not_implemented("Access::override_encryption_key"))
    }

    /// CPU-heavy (Argon2id t=1, m=64MiB, **p=8**). Talks to satellite `ProjectInfo`.
    pub async fn request_with_passphrase(
        satellite_address: &str,
        api_key: &str,
        passphrase: &str,
    ) -> Result<Self> {
        Self::request_with_passphrase_and_config(
            &Config::default(),
            satellite_address,
            api_key,
            passphrase,
        )
        .await
    }

    /// Same as [`Self::request_with_passphrase`] with an explicit config.
    pub async fn request_with_passphrase_and_config(
        config: &Config,
        satellite_address: &str,
        api_key: &str,
        passphrase: &str,
    ) -> Result<Self> {
        let _ = (config, satellite_address, api_key, passphrase);
        Err(Error::not_implemented("Access::request_with_passphrase"))
    }

    #[cfg(test)]
    pub(crate) fn placeholder(satellite_address: impl Into<String>) -> Self {
        Self {
            satellite_address: satellite_address.into(),
        }
    }
}

/// Unencrypted share prefix. Encryption info is derived up to the last `/`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SharePrefix {
    /// Bucket name (plaintext).
    pub bucket: String,
    /// Unencrypted object-key prefix. Empty = whole bucket.
    pub prefix: String,
}

impl SharePrefix {
    /// Whole-bucket prefix (2025 `SharePrefix::full_bucket`).
    pub fn full_bucket(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: String::new(),
        }
    }

    /// Prefix inside a bucket. Non-empty `prefix` must end with `/`.
    pub fn new(bucket: impl Into<String>, prefix: impl Into<String>) -> Result<Self> {
        let prefix = prefix.into();
        crate::types::require_trailing_slash_if_nonempty("prefix", &prefix)?;
        Ok(Self {
            bucket: bucket.into(),
            prefix,
        })
    }
}

/// Permission bits for `Access::share`.
///
/// `full()` matches Go `FullPermission()`: four CRUD allows **plus** all
/// granular Object Lock / legal-hold / bypass-governance bits. Does **not**
/// set deprecated `allow_lock` (Go same). Does **not** grant bucket
/// notification configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Permission {
    /// Download object content and metadata.
    pub allow_download: bool,
    /// Create buckets and upload objects.
    pub allow_upload: bool,
    /// List buckets / objects.
    pub allow_list: bool,
    /// Delete buckets / objects.
    pub allow_delete: bool,
    /// Deprecated in Go; `share()` maps this onto the granular lock bits.
    pub allow_lock: bool,
    /// Put object retention.
    pub allow_put_object_retention: bool,
    /// Get object retention.
    pub allow_get_object_retention: bool,
    /// Put object legal hold.
    pub allow_put_object_legal_hold: bool,
    /// Get object legal hold.
    pub allow_get_object_legal_hold: bool,
    /// Bypass governance-mode retention (still requires the request to ask).
    pub allow_bypass_governance_retention: bool,
    /// Put bucket Object Lock configuration.
    pub allow_put_bucket_object_lock_configuration: bool,
    /// Get bucket Object Lock configuration.
    pub allow_get_bucket_object_lock_configuration: bool,
    /// Grant not valid before this time.
    pub not_before: Option<std::time::SystemTime>,
    /// Grant not valid after this time.
    pub not_after: Option<std::time::SystemTime>,
    /// Max TTL for newly uploaded objects.
    pub max_object_ttl: Option<std::time::Duration>,
}

impl Permission {
    /// Matches Go `FullPermission()`.
    pub fn full() -> Self {
        Self {
            allow_download: true,
            allow_upload: true,
            allow_list: true,
            allow_delete: true,
            allow_lock: false,
            allow_put_object_retention: true,
            allow_get_object_retention: true,
            allow_put_object_legal_hold: true,
            allow_get_object_legal_hold: true,
            allow_bypass_governance_retention: true,
            allow_put_bucket_object_lock_configuration: true,
            allow_get_bucket_object_lock_configuration: true,
            not_before: None,
            not_after: None,
            max_object_ttl: None,
        }
    }

    /// Download + list.
    pub fn read_only() -> Self {
        Self {
            allow_download: true,
            allow_list: true,
            ..Self::default()
        }
    }

    /// Upload + delete.
    pub fn write_only() -> Self {
        Self {
            allow_upload: true,
            allow_delete: true,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_is_invalid_grant() {
        let e = Access::parse("").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidGrant);
    }

    #[test]
    fn parse_nonempty_not_implemented() {
        let e = Access::parse("12abcNotARealGrant").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        assert!(e.to_string().contains("not implemented"));
    }

    #[test]
    fn override_requires_trailing_slash() {
        let mut access = Access::placeholder("12id@us1.storj.io:7777");
        let key = EncryptionKey::from_bytes([2u8; 32]);
        let e = access
            .override_encryption_key("app", "user1", &key)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);

        let e = access
            .override_encryption_key("app", "user1/", &key)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol); // slash ok; impl pending
    }

    #[test]
    fn share_prefix_constructor() {
        assert!(SharePrefix::new("b", "p").is_err());
        assert!(SharePrefix::new("b", "p/").is_ok());
        assert_eq!(SharePrefix::full_bucket("b").prefix, "");
    }

    #[test]
    fn full_permission_matches_go() {
        let p = Permission::full();
        assert!(p.allow_download && p.allow_upload && p.allow_list && p.allow_delete);
        assert!(
            !p.allow_lock,
            "Go FullPermission does not set deprecated AllowLock"
        );
        assert!(p.allow_put_object_retention);
        assert!(p.allow_get_object_retention);
        assert!(p.allow_put_object_legal_hold);
        assert!(p.allow_get_object_legal_hold);
        assert!(p.allow_bypass_governance_retention);
        assert!(p.allow_put_bucket_object_lock_configuration);
        assert!(p.allow_get_bucket_object_lock_configuration);
    }

    #[test]
    fn read_only_and_write_only() {
        let r = Permission::read_only();
        assert!(r.allow_download && r.allow_list);
        assert!(!r.allow_upload && !r.allow_delete);
        assert!(!r.allow_put_object_retention);

        let w = Permission::write_only();
        assert!(w.allow_upload && w.allow_delete);
        assert!(!w.allow_download && !w.allow_list);
    }

    #[test]
    fn debug_redacts_api_key() {
        let a = Access::placeholder("sat");
        let s = format!("{a:?}");
        assert!(s.contains("REDACTED"));
    }
}
