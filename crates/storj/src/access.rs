//! Access grants: parse, serialize, share (restrict), and encryption-key override.

use std::sync::Arc;

use crate::encryption::EncryptionKey;
use crate::error::{Error, ErrorKind, Result};
use crate::types::{Config, require_encryption_prefix};

/// Parsed access grant. Cheap to clone (`Arc` internally).
/// 2025 name: `uplink::access::Grant`.
#[derive(Clone)]
pub struct Access {
    inner: Arc<storj_access::Grant>,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access")
            .field("satellite_address", &self.satellite_address())
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl Access {
    /// Parse a serialized grant (`base58check` protobuf Scope).
    /// 2025: `Grant::new`.
    pub fn parse(serialized: &str) -> Result<Self> {
        let grant = storj_access::Grant::parse(serialized).map_err(|e| {
            Error::new(ErrorKind::InvalidGrant, e.message().to_owned()).with_source(e)
        })?;
        Ok(Self {
            inner: Arc::new(grant),
        })
    }

    /// Serialize for storage or `Share` distribution.
    ///
    /// Unmodified grants return the original string so unknown protobuf fields
    /// are preserved. `share` / `override_encryption_key` re-encode from fields
    /// (and may drop unknown fields, same as Go).
    pub fn serialize(&self) -> Result<String> {
        self.inner
            .serialize()
            .map_err(|e| Error::new(ErrorKind::InvalidGrant, e.message().to_owned()).with_source(e))
    }

    /// Satellite NodeURL, e.g. `12EayRS2…@us1.storj.io:7777`.
    pub fn satellite_address(&self) -> &str {
        self.inner.satellite_addr()
    }

    /// Restrict permissions and (optionally) path prefixes.
    /// Intersection with existing caveats; cannot widen.
    ///
    /// `allow_lock` is mapped onto the granular Object Lock bits (Go v1.14
    /// `Share`); the deprecated coarse lock flag is not granted.
    pub fn share(&self, permission: Permission, prefixes: &[SharePrefix]) -> Result<Self> {
        let mut grant_perm = to_grant_permission(&permission);
        if permission.allow_lock {
            grant_perm.allow_put_object_retention = true;
            grant_perm.allow_get_object_retention = true;
            grant_perm.allow_put_bucket_object_lock_configuration = true;
            grant_perm.allow_get_bucket_object_lock_configuration = true;
        }
        let prefixes: Vec<storj_access::SharePrefix> = prefixes
            .iter()
            .map(|p| storj_access::SharePrefix {
                bucket: p.bucket.clone(),
                prefix: p.prefix.clone(),
            })
            .collect();
        let grant = self
            .inner
            .restrict(&grant_perm, &prefixes)
            .map_err(map_grant_err)?;
        Ok(Self {
            inner: Arc::new(grant),
        })
    }

    /// Multitenancy: replace the encryption key for `bucket/prefix/`.
    /// `prefix` must end with `/` (same as 2025 and Go).
    pub fn override_encryption_key(
        &mut self,
        bucket: &str,
        prefix: &str,
        key: &EncryptionKey,
    ) -> Result<()> {
        require_encryption_prefix(prefix)?;
        let grant = Arc::make_mut(&mut self.inner);
        grant
            .override_encryption_key(bucket, prefix, key.as_bytes())
            .map_err(map_grant_err)
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
        let parsed = storj_access::ApiKey::parse(api_key).map_err(|e| {
            Error::new(ErrorKind::InvalidGrant, e.message().to_owned()).with_source(e)
        })?;
        let node = crate::metainfo::parse_satellite_url(satellite_address)?;
        let client =
            crate::metainfo::MetainfoClient::connect(node.clone(), parsed.serialize_raw(), config)
                .await?;
        let info = client.project_info().await?;
        client.close().await;

        let passphrase = passphrase.to_owned();
        let salt = info.project_salt;
        let key = tokio::task::spawn_blocking(move || {
            crate::encryption::derive_root_key(
                passphrase.as_bytes(),
                &salt,
                b"",
                crate::constants::ARGON2_PARALLELISM_REQUEST,
            )
        })
        .await??;

        let mut default_key = [0u8; 32];
        default_key.copy_from_slice(key.as_bytes());
        Ok(Self::from_grant(storj_access::Grant::from_parts(
            node.to_string(),
            parsed.serialize_raw(),
            storj_access::EncryptionAccess {
                default_key: Some(default_key),
                default_path_cipher: storj_access::CipherSuite::AES_GCM,
                store_entries: Vec::new(),
                default_encryption_parameters: None,
            },
        )))
    }

    pub(crate) fn from_grant(grant: storj_access::Grant) -> Self {
        Self {
            inner: Arc::new(grant),
        }
    }

    pub(crate) fn api_key_raw(&self) -> &[u8] {
        self.inner.api_key()
    }

    #[cfg(test)]
    pub(crate) fn placeholder(satellite_address: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(storj_access::Grant::from_parts(
                satellite_address.into(),
                Vec::new(),
                storj_access::EncryptionAccess {
                    default_key: Some([1u8; 32]),
                    ..Default::default()
                },
            )),
        }
    }
}

fn to_grant_permission(p: &Permission) -> storj_access::Permission {
    storj_access::Permission {
        allow_download: p.allow_download,
        allow_upload: p.allow_upload,
        allow_list: p.allow_list,
        allow_delete: p.allow_delete,
        allow_lock: false,
        allow_put_object_retention: p.allow_put_object_retention,
        allow_get_object_retention: p.allow_get_object_retention,
        allow_put_object_legal_hold: p.allow_put_object_legal_hold,
        allow_get_object_legal_hold: p.allow_get_object_legal_hold,
        allow_bypass_governance_retention: p.allow_bypass_governance_retention,
        allow_put_bucket_object_lock_configuration: p.allow_put_bucket_object_lock_configuration,
        allow_get_bucket_object_lock_configuration: p.allow_get_bucket_object_lock_configuration,
        not_before: p.not_before,
        not_after: p.not_after,
        max_object_ttl: p.max_object_ttl,
    }
}

fn map_grant_err(e: storj_access::Error) -> Error {
    Error::new(ErrorKind::InvalidGrant, e.message().to_owned()).with_source(e)
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
    fn parse_garbage_is_invalid_grant() {
        let e = Access::parse("12abcNotARealGrant").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidGrant);
        assert!(!e.to_string().contains("not implemented"));
    }

    #[test]
    fn override_requires_trailing_slash() {
        let mut access = Access::placeholder("12id@us1.storj.io:7777");
        let key = EncryptionKey::from_bytes([2u8; 32]);
        let e = access
            .override_encryption_key("app", "user1", &key)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);

        access
            .override_encryption_key("app", "user1/", &key)
            .expect("trailing slash is sufficient");
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

    #[tokio::test]
    async fn request_host_only_unknown_needs_node_id() {
        let e = Access::request_with_passphrase("us1.storj.io:7777", "not-a-key", "pw")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidGrant);
        // API key is parsed first; this still fails before dial.
        assert!(
            e.to_string().contains("invalid api key")
                || e.to_string().contains("node id is required")
        );
    }

    #[tokio::test]
    async fn request_invalid_api_key() {
        let e = Access::request_with_passphrase(
            "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@127.0.0.1:1",
            "not-a-key",
            "pw",
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidGrant);
        assert!(e.to_string().contains("invalid api key"));
    }

    #[tokio::test]
    async fn request_unknown_host_reports_node_id_required() {
        let key = storj_access::ApiKey::from_parts(b"head".to_vec(), &[0x11; 32]).serialize();
        let e = Access::request_with_passphrase("us1.storj.io:7777", &key, "pw")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidGrant);
        assert!(
            e.to_string()
                .contains("node id is required in satelliteNodeURL")
        );
    }
}
