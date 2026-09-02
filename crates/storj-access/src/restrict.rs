//! `Grant::restrict` and `override_encryption_key` (Go `grant.Restrict` / uplink `OverrideEncryptionKey`).

use storj_encryption::{
    CipherSuite as EncCipher, Key, Store, decrypt_path, derive_path_key, encrypt_path,
};

use crate::grant::{CipherSuite, EncryptionAccess, Error, Grant, StoreEntry};
use crate::macaroon::{ApiKey, Caveat, CaveatPath, Permission};

/// Unencrypted share prefix (Go `grant.SharePrefix`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SharePrefix {
    /// Bucket name (plaintext).
    pub bucket: String,
    /// Unencrypted object-key prefix. Empty = whole bucket.
    ///
    /// A trailing `/` is stripped before path encryption (Go `strings.TrimSuffix`).
    pub prefix: String,
}

impl Grant {
    /// Restrict permissions and (optionally) path prefixes.
    ///
    /// Intersection with existing caveats; cannot widen. Prefixes derive child
    /// encryption keys and drop ancestor keys (Go `EncryptionAccess.LimitTo`).
    pub fn restrict(
        &self,
        permission: &Permission,
        prefixes: &[SharePrefix],
    ) -> Result<Self, Error> {
        validate_permission(permission)?;

        let store = store_from_enc(self.enc_access())?;
        let mut caveat = Caveat::from_permission(permission);
        caveat.nonce = random_nonce()?;

        for prefix in prefixes {
            // One trailing slash only (Go `strings.TrimSuffix(prefix, "/")`).
            let unenc = prefix.prefix.strip_suffix('/').unwrap_or(&prefix.prefix);
            let enc_path = encrypt_path(&prefix.bucket, unenc, &store).map_err(map_enc)?;
            caveat.allowed_paths.push(CaveatPath {
                bucket: prefix.bucket.as_bytes().to_vec(),
                encrypted_path_prefix: enc_path,
            });
        }

        let restricted = ApiKey::parse_raw(self.api_key())?.restrict(&caveat);
        let enc_access = limit_to(self.enc_access(), &restricted)?;

        Ok(Self::from_parts(
            self.satellite_addr(),
            restricted.serialize_raw(),
            enc_access,
        ))
    }

    /// Replace the encryption key for `bucket/prefix/`.
    ///
    /// `prefix` must end with `/` (Go `OverrideEncryptionKey`).
    pub fn override_encryption_key(
        &mut self,
        bucket: &str,
        prefix: &str,
        key: &[u8; 32],
    ) -> Result<(), Error> {
        if !prefix.ends_with('/') {
            return Err(Error::new("prefix must end with slash"));
        }
        let unenc = prefix.strip_suffix('/').unwrap_or(prefix);

        let mut store = store_from_enc(self.enc_access())?;
        let enc_path = encrypt_path(bucket, unenc, &store).map_err(map_enc)?;
        store
            .add(bucket, unenc.as_bytes(), &enc_path, Key::from_bytes(*key))
            .map_err(map_enc)?;

        *self.enc_access_mut() = enc_from_store(&store);
        Ok(())
    }
}

fn validate_permission(permission: &Permission) -> Result<(), Error> {
    if permission.is_empty() {
        return Err(Error::new("permission is empty"));
    }
    if let (Some(not_before), Some(not_after)) = (permission.not_before, permission.not_after)
        && not_after < not_before
    {
        return Err(Error::new("invalid time range"));
    }
    if permission.max_object_ttl == Some(std::time::Duration::ZERO) {
        return Err(Error::new("non-positive ttl period"));
    }
    Ok(())
}

fn random_nonce() -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; 4];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| Error::new(format!("unable to generate nonce: {e}")))?;
    Ok(nonce.to_vec())
}

fn map_enc(err: storj_encryption::Error) -> Error {
    Error::new(err.to_string())
}

pub(crate) fn store_from_enc(enc: &EncryptionAccess) -> Result<Store, Error> {
    let mut store = Store::new();
    if let Some(key) = enc.default_key {
        store.set_default_key(Key::from_bytes(key));
    }
    store.set_default_path_cipher(EncCipher(enc.default_path_cipher.0));
    for entry in &enc.store_entries {
        // Bucket names are UTF-8 on the satellite; never rewrite bytes.
        let bucket = std::str::from_utf8(&entry.bucket)
            .map_err(|_| Error::new("encryption access entry bucket is not utf-8"))?;
        store
            .add_with_cipher(
                bucket,
                &entry.unencrypted_path,
                &entry.encrypted_path,
                Key::from_bytes(entry.key),
                EncCipher(entry.path_cipher.0),
            )
            .map_err(map_enc)?;
    }
    Ok(store)
}

fn enc_from_store(store: &Store) -> EncryptionAccess {
    let mut store_entries = Vec::new();
    let _ = store.iterate_with_cipher(|bucket, unenc, enc, key, cipher| {
        store_entries.push(StoreEntry {
            bucket: bucket.as_bytes().to_vec(),
            unencrypted_path: unenc.to_vec(),
            encrypted_path: enc.to_vec(),
            key: key.to_bytes(),
            path_cipher: CipherSuite(cipher.0),
            encryption_parameters: None,
        });
        Ok(())
    });
    EncryptionAccess {
        default_key: store.default_key().map(Key::to_bytes),
        default_path_cipher: CipherSuite(store.default_path_cipher().0),
        store_entries,
        default_encryption_parameters: None,
    }
}

impl EncryptionAccess {
    /// Keep only encryption bases allowed by the API key's path caveats.
    ///
    /// Go `EncryptionAccess.LimitTo`: a path-restricted API key must not
    /// serialize the project root key.
    pub fn limit_to(&self, api_key: &ApiKey) -> Result<Self, Error> {
        limit_to(self, api_key)
    }
}

/// Keep only encryption bases allowed by the API key's path caveats (Go `LimitTo`).
fn limit_to(enc: &EncryptionAccess, api_key: &ApiKey) -> Result<EncryptionAccess, Error> {
    let (prefixes, restricted) = collapse_prefixes(api_key)?;
    if !restricted {
        return Ok(enc.clone());
    }

    let src = store_from_enc(enc)?;
    let mut store = Store::new();
    store.set_default_path_cipher(src.default_path_cipher());

    for prefix in prefixes {
        // A non-UTF-8 bucket cannot match any store entry: skip, don't rewrite.
        let Ok(bucket) = std::str::from_utf8(&prefix.bucket) else {
            continue;
        };
        let enc_path = prefix.encrypted_path_prefix;
        let Ok(unenc) = decrypt_path(bucket, &enc_path, &src) else {
            continue;
        };
        let Ok(key) = derive_path_key(bucket, &unenc, &src) else {
            continue;
        };
        let Some(base) = src.lookup_encrypted(bucket, &enc_path).base else {
            continue;
        };
        let _ = store.add_with_cipher(bucket, &unenc, &enc_path, key, base.path_cipher);
    }

    Ok(enc_from_store(&store))
}

/// Collapse stacked path caveats into prefixes allowed by every group (Go `collapsePrefixes`).
fn collapse_prefixes(api_key: &ApiKey) -> Result<(Vec<CaveatPath>, bool), Error> {
    let mut groups: Vec<Vec<CaveatPath>> = Vec::new();
    let mut prefixes: Vec<CaveatPath> = Vec::new();
    for cav_data in api_key.macaroon().caveats() {
        let cav = Caveat::decode(cav_data)?;
        if !cav.allowed_paths.is_empty() {
            groups.push(cav.allowed_paths.clone());
            prefixes.extend(cav.allowed_paths);
        }
    }
    if groups.is_empty() || prefixes.is_empty() {
        return Ok((Vec::new(), false));
    }

    prefixes.retain(|cav| {
        groups.iter().all(|group| {
            group.iter().any(|other| {
                cav.bucket == other.bucket
                    && cav
                        .encrypted_path_prefix
                        .starts_with(&other.encrypted_path_prefix)
            })
        })
    });
    Ok((prefixes, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macaroon::ApiKey;
    use std::time::{Duration, UNIX_EPOCH};

    const HEAD: [u8; 32] = [0x11; 32];
    const SECRET: [u8; 32] = [0x22; 32];

    fn sample_grant() -> Grant {
        Grant::from_parts(
            "12edKaxTestSatelliteId@127.0.0.1:7777",
            ApiKey::from_parts(HEAD.to_vec(), &SECRET).serialize_raw(),
            EncryptionAccess {
                default_key: Some([0x33; 32]),
                default_path_cipher: CipherSuite::AES_GCM,
                store_entries: vec![StoreEntry {
                    bucket: b"app".to_vec(),
                    unencrypted_path: b"user1".to_vec(),
                    encrypted_path: b"enc-user1".to_vec(),
                    key: [0x44; 32],
                    path_cipher: CipherSuite::AES_GCM,
                    encryption_parameters: None,
                }],
                default_encryption_parameters: None,
            },
        )
    }

    fn caveats(grant: &Grant) -> Vec<Caveat> {
        let key = ApiKey::parse_raw(grant.api_key()).unwrap();
        key.macaroon()
            .caveats()
            .iter()
            .map(|c| Caveat::decode(c).unwrap())
            .collect()
    }

    #[test]
    fn empty_permission_is_error() {
        let g = sample_grant();
        let e = g.restrict(&Permission::default(), &[]).unwrap_err();
        assert_eq!(e.message(), "permission is empty");
    }

    #[test]
    fn invalid_time_range_is_error() {
        let g = sample_grant();
        let p = Permission {
            allow_download: true,
            not_before: Some(UNIX_EPOCH + Duration::from_secs(20)),
            not_after: Some(UNIX_EPOCH + Duration::from_secs(10)),
            ..Permission::default()
        };
        assert_eq!(
            g.restrict(&p, &[]).unwrap_err().message(),
            "invalid time range"
        );
    }

    #[test]
    fn zero_ttl_is_error() {
        let g = sample_grant();
        let p = Permission {
            allow_upload: true,
            max_object_ttl: Some(Duration::ZERO),
            ..Permission::default()
        };
        assert_eq!(
            g.restrict(&p, &[]).unwrap_err().message(),
            "non-positive ttl period"
        );
    }

    #[test]
    fn restrict_without_prefixes_keeps_default_key() {
        let g = sample_grant();
        let out = g.restrict(&Permission::read_only(), &[]).unwrap();
        assert_eq!(out.enc_access().default_key, Some([0x33; 32]));
        assert_eq!(out.enc_access().store_entries.len(), 1);
        let cavs = caveats(&out);
        assert_eq!(cavs.len(), 1);
        assert!(cavs[0].disallow_writes && cavs[0].disallow_deletes);
        assert!(!cavs[0].disallow_reads && !cavs[0].disallow_lists);
        assert_eq!(cavs[0].nonce.len(), 4);
    }

    #[test]
    fn restrict_prefix_drops_default_key() {
        let g = sample_grant();
        let out = g
            .restrict(
                &Permission::read_only(),
                &[SharePrefix {
                    bucket: "app".into(),
                    prefix: "user1/".into(),
                }],
            )
            .unwrap();
        assert!(
            out.enc_access().default_key.is_none(),
            "ancestor default key must be dropped"
        );
        assert_eq!(out.enc_access().store_entries.len(), 1);
        let entry = &out.enc_access().store_entries[0];
        assert_eq!(entry.bucket, b"app");
        assert_eq!(entry.unencrypted_path, b"user1");
        assert_eq!(entry.encrypted_path, b"enc-user1");
        assert_eq!(entry.key, [0x44; 32]);
        let cavs = caveats(&out);
        assert_eq!(cavs[0].allowed_paths.len(), 1);
        assert_eq!(cavs[0].allowed_paths[0].bucket, b"app");
        assert_eq!(cavs[0].allowed_paths[0].encrypted_path_prefix, b"enc-user1");
    }

    #[test]
    fn chained_restrict_does_not_widen() {
        let g = sample_grant();
        let read = g.restrict(&Permission::read_only(), &[]).unwrap();
        let widened = read.restrict(&Permission::full(), &[]).unwrap();
        let cavs = caveats(&widened);
        assert_eq!(cavs.len(), 2);
        assert!(
            cavs.iter().any(|c| c.disallow_writes),
            "parent disallow_writes must still apply"
        );
        assert!(!cavs[1].disallow_writes, "new caveat may allow writes");
        assert!(cavs[1].disallow_locks);
        assert!(!cavs[1].disallow_put_retention);
    }

    #[test]
    fn override_requires_slash_and_replaces_key() {
        let mut g = sample_grant();
        assert_eq!(
            g.override_encryption_key("app", "user1", &[0x55; 32])
                .unwrap_err()
                .message(),
            "prefix must end with slash"
        );
        g.override_encryption_key("app", "user1/", &[0x55; 32])
            .unwrap();
        let entry = g
            .enc_access()
            .store_entries
            .iter()
            .find(|e| e.unencrypted_path == b"user1")
            .unwrap();
        assert_eq!(entry.key, [0x55; 32]);
        assert_eq!(entry.encrypted_path, b"enc-user1");
        assert_eq!(g.enc_access().default_key, Some([0x33; 32]));
    }

    #[test]
    fn limit_to_unrestricted_key_keeps_default_key() {
        let enc = EncryptionAccess {
            default_key: Some([0x33; 32]),
            default_path_cipher: CipherSuite::AES_GCM,
            ..Default::default()
        };
        let api = ApiKey::from_parts(HEAD.to_vec(), &SECRET);
        let limited = enc.limit_to(&api).unwrap();
        assert_eq!(limited.default_key, Some([0x33; 32]));
        assert!(limited.store_entries.is_empty());
    }

    #[test]
    fn limit_to_path_restricted_key_drops_default_key() {
        let enc = EncryptionAccess {
            default_key: Some([0x33; 32]),
            default_path_cipher: CipherSuite::AES_GCM,
            ..Default::default()
        };
        let store = store_from_enc(&enc).unwrap();
        let enc_path = encrypt_path("app", "user1", &store).unwrap();
        let api = ApiKey::from_parts(HEAD.to_vec(), &SECRET).restrict(&Caveat {
            allowed_paths: vec![CaveatPath {
                bucket: b"app".to_vec(),
                encrypted_path_prefix: enc_path,
            }],
            nonce: vec![1, 2, 3, 4],
            ..Caveat::default()
        });
        let limited = enc.limit_to(&api).unwrap();
        assert!(
            limited.default_key.is_none(),
            "path-restricted API key must not serialize the project root key"
        );
        assert_eq!(limited.store_entries.len(), 1);
        assert_eq!(limited.store_entries[0].bucket, b"app");
        assert_eq!(limited.store_entries[0].unencrypted_path, b"user1");
    }

    #[test]
    fn equal_time_bounds_are_valid() {
        let g = sample_grant();
        let t = UNIX_EPOCH + Duration::from_secs(50);
        let p = Permission {
            allow_download: true,
            not_before: Some(t),
            not_after: Some(t),
            ..Permission::default()
        };
        assert!(g.restrict(&p, &[]).is_ok());
    }
}
