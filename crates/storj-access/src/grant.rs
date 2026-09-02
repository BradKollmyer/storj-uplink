//! Parsed access grant (Scope protobuf + Base58Check).

use std::fmt;

use prost::Message;

use crate::base58::{GRANT_VERSION, check_decode, check_encode};
use crate::pb;

/// Parse/serialize failure. Mapped to `storj::ErrorKind::InvalidGrant` by the facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    message: String,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Human-readable message (Go `ParseAccess` phrasing where it applies).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Path/content cipher identifier. Unknown values are preserved.
///
/// Matches `encryption.CipherSuite` / `storj.CipherSuite`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CipherSuite(pub i32);

impl CipherSuite {
    /// Proto zero value. `ParseAccess` rewrites the *default* path cipher to [`Self::AES_GCM`].
    pub const UNSPECIFIED: Self = Self(0);
    /// No encryption (`ENC_NULL`).
    pub const NULL: Self = Self(1);
    /// AES-GCM (`ENC_AESGCM`). Default path cipher for old grants.
    pub const AES_GCM: Self = Self(2);
    /// NaCl secretbox (`ENC_SECRETBOX`).
    pub const SECRET_BOX: Self = Self(3);
}

/// Optional content-encryption parameters (proto field 4 / store-entry field 6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionParameters {
    /// Cipher for content blocks.
    pub cipher_suite: CipherSuite,
    /// Block size in bytes.
    pub block_size: i64,
}

/// One `(bucket, path)` encryption-store mapping.
#[derive(Clone, Eq, PartialEq)]
pub struct StoreEntry {
    /// Bucket name bytes.
    pub bucket: Vec<u8>,
    /// Unencrypted path bytes.
    pub unencrypted_path: Vec<u8>,
    /// Encrypted path bytes.
    pub encrypted_path: Vec<u8>,
    /// 32-byte path key.
    pub key: [u8; 32],
    /// Cipher for this path.
    pub path_cipher: CipherSuite,
    /// Present on parse if the proto had field 6; omitted on serialize-from-fields.
    pub encryption_parameters: Option<EncryptionParameters>,
}

impl fmt::Debug for StoreEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreEntry")
            .field("bucket", &String::from_utf8_lossy(&self.bucket))
            .field(
                "unencrypted_path",
                &String::from_utf8_lossy(&self.unencrypted_path),
            )
            .field("key", &"[REDACTED]")
            .field("path_cipher", &self.path_cipher)
            .finish()
    }
}

/// Hierarchical encryption access (proto `EncryptionAccess`).
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptionAccess {
    /// 32-byte default/root key, if the grant has one.
    pub default_key: Option<[u8; 32]>,
    /// Default path cipher. Unspecified is rewritten to [`CipherSuite::AES_GCM`] on parse.
    pub default_path_cipher: CipherSuite,
    /// Explicit store entries (restricted grants).
    pub store_entries: Vec<StoreEntry>,
    /// Present on parse if the proto had field 4; omitted on serialize-from-fields.
    pub default_encryption_parameters: Option<EncryptionParameters>,
}

impl Default for EncryptionAccess {
    fn default() -> Self {
        Self {
            default_key: None,
            default_path_cipher: CipherSuite::AES_GCM,
            store_entries: Vec::new(),
            default_encryption_parameters: None,
        }
    }
}

impl fmt::Debug for EncryptionAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionAccess")
            .field(
                "default_key",
                &self.default_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("default_path_cipher", &self.default_path_cipher)
            .field("store_entries", &self.store_entries)
            .finish()
    }
}

/// Parsed access grant: satellite URL, raw API key, encryption store.
///
/// `parse` keeps the original serialized string; [`Self::serialize`] returns it
/// until [`Self::mark_mutated`] (share / override) forces a re-encode.
#[derive(Clone)]
pub struct Grant {
    satellite_addr: String,
    api_key: Vec<u8>,
    enc_access: EncryptionAccess,
    original: Option<String>,
}

impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant")
            .field("satellite_addr", &self.satellite_addr)
            .field("api_key", &"[REDACTED]")
            .field("enc_access", &self.enc_access)
            .finish()
    }
}

impl Grant {
    /// Parse a Base58Check (version 0) protobuf `Scope`.
    pub fn parse(serialized: &str) -> Result<Self, Error> {
        if serialized.is_empty() {
            return Err(Error::new("empty access grant"));
        }

        let (data, version) =
            check_decode(serialized).map_err(|_| Error::new("invalid access grant format"))?;
        if version != GRANT_VERSION {
            return Err(Error::new("invalid access grant format"));
        }

        let scope = pb::Scope::decode(data.as_slice())
            .map_err(|e| Error::new(format!("unable to unmarshal access grant: {e}")))?;

        if scope.satellite_addr.is_empty() {
            return Err(Error::new("access grant is missing satellite address"));
        }
        if scope.api_key.is_empty() {
            return Err(Error::new("access grant is missing api key"));
        }
        let Some(enc_pb) = scope.encryption_access else {
            return Err(Error::new("access grant is missing encryption access"));
        };

        let enc_access = EncryptionAccess::from_proto(enc_pb).map_err(|e| {
            Error::new(format!("access grant has malformed encryption access: {e}"))
        })?;

        Ok(Self {
            satellite_addr: scope.satellite_addr,
            api_key: scope.api_key,
            enc_access,
            original: Some(serialized.to_owned()),
        })
    }

    /// Build from parts. `serialize` encodes from fields (no original string).
    pub fn from_parts(
        satellite_addr: impl Into<String>,
        api_key: Vec<u8>,
        enc_access: EncryptionAccess,
    ) -> Self {
        Self {
            satellite_addr: satellite_addr.into(),
            api_key,
            enc_access,
            original: None,
        }
    }

    /// Satellite NodeURL string from the Scope.
    pub fn satellite_addr(&self) -> &str {
        &self.satellite_addr
    }

    /// Raw macaroon bytes (not Base58).
    pub fn api_key(&self) -> &[u8] {
        &self.api_key
    }

    /// Encryption store parsed from the Scope.
    pub fn enc_access(&self) -> &EncryptionAccess {
        &self.enc_access
    }

    /// Mutable encryption store; drops the cached original serialization.
    pub fn enc_access_mut(&mut self) -> &mut EncryptionAccess {
        self.mark_mutated();
        &mut self.enc_access
    }

    /// Mutable raw API key; drops the cached original serialization.
    pub fn api_key_mut(&mut self) -> &mut Vec<u8> {
        self.mark_mutated();
        &mut self.api_key
    }

    /// Drop the cached original so the next [`Self::serialize`] re-encodes.
    pub fn mark_mutated(&mut self) {
        self.original = None;
    }

    /// Serialize. Unmodified parsed grants return the original string.
    pub fn serialize(&self) -> Result<String, Error> {
        if let Some(original) = &self.original {
            return Ok(original.clone());
        }
        self.serialize_from_fields()
    }

    /// Encode Scope + Base58Check from in-memory fields (Go `Serialize`).
    ///
    /// EncryptionAccess fields 1–3 only, matching Go `toProto`.
    pub fn serialize_from_fields(&self) -> Result<String, Error> {
        if self.satellite_addr.is_empty() {
            return Err(Error::new("access grant is missing satellite address"));
        }
        if self.api_key.is_empty() {
            return Err(Error::new("access grant is missing api key"));
        }

        let scope = pb::Scope {
            satellite_addr: self.satellite_addr.clone(),
            api_key: self.api_key.clone(),
            encryption_access: Some(self.enc_access.to_proto()),
        };
        let data = scope.encode_to_vec();
        Ok(check_encode(&data, GRANT_VERSION))
    }
}

impl EncryptionAccess {
    fn from_proto(p: pb::EncryptionAccess) -> Result<Self, Error> {
        let default_key = if p.default_key.is_empty() {
            None
        } else {
            Some(key32(
                &p.default_key,
                "invalid default key in encryption access",
            )?)
        };

        let default_path_cipher = if p.default_path_cipher == pb::CipherSuite::EncUnspecified as i32
        {
            CipherSuite::AES_GCM
        } else {
            CipherSuite(p.default_path_cipher)
        };

        let mut store_entries = Vec::with_capacity(p.store_entries.len());
        for entry in p.store_entries {
            store_entries.push(StoreEntry::from_proto(entry)?);
        }

        Ok(Self {
            default_key,
            default_path_cipher,
            store_entries,
            default_encryption_parameters: p.default_encryption_parameters.map(Into::into),
        })
    }

    fn to_proto(&self) -> pb::EncryptionAccess {
        pb::EncryptionAccess {
            default_key: self.default_key.map(|k| k.to_vec()).unwrap_or_default(),
            store_entries: self
                .store_entries
                .iter()
                .map(StoreEntry::to_proto)
                .collect(),
            default_path_cipher: self.default_path_cipher.0,
            // Go `toProto` writes only fields 1–3.
            default_encryption_parameters: None,
        }
    }
}

impl StoreEntry {
    fn from_proto(e: pb::StoreEntry) -> Result<Self, Error> {
        Ok(Self {
            bucket: e.bucket,
            unencrypted_path: e.unencrypted_path,
            encrypted_path: e.encrypted_path,
            key: key32(&e.key, "invalid key in encryption access entry")?,
            path_cipher: CipherSuite(e.path_cipher),
            encryption_parameters: e.encryption_parameters.map(Into::into),
        })
    }

    fn to_proto(&self) -> pb::StoreEntry {
        pb::StoreEntry {
            bucket: self.bucket.clone(),
            unencrypted_path: self.unencrypted_path.clone(),
            encrypted_path: self.encrypted_path.clone(),
            key: self.key.to_vec(),
            path_cipher: self.path_cipher.0,
            encryption_parameters: None,
        }
    }
}

impl From<pb::EncryptionParameters> for EncryptionParameters {
    fn from(p: pb::EncryptionParameters) -> Self {
        Self {
            cipher_suite: CipherSuite(p.cipher_suite),
            block_size: p.block_size,
        }
    }
}

fn key32(bytes: &[u8], err: &str) -> Result<[u8; 32], Error> {
    <[u8; 32]>::try_from(bytes).map_err(|_| Error::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base58;

    fn sample_enc() -> EncryptionAccess {
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
        }
    }

    fn sample_grant() -> Grant {
        Grant::from_parts(
            "12edKaxTestSatelliteId@127.0.0.1:7777",
            vec![2, 0, 32, 0x11],
            sample_enc(),
        )
    }

    #[test]
    fn parse_empty() {
        let e = Grant::parse("").unwrap_err();
        assert_eq!(e.message(), "empty access grant");
    }

    #[test]
    fn parse_rejects_garbage_and_bad_checksum() {
        assert_eq!(
            Grant::parse("!!!not-base58!!!").unwrap_err().message(),
            "invalid access grant format"
        );
        assert_eq!(
            Grant::parse("12abcNotARealGrant").unwrap_err().message(),
            "invalid access grant format"
        );
    }

    #[test]
    fn parse_rejects_version_nonzero() {
        let encoded = base58::check_encode(b"Hello World", 1);
        assert_eq!(
            Grant::parse(&encoded).unwrap_err().message(),
            "invalid access grant format"
        );
    }

    #[test]
    fn parse_rejects_missing_fields() {
        let missing_sat = pb::Scope {
            satellite_addr: String::new(),
            api_key: vec![1, 2, 3],
            encryption_access: Some(pb::EncryptionAccess::default()),
        };
        let s = base58::check_encode(&missing_sat.encode_to_vec(), 0);
        assert_eq!(
            Grant::parse(&s).unwrap_err().message(),
            "access grant is missing satellite address"
        );

        let missing_key = pb::Scope {
            satellite_addr: "sat".into(),
            api_key: vec![],
            encryption_access: Some(pb::EncryptionAccess::default()),
        };
        let s = base58::check_encode(&missing_key.encode_to_vec(), 0);
        assert_eq!(
            Grant::parse(&s).unwrap_err().message(),
            "access grant is missing api key"
        );

        let missing_enc = pb::Scope {
            satellite_addr: "sat".into(),
            api_key: vec![1, 2, 3],
            encryption_access: None,
        };
        let s = base58::check_encode(&missing_enc.encode_to_vec(), 0);
        assert_eq!(
            Grant::parse(&s).unwrap_err().message(),
            "access grant is missing encryption access"
        );
    }

    #[test]
    fn unspecified_path_cipher_defaults_to_aesgcm() {
        let scope = pb::Scope {
            satellite_addr: "sat".into(),
            api_key: vec![1, 2, 3],
            encryption_access: Some(pb::EncryptionAccess {
                default_key: vec![0x33; 32],
                default_path_cipher: 0,
                ..Default::default()
            }),
        };
        let s = base58::check_encode(&scope.encode_to_vec(), 0);
        let g = Grant::parse(&s).unwrap();
        assert_eq!(g.enc_access().default_path_cipher, CipherSuite::AES_GCM);
    }

    #[test]
    fn rejects_short_keys() {
        let scope = pb::Scope {
            satellite_addr: "sat".into(),
            api_key: vec![1],
            encryption_access: Some(pb::EncryptionAccess {
                default_key: vec![1, 2, 3],
                default_path_cipher: 2,
                ..Default::default()
            }),
        };
        let s = base58::check_encode(&scope.encode_to_vec(), 0);
        let msg = Grant::parse(&s).unwrap_err().message().to_string();
        assert!(
            msg.contains("invalid default key"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn unmodified_serialize_is_identity() {
        let g = sample_grant();
        let serialized = g.serialize().unwrap();
        let parsed = Grant::parse(&serialized).unwrap();
        assert_eq!(parsed.serialize().unwrap(), serialized);
        assert_eq!(parsed.satellite_addr(), g.satellite_addr());
        assert_eq!(parsed.api_key(), g.api_key());
        assert_eq!(parsed.enc_access().default_key, g.enc_access().default_key);
        assert_eq!(
            parsed.enc_access().store_entries[0].key,
            g.enc_access().store_entries[0].key
        );
    }

    #[test]
    fn mutated_serialize_drops_original_and_field_4() {
        let mut scope = pb::Scope {
            satellite_addr: "sat".into(),
            api_key: vec![9, 9, 9],
            encryption_access: Some(pb::EncryptionAccess {
                default_key: vec![0x33; 32],
                default_path_cipher: 2,
                default_encryption_parameters: Some(pb::EncryptionParameters {
                    cipher_suite: 2,
                    block_size: 7424,
                }),
                ..Default::default()
            }),
        };
        let original = base58::check_encode(&scope.encode_to_vec(), 0);
        let mut g = Grant::parse(&original).unwrap();
        assert_eq!(g.serialize().unwrap(), original);
        assert!(g.enc_access().default_encryption_parameters.is_some());

        g.mark_mutated();
        let reencoded = g.serialize().unwrap();
        assert_ne!(reencoded, original);
        let again = Grant::parse(&reencoded).unwrap();
        assert!(again.enc_access().default_encryption_parameters.is_none());
        assert_eq!(again.satellite_addr(), "sat");

        // Confirm field 4 is absent on the wire.
        let (payload, _) = base58::check_decode(&reencoded).unwrap();
        scope = pb::Scope::decode(payload.as_slice()).unwrap();
        assert!(
            scope
                .encryption_access
                .unwrap()
                .default_encryption_parameters
                .is_none()
        );
    }

    #[test]
    fn serialize_from_parts_roundtrip() {
        let g = sample_grant();
        let s = g.serialize().unwrap();
        let parsed = Grant::parse(&s).unwrap();
        assert_eq!(
            parsed.satellite_addr(),
            "12edKaxTestSatelliteId@127.0.0.1:7777"
        );
        assert_eq!(
            parsed.enc_access().default_path_cipher,
            CipherSuite::AES_GCM
        );
        assert_eq!(parsed.enc_access().store_entries.len(), 1);
        assert_eq!(parsed.enc_access().store_entries[0].bucket, b"app");
    }

    #[test]
    fn debug_redacts_secrets() {
        let s = format!("{:?}", sample_grant());
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("333333"));
    }

    #[test]
    fn go_fixture_parse_and_reencode() {
        let original = include_str!("../../storj/tests/fixtures/grant_go.txt").trim();
        let mut g = Grant::parse(original).expect("parse Go Serialize fixture");
        assert_eq!(g.satellite_addr(), "12edKaxTestSatelliteId@127.0.0.1:7777");
        assert_eq!(g.enc_access().default_key, Some([0x33; 32]));
        assert_eq!(g.enc_access().default_path_cipher, CipherSuite::AES_GCM);
        assert_eq!(
            hex::encode(g.api_key()),
            "020220111111111111111111111111111111111111111111111111111111111111111100000620f0926e6c10f7df4255267f188f709515131b530a341cde14415129209b7ef42a"
        );

        g.mark_mutated();
        let reencoded = g.serialize().unwrap();
        let again = Grant::parse(&reencoded).unwrap();
        assert_eq!(again.satellite_addr(), g.satellite_addr());
        assert_eq!(again.api_key(), g.api_key());
        assert_eq!(again.enc_access().default_key, Some([0x33; 32]));
        assert_eq!(again.enc_access().store_entries.len(), 1);
        assert_eq!(again.enc_access().store_entries[0].bucket, b"app");
        assert_eq!(again.enc_access().store_entries[0].key, [0x44; 32]);
    }
}
