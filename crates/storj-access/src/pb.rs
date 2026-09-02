//! Prost types matching vendored `proto/{encryption,encryption_access,scope,caveat}.proto`
//! (copied from `storj.io/common/pb` / `grant/internal/pb` / `macaroon`).
//!
//! `Caveat` field order is the encode-order source of truth (picobuf `Encode`).
//! Do not regenerate it from `caveat.proto` without Restrict goldens.

use prost::Message;

/// `encryption.CipherSuite`.
#[allow(clippy::enum_variant_names)] // proto/Go names are Enc*
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum CipherSuite {
    EncUnspecified = 0,
    EncNull = 1,
    EncAesgcm = 2,
    EncSecretbox = 3,
}

/// `encryption.EncryptionParameters`.
#[derive(Clone, PartialEq, Message)]
pub struct EncryptionParameters {
    #[prost(enumeration = "CipherSuite", tag = "1")]
    pub cipher_suite: i32,
    #[prost(int64, tag = "2")]
    pub block_size: i64,
}

/// `encryption_access.EncryptionAccess.StoreEntry`.
#[derive(Clone, PartialEq, Message)]
pub struct StoreEntry {
    #[prost(bytes = "vec", tag = "1")]
    pub bucket: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub unencrypted_path: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub encrypted_path: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub key: Vec<u8>,
    #[prost(enumeration = "CipherSuite", tag = "5")]
    pub path_cipher: i32,
    #[prost(message, optional, tag = "6")]
    pub encryption_parameters: Option<EncryptionParameters>,
}

/// `encryption_access.EncryptionAccess`.
#[derive(Clone, PartialEq, Message)]
pub struct EncryptionAccess {
    #[prost(bytes = "vec", tag = "1")]
    pub default_key: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub store_entries: Vec<StoreEntry>,
    #[prost(enumeration = "CipherSuite", tag = "3")]
    pub default_path_cipher: i32,
    #[prost(message, optional, tag = "4")]
    pub default_encryption_parameters: Option<EncryptionParameters>,
}

/// `scope.Scope`.
#[derive(Clone, PartialEq, Message)]
pub struct Scope {
    #[prost(string, tag = "1")]
    pub satellite_addr: String,
    #[prost(bytes = "vec", tag = "2")]
    pub api_key: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub encryption_access: Option<EncryptionAccess>,
}

/// Wire-compatible with `google.protobuf.Timestamp`.
#[derive(Clone, PartialEq, Message)]
pub struct Timestamp {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

/// Wire-compatible with `google.protobuf.Duration`.
#[derive(Clone, PartialEq, Message)]
pub struct Duration {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

/// `macaroon.Caveat.Path`.
#[derive(Clone, PartialEq, Message)]
pub struct CaveatPath {
    #[prost(bytes = "vec", tag = "1")]
    pub bucket: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub encrypted_path_prefix: Vec<u8>,
}

/// `macaroon.Caveat`. Field declaration order matches picobuf `Encode`
/// (1–9, 10, 11–15, 20–22, 30) so Restrict bytes match Go `APIKey.Restrict`.
#[derive(Clone, PartialEq, Message)]
pub struct Caveat {
    #[prost(bool, tag = "1")]
    pub disallow_reads: bool,
    #[prost(bool, tag = "2")]
    pub disallow_writes: bool,
    #[prost(bool, tag = "3")]
    pub disallow_lists: bool,
    #[prost(bool, tag = "4")]
    pub disallow_deletes: bool,
    #[prost(bool, tag = "5")]
    pub disallow_locks: bool,
    #[prost(bool, tag = "6")]
    pub disallow_put_retention: bool,
    #[prost(bool, tag = "7")]
    pub disallow_get_retention: bool,
    #[prost(bool, tag = "8")]
    pub disallow_put_legal_hold: bool,
    #[prost(bool, tag = "9")]
    pub disallow_get_legal_hold: bool,
    #[prost(message, repeated, tag = "10")]
    pub allowed_paths: Vec<CaveatPath>,
    #[prost(bool, tag = "11")]
    pub disallow_bypass_governance_retention: bool,
    #[prost(bool, tag = "12")]
    pub disallow_put_bucket_object_lock_configuration: bool,
    #[prost(bool, tag = "13")]
    pub disallow_get_bucket_object_lock_configuration: bool,
    #[prost(bool, tag = "14")]
    pub disallow_put_bucket_notification_configuration: bool,
    #[prost(bool, tag = "15")]
    pub disallow_get_bucket_notification_configuration: bool,
    #[prost(message, optional, tag = "20")]
    pub not_after: Option<Timestamp>,
    #[prost(message, optional, tag = "21")]
    pub not_before: Option<Timestamp>,
    #[prost(message, optional, tag = "22")]
    pub max_object_ttl: Option<Duration>,
    #[prost(bytes = "vec", tag = "30")]
    pub nonce: Vec<u8>,
}
