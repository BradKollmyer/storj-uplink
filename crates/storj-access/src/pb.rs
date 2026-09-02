//! Prost types matching vendored `proto/{encryption,encryption_access,scope}.proto`
//! (copied from `storj.io/common/pb` / `grant/internal/pb`).

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
