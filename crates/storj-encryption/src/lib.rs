//! Path encryption, HD key derivation, and the encryption store.
//!
//! Matches `storj.io/common/encryption` (`DeriveRootKey`, `DeriveKey`, `Store`,
//! `EncryptPath` / `DecryptPath`). Content-block transformers land in a later PR.
//!
//! Argon2id parallelism is a parameter: **p=8** for `request_with_passphrase`,
//! **p=1** for `Key::derive`.

#![deny(clippy::undocumented_unsafe_blocks)]

mod cipher;
mod error;
mod key;
mod path;
mod store;

pub use cipher::{AES_GCM_NONCE_SIZE, CipherSuite, NONCE_SIZE, decrypt, encrypt};
pub use error::{Error, ErrorKind, Result};
pub use key::{
    ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN, ARGON2_PARALLELISM_DERIVE, ARGON2_PARALLELISM_REQUEST,
    ARGON2_TIME, Key, PATH_HMAC_PREFIX, derive_key, derive_nonce, derive_path_key_component,
    derive_root_key,
};
pub use path::{
    PathIter, decrypt_iterator, decrypt_path, decrypt_path_with_cipher, derive_content_key,
    derive_path_key, encrypt_iterator, encrypt_path, encrypt_path_with_cipher, encrypt_prefix,
};
pub use store::{Base, Lookup, Store};
