//! Path encryption, HD key derivation, encryption store, and content-block
//! transformers (AES-256-GCM, NaCl secretbox).
//!
//! Matches `storj.io/common/encryption` (`DeriveRootKey`, `DeriveKey`, `Store`,
//! `EncryptPath` / `DecryptPath`, `Transformer`, `Increment`, `Pad`,
//! `CalcEncryptedSize`, `CalcEncompassingBlocks`).
//!
//! Argon2id parallelism is a parameter: **p=8** for `request_with_passphrase`,
//! **p=1** for `Key::derive`.

#![deny(clippy::undocumented_unsafe_blocks)]

mod aesgcm;
mod cipher;
mod error;
mod key;
mod pad;
mod path;
mod secretbox;
mod store;
mod transform;

pub use aesgcm::{AES_GCM_TAG_SIZE, AesGcmDecrypter, AesGcmEncrypter};
pub use cipher::{AES_GCM_NONCE_SIZE, CipherSuite, NONCE_SIZE, ZERO_NONCE, decrypt, encrypt};
pub use error::{Error, ErrorKind, Result};
pub use key::{
    ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN, ARGON2_PARALLELISM_DERIVE, ARGON2_PARALLELISM_REQUEST,
    ARGON2_TIME, Key, PATH_HMAC_PREFIX, derive_key, derive_nonce, derive_path_key_component,
    derive_root_key,
};
pub use pad::{UINT32_SIZE, make_padding, pad, unpad, unpad_len};
pub use path::{
    PathIter, decrypt_iterator, decrypt_path, decrypt_path_with_cipher, derive_content_key,
    derive_path_key, encrypt_iterator, encrypt_path, encrypt_path_with_cipher, encrypt_prefix,
};
pub use secretbox::{SECRETBOX_OVERHEAD, SecretboxDecrypter, SecretboxEncrypter};
pub use store::{Base, Lookup, Store};
pub use transform::{
    DEFAULT_ENCRYPTED_BLOCK_SIZE, EncryptionParameters, NoopTransformer, Transformer,
    calc_encompassing_blocks, calc_encrypted_size, calc_transformer_encrypted_size, increment,
    increment_bytes, new_decrypter, new_encrypter, transform_blocks, transform_padded,
    transform_unpad,
};
