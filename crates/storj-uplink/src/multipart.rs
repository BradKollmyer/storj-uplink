//! Multipart upload ID encoding and part ETag encryption.

use storj_access::{check_decode, check_encode};
use storj_encryption::{CipherSuite, Key, NONCE_SIZE, decrypt, derive_key, encrypt};

use crate::{Error, Result};

/// Base58Check version byte for StreamID / multipart `upload_id` (Go uses 1).
/// Distinct from grant encoding, which uses version 0.
pub const STREAM_ID_VERSION: u8 = 1;

/// HMAC info for deriving a part ETag key (Go `deriveETagKey` / `DeriveKey(..., "storj-etag-v1")`).
const ETAG_HMAC_INFO: &str = "storj-etag-v1";

/// Encode a satellite StreamID as a public `upload_id` (Base58Check version 1).
#[must_use]
pub fn encode_upload_id(stream_id: &[u8]) -> String {
    check_encode(stream_id, STREAM_ID_VERSION)
}

/// Decode a public `upload_id` into a StreamID. Rejects grant version 0.
pub fn decode_upload_id(upload_id: &str) -> Result<Vec<u8>> {
    if upload_id.is_empty() {
        return Err(Error::protocol("upload ID invalid"));
    }
    let (payload, version) =
        check_decode(upload_id).map_err(|_| Error::protocol("upload ID invalid"))?;
    if version != STREAM_ID_VERSION {
        return Err(Error::protocol("upload ID invalid"));
    }
    Ok(payload)
}

/// Encrypt a part ETag with a key derived from the last segment's content key.
pub fn encrypt_etag(etag: &[u8], cipher: CipherSuite, segment_key: &Key) -> Result<Vec<u8>> {
    if etag.is_empty() {
        return Ok(Vec::new());
    }
    let etag_key = derive_key(segment_key, ETAG_HMAC_INFO);
    Ok(encrypt(etag, cipher, &etag_key, &[0u8; NONCE_SIZE])?)
}

/// Decrypt a part ETag stored on the last segment of a part.
pub fn decrypt_etag(
    encrypted_etag: &[u8],
    cipher: CipherSuite,
    segment_key: &Key,
) -> Result<Vec<u8>> {
    if encrypted_etag.is_empty() {
        return Ok(Vec::new());
    }
    let etag_key = derive_key(segment_key, ETAG_HMAC_INFO);
    Ok(decrypt(
        encrypted_etag,
        cipher,
        &etag_key,
        &[0u8; NONCE_SIZE],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use storj_access::check_encode;

    #[test]
    fn upload_id_roundtrip_version_1() {
        let stream_id = b"stream-id-bytes-0123456789abcd";
        let encoded = encode_upload_id(stream_id);
        let decoded = decode_upload_id(&encoded).expect("decode");
        assert_eq!(decoded, stream_id);

        let (payload, version) = storj_access::check_decode(&encoded).expect("check_decode");
        assert_eq!(version, STREAM_ID_VERSION);
        assert_eq!(version, 1);
        assert_eq!(payload, stream_id);

        let grant_shaped = check_encode(stream_id, 0);
        assert_ne!(encoded, grant_shaped);
        assert!(decode_upload_id(&grant_shaped).is_err());
    }

    #[test]
    fn upload_id_rejects_empty_and_garbage() {
        assert!(decode_upload_id("").is_err());
        assert!(decode_upload_id("!!!not-base58!!!").is_err());
    }

    #[test]
    fn etag_roundtrip() {
        let key = Key::from_bytes([9u8; 32]);
        let etag = b"part-etag";
        let enc = encrypt_etag(etag, CipherSuite::AES_GCM, &key).unwrap();
        assert_ne!(enc, etag);
        let got = decrypt_etag(&enc, CipherSuite::AES_GCM, &key).unwrap();
        assert_eq!(got, etag);
        assert!(
            encrypt_etag(b"", CipherSuite::AES_GCM, &key)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn etag_uses_storj_etag_v1_info() {
        assert_eq!(ETAG_HMAC_INFO, "storj-etag-v1");
        let key = Key::from_bytes([9u8; 32]);
        let etag = b"part-etag";
        let enc = encrypt_etag(etag, CipherSuite::AES_GCM, &key).unwrap();
        let expected_key = derive_key(&key, "storj-etag-v1");
        let expected = encrypt(
            etag,
            CipherSuite::AES_GCM,
            &expected_key,
            &[0u8; NONCE_SIZE],
        )
        .unwrap();
        assert_eq!(enc, expected);
        let legacy_key = derive_key(&key, "etag");
        let legacy = encrypt(etag, CipherSuite::AES_GCM, &legacy_key, &[0u8; NONCE_SIZE]).unwrap();
        assert_ne!(enc, legacy);
    }
}
