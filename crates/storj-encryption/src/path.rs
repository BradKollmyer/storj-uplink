//! Path-component iteration, encoding, and AES-GCM path cipher.
//!
//! Matches `storj.io/common/encryption` path.go and `storj.io/common/paths`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;

use crate::cipher::{AES_GCM_NONCE_SIZE, CipherSuite, NONCE_SIZE, decrypt, encrypt};
use crate::error::{Error, ErrorKind, Result};
use crate::key::{CONTENT_HMAC_INFO, Key, derive_key, derive_nonce};
use crate::store::Store;

const EMPTY_COMPONENT_PREFIX: u8 = 0x01;
const NOT_EMPTY_COMPONENT_PREFIX: u8 = 0x02;
const ESCAPE_SLASH: u8 = 0x2e;
const ESCAPE_FF: u8 = 0xfe;
const ESCAPE_01: u8 = 0x01;

/// Iterator over `/`-separated path components. Matches Go `paths.Iterator`.
///
/// Trailing slashes yield a final empty component (`"a/"` → `["a", ""]`).
/// `"/"` is `["", ""]`. The empty path is already done.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathIter {
    raw: Vec<u8>,
    consumed: usize,
    last_empty: bool,
}

impl PathIter {
    /// Iterate `raw`. The empty path is immediately done.
    pub fn new(raw: impl Into<Vec<u8>>) -> Self {
        let raw = raw.into();
        let last_empty = !raw.is_empty();
        Self {
            raw,
            consumed: 0,
            last_empty,
        }
    }

    /// Bytes already consumed (not including a trailing empty component).
    pub fn consumed(&self) -> &[u8] {
        &self.raw[..self.consumed]
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> &[u8] {
        &self.raw[self.consumed..]
    }

    /// True when every component (including a trailing empty one) has been yielded.
    pub fn done(&self) -> bool {
        self.raw.len() == self.consumed && !self.last_empty
    }

    /// Remaining components as a vec (does not mutate self).
    pub fn remaining_components(&self) -> Vec<Vec<u8>> {
        self.clone().collect()
    }
}

impl Iterator for PathIter {
    type Item = Vec<u8>;

    /// Next component, or `None` if done. An empty component is `Some([])`.
    fn next(&mut self) -> Option<Vec<u8>> {
        if self.done() {
            return None;
        }
        let rem_len = self.raw.len() - self.consumed;
        let rem = &self.raw[self.consumed..];
        match rem.iter().position(|&b| b == b'/') {
            None => {
                let part = rem.to_vec();
                self.consumed += rem_len;
                self.last_empty = false;
                Some(part)
            }
            Some(index) => {
                let part = rem[..index].to_vec();
                self.last_empty = index + 1 == rem_len;
                self.consumed += index + 1;
                Some(part)
            }
        }
    }
}

/// Join components with `/` (Go `pathBuilder`).
fn join_components(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    out
}

/// Encrypt `path` using the store's cipher at the matched base.
pub fn encrypt_path(bucket: &str, path: &str, store: &Store) -> Result<Vec<u8>> {
    encrypt_path_bytes(bucket, path.as_bytes(), None, store)
}

/// Encrypt `path` with an explicit path cipher.
pub fn encrypt_path_with_cipher(
    bucket: &str,
    path: &str,
    path_cipher: CipherSuite,
    store: &Store,
) -> Result<Vec<u8>> {
    encrypt_path_bytes(bucket, path.as_bytes(), Some(path_cipher), store)
}

/// Encrypt a listing prefix. A trailing `/` is stripped, encrypted, then reattached
/// so it is not treated as an extra empty component (Go `EncryptPrefixWithStoreCipher`).
pub fn encrypt_prefix(bucket: &str, path: &str, store: &Store) -> Result<Vec<u8>> {
    let raw = path.as_bytes();
    let has_trailing = raw.ends_with(b"/");
    let stripped = if has_trailing {
        &raw[..raw.len() - 1]
    } else {
        raw
    };
    let mut enc = encrypt_path_bytes(bucket, stripped, None, store)?;
    if has_trailing {
        enc.push(b'/');
    }
    Ok(enc)
}

/// Decrypt `path` using the store's cipher at the matched base.
pub fn decrypt_path(bucket: &str, path: &[u8], store: &Store) -> Result<Vec<u8>> {
    decrypt_path_bytes(bucket, path, None, store)
}

/// Decrypt `path` with an explicit path cipher.
pub fn decrypt_path_with_cipher(
    bucket: &str,
    path: &[u8],
    path_cipher: CipherSuite,
    store: &Store,
) -> Result<Vec<u8>> {
    decrypt_path_bytes(bucket, path, Some(path_cipher), store)
}

fn encrypt_path_bytes(
    bucket: &str,
    path: &[u8],
    path_cipher: Option<CipherSuite>,
    store: &Store,
) -> Result<Vec<u8>> {
    // Invalid/empty paths map to empty (Go `!path.Valid()`).
    if path.is_empty() {
        return Ok(Vec::new());
    }

    let lookup = store.lookup_unencrypted(bucket, path);
    let Some(base) = lookup.base else {
        return Err(Error::missing_encryption_base(bucket, path));
    };

    let path_cipher = path_cipher.unwrap_or(base.path_cipher);
    let mut key = base.key.clone();
    if base.default {
        key = key.derive_path_component(bucket.as_bytes());
    }

    let remaining_done = lookup.remaining.done();
    let encrypted = encrypt_iterator(lookup.remaining, path_cipher, &key)?;

    let mut parts = Vec::new();
    if !base.encrypted.is_empty() {
        parts.push(base.encrypted);
    }
    if !remaining_done {
        parts.push(encrypted);
    }
    Ok(join_components(&parts))
}

fn decrypt_path_bytes(
    bucket: &str,
    path: &[u8],
    path_cipher: Option<CipherSuite>,
    store: &Store,
) -> Result<Vec<u8>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }

    let lookup = store.lookup_encrypted(bucket, path);
    let Some(base) = lookup.base else {
        return Err(Error::missing_decryption_base(bucket, path));
    };

    let path_cipher = path_cipher.unwrap_or(base.path_cipher);
    let mut key = base.key.clone();
    if base.default {
        key = key.derive_path_component(bucket.as_bytes());
    }

    let remaining_done = lookup.remaining.done();
    let decrypted = decrypt_iterator(lookup.remaining, path_cipher, &key)?;

    let mut parts = Vec::new();
    if !base.unencrypted.is_empty() {
        parts.push(base.unencrypted);
    }
    if !remaining_done {
        parts.push(decrypted);
    }
    Ok(join_components(&parts))
}

/// Encrypt remaining path components with `key` (bucket fold already applied).
pub fn encrypt_iterator(iter: PathIter, cipher: CipherSuite, key: &Key) -> Result<Vec<u8>> {
    let mut key = key.clone();
    let mut parts = Vec::new();
    for component in iter {
        let enc = encrypt_path_component(&component, cipher, &key)?;
        key = key.derive_path_component(&component);
        parts.push(enc);
    }
    Ok(join_components(&parts))
}

/// Decrypt remaining path components with `key` (bucket fold already applied).
pub fn decrypt_iterator(iter: PathIter, cipher: CipherSuite, key: &Key) -> Result<Vec<u8>> {
    let mut key = key.clone();
    let mut parts = Vec::new();
    for component in iter {
        let unenc = decrypt_path_component(&component, cipher, &key)?;
        key = key.derive_path_component(&unenc);
        parts.push(unenc);
    }
    Ok(join_components(&parts))
}

/// Path key at `bucket`/`path` by looking up the store and deriving the remainder.
pub fn derive_path_key(bucket: &str, path: &[u8], store: &Store) -> Result<Key> {
    let lookup = store.lookup_unencrypted(bucket, path);
    let Some(base) = lookup.base else {
        return Err(Error::missing_encryption_base(bucket, path));
    };

    let mut key = base.key.clone();
    if base.default {
        key = key.derive_path_component(bucket.as_bytes());
    }
    if path.is_empty() {
        return Ok(key);
    }

    for component in lookup.remaining {
        key = key.derive_path_component(&component);
    }
    Ok(key)
}

/// Content key: `DeriveKey(path_key, "content")`.
pub fn derive_content_key(bucket: &str, path: &[u8], store: &Store) -> Result<Key> {
    let path_key = derive_path_key(bucket, path, store)?;
    Ok(derive_key(&path_key, CONTENT_HMAC_INFO))
}

fn encrypt_path_component(comp: &[u8], cipher: CipherSuite, key: &Key) -> Result<Vec<u8>> {
    if cipher == CipherSuite::NULL {
        return Ok(comp.to_vec());
    }
    if cipher == CipherSuite::NULL_BASE64_URL {
        let decoded = URL_SAFE.decode(comp).map_err(|e| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("invalid base64 data: {e}"),
            )
        })?;
        return Ok(decoded);
    }

    // Unique nonce per component: derive from this component, encrypt with parent key.
    let derived = key.derive_path_component(comp);
    let nonce = derive_nonce(&derived);
    let cipher_text = encrypt(comp, cipher, key, &nonce)?;

    let nonce_size = if cipher == CipherSuite::AES_GCM {
        AES_GCM_NONCE_SIZE
    } else {
        NONCE_SIZE
    };
    let mut packed = Vec::with_capacity(nonce_size + cipher_text.len());
    packed.extend_from_slice(&nonce[..nonce_size]);
    packed.extend_from_slice(&cipher_text);
    Ok(encode_segment(&packed))
}

fn decrypt_path_component(comp: &[u8], cipher: CipherSuite, key: &Key) -> Result<Vec<u8>> {
    if comp.is_empty() {
        return Ok(Vec::new());
    }
    if cipher == CipherSuite::NULL {
        return Ok(comp.to_vec());
    }
    if cipher == CipherSuite::NULL_BASE64_URL {
        return Ok(URL_SAFE.encode(comp).into_bytes());
    }

    let data = decode_segment(comp)?;
    let nonce_size = if cipher == CipherSuite::AES_GCM {
        AES_GCM_NONCE_SIZE
    } else {
        NONCE_SIZE
    };
    if data.len() < nonce_size {
        return Err(Error::new(
            ErrorKind::DecryptionFailed,
            "component did not contain enough nonce bytes",
        ));
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..nonce_size].copy_from_slice(&data[..nonce_size]);
    decrypt(&data[nonce_size..], cipher, key, &nonce)
}

/// Empty component → `\x01`. Otherwise `\x02` + escaped bytes.
///
/// Escapes so encoded components never contain `0x00`, `0xff`, or `/`.
pub(crate) fn encode_segment(segment: &[u8]) -> Vec<u8> {
    if segment.is_empty() {
        return vec![EMPTY_COMPONENT_PREFIX];
    }
    let mut result = Vec::with_capacity(segment.len() * 2 + 1);
    result.push(NOT_EMPTY_COMPONENT_PREFIX);
    for &b in segment {
        match b {
            ESCAPE_SLASH => result.extend_from_slice(&[ESCAPE_SLASH, 1]),
            b if b == ESCAPE_SLASH + 1 => result.extend_from_slice(&[ESCAPE_SLASH, 2]),
            ESCAPE_FF => result.extend_from_slice(&[ESCAPE_FF, 1]),
            b if b == ESCAPE_FF + 1 => result.extend_from_slice(&[ESCAPE_FF, 2]),
            b if b == ESCAPE_01 - 1 => result.extend_from_slice(&[ESCAPE_01, 1]),
            ESCAPE_01 => result.extend_from_slice(&[ESCAPE_01, 2]),
            other => result.push(other),
        }
    }
    result
}

pub(crate) fn decode_segment(segment: &[u8]) -> Result<Vec<u8>> {
    validate_encoded_segment(segment)?;
    if segment[0] == EMPTY_COMPONENT_PREFIX {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(segment.len() - 1);
    let mut i = 1;
    while i < segment.len() {
        if i == segment.len() - 1 {
            out.push(segment[i]);
            break;
        }
        match segment[i] {
            b if b == ESCAPE_SLASH || b == ESCAPE_FF => {
                // Go `byte` arithmetic wraps; `\xfe`+2-1 must be `\xff`.
                out.push(segment[i].wrapping_add(segment[i + 1]).wrapping_sub(1));
                i += 2;
            }
            ESCAPE_01 => {
                out.push(segment[i + 1].wrapping_sub(1));
                i += 2;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn validate_encoded_segment(segment: &[u8]) -> Result<()> {
    let fail = |msg: &str| Error::new(ErrorKind::DecryptionFailed, msg.to_owned());
    match segment {
        [] => return Err(fail("encoded segment cannot be empty")),
        [b, ..] if *b != EMPTY_COMPONENT_PREFIX && *b != NOT_EMPTY_COMPONENT_PREFIX => {
            return Err(fail("invalid segment prefix"));
        }
        [EMPTY_COMPONENT_PREFIX, _, ..] => {
            return Err(fail("segment encoded as empty but contains data"));
        }
        [NOT_EMPTY_COMPONENT_PREFIX] => {
            return Err(fail(
                "segment encoded as not empty but doesn't contain data",
            ));
        }
        _ => {}
    }
    if segment.len() == 1 {
        return Ok(());
    }

    let mut index = 1;
    while index < segment.len() - 1 {
        if is_escape_byte(segment[index]) {
            if segment[index + 1] == 1 || segment[index + 1] == 2 {
                index += 2;
                continue;
            }
            return Err(fail("invalid escape sequence"));
        }
        if is_disallowed_byte(segment[index]) {
            return Err(fail("invalid character in segment"));
        }
        index += 1;
    }
    if index == segment.len() - 1 {
        if is_escape_byte(segment[index]) {
            return Err(fail("invalid escape sequence"));
        }
        if is_disallowed_byte(segment[index]) {
            return Err(fail("invalid character"));
        }
    }
    Ok(())
}

fn is_escape_byte(b: u8) -> bool {
    b == ESCAPE_SLASH || b == ESCAPE_FF || b == ESCAPE_01
}

fn is_disallowed_byte(b: u8) -> bool {
    b == 0 || b == 0xff || b == b'/'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::derive_path_key_component;

    fn components(path: &str) -> Vec<String> {
        PathIter::new(path.as_bytes())
            .remaining_components()
            .into_iter()
            .map(|p| String::from_utf8(p).unwrap())
            .collect()
    }

    #[test]
    fn iterator_matches_go() {
        assert!(PathIter::new("").done());
        assert_eq!(components(""), Vec::<String>::new());
        assert_eq!(components("a"), vec!["a"]);
        assert_eq!(components("a/"), vec!["a", ""]);
        assert_eq!(components("/a"), vec!["", "a"]);
        assert_eq!(components("/"), vec!["", ""]);
        assert_eq!(components("//"), vec!["", "", ""]);
        assert_eq!(components("a/b"), vec!["a", "b"]);
        assert_eq!(components("a/b/"), vec!["a", "b", ""]);
        assert_eq!(components("file.txt/"), vec!["file.txt", ""]);
    }

    #[test]
    fn encode_decode_segment_roundtrip() {
        let segments: &[&[u8]] = &[
            b"",
            b"a",
            &[0],
            b"/",
            b"abc12345",
            b"/////",
            &[0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[b'a', b'/', b'a', b'2', b'a', b'a', 0, b'1', b'b', 255],
        ];
        for segment in segments {
            let encoded = encode_segment(segment);
            assert!(!encoded.contains(&0), "{encoded:?}");
            assert!(!encoded.contains(&255), "{encoded:?}");
            assert!(!encoded.contains(&b'/'), "{encoded:?}");
            let decoded = decode_segment(&encoded).unwrap();
            assert_eq!(&decoded, segment);
        }
    }

    #[test]
    fn invalid_segment_decoding() {
        for segment in [
            vec![],
            vec![1, 1],
            vec![2],
            vec![2, 0],
            vec![2, 0xff],
            vec![2, 0x2f],
            vec![2, ESCAPE_SLASH, b'3'],
            vec![3, 4, 4, 4],
        ] {
            let err = decode_segment(&segment).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DecryptionFailed, "{segment:?}");
        }
    }

    fn default_store(cipher: CipherSuite) -> Store {
        let mut store = Store::new();
        store.set_default_key(Key::from_bytes([7u8; 32]));
        store.set_default_path_cipher(cipher);
        store
    }

    #[test]
    fn encrypt_decrypt_roundtrip_aes_gcm() {
        let store = default_store(CipherSuite::AES_GCM);
        for path in [
            "",
            "/",
            "//",
            "file.txt",
            "file.txt/",
            "fold1/file.txt",
            "fold1/fold2/file.txt",
            "/fold1/fold2/fold3/file.txt",
            "/fold1/fold2/fold3/file.txt/",
            "café",
            "café/naïve.txt",
            "logs/2024/ünicode",
        ] {
            let enc = encrypt_path("bucket", path, &store).unwrap();
            if !path.is_empty() {
                assert!(
                    !enc.ends_with(b"/"),
                    "AES-GCM encoded path must not end with /: {path:?}"
                );
            }
            let dec = decrypt_path("bucket", &enc, &store).unwrap();
            assert_eq!(dec, path.as_bytes(), "path={path:?}");
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip_null() {
        let store = default_store(CipherSuite::NULL);
        for path in [
            "",
            "/",
            "//",
            "file.txt",
            "file.txt/",
            "fold1/file.txt",
            "café",
        ] {
            let enc = encrypt_path("bucket", path, &store).unwrap();
            let dec = decrypt_path("bucket", &enc, &store).unwrap();
            assert_eq!(dec, path.as_bytes(), "path={path:?}");
        }
    }

    #[test]
    fn encrypt_prefix_preserves_trailing_slash() {
        let store = default_store(CipherSuite::AES_GCM);
        for path in ["", "file.txt", "file.txt/", "fold1/file.txt/", "café/"] {
            let enc = encrypt_prefix("bucket", path, &store).unwrap();
            assert_eq!(
                path.ends_with('/'),
                enc.ends_with(b"/"),
                "path={path:?} enc={enc:?}"
            );
            let dec = decrypt_path("bucket", &enc, &store).unwrap();
            assert_eq!(dec, path.as_bytes(), "path={path:?}");
        }
    }

    #[test]
    fn bucket_fold_matches_derived_bucket_root() {
        let root_key = Key::from_bytes([9u8; 32]);
        let mut root = Store::new();
        root.set_default_key(root_key.clone());
        root.set_default_path_cipher(CipherSuite::AES_GCM);

        let bucket_key = derive_path_key("bucket", b"", &root).unwrap();
        let mut bucket_store = Store::new();
        bucket_store
            .add_with_cipher("bucket", b"", b"", bucket_key, CipherSuite::AES_GCM)
            .unwrap();

        for path in ["", "file.txt", "a/b/c", "café", "file.txt/"] {
            let a = encrypt_path("bucket", path, &root).unwrap();
            let b = encrypt_path("bucket", path, &bucket_store).unwrap();
            assert_eq!(a, b, "path={path:?}");
        }
    }

    #[test]
    fn missing_base_errors() {
        let store = Store::new();
        let err = encrypt_path("b", "p", &store).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingEncryptionBase);
        let err = decrypt_path("b", b"p", &store).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingDecryptionBase);
    }

    #[test]
    fn unicode_component_hmac_differs_from_ascii() {
        let key = [1u8; 32];
        assert_ne!(
            derive_path_key_component(&key, "cafe"),
            derive_path_key_component(&key, "café")
        );
    }

    #[test]
    fn content_key_differs_from_path_key() {
        let store = default_store(CipherSuite::AES_GCM);
        let path = derive_path_key("bucket", b"logs/a", &store).unwrap();
        let content = derive_content_key("bucket", b"logs/a", &store).unwrap();
        assert_ne!(path.as_bytes(), content.as_bytes());
        assert_eq!(content.as_bytes(), derive_key(&path, "content").as_bytes());
    }
}
