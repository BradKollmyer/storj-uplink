//! Encryption store: `(bucket, unencrypted path) ↔ (encrypted path, key, cipher)`.
//!
//! Remainder semantics copy [`encryption.Store`](https://pkg.go.dev/storj.io/common/encryption#Store)
//! `LookupUnencrypted` / `LookupEncrypted`.

use std::collections::HashMap;

use crate::cipher::CipherSuite;
use crate::error::{Error, ErrorKind, Result};
use crate::key::Key;
use crate::path::PathIter;

/// Key with which to derive further keys at some encrypted/unencrypted path.
#[derive(Clone, Debug)]
pub struct Base {
    /// Unencrypted path of this store entry (empty for the default key).
    pub unencrypted: Vec<u8>,
    /// Encrypted path of this store entry (empty for the default key).
    pub encrypted: Vec<u8>,
    /// Path key at this prefix.
    pub key: Key,
    /// Cipher used for components below this base.
    pub path_cipher: CipherSuite,
    /// True when this base is the store's default key (bucket is folded in).
    pub default: bool,
}

/// Result of [`Store::lookup_unencrypted`] / [`Store::lookup_encrypted`].
#[derive(Clone)]
pub struct Lookup {
    /// Child component mappings at the matched node.
    ///
    /// `None` if the walk stopped because a component was missing (Go `nil` map).
    /// `Some` (possibly empty) if the iterator was exhausted at this node.
    pub revealed: Option<HashMap<Vec<u8>, Vec<u8>>>,
    /// Unconsumed suffix after the deepest matching store entry.
    pub remaining: PathIter,
    /// Deepest matching base, or the default key. `None` if neither exists.
    pub base: Option<Base>,
}

/// In-memory trie of encryption bases, plus an optional default key.
#[derive(Clone, Default)]
pub struct Store {
    roots: HashMap<String, Node>,
    default_key: Option<Key>,
    default_path_cipher: CipherSuite,
    /// When true, lookups rewrite `PathCipher` to [`CipherSuite::NULL_BASE64_URL`].
    pub encryption_bypass: bool,
}

/// `Debug` prints counts only: the store maps plaintext object keys, which
/// path encryption exists to hide from logs.
impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("buckets", &self.roots.len())
            .field("default_key", &self.default_key.is_some())
            .field("default_path_cipher", &self.default_path_cipher)
            .field("encryption_bypass", &self.encryption_bypass)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Lookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lookup")
            .field("revealed", &self.revealed.as_ref().map(HashMap::len))
            .field("remaining_components", &self.remaining.clone().count())
            .field("base", &self.base.as_ref().map(|b| b.path_cipher))
            .finish()
    }
}

#[derive(Clone, Default)]
struct Node {
    /// Children keyed by unencrypted component.
    unenc: HashMap<Vec<u8>, Node>,
    /// unenc component → enc component.
    unenc_map: HashMap<Vec<u8>, Vec<u8>>,
    /// enc component → unenc component.
    enc_map: HashMap<Vec<u8>, Vec<u8>>,
    base: Option<Base>,
}

impl Store {
    /// Empty store with no default key.
    pub fn new() -> Self {
        Self::default()
    }

    /// Default key returned when a lookup matches no store entry.
    pub fn set_default_key(&mut self, key: Key) {
        self.default_key = Some(key);
    }

    /// Current default key, if any.
    pub fn default_key(&self) -> Option<&Key> {
        self.default_key.as_ref()
    }

    /// Default path cipher for lookups that use the default key.
    pub fn set_default_path_cipher(&mut self, cipher: CipherSuite) {
        self.default_path_cipher = cipher;
    }

    /// Current default path cipher (`EncUnspecified` if never set).
    pub fn default_path_cipher(&self) -> CipherSuite {
        self.default_path_cipher
    }

    /// Add a mapping using the store's default path cipher.
    pub fn add(&mut self, bucket: &str, unenc: &[u8], enc: &[u8], key: Key) -> Result<()> {
        self.add_with_cipher(bucket, unenc, enc, key, self.default_path_cipher)
    }

    /// Add a mapping with an explicit path cipher.
    pub fn add_with_cipher(
        &mut self,
        bucket: &str,
        unenc: &[u8],
        enc: &[u8],
        key: Key,
        path_cipher: CipherSuite,
    ) -> Result<()> {
        let mut root = self.roots.get(bucket).cloned().unwrap_or_default();
        root.add(
            PathIter::new(unenc),
            PathIter::new(enc),
            Base {
                unencrypted: unenc.to_vec(),
                encrypted: enc.to_vec(),
                key,
                path_cipher,
                default: false,
            },
        )?;
        self.roots.insert(bucket.to_owned(), root);
        Ok(())
    }

    /// Look up by unencrypted path. Remainder is the unencrypted suffix.
    pub fn lookup_unencrypted(&self, bucket: &str, path: &[u8]) -> Lookup {
        self.lookup(bucket, path, true)
    }

    /// Look up by encrypted path. Remainder is the encrypted suffix.
    pub fn lookup_encrypted(&self, bucket: &str, path: &[u8]) -> Lookup {
        self.lookup(bucket, path, false)
    }

    fn lookup(&self, bucket: &str, path: &[u8], unenc: bool) -> Lookup {
        let mut revealed = None;
        let mut remaining = PathIter::new(Vec::<u8>::new());
        let mut base = None;

        if let Some(root) = self.roots.get(bucket) {
            let walked = root.lookup(
                PathIter::new(path),
                PathIter::new(Vec::<u8>::new()),
                None,
                unenc,
            );
            revealed = walked.revealed;
            remaining = walked.remaining;
            base = walked.base;
        }

        if base.is_none() {
            if let Some(key) = &self.default_key {
                let mut lookup = Lookup {
                    revealed: None,
                    remaining: PathIter::new(path),
                    base: Some(self.default_base(key)),
                };
                self.apply_bypass(&mut lookup);
                return lookup;
            }
        }

        let mut lookup = Lookup {
            revealed,
            remaining,
            base,
        };
        self.apply_bypass(&mut lookup);
        lookup
    }

    fn default_base(&self, key: &Key) -> Base {
        Base {
            unencrypted: Vec::new(),
            encrypted: Vec::new(),
            key: key.clone(),
            path_cipher: self.default_path_cipher,
            default: true,
        }
    }

    fn apply_bypass(&self, lookup: &mut Lookup) {
        if self.encryption_bypass {
            if let Some(base) = lookup.base.as_mut() {
                base.path_cipher = CipherSuite::NULL_BASE64_URL;
            }
        }
    }

    /// Visit every added mapping.
    pub fn iterate_with_cipher(
        &self,
        mut fn_: impl FnMut(&str, &[u8], &[u8], &Key, CipherSuite) -> Result<()>,
    ) -> Result<()> {
        for (bucket, root) in &self.roots {
            root.iterate_with_cipher(bucket, &mut fn_)?;
        }
        Ok(())
    }
}

impl Node {
    fn add(&mut self, mut unenc: PathIter, mut enc: PathIter, base: Base) -> Result<()> {
        if unenc.done() != enc.done() {
            return Err(Error::new(
                ErrorKind::Conflict,
                "encrypted and unencrypted paths had different number of components",
            ));
        }
        if unenc.done() {
            self.base = Some(base);
            return Ok(());
        }

        let unenc_part = unenc.next().expect("not done");
        let enc_part = enc.next().expect("not done");

        if let Some(ex) = self.enc_map.get(&enc_part)
            && ex != &unenc_part
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "conflicting encrypted parts for unencrypted path",
            ));
        }
        if let Some(ex) = self.unenc_map.get(&unenc_part)
            && ex != &enc_part
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "conflicting encrypted parts for unencrypted path",
            ));
        }

        // Mutate in place (Go does too): every check at every level runs
        // before the only mutation, which is at the leaf, so a failed
        // recursive add cannot leave partial state. A *new* child is inserted
        // only after its subtree was added successfully.
        match self.unenc.get_mut(&unenc_part) {
            Some(child) => child.add(unenc, enc, base)?,
            None => {
                let mut child = Node::default();
                child.add(unenc, enc, base)?;
                self.unenc.insert(unenc_part.clone(), child);
            }
        }
        self.unenc_map.insert(unenc_part.clone(), enc_part.clone());
        self.enc_map.insert(enc_part, unenc_part);
        Ok(())
    }

    fn lookup(
        &self,
        mut iter: PathIter,
        mut best_remaining: PathIter,
        mut best_base: Option<Base>,
        unenc: bool,
    ) -> Lookup {
        if self.base.is_some() || best_base.is_none() {
            best_remaining = iter.clone();
            best_base = self.base.clone();
        }

        if iter.done() {
            // Only the terminal node's map is revealed; intermediate nodes
            // never clone theirs.
            let revealed = if unenc {
                self.enc_map.clone()
            } else {
                // LookupEncrypted reveals unenc → enc.
                self.unenc_map.clone()
            };
            return Lookup {
                revealed: Some(revealed),
                remaining: best_remaining,
                base: best_base,
            };
        }

        let part = iter.next().expect("not done");
        let child = if unenc {
            self.unenc.get(&part)
        } else {
            self.enc_map
                .get(&part)
                .and_then(|unenc_part| self.unenc.get(unenc_part))
        };
        let Some(child) = child else {
            return Lookup {
                revealed: None,
                remaining: best_remaining,
                base: best_base,
            };
        };
        child.lookup(iter, best_remaining, best_base, unenc)
    }

    fn iterate_with_cipher(
        &self,
        bucket: &str,
        fn_: &mut impl FnMut(&str, &[u8], &[u8], &Key, CipherSuite) -> Result<()>,
    ) -> Result<()> {
        if let Some(base) = &self.base {
            fn_(
                bucket,
                &base.unencrypted,
                &base.encrypted,
                &base.key,
                base.path_cipher,
            )?;
        }
        for child in self.unenc.values() {
            child.iterate_with_cipher(bucket, fn_)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(label: &str) -> Key {
        let mut bytes = [0u8; 32];
        let src = label.as_bytes();
        bytes[..src.len()].copy_from_slice(src);
        Key::from_bytes(bytes)
    }

    fn remaining_strs(iter: &PathIter) -> Vec<String> {
        iter.remaining_components()
            .into_iter()
            .map(|p| String::from_utf8(p).unwrap())
            .collect()
    }

    fn revealed_pairs(m: &Option<HashMap<Vec<u8>, Vec<u8>>>) -> Option<Vec<(String, String)>> {
        m.as_ref().map(|map| {
            let mut v: Vec<_> = map
                .iter()
                .map(|(k, val)| {
                    (
                        String::from_utf8(k.clone()).unwrap(),
                        String::from_utf8(val.clone()).unwrap(),
                    )
                })
                .collect();
            v.sort();
            v
        })
    }

    fn sample_store() -> Store {
        let mut s = Store::new();
        let add = |s: &mut Store, b: &str, u: &str, e: &str, k: &str| {
            s.add_with_cipher(b, u.as_bytes(), e.as_bytes(), key(k), CipherSuite::AES_GCM)
                .unwrap();
        };
        add(&mut s, "b1", "u1/u2/u3", "e1/e2/e3", "k3");
        add(&mut s, "b1", "u1/u2/u3/u4", "e1/e2/e3/e4", "k4");
        add(&mut s, "b1", "u1/u5", "e1/e5", "k5");
        add(&mut s, "b1", "u6", "e6", "k6");
        add(&mut s, "b1", "u6/u7/u8", "e6/e7/e8", "k8");
        add(&mut s, "b2", "u1", "e1'", "k1");
        add(&mut s, "b3", "", "", "m1");
        s
    }

    #[test]
    fn lookup_unencrypted_remainders_match_go() {
        let s = sample_store();

        let u1 = s.lookup_unencrypted("b1", b"u1");
        assert!(u1.base.is_none());
        assert_eq!(remaining_strs(&u1.remaining), Vec::<String>::new());
        let mut revealed = revealed_pairs(&u1.revealed).unwrap();
        revealed.sort();
        assert_eq!(
            revealed,
            vec![("e2".into(), "u2".into()), ("e5".into(), "u5".into()),]
        );

        let u123 = s.lookup_unencrypted("b1", b"u1/u2/u3");
        assert_eq!(u123.base.as_ref().unwrap().unencrypted, b"u1/u2/u3");
        assert!(!u123.base.as_ref().unwrap().default);
        assert_eq!(remaining_strs(&u123.remaining), Vec::<String>::new());
        assert_eq!(
            revealed_pairs(&u123.revealed).unwrap(),
            vec![("e4".into(), "u4".into())]
        );

        let u1236 = s.lookup_unencrypted("b1", b"u1/u2/u3/u6");
        assert_eq!(&u1236.base.as_ref().unwrap().key.as_bytes()[..2], b"k3");
        assert_eq!(remaining_strs(&u1236.remaining), vec!["u6"]);
        assert!(u1236.revealed.is_none());

        let u1234 = s.lookup_unencrypted("b1", b"u1/u2/u3/u4");
        assert_eq!(u1234.base.as_ref().unwrap().unencrypted, b"u1/u2/u3/u4");
        assert_eq!(remaining_strs(&u1234.remaining), Vec::<String>::new());

        let u67 = s.lookup_unencrypted("b1", b"u6/u7");
        assert_eq!(u67.base.as_ref().unwrap().unencrypted, b"u6");
        assert_eq!(remaining_strs(&u67.remaining), vec!["u7"]);
        assert_eq!(
            revealed_pairs(&u67.revealed).unwrap(),
            vec![("e8".into(), "u8".into())]
        );

        let b2 = s.lookup_unencrypted("b2", b"u1");
        assert_eq!(b2.base.as_ref().unwrap().encrypted, b"e1'");
        assert_eq!(remaining_strs(&b2.remaining), Vec::<String>::new());

        let b3 = s.lookup_unencrypted("b3", b"");
        assert_eq!(&b3.base.as_ref().unwrap().key.as_bytes()[..2], b"m1");
        assert!(!b3.base.as_ref().unwrap().default);

        let b3z = s.lookup_unencrypted("b3", b"z1");
        assert_eq!(&b3z.base.as_ref().unwrap().key.as_bytes()[..2], b"m1");
        assert_eq!(remaining_strs(&b3z.remaining), vec!["z1"]);
    }

    #[test]
    fn lookup_encrypted_remainders_match_go() {
        let s = sample_store();
        let e1 = s.lookup_encrypted("b1", b"e1");
        assert!(e1.base.is_none());
        let mut revealed = revealed_pairs(&e1.revealed).unwrap();
        revealed.sort();
        assert_eq!(
            revealed,
            vec![("u2".into(), "e2".into()), ("u5".into(), "e5".into()),]
        );

        let e1236 = s.lookup_encrypted("b1", b"e1/e2/e3/e6");
        assert_eq!(e1236.base.as_ref().unwrap().encrypted, b"e1/e2/e3");
        assert_eq!(remaining_strs(&e1236.remaining), vec!["e6"]);
        assert!(e1236.revealed.is_none());
    }

    #[test]
    fn default_key_remainder_is_full_path() {
        let mut s = Store::new();
        s.set_default_key(key("dk"));
        s.set_default_path_cipher(CipherSuite::AES_GCM);
        s.add_with_cipher(
            "b1",
            b"u1/u2/u3",
            b"e1/e2/e3",
            key("k3"),
            CipherSuite::AES_GCM,
        )
        .unwrap();

        let u1 = s.lookup_unencrypted("b1", b"u1");
        assert!(u1.base.as_ref().unwrap().default);
        assert_eq!(remaining_strs(&u1.remaining), vec!["u1"]);
        assert!(u1.revealed.is_none());

        let u12 = s.lookup_unencrypted("b1", b"u1/u2");
        assert!(u12.base.as_ref().unwrap().default);
        assert_eq!(remaining_strs(&u12.remaining), vec!["u1", "u2"]);

        let u123 = s.lookup_unencrypted("b1", b"u1/u2/u3");
        assert!(!u123.base.as_ref().unwrap().default);
        assert_eq!(u123.base.as_ref().unwrap().unencrypted, b"u1/u2/u3");
        assert_eq!(remaining_strs(&u123.remaining), Vec::<String>::new());

        let u1234 = s.lookup_unencrypted("b1", b"u1/u2/u3/u4");
        assert!(!u1234.base.as_ref().unwrap().default);
        assert_eq!(remaining_strs(&u1234.remaining), vec!["u4"]);
    }

    #[test]
    fn add_rejects_component_count_mismatch_and_conflicts() {
        let mut s = Store::new();
        assert!(
            s.add_with_cipher("b1", b"u1", b"e1/e2/e3", key("k"), CipherSuite::AES_GCM)
                .is_err()
        );
        assert!(
            s.add_with_cipher("b1", b"u1/u2/u3", b"e1", key("k"), CipherSuite::AES_GCM)
                .is_err()
        );
        s.add_with_cipher("b1", b"u1", b"e1", key("k"), CipherSuite::AES_GCM)
            .unwrap();
        assert!(
            s.add_with_cipher("b1", b"u2", b"e1", key("k"), CipherSuite::AES_GCM)
                .is_err()
        );
        assert!(
            s.add_with_cipher("b1", b"u1", b"f1", key("k"), CipherSuite::AES_GCM)
                .is_err()
        );
    }

    #[test]
    fn failed_add_does_not_mutate() {
        let mut s = Store::new();
        let before = s.lookup_unencrypted("b1", b"u1/u2");
        assert!(
            s.add_with_cipher("b1", b"u1/u2", b"e1/e2/e3", key("k"), CipherSuite::AES_GCM)
                .is_err()
        );
        let after = s.lookup_unencrypted("b1", b"u1/u2");
        assert_eq!(before.base.is_some(), after.base.is_some());
        assert_eq!(
            remaining_strs(&before.remaining),
            remaining_strs(&after.remaining)
        );
    }

    #[test]
    fn encryption_bypass_rewrites_cipher() {
        let mut s = Store::new();
        s.set_default_key(key("dk"));
        s.set_default_path_cipher(CipherSuite::AES_GCM);
        let lookup = s.lookup_unencrypted("bucket", b"");
        assert_eq!(lookup.base.unwrap().path_cipher, CipherSuite::AES_GCM);

        s.encryption_bypass = true;
        let lookup = s.lookup_unencrypted("bucket", b"");
        assert_eq!(
            lookup.base.unwrap().path_cipher,
            CipherSuite::NULL_BASE64_URL
        );
    }
}
