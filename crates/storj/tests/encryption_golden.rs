//! Encryption goldens vs `storj.io/common/encryption`.
//!
//! Generate with `go run ./scripts/gen-vectors.go`.

use std::fs;

use storj::EncryptionKey;
use storj::constants::ARGON2_PARALLELISM_REQUEST;
use storj::encryption::{derive_path_key_component, derive_root_key};

#[derive(Debug)]
struct DeriveVector {
    passphrase: String,
    salt_hex: String,
    path: String,
    parallelism: u32,
    key_hex: String,
}

fn parse_json_lines(path: &str) -> Vec<DeriveVector> {
    let text = fs::read_to_string(storj_test::fixture(path)).unwrap_or_else(|e| {
        panic!("missing fixture {path} ({e}). Run: go run ./scripts/gen-vectors.go")
    });
    // Minimal JSON object parser for the generator's stable shape:
    // {"passphrase":"...","salt_hex":"...","path":"...","parallelism":1,"key_hex":"..."}
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .map(|line| {
            let get = |k: &str| -> String {
                let key = format!("\"{k}\":");
                let i = line
                    .find(&key)
                    .unwrap_or_else(|| panic!("key {k} in {line}"));
                let rest = &line[i + key.len()..];
                let rest = rest.trim_start();
                if let Some(stripped) = rest.strip_prefix('"') {
                    let end = stripped.find('"').expect("string");
                    stripped[..end].to_string()
                } else {
                    rest.split([',', '}']).next().unwrap().trim().to_string()
                }
            };
            DeriveVector {
                passphrase: get("passphrase"),
                salt_hex: get("salt_hex"),
                path: get("path"),
                parallelism: get("parallelism").parse().unwrap(),
                key_hex: get("key_hex"),
            }
        })
        .collect()
}

#[test]
fn derive_root_key_matches_go() {
    let vectors = parse_json_lines("derive_root_key.jsonl");
    assert!(!vectors.is_empty(), "fixture has no vectors");
    for v in vectors {
        let salt = hex::decode(&v.salt_hex).expect("salt hex");
        let got = derive_root_key(
            v.passphrase.as_bytes(),
            &salt,
            v.path.as_bytes(),
            v.parallelism,
        )
        .unwrap();
        assert_eq!(
            hex::encode(got.as_bytes()),
            v.key_hex,
            "p={} path={:?}",
            v.parallelism,
            v.path
        );
        if v.parallelism == 1 && v.path.is_empty() {
            let api = EncryptionKey::derive(&v.passphrase, &salt).unwrap();
            assert_eq!(hex::encode(api.as_bytes()), v.key_hex);
        }
        if v.parallelism == ARGON2_PARALLELISM_REQUEST {
            assert_ne!(v.parallelism, 1);
        }
    }
}

#[test]
fn path_component_matches_go() {
    let text = fs::read_to_string(storj_test::fixture("path_hmac.jsonl")).unwrap_or_else(|e| {
        panic!("missing path_hmac.jsonl ({e}). Run: go run ./scripts/gen-vectors.go")
    });
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let get = |k: &str| {
            let key = format!("\"{k}\":\"");
            let i = line.find(&key).unwrap();
            let rest = &line[i + key.len()..];
            rest.split('"').next().unwrap().to_string()
        };
        let key = hex::decode(get("key_hex")).unwrap();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);
        let got = derive_path_key_component(&key_arr, &get("component"));
        assert_eq!(hex::encode(got), get("out_hex"));
    }
}

#[test]
fn path_encrypt_decrypt_empty_unicode_prefixes() {
    use storj::encryption::{CipherSuite, Store, decrypt_path, encrypt_path, encrypt_prefix};

    let mut store = Store::new();
    store.set_default_key(EncryptionKey::from_bytes([7u8; 32]).inner().clone());
    store.set_default_path_cipher(CipherSuite::AES_GCM);

    for path in [
        "",
        "/",
        "file.txt",
        "file.txt/",
        "café",
        "café/naïve",
        "logs/",
    ] {
        let enc = encrypt_path("bucket", path, &store).unwrap();
        let dec = decrypt_path("bucket", &enc, &store).unwrap();
        assert_eq!(dec, path.as_bytes(), "path={path:?}");

        let penc = encrypt_prefix("bucket", path, &store).unwrap();
        assert_eq!(path.ends_with('/'), penc.ends_with(b"/"), "prefix {path:?}");
        let pdec = decrypt_path("bucket", &penc, &store).unwrap();
        assert_eq!(pdec, path.as_bytes(), "prefix path={path:?}");
    }
}
