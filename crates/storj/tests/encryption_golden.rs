//! Encryption goldens vs `storj.io/common/encryption`.
//!
//! Generate with `go run -C scripts .`.

use std::fs;

use storj::EncryptionKey;
use storj::constants::{ARGON2_PARALLELISM_REQUEST, ENCRYPTION_BLOCK_SIZE};
use storj::encryption::{
    CipherSuite, EncryptionParameters, Store, calc_encompassing_blocks, calc_encrypted_size,
    decrypt, decrypt_path, derive_path_key_component, derive_root_key, encrypt, encrypt_path,
    encrypt_prefix, increment_bytes, pad, unpad,
};

#[derive(Debug)]
struct DeriveVector {
    passphrase: String,
    salt_hex: String,
    path: String,
    parallelism: u32,
    key_hex: String,
}

fn parse_json_lines(path: &str) -> Vec<DeriveVector> {
    let text = fs::read_to_string(storj_test::fixture(path))
        .unwrap_or_else(|e| panic!("missing fixture {path} ({e}). Run: go run -C scripts ."));
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
    let text = fs::read_to_string(storj_test::fixture("path_hmac.jsonl"))
        .unwrap_or_else(|e| panic!("missing path_hmac.jsonl ({e}). Run: go run -C scripts ."));
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

/// Go `encryption.ExampleEncryptPath` (pkg.go.dev/storj.io/common/encryption).
///
/// Seed `00..1f`, bucket `bucket`, path `fold1/fold2/fold3/file.txt`, EncAESGCM.
/// Locks 12-byte AES-GCM nonce packing (a 24-byte packing bug still round-trips).
const GO_EXAMPLE_ENCRYPT_PATH_HEX: &str = "02387ce34e2054bcb9a0428b820102876eef8325a8397bf7568e91afc40739406ffad12f02453d291b9cb8947155462d6c1edc2367507b0de55b46fa7231f3ba6ad7ce79f4822f02ad7257e8ef4f938ac6b6794b50852873d1b3d32e018dfb17a674dc806ac6e8ddd4262f02aa2128dc8614940f7cf6628513b581f7c18724af3c01018f7c861520c2fdfd78f7b1b25ce0";

#[test]
fn encrypt_path_matches_go_example() {
    let seed: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).expect("i < 32"));
    let mut store = Store::new();
    store.set_default_key(EncryptionKey::from_bytes(seed).inner().clone());
    store.set_default_path_cipher(CipherSuite::AES_GCM);

    let enc = encrypt_path("bucket", "fold1/fold2/fold3/file.txt", &store).unwrap();
    assert_eq!(hex::encode(&enc), GO_EXAMPLE_ENCRYPT_PATH_HEX);

    let dec = decrypt_path("bucket", &enc, &store).unwrap();
    assert_eq!(dec, b"fold1/fold2/fold3/file.txt");
}

#[test]
fn path_encrypt_decrypt_empty_unicode_prefixes() {
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

/// Go `nacl/secretbox.Seal` + `crypto/aes` GCM, key `00..1f`, nonce zeros, pt `hello`.
#[test]
fn content_encrypt_matches_go_primitives() {
    let key = EncryptionKey::from_bytes(std::array::from_fn(|i| u8::try_from(i).expect("i < 32")));
    let nonce = [0u8; 24];
    let aes = encrypt(b"hello", CipherSuite::AES_GCM, key.inner(), &nonce).unwrap();
    assert_eq!(
        hex::encode(&aes),
        "66d9d9b2da0e0c4679f3a82524f5e0499271e16f30"
    );
    let sb = encrypt(b"hello", CipherSuite::SECRET_BOX, key.inner(), &nonce).unwrap();
    assert_eq!(
        hex::encode(&sb),
        "9031d88e6447f0b8bf44357c58bf25f4226b9c2df7"
    );
    assert_eq!(
        decrypt(&aes, CipherSuite::AES_GCM, key.inner(), &nonce).unwrap(),
        b"hello"
    );
    assert_eq!(
        decrypt(&sb, CipherSuite::SECRET_BOX, key.inner(), &nonce).unwrap(),
        b"hello"
    );
}

#[test]
fn nonce_increment_pad_and_encrypted_size_match_go() {
    let mut buf = [0u8, 0, 0, 0];
    assert!(!increment_bytes(&mut buf, 1).unwrap());
    assert_eq!(buf, [1, 0, 0, 0]);

    let mut wrap = [255u8, 0, 0, 0];
    assert!(!increment_bytes(&mut wrap, 1).unwrap());
    assert_eq!(wrap, [0, 1, 0, 0]);

    assert_eq!(hex::encode(pad(b"hi", 8).unwrap()), "6869000000000006");
    assert_eq!(unpad(&pad(b"hi", 8).unwrap()).unwrap(), b"hi");

    let aes = EncryptionParameters {
        cipher_suite: CipherSuite::AES_GCM,
        block_size: 1024,
    };
    assert_eq!(calc_encrypted_size(0, aes).unwrap(), 1024);
    assert_eq!(calc_encrypted_size(1, aes).unwrap(), 1024);
    assert_eq!(calc_encrypted_size(1020, aes).unwrap(), 2048);

    assert_eq!(calc_encompassing_blocks(0, 11, 10), (0, 2));
    assert_eq!(
        calc_encompassing_blocks(1, ENCRYPTION_BLOCK_SIZE as i64, ENCRYPTION_BLOCK_SIZE),
        (0, 2)
    );
}
