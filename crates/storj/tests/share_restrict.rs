//! `Access::share` is an intersection, never a widening (R10 / interop req 4).

use storj::{Access, EncryptionKey, Permission, SharePrefix};
use storj_access::{ApiKey, Caveat, Grant};

fn parse_fixture() -> Access {
    Access::parse(include_str!("fixtures/grant_go.txt").trim()).unwrap()
}

fn grant_caveats(access: &Access) -> Vec<Caveat> {
    let g = Grant::parse(&access.serialize().unwrap()).unwrap();
    let key = ApiKey::parse_raw(g.api_key()).unwrap();
    key.macaroon()
        .caveats()
        .iter()
        .map(|c| Caveat::decode(c).unwrap())
        .collect()
}

fn parsed_grant(access: &Access) -> Grant {
    Grant::parse(&access.serialize().unwrap()).unwrap()
}

#[test]
fn share_cannot_widen_permissions() {
    let root = parse_fixture();
    let original = root.serialize().unwrap();
    let read = root.share(Permission::read_only(), &[]).unwrap();
    assert_eq!(
        root.serialize().unwrap(),
        original,
        "share must not mutate the parent"
    );

    let read_cavs = grant_caveats(&read);
    assert_eq!(read_cavs.len(), 1);
    assert!(read_cavs[0].disallow_writes && read_cavs[0].disallow_deletes);
    assert!(!read_cavs[0].disallow_reads && !read_cavs[0].disallow_lists);

    let widened = read.share(Permission::full(), &[]).unwrap();
    let cavs = grant_caveats(&widened);
    assert!(
        cavs.iter().any(|c| c.disallow_writes),
        "share(full) on a read-only parent must not succeed with wider rights"
    );
}

#[test]
fn share_prefix_drops_keys_outside_prefix() {
    let root = parse_fixture();
    let prefix = SharePrefix::new("app", "user1/").unwrap();
    let user = root.share(Permission::read_only(), &[prefix]).unwrap();
    let g = parsed_grant(&user);
    assert!(
        g.enc_access().default_key.is_none(),
        "ancestor default key must be dropped"
    );
    assert_eq!(g.enc_access().store_entries.len(), 1);
    let entry = &g.enc_access().store_entries[0];
    assert_eq!(entry.bucket, b"app");
    assert_eq!(entry.unencrypted_path, b"user1");
    assert_eq!(entry.key, [0x44; 32]);
    let _ = user.serialize().unwrap();
}

#[test]
fn override_encryption_key_requires_slash() {
    let mut access = parse_fixture();
    let key = EncryptionKey::derive("user-pass", b"user-salt-16bytes").unwrap();
    assert!(
        access
            .override_encryption_key("app", "user1", &key)
            .is_err()
    );
    assert!(
        access
            .override_encryption_key("app", "user1/", &key)
            .is_ok()
    );
    let g = parsed_grant(&access);
    let entry = g
        .enc_access()
        .store_entries
        .iter()
        .find(|e| e.unencrypted_path == b"user1")
        .expect("user1 store entry");
    assert_eq!(entry.key, *key.as_bytes());
}

#[test]
fn share_maps_allow_lock_onto_granular_bits() {
    let root = parse_fixture();
    let shared = root
        .share(
            Permission {
                allow_lock: true,
                ..Permission::default()
            },
            &[],
        )
        .unwrap();
    let cavs = grant_caveats(&shared);
    assert_eq!(cavs.len(), 1);
    assert!(
        cavs[0].disallow_locks,
        "deprecated coarse lock flag is not granted"
    );
    assert!(
        !cavs[0].disallow_put_retention
            && !cavs[0].disallow_get_retention
            && !cavs[0].disallow_put_bucket_object_lock_configuration
            && !cavs[0].disallow_get_bucket_object_lock_configuration,
        "allow_lock maps onto granular Object Lock bits"
    );
    assert!(cavs[0].disallow_put_legal_hold && cavs[0].disallow_get_legal_hold);
}

#[test]
fn share_empty_permission_is_error() {
    let root = parse_fixture();
    let e = root.share(Permission::default(), &[]).unwrap_err();
    assert_eq!(e.kind(), storj::ErrorKind::InvalidGrant);
    assert!(e.to_string().contains("permission is empty"));
}
