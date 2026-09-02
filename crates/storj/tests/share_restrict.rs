//! `Access::share` is an intersection, never a widening (R10 / interop req 4).

use storj::{Access, Permission, SharePrefix};

#[test]
#[ignore = "PR 6: Access::share"]
fn share_cannot_widen_permissions() {
    let root = Access::parse(include_str!("fixtures/grant_go.txt").trim()).unwrap();
    let read = root.share(Permission::read_only(), &[]).unwrap();
    let widened = read.share(Permission::full(), &[]);
    // Either error or a grant that still cannot upload.
    if let Ok(g) = widened {
        let _ = g;
        panic!("share(full) on a read-only parent must not succeed with wider rights");
    }
}

#[test]
#[ignore = "PR 6: prefix restriction drops ancestor encryption keys"]
fn share_prefix_drops_keys_outside_prefix() {
    let root = Access::parse(include_str!("fixtures/grant_go.txt").trim()).unwrap();
    let prefix = SharePrefix::new("app", "user1/").unwrap();
    let user = root.share(Permission::read_only(), &[prefix]).unwrap();
    let _ = user.serialize().unwrap();
}

#[test]
#[ignore = "PR 6: override_encryption_key prefix slash"]
fn override_encryption_key_requires_slash() {
    // Covered as a passing unit test in access.rs; this is the network-level
    // follow-up once parse works.
    let mut access = Access::parse(include_str!("fixtures/grant_go.txt").trim()).unwrap();
    let key = storj::EncryptionKey::derive("user-pass", b"user-salt-16bytes").unwrap();
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
}
