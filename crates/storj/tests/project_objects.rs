//! Object metadata operations (PR 23) and list prefix rules.

use futures_util::StreamExt;
use storj::{ErrorKind, ListObjectsOptions, Project};

#[tokio::test]
#[ignore = "PR 23: object metadata"]
async fn stat_delete_copy_move() {
    let project = open_test_project().await;
    let _ = (
        project.stat_object("b", "k").await,
        project.delete_object("b", "k").await,
        project.copy_object("b", "k", "b", "k2").await,
        project.move_object("b", "k2", "b", "k3").await,
    );
}

#[tokio::test]
#[ignore = "PR 23: delete_object Option semantics"]
async fn delete_object_returns_none_without_read() {
    // Grant with delete but not download/list → Ok(None), not ObjectNotFound.
    let project = open_test_project().await;
    let deleted = project
        .delete_object("b", "missing-or-no-read")
        .await
        .unwrap();
    assert!(deleted.is_none());
}

#[tokio::test]
async fn list_objects_rejects_prefix_without_slash() {
    // This validation is implemented now (no satellite required).
    // We cannot construct a Project without open(), so we test the options type
    // and the stream helper via a compile-only path: ListObjectsOptions::validate.
    let opts = ListObjectsOptions {
        prefix: "no-slash".into(),
        ..Default::default()
    };
    assert_eq!(
        opts.validate().unwrap_err().kind(),
        ErrorKind::ObjectKeyInvalid
    );
}

#[tokio::test]
#[ignore = "PR 23: listing streams"]
async fn list_objects_stream() {
    let project = open_test_project().await;
    let mut s = project.list_objects(
        "b",
        ListObjectsOptions {
            prefix: "p/".into(),
            recursive: true,
            system: true,
            custom: true,
            cursor: String::new(),
        },
    );
    while let Some(item) = s.next().await {
        let _ = item.unwrap();
    }
}

async fn open_test_project() -> Project {
    panic!("needs mock satellite or STORJ_SIM_ACCESS");
}
