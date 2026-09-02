# storj-rust

Native Rust [Uplink](https://pkg.go.dev/storj.io/uplink) client for [Storj](https://storj.io).

**1.0.0** freezes the public `storj::*` API: access grants, buckets, objects
(multi-segment upload/download), listing, copy/move, multipart, revoke, and
Object Lock. Spec: [docs/design-native-uplink.md](docs/design-native-uplink.md).

This is **not** an S3 SDK, **not** an FFI wrapper around
[`uplink-c`](https://github.com/storj/uplink-c), and **not** a drop-in for
crates.io [`uplink` 0.11.0](https://docs.rs/uplink/0.11.0/uplink/) (blocking,
`!Send`). Go is never required to build or use the crate.

`storj::edge` (GatewayMT / linksharing) is specified for 1.x and is not in this
tree.

## Install

Internal crates are workspace-only (`publish = false`), so 1.0.0 is consumed
via git or path. Callers need their own Tokio runtime; `tokio` is not
re-exported.

```toml
[dependencies]
storj = { git = "https://github.com/storj/storj-rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "io-util"] }
```

From this workspace: `storj = { path = "crates/storj" }`.

## Quick start

Parse an access grant, open a project, upload and download. Full CLI:
[`crates/storj/examples/walkthrough.rs`](crates/storj/examples/walkthrough.rs).

```rust
use storj::{Access, Project};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> storj::Result<()> {
    let access = Access::parse(&std::env::args().nth(1).expect("grant"))?;
    let project = Project::open(&access).await?;
    project.ensure_bucket("logs").await?;

    let mut upload = project
        .upload_object("logs", "hello.txt", Default::default())
        .await?;
    upload.write_all(b"hello storj").await?;
    let _obj = upload.commit().await?;

    let mut download = project
        .download_object("logs", "hello.txt", Default::default())
        .await?;
    let mut buf = Vec::new();
    tokio::io::copy(&mut download, &mut buf).await?;
    download.close().await?;
    project.close().await?;
    Ok(())
}
```

```bash
cargo run -p storj --example walkthrough -- "$STORJ_ACCESS"
```

`commit()` is the only path that publishes an upload. Dropping `Upload` without
`commit` aborts. `poll_shutdown` does not commit.

## Comparison with `uplink` 0.11.0 (FFI)

| `uplink` 0.11.0 | `storj` 1.0.0 |
|---|---|
| crate name `uplink` | crate name `storj` |
| `uplink::access::Grant` | `storj::Access` (`Access::parse`) |
| blocking `std::io` | Tokio `AsyncRead` / `AsyncWrite` |
| `Project`, `Grant`, … are `!Send + !Sync` | public handle types are `Send + Sync` |
| `Project::open` is infallible | `Project::open` returns `Result` |
| Go required at build time | Go never required to build or use |

## MSRV

Rust 1.85 (edition 2024).

## Tests

```bash
cargo test --workspace              # contract + mock satellite (no Go / live network)
go run -C scripts .                 # Argon2 / path-HMAC / grant goldens
STORJ_INTEROP=1 cargo test -p storj --test interop -- --ignored --skip writer_reader_size_matrix
```

Object-matrix interop and `storj-sim` need a live grant (`STORJ_INTEROP_ACCESS` /
`STORJ_SIM_ACCESS`). See [crates/storj/tests/README.md](crates/storj/tests/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changelog: [CHANGELOG.md](CHANGELOG.md).

## License

Dual-licensed MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
