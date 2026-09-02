# storj-rust

Native Rust [Uplink](https://pkg.go.dev/storj.io/uplink) client for [Storj](https://storj.io).

**1.0.0** is the native Uplink API freeze of the public `storj::*` surface:
access grants, buckets, objects, multi-segment I/O, listing, copy/move,
multipart, revoke, and Object Lock. Edge / GatewayMT is an optional later
feature and is not required for 1.0.

The published crate is [`storj`](https://crates.io/crates/storj). It implements
the Storj client protocol in Rust (Tokio + rustls): access grants, satellite
metainfo, storage-node piecestore, and client-side encryption. Design:
[docs/design-native-uplink.md](docs/design-native-uplink.md).

## Walkthrough

See the [target walkthrough](docs/design-native-uplink.md) in the design doc
(`Example (target walkthrough)`) and the crate rustdoc example on
[`storj`](https://docs.rs/storj).

```rust
use storj::{Access, Project};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> storj::Result<()> {
    let access = Access::parse(&std::env::args().nth(1).expect("grant"))?;
    let project = Project::open(&access).await?;
    project.ensure_bucket("logs").await?;

    let mut upload = project
        .upload_object("logs", "2026-09-01/app.log", Default::default())
        .await?;
    upload.write_all(b"hello storj").await?;
    let _obj = upload.commit().await?;
    Ok(())
}
```

## MSRV

Rust 1.85 (edition 2024).

## Non-goals

This is **not**:

- an S3 SDK (use GatewayMT + `aws-sdk-s3` / `object_store` if you want S3)
- an FFI wrapper around [`uplink-c`](https://github.com/storj/uplink-c)
- a drop-in for crates.io [`uplink` 0.11.0](https://docs.rs/uplink/0.11.0/uplink/) (May 2025); that crate is blocking FFI and `!Send`

Go is **not** required to build or use the crate. It is only used to generate goldens and in the optional interop CI job.

## License

Dual-licensed MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Tests

```bash
cargo test --workspace              # contract + mock (no Go / satellite)
cargo test -p storj --test interop -- --ignored   # needs STORJ_INTEROP=1 (+ grant for objects)
go run -C scripts .                 # Argon2 / path-HMAC / grant goldens
```

See [crates/storj/tests/README.md](crates/storj/tests/README.md).
