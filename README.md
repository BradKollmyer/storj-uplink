# storj-rust

Native Rust [Uplink](https://pkg.go.dev/storj.io/uplink) client for [Storj](https://storj.io).

The published crate is [`storj`](https://crates.io/crates/storj). It implements the Storj client protocol in Rust (Tokio + rustls): access grants, satellite metainfo, storage-node piecestore, and client-side encryption. Design: [docs/design-native-uplink.md](https://github.com/storj/storj-rust/blob/main/docs/design-native-uplink.md).

## Non-goals

This is **not**:

- an S3 SDK (use GatewayMT + `aws-sdk-s3` / `object_store` if you want S3)
- an FFI wrapper around [`uplink-c`](https://github.com/storj/uplink-c)
- a drop-in for crates.io [`uplink` 0.11.0](https://docs.rs/uplink/0.11.0/uplink/) (May 2025); that crate is blocking FFI and `!Send`

Go is **not** required to build or use the crate. It is only used to generate goldens and in the optional interop CI job.

## License

Dual-licensed MIT OR Apache-2.0. See [LICENSE-MIT](https://github.com/storj/storj-rust/blob/main/LICENSE-MIT) and [LICENSE-APACHE](https://github.com/storj/storj-rust/blob/main/LICENSE-APACHE).

## Tests

```bash
cargo test -p storj                 # contract suite (no network)
cargo test -p storj -- --ignored    # protocol/interop (expected fail until implemented)
go run -C scripts .                 # Argon2 / path-HMAC / grant goldens
```

See [crates/storj/tests/README.md](https://github.com/storj/storj-rust/blob/main/crates/storj/tests/README.md).
