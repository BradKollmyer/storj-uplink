# storj-rust

Native Rust Uplink client for [Storj](https://storj.io). Not an FFI wrapper around `uplink-c`, and not a drop-in for crates.io `uplink` 0.11.0 (May 2025).

Design: [`docs/design-native-uplink.md`](docs/design-native-uplink.md).

## Tests

```bash
cargo test -p storj                 # contract suite (no network)
cargo test -p storj -- --ignored    # protocol/interop (expected fail until implemented)
go run -C scripts .                 # Argon2 / path-HMAC goldens
```

See [`crates/storj/tests/README.md`](crates/storj/tests/README.md).

Go is **not** required to build or use the crate. It is only used to generate goldens and in the optional interop CI job.
