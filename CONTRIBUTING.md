# Contributing

Thanks for contributing to `storj-uplink`.

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

Contributions are dual-licensed **MIT OR Apache-2.0**, the same as the crate.
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE). There is
no CLA.

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) 1.1. Every commit must include:

```
Signed-off-by: Your Name <you@example.com>
```

Create commits with `git commit -s` so Git adds that line from `user.name` /
`user.email`. Use your real name.

By signing off, you certify that you wrote the change or otherwise have the
right to submit it under the project license(s).

## Toolchain

- **MSRV:** 1.85
- **Edition:** 2024

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc -p storj --no-deps
```

## Go

Go is **not** required to build or use the crate. It is used only to generate
goldens (`go run -C scripts .`) and in the optional interop CI job. Do not add
a Go toolchain requirement to `cargo build` of dependents.

## Public API

The published surface is `storj::*` only. Implementation crates are on
crates.io so Cargo can resolve them; do not treat their APIs as stable.
`storj-test` stays `publish = false`. Do not expand the public API without a
CHANGELOG entry.

## Packaging

Publish in dependency order. Never publish `storj-test`.

```bash
cargo publish -p storj-proto
cargo publish -p storj-ec
cargo publish -p storj-encryption
cargo publish -p storj-rpc
cargo publish -p storj-access
cargo publish -p storj-uplink
cargo publish -p storj
```

Workspace path deps include `version` so Cargo rewrites them to registry deps
on publish. Wait for the index if a later crate cannot yet see an earlier one.
