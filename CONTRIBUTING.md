# Contributing

Thanks for contributing to `storj-rust`.

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

The published (git/path) surface is `storj::*` only. Internal crates stay
`publish = false`. Do not expand the public API without a CHANGELOG entry.

## Packaging

Do not `cargo publish -p storj` yet: internal crates are path-only and
`publish = false`, so the facade cannot be packaged for crates.io. Consume 1.0
via git or path until internals are published.
