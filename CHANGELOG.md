# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The public API is `storj::*` only. Internal crates (`storj-access`, `storj-proto`,
`storj-rpc`, `storj-encryption`, `storj-ec`, `storj-uplink`, `storj-test`) stay
unpublished.

## [Unreleased]

### Changed

- Repository name is `storj-uplink` (was `storj-rust`). The public crate remains `storj`.

## [1.0.0] - 2026-09-02

Native Uplink API freeze. This crate is not a wrapper around `uplink-c` and is
not a drop-in for crates.io `uplink` 0.11.0 (blocking FFI, `!Send`).

### Added

- Multi-segment upload/download, including objects larger than one 64 MiB segment
- Object list, stat, delete, copy, and move
- Multipart uploads (`begin_upload` / `upload_part` / `commit_upload` / abort / list)
- `revoke_access`, `update_object_metadata`, `upload_from` / `download_to`
- Object Lock: retention, legal hold, and bucket lock configuration
- Full Go↔Rust writer/reader size matrix including `64MiB+1` (gated on
  `STORJ_INTEROP` plus a live grant; not required of crate consumers)

### Notes

- MSRV is 1.85 (edition 2024)
- Dual-licensed MIT OR Apache-2.0
- Consume via git or path: internal crates are `publish = false`, so
  `cargo publish -p storj` is not possible yet
- Edge / GatewayMT (`storj::edge`) is specified for 1.x and is not in this
  release
