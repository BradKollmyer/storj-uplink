# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The public API is `storj::*` only. Internal crates (`storj-access`, `storj-proto`,
`storj-rpc`, `storj-encryption`, `storj-ec`, `storj-uplink`, `storj-test`) stay
unpublished.

## [Unreleased]

### Changed

- The GitHub repository is public. CI and grant-roundtrip interop run on `main`
  and pull requests (not every feature-branch push), with concurrency
  cancellation. Fork pull requests never receive `STORJ_SIM_ACCESS`.

### Fixed

- **Wire compatibility:** order-limit and piece-hash signatures are now verified
  against the peer's *leaf* certificate (Go `SigneeFromPeerIdentity`), and the
  uplink signs with its leaf key. 1.0.0 verified against the CA key, which
  fails every remote-segment upload/download against a real satellite.
- `RetryBeginSegmentPieces` responses are indexed by piece number (the satellite
  returns the full limit list), so retry rounds upload under the right limits.
- Multipart abort sends only `BeginDeleteObject` (Go never calls
  `FinishDeleteObject`, which the satellite does not implement).
- `list_uploads` with a prefix decrypts prefix-relative keys with the parent
  key and sends a prefix-relative cursor, like `list_objects`.
- Every DRPC read/write now has a deadline (10 min default), a cancelled write
  poisons the connection so it is never recycled, transport-failed connections
  are dropped from the storage-node pool, and idle connections expire.
- `CommitObject`/`CommitSegment`/`Begin*`/delete batches are no longer retried on
  transport errors (design: not idempotent); reads keep exponential backoff with jitter.
- `Access::parse` applies `LimitTo` like Go `ParseAccess`, dropping the root key
  from a path-caveated grant.
- Error mapping no longer turns any `InvalidArgument`/`FailedPrecondition`/
  `NotFound` into bucket/object kinds merely because a bucket or key was in scope;
  `Unauthenticated` maps to `PermissionDenied`.
- A failed background segment flush is sticky: later writes and `commit` fail
  instead of publishing an object with a missing segment.
- Pieces that finished while the long tail was being cancelled are reported to
  `CommitSegment`; threshold failures include recent piece errors.
- `proto_timestamp` and block/range math no longer panic on satellite extremes.
- `cargo deny check` and `proto/check-pin.sh` pass again; rustdoc is warning-free.
- Satellite RPCs use a small connection pool (up to 8) instead of one locked
  connection, so concurrent uploads no longer serialize on every segment RPC.
- Download orders are allocated incrementally (initial step, 1.5x growth) like
  Go, so a long-tail-cancelled piece is only settled for what was read.
- `Access::parse` stores the canonical macaroon, rejects conflicting store
  entries, and never rewrites non-UTF-8 bucket names.
- Go-signed `OrderLimit`/`PieceHash` goldens (`signed_go.jsonl`) verify with the
  leaf certificate and are rejected by the CA certificate.
- **Found by the first live runs against a production satellite** (the full
  Go↔Rust size matrix, including 64 MiB+1, now passes there and against storj-sim):
  - TLS peer verification accepts signed identity chains (`leaf, CA, signer`)
    like Go `peertls`; 1.0.0 required the CA to be self-signed and could not
    open a `Project` against a real satellite.
  - Order-limit / piece-hash signing bytes omit Go-zero timestamps (year-1
    seconds on the wire) and zero keys, matching `signing.EncodeOrderLimit`;
    every limit without a piece expiration failed verification before.
  - Encrypted segments are padded with Go's length-trailer padding before
    erasure coding, so piece sizes match the satellite's `CalcPieceSize`.
  - `CommitSegment` pieces are sorted by piece number (metabase rejects
    unordered pieces).
  - The mocks now present signed identity chains and enforce piece sizes and
    ordering, so these paths are covered without a satellite.

### Added

- `Config.message_timeout` (per-read/write deadline, default 10 min).
- `UploadOptions.retention` / `UploadOptions.legal_hold`, sent in `BeginObject`.
- `storj-ec`: NEON/SSSE3 `addmul` (≈8x scalar), `ReedSolomon::decode_plan`
  (matrix inverted once per share set), in-place stripe encoding.
- `storj-encryption`: in-place block transforms, in-place store adds, redacted
  `Debug` for `Store`/`Lookup`/`PathIter`, zeroized derivation scratch.
- `cargo-fuzz` targets under `fuzz/` (DRPC frames, macaroons, grants, path
  components, CompressedBatch).
- Mock satellite enforces `disallow_*` caveats per RPC; mock storage node honors
  download order allocation and verifies orders and the uplink piece hash.

### Changed

- **Breaking:** `storj::encryption` no longer re-exports `storj_encryption`
  internals; only `EncryptionKey` and `derive_root_key` remain public.
- **Breaking:** `Object`, `UploadInfo`, `Part` and `RetentionMode` are
  `#[non_exhaustive]`; `Object` gained `version` (pass it to Object Lock calls).
- Repository name is `storj-uplink` (was `storj-rust`). The public crate remains `storj`.
- CI: rustdoc, MSRV (1.85) and Linux/macOS/Windows jobs; `--locked`; read-only
  token; whole-fixture staleness check; nightly object matrix when the
  `STORJ_SIM_ACCESS` secret is present.
- aarch64 builds enable ARMv8 AES/PMULL via `.cargo/config.toml` (~10x AES-GCM).

## [1.0.0] - 2026-09-02

Native Uplink API freeze. This crate is not a wrapper around `uplink-c` and is
not a drop-in for crates.io `uplink` 0.11.0 (blocking FFI, `!Send`).

### Added

- Multi-segment upload/download, including objects larger than one 64 MiB segment
- Object list, stat, delete, copy, and move
- Multipart uploads (`begin_upload` / `upload_part` / `commit_upload` / abort / list)
- `revoke_access`, `update_object_metadata`, `upload_from` / `download_to`
- Object Lock: retention, legal hold, and bucket lock configuration
- Go↔Rust writer/reader size matrix test including `64MiB+1` (opt-in: gated on
  `STORJ_INTEROP` plus a live grant; it was not run in CI for this release)

### Notes

- MSRV is 1.85 (edition 2024)
- Dual-licensed MIT OR Apache-2.0
- Consume via git or path: internal crates are `publish = false`, so
  `cargo publish -p storj` is not possible yet
- Edge / GatewayMT (`storj::edge`) is specified for 1.x and is not in this
  release
