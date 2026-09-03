# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A native Rust implementation of the Storj Uplink client (the Go reference is
`storj.io/uplink` and `storj.io/common`, pinned in `proto/README.md` and
`scripts/go.mod`). It speaks DRPC over TLS directly to satellites and storage
nodes; it is not an FFI wrapper. Only the `storj` crate is public API. Implementation crates are published to
crates.io so the facade can resolve; `storj-test` is `publish = false`. Go is
never needed to build or use the crate, only to regenerate test fixtures and
run the interop helper.

## Commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # CI uses --locked too
cargo test --workspace                                  # mock satellite + node, no network
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check                                        # pinned to 0.20.2 in CI
bash proto/check-pin.sh                                 # vendored protos vs upstream pin (network)
bash proto/gen-prost.sh                                 # regenerate crates/storj-proto/src/gen (must leave git clean)
```

Single tests:

```bash
cargo test -p storj --test mock_faults stalled_storage_node      # one integration test
cargo test -p storj-uplink orders::                               # unit tests by path
cargo test -p storj-ec --release -- --ignored addmul_throughput --nocapture   # bench-style
```

Fixtures (Go 1.25+ required):

```bash
go run -C scripts .        # regenerates crates/storj/tests/fixtures/*; CI fails if the diff is non-empty
```

`signed_go.jsonl` is generated only when missing (random identities); delete
it to regenerate. Bump `storj.io/*` pins in `scripts/go.mod`, `scripts/interop/go.mod`
and `proto/README.md` together.

CI runs on `main` and pull requests (not every feature-branch push).

Live tests (all `#[ignore]`, opt-in by env; they create and delete their own bucket):

```bash
STORJ_INTEROP=1 cargo test -p storj --test interop -- --ignored --skip writer_reader_size_matrix   # grant round trips, needs Go only
STORJ_SIM=1 STORJ_INTEROP=1 STORJ_SIM_ACCESS=<grant> cargo test -p storj --test sim --test interop -- --ignored --nocapture
```

The matrix test (`writer_reader_size_matrix`) runs all 24 writer×reader×size
cells and reports a summary; it takes ~2 min against a local storj-sim and
~8 min against a production satellite. `crates/storj/tests/README.md` has the
storj-sim recipe (`scripts/sim-pg.sh` starts Postgres via Docker or Apple
Container), including the two storj-sim patches it needs on macOS. The
nightly `interop` workflow runs both against the `STORJ_SIM_ACCESS` secret.

Fuzz targets live in `fuzz/` (excluded from the workspace, needs nightly and `cargo-fuzz`).

## Contributing rules that CI or reviewers enforce

- DCO: every commit needs `Signed-off-by:` — use `git commit -s`.
- MSRV 1.85 / edition 2024; CI has an MSRV job, so no newer std APIs.
- Workflows run with `--locked`; commit `Cargo.lock` changes.
- `.cargo/config.toml` sets `--cfg aes_armv8 --cfg polyval_armv8` on aarch64;
  without it AES-GCM is ~10x slower. Downstream users must set the same.
- Public option structs (`UploadOptions`, `Config`, …) stay constructible by
  literal; satellite-produced types (`Object`, `UploadInfo`, `Part`,
  `RetentionMode`, `ErrorKind`) are `#[non_exhaustive]`. Do not re-export
  internal-crate items from `storj` (that leak was removed after 1.0.0).

## Architecture

Crate layering, bottom up:

- `storj-proto`: prost types generated from `proto/*.proto` (vendored,
  byte-checked against the upstream pin) plus the zstd `CompressedBatch` codec
  (64 MiB cap). `caveat.proto` is deliberately not compiled here.
- `storj-rpc`: DRPC client (`conn.rs` frame codec, one RPC per connection,
  per-read/write deadline, `is_poisoned()` after a cancelled write), TLS with
  Storj NodeID pinning (`tls.rs`), identities and certificate-chain
  verification (`identity.rs`).
- `storj-encryption`: Argon2id root key, HMAC-SHA512 path/content key
  derivation, encrypted path components, AES-GCM/secretbox block transformers,
  the padding trailer (`pad`/`unpad`), and the prefix `Store`.
- `storj-ec`: Reed-Solomon compatible with Go `infectious` (SIMD `addmul`,
  `DecodePlan` cached per share set).
- `storj-access`: macaroon API keys and access grants (`Grant::parse` applies
  Go's `LimitTo`; `pb.rs` hand-maintains the grant/caveat wire types because
  caveat encode order matters for the HMAC).
- `storj-uplink`: the data plane. `pipeline.rs` (encrypt segment, pad, erasure
  encode into pieces), `orders.rs` (order-limit / order / piece-hash signing
  bytes), `piecestore.rs` (upload/download stream protocol with incremental
  orders), `segment.rs` (long-tail piece upload with `RetryBeginSegmentPieces`),
  `download.rs` (k+1 piece fan-out, decode), `pool.rs` (per-node connection
  pool with idle timeout).
- `storj`: the public facade. `metainfo.rs` is the satellite client (a small
  connection pool; retries only idempotent RPCs; error-code mapping scoped by
  RPC), `project.rs` holds the upload/download/multipart flows, `objects.rs`
  the listing key codec shared by object and pending-upload listing,
  `upload.rs` the `Upload`/`Download` handles.
- `storj-test`: mock satellite (`mock.rs`) and mock storage node
  (`mock_sn.rs`) that speak the real TCP+TLS+DRPC path with signed identity
  chains, plus `with_bucket_cleanup` for live tests.

Upload flow: `Project::upload_object` → `Upload` buffers up to 64 MiB, then
`spawn_flush_segment` encrypts, pads, and erasure-encodes on the blocking pool
→ `upload_pieces_long_tail` fans out to nodes and retries failed piece numbers
with fresh limits → `CommitSegment` with pieces sorted by number → `commit()`
sends `CommitObject`. Dropping an `Upload` without `commit` aborts it. Segments
≤ 4 KiB encrypted become inline segments.

Download flow: `download_object` resolves the segment list, then a spawned
producer fetches, decodes and decrypts one segment at a time with one-segment
lookahead; `Download` is an `AsyncRead` over that channel. Errors surface on
read, not on open (as in Go).

## Wire-compatibility rules learned the hard way

These all passed the mocks and failed against a real satellite; the mocks now
enforce them, and Go-produced fixtures pin several. Keep them true:

- Peers sign with the **leaf** key; verify order limits / piece hashes with
  `peer_certificates()[0]`, never the CA. NodeID comes from the CA (index 1).
- Production identities are `[leaf, CA, signer]`; verify each cert against the
  next and only the last as self-signed (`identity::verify_chain`).
- Signing bytes must match Go `signing.EncodeOrderLimit`: omit Go-zero
  timestamps (year-1 seconds on the wire) and zero keys. `signed_go.jsonl`
  carries Go's exact signing bytes for a full limit; diff against it.
- Encrypted segments are padded with the length-trailer padding (≥ 4 bytes)
  before erasure coding; piece size must equal `pipeline::calc_piece_size`.
- `CommitSegment` pieces must be sorted by piece number.
- `RetryBeginSegmentPieces` returns the full n-length limit list indexed by
  piece number. `FinishDeleteObject` is unimplemented on the satellite; abort is
  `BeginDeleteObject` alone. Listing responses (objects and pending uploads)
  carry prefix-relative keys encrypted under the prefix's parent key.
- Go never retries commit/begin/delete RPCs on transport errors; neither do we.

When a live run fails, the fastest loop is the local storj-sim (see the tests
README); the mocks should then be extended to reject the same input.
