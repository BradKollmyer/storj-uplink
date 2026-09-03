# Test suite

Maps to `docs/design-native-uplink.md` § Testing Strategy.

`cargo test --workspace` runs contract tests and the in-process mock satellite
(no Go, no live network). Interop and sim tests are `#[ignore]` and need extra
env.

| File | Layer | Always runs? |
|---|---|---|
| `api_contract.rs` | Public API vs 2025 `uplink` 0.11 / Go uplink | yes |
| `error_mapping.rs` | Dual returns, I/O, kinds | yes |
| `encryption_kdf.rs` | Argon2id p=1 vs p=8, HMAC mix | yes |
| `encryption_golden.rs` | Go `DeriveRootKey` / path HMAC | yes |
| `grant_golden.rs` | Parse Go grants | yes |
| `share_restrict.rs` | `share()` intersection | yes |
| `ec_golden.rs` | infectious RS (Berlekamp-Welch still ignore) | yes |
| `signing_golden.rs` | Go-signed order limits / piece hashes verify with the leaf cert, not the CA | yes |
| `project_buckets.rs` | Bucket CRUD (mock) | yes |
| `project_objects.rs` | List/stat/delete/copy/move/revoke (mock) | yes |
| `upload_download.rs` | Pipeline including 64MiB+1 (mock) | yes |
| `multipart.rs` | Begin/Part/Commit (mock) | yes |
| `object_lock.rs` | Retention / legal hold (mock) | yes |
| `interop.rs` | Go↔Rust grant + size matrix including `64MiB+1` | ignore + `STORJ_INTEROP=1` (objects also need `STORJ_INTEROP_ACCESS` / `STORJ_SIM_ACCESS`) |
| `sim.rs` | `storj-sim` walkthrough | ignore + `STORJ_SIM=1` |

## Commands

```bash
cargo test -p storj                  # contract suite
go run -C scripts .                  # KDF + path HMAC + infectious RS + synthetic grant fixtures
go run -C scripts/interop . parse "$(tr -d '\n' < crates/storj/tests/fixtures/grant_go.txt)"
STORJ_INTEROP=1 cargo test -p storj --test interop -- --ignored --skip writer_reader_size_matrix
STORJ_INTEROP=1 STORJ_INTEROP_ACCESS=... cargo test -p storj --test interop writer_reader_size_matrix -- --ignored
STORJ_SIM=1 STORJ_SIM_ACCESS=... cargo test -p storj --test sim -- --ignored
cargo test -p storj --test encryption_golden --test grant_golden
```

`cargo test -p storj -- --ignored` still runs interop/sim tests that need Go or a satellite. Use `--test interop` / `--test sim` as above.

## Interop matrix (v1.0 exit criterion)

`{go,rust} writer × {go,rust} reader × {empty, 1B, inline-1, inline+1, 1seg, 64MiB+1}` (full upload/download round trips) plus grant parse/serialize/`Share` restriction. Ranged reads and prefix listing are covered against the mock satellite, not against Go. Defined in `storj-test::INTEROP_SIZES` / `INTEROP_SIDES`. PR CI `grant-roundtrip` runs grant parse/serialize/share on every PR (no satellite) and `--skip`s the object matrix. The object matrix, including `64MiB+1`, is opt-in (`STORJ_INTEROP=1` plus `STORJ_INTEROP_ACCESS` / `STORJ_SIM_ACCESS`); the nightly `interop` workflow runs it when the `STORJ_SIM_ACCESS` secret is configured.

## Local storj-sim

The Go↔Rust matrix runs in about two minutes against a local `storj-sim`
network (vs. ~15 min against a live satellite). What worked on macOS:

```bash
# Postgres + Redis for the satellite
docker run -d --name storj-sim-pg -e POSTGRES_USER=storj -e POSTGRES_PASSWORD=storj \
  -e POSTGRES_DB=master -p 5433:5432 postgres:16
brew install redis            # storj-sim spawns redis-server itself

# storj binaries (jobq and multinode are required by current storj-sim)
GOBIN=$HOME/storj-sim-bin go install storj.io/storj/cmd/{storj-sim,satellite,storagenode,\
versioncontrol,identity,uplink,jobq,multinode}@latest
export PATH=$HOME/storj-sim-bin:$PATH

storj-sim network setup --postgres="postgres://storj:storj@localhost:5433/master?sslmode=disable"
storj-sim network run
```

Two upstream storj-sim issues needed local patches to `cmd/storj-sim/network.go`
(copy the module out of `$GOPATH/pkg/mod`, edit, `go build ./cmd/storj-sim`):

- the satellite core/rangedloop/repairer processes dial `jobq` at startup but
  only wait for the migration, so they race it; add `.WaitForStart(jobqProcess)`
  to those three processes;
- the S3 gateway fails its port check inside the simulator; it is not needed
  for these tests, so skip creating the gateway process when
  `STORJ_SIM_NO_GATEWAY` is set (`storj-sim network env GATEWAY_0_ACCESS` still
  reads the grant from the generated config).

Then:

```bash
export STORJ_SIM=1 STORJ_INTEROP=1
export STORJ_SIM_ACCESS="$(storj-sim network env GATEWAY_0_ACCESS)"
cargo test -p storj --test sim --test interop -- --ignored
```
