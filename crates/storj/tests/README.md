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
