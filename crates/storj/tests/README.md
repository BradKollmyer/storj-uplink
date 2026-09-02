# Test suite

Maps to `docs/design-native-uplink.md` § Testing Strategy.

`cargo test -p storj` runs **contract** tests (always green). Protocol, golden, interop, and sim tests are `#[ignore]` until the matching PR lands.

| File | Layer | Gate | Always runs? |
|---|---|---|---|
| `api_contract.rs` | Public API vs 2025 `uplink` 0.11 / Go uplink | — | yes |
| `error_mapping.rs` | Dual returns, I/O, kinds | — | yes |
| `encryption_kdf.rs` | Argon2id p=1 vs p=8, HMAC mix | — | yes |
| `object_lock.rs` (unit part) | `Permission::full()` lock bits | — | yes |
| `multipart.rs` (limits) | 5 MiB / 10k parts | — | yes |
| `ec_golden.rs` (scheme consts) | RS `29/35/80/110-256B` test-only | — | yes |
| `upload_download.rs` (sizes / range validate) | Exit-criterion sizes | — | yes |
| `grant_golden.rs` | Parse Go grants | PR 3 | ignore |
| `encryption_golden.rs` | Go `DeriveRootKey` / path HMAC | fixtures checked in | yes |
| `share_restrict.rs` | `share()` intersection | PR 6 | ignore |
| `ec_golden.rs` (encode/decode) | infectious vectors | PR 8 | yes (BW still ignore) |
| `project_buckets.rs` | Bucket CRUD | PR 11 | ignore |
| `project_objects.rs` | List/stat/delete/copy/move | PR 23 | ignore |
| `upload_download.rs` (I/O) | Pipeline | PR 13–14, 22 | ignore |
| `multipart.rs` (RPCs) | Begin/Part/Commit | PR 24 | ignore |
| `object_lock.rs` (RPCs) | Lock RPCs | PR 25a | ignore |
| `interop.rs` | Go↔Rust matrix | PR 20 / 26 | ignore + `STORJ_INTEROP=1` |
| `sim.rs` | `storj-sim` | nightly | ignore + `STORJ_SIM=1` |

## Commands

```bash
cargo test -p storj                  # contract suite
cargo test -p storj -- --ignored     # full (expected fail until impl)
go run -C scripts .                  # KDF + path HMAC + infectious RS fixtures
cargo test -p storj --test encryption_golden -- --ignored --exact derive_root_key_matches_go
```

## Interop matrix (v1.0 exit criterion)

`{go,rust} writer × {go,rust} reader × {empty, 1B, inline-1, inline+1, 1seg, 64MiB+1}` plus ranged read, prefix list, and `Share` restriction. Defined in `storj-test::INTEROP_SIZES` / `INTEROP_SIDES`.
