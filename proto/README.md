# Vendored protocol buffers

Pinned snapshots of Storj RPC `.proto` files from [`storj/common`](https://github.com/storj/common)
(and the matching [`storj/uplink`](https://github.com/storj/uplink) client). Review proto diffs as
PRs (design K8). Do not edit these files by hand.

Original copyright headers are retained (Storj Labs, Inc.; GoGo Authors for `gogo.proto`).

## Pins

Parseable by `proto/check-pin.sh` / CI:

STORJ_COMMON_SHA=d38275a3768ba356144814f3ec5d62eeca670e49
STORJ_UPLINK_SHA=2fef38720d8395837567da60ab69016099dca9f5

`storj/uplink` at the pin depends on `storj.io/common` at that common SHA
(`go.mod` pseudoversion `v0.0.0-20260818140313-d38275a3768b`). v1.14.5
(`2fef387`, released 2026-09-01) is still the latest tag.

Reviewed 2026-10-02. `storj/uplink` main `764fb8b` is two commits past the pin
and still depends on this common SHA. `storj/common` main `58b262d` does not
change metainfo, orders, encryption, or grant protos. No pin bump.

- `e574a6d` deletes unused Go upload-path API (`PutSingleResult`,
  `EncodedRanger`). This client never had that path.
- `764fb8b` returns the real abort error from Go's stream-buffer `WaitWrite`
  when the writer is between calls. `UploadInner::poll_pending_flush` already
  returns the segment task's error and keeps it sticky for later writes and
  `commit`.
- Common additions since the pin (`sync.WaitGroup.Go`, tee-block release,
  USDC, a `CheckInResponse` notification) are outside the uplink client.

## Files

| Vendored | Upstream (`storj/common` `pb/`) |
|---|---|
| `metainfo.proto` | `metainfo.proto` |
| `piecestore2.proto` | `piecestore2.proto` (piecestore RPC) |
| `orders.proto` | `orders.proto` |
| `encryption.proto` | `encryption.proto` |
| `encryption_access.proto` | `encryption_access.proto` (grant store) |
| `scope.proto` | `scope.proto` (access grant Scope) |
| `node.proto` | `node.proto` |
| `noise.proto` | `noise.proto` |
| `pointerdb.proto` | `pointerdb.proto` |
| `gogo.proto` | `gogo.proto` (gogo options; not generated to Rust) |

`proto/check-pin.sh` globs `proto/*.proto` against `storj/common` `pb/` at the pin.
Vendored files must be byte-identical to that pin (no local annotation comments).
Grant wire types (`Scope`, `EncryptionAccess`, `Caveat`) are hand-maintained in `crates/storj-access/src/pb.rs` (kept in sync with these protos; see `check-pin.sh`), not generated into `crates/storj-proto`.
Do not invent proto fields. Go `EncryptionAccess.toProto` writes only fields 1–3.

Checked-in prost types live in `crates/storj-proto/src/gen/`.

## Commands

```bash
bash proto/check-pin.sh    # CI: fail if vendored files drift from the pin
bash proto/gen-prost.sh    # regenerate crates/storj-proto/src/gen from proto/
cargo fmt --all && git diff --exit-code crates/storj-proto/src/gen
```

CI runs the pin checksum, then regen + `git diff --exit-code` so checked-in prost cannot drift from the vendored `.proto` files. `gen-prost.sh` pins `prost-build = 0.14.4` and a vendored `protoc` (`protoc-bin-vendored`).
