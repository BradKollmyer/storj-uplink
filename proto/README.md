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
(`go.mod` pseudoversion `v0.0.0-20260818140313-d38275a3768b`).

## Files

| Vendored | Upstream (`storj/common` `pb/`) |
|---|---|
| `metainfo.proto` | `metainfo.proto` |
| `piecestore2.proto` | `piecestore2.proto` (piecestore RPC) |
| `orders.proto` | `orders.proto` |
| `encryption.proto` | `encryption.proto` |
| `node.proto` | `node.proto` |
| `noise.proto` | `noise.proto` |
| `pointerdb.proto` | `pointerdb.proto` |
| `gogo.proto` | `gogo.proto` (gogo options; not generated to Rust) |

Import closure of metainfo / piecestore / orders. Grant `scope.proto` /
`encryption_access.proto` land with the access-grant PR.

Checked-in prost types live in `crates/storj-proto/src/gen/`.

## Commands

```bash
bash proto/check-pin.sh    # CI: fail if vendored files drift from the pin
bash proto/gen-prost.sh    # regenerate crates/storj-proto/src/gen from proto/
```
