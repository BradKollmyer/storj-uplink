# Fuzz targets

Parsers that must not panic (design Testing Strategy):

| Target | Crate |
|---|---|
| `Access::parse` / grant Base58Check | `storj-access` |
| Macaroon parser | `storj-access` |
| RS encode/decode | `storj-ec` (crate tests cover infectious goldens) |
| DRPC frame parser | `storj-rpc` |
| Path decrypt | `storj-encryption` |

Use `cargo fuzz` against those entry points. Do not fuzz production grants into CI logs.
