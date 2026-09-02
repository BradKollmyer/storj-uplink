# Fuzz targets (later PRs)

Design targets:

| Target | PR |
|---|---|
| `Access::parse` | 3 |
| macaroon parser | 4 |
| DRPC frame parser | 9a |
| path decrypt (must not panic) | 5–7 |

Use `cargo fuzz` once those parsers exist. Do not fuzz production grants into CI logs.
