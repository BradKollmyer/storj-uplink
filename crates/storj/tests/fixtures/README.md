# Golden fixtures

Do **not** check in production access grants.

Generate local, disposable vectors from Go uplink / `storj.io/common`:

```bash
go run ./scripts/gen-vectors.go
```

Expected files:

| File | Contents |
|---|---|
| `grant_go.txt` | One serialized access grant from `uplink.ParseAccess` round-trip of a synthetic Scope |
| `derive_root_key.jsonl` | Argon2id vectors (`p=1` and `p=8`) |
| `path_hmac.jsonl` | HMAC-SHA512 `"path:"+component` vectors |
| `rs_stripe.bin` / `rs_shares.jsonl` | Infectious-compatible RS encode of a known stripe (PR 8) |

`grant_go.txt` is a synthetic Scope produced by Go `grant.Serialize` / `ParseAccess` (deterministic test macaroon + encryption keys, not a production secret).
