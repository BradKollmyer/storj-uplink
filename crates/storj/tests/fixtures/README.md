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
| `rs_stripe.bin` / `rs_shares.jsonl` | Infectious RS encode of known stripes (`4/6-8B`, `8/14-2B` hello-world, `29/110-256B`) |

`grant_go.txt` in git is a stub so ignored tests compile (`include_str!`). Replace it by running the generator.
