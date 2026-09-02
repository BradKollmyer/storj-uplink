# Fuzzing

`cargo-fuzz` targets for the parsers that consume untrusted bytes. The
`fuzz` package is excluded from the workspace so it does not affect normal
builds; it needs nightly Rust.

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run drpc_frame          # DRPC frame parse + packet reassembly
cargo +nightly fuzz run macaroon_parse      # macaroon parse/serialize/validate
cargo +nightly fuzz run grant_parse         # access grant parse/serialize
cargo +nightly fuzz run path_iter           # path components + encrypted-component decode
cargo +nightly fuzz run compressed_batch    # zstd CompressedBatch (64 MiB cap)
```

Artifacts, corpus and coverage directories are git-ignored.
