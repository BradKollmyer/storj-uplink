#!/usr/bin/env bash
# Regenerate crates/storj-proto/src/gen from proto/*.proto (requires protoc).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/gen-prost/src"
cat > "$TMP/gen-prost/Cargo.toml" << 'EOF'
[package]
name = "gen-prost"
version = "0.1.0"
edition = "2021"

[dependencies]
prost-build = "=0.13.5"
protoc-bin-vendored = "3"
EOF

cat > "$TMP/gen-prost/src/main.rs" << 'EOF'
fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", &protoc);
    let root = std::env::var("STORJ_ROOT").expect("STORJ_ROOT");
    let proto_dir = format!("{root}/proto");
    let out = format!("{root}/crates/storj-proto/src/gen");
    std::fs::create_dir_all(&out).unwrap();
    let mut cfg = prost_build::Config::new();
    cfg.out_dir(&out);
    let mut paths: Vec<String> = std::fs::read_dir(&proto_dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension()?.to_str()? != "proto" {
                return None;
            }
            let name = p.file_name()?.to_string_lossy();
            // gogo.proto is options only; not generated to Rust.
            // caveat.proto's types are hand-maintained in
            // crates/storj-access/src/pb.rs (picobuf encode order matters).
            if name == "gogo.proto" || name == "caveat.proto" {
                return None;
            }
            Some(p.to_string_lossy().into_owned())
        })
        .collect();
    paths.sort();
    cfg.compile_protos(&paths, &[&proto_dir]).expect("compile protos");
}
EOF

export STORJ_ROOT="$ROOT"
(cd "$TMP/gen-prost" && cargo run --release)
echo "wrote $ROOT/crates/storj-proto/src/gen"
