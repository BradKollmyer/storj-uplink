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
    let protos = [
        "metainfo.proto",
        "piecestore2.proto",
        "orders.proto",
        "encryption.proto",
        "node.proto",
        "noise.proto",
        "pointerdb.proto",
    ];
    let paths: Vec<String> = protos.iter().map(|p| format!("{proto_dir}/{p}")).collect();
    cfg.compile_protos(&paths, &[&proto_dir]).expect("compile protos");
}
EOF

export STORJ_ROOT="$ROOT"
(cd "$TMP/gen-prost" && cargo run --release)
echo "wrote $ROOT/crates/storj-proto/src/gen"
