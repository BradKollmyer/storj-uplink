//! Go-signed `OrderLimit` / `PieceHash` / `Order` goldens
//! (`crates/storj/tests/fixtures/signed_go.jsonl`, from `go run -C scripts .`).
//!
//! Go signs with the identity's *leaf* key (`signing.SignerFromFullIdentity`)
//! and verifies with `PeerIdentity.Leaf.PublicKey`. These tests pin that the
//! Rust verifiers accept the leaf certificate and reject the CA certificate.

use prost::Message;
use storj_proto::orders::{Order, OrderLimit, PieceHash};
use storj_uplink::orders::{
    PiecePublicKey, verify_order, verify_order_limit, verify_piece_hash_node,
    verify_piece_hash_uplink,
};

fn fixture() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/signed_go.jsonl"
    );
    std::fs::read_to_string(path).expect("signed_go.jsonl (run: go run -C scripts .)")
}

fn field(line: &str, key: &str) -> String {
    let marker = format!("\"{key}\":\"");
    let start = line.find(&marker).expect(key) + marker.len();
    let end = line[start..].find('"').expect("closing quote") + start;
    line[start..end].to_owned()
}

fn hex_field(line: &str, key: &str) -> Vec<u8> {
    hex::decode(field(line, key)).expect("hex")
}

#[test]
fn satellite_order_limit_verifies_with_leaf_not_ca() {
    let line = fixture();
    let limit = OrderLimit::decode(hex_field(&line, "order_limit").as_slice()).expect("proto");
    let leaf = hex_field(&line, "satellite_leaf_der");
    let ca = hex_field(&line, "satellite_ca_der");
    verify_order_limit(&limit, &leaf).expect("Go-signed order limit verifies with the leaf cert");
    assert!(
        verify_order_limit(&limit, &ca).is_err(),
        "the CA key must not verify a Go-signed order limit"
    );
    let mut tampered = limit.clone();
    tampered.limit += 1;
    assert!(verify_order_limit(&tampered, &leaf).is_err());
}

#[test]
fn node_piece_hash_verifies_with_leaf_not_ca() {
    let line = fixture();
    let hash = PieceHash::decode(hex_field(&line, "piece_hash_node").as_slice()).expect("proto");
    let leaf = hex_field(&line, "node_leaf_der");
    let ca = hex_field(&line, "node_ca_der");
    verify_piece_hash_node(&hash, &leaf).expect("Go-signed piece hash verifies with the leaf cert");
    assert!(verify_piece_hash_node(&hash, &ca).is_err());
}

#[test]
fn uplink_order_and_piece_hash_verify_with_piece_key() {
    let line = fixture();
    let pk = PiecePublicKey::from_bytes(&hex_field(&line, "piece_public_key")).expect("piece key");
    let order = Order::decode(hex_field(&line, "order_uplink").as_slice()).expect("proto");
    verify_order(&order, &pk).expect("Go-signed uplink order");
    let hash = PieceHash::decode(hex_field(&line, "piece_hash_uplink").as_slice()).expect("proto");
    verify_piece_hash_uplink(&hash, &pk).expect("Go-signed uplink piece hash");
}

#[test]
fn node_id_comes_from_the_ca_certificate() {
    let line = fixture();
    let ca = hex_field(&line, "satellite_ca_der");
    let id = storj_rpc::NodeId::from_certificate_der(&ca).expect("node id");
    assert_eq!(id.to_string(), field(&line, "satellite_node_id"));
}
