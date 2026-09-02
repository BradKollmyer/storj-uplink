//! Order-limit / order / piece-hash encoding and signatures.
//!
//! Matches Go `storj.io/common/signing`:
//! - Satellite and storage-node signatures are ECDSA P-256 over SHA-256
//!   (`pkcrypto.HashAndSign`) using the identity CA key.
//! - Uplink order and piece-hash signatures are Ed25519 over the signing
//!   protobuf (`PiecePrivateKey.Sign`).
//!
//! Signing bytes are the `*Signing` messages with the signature field left
//! empty (Go `EncodeOrderLimit` / `EncodeOrder` / `EncodePieceHash`).

use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use storj_proto::orders::{
    Order, OrderLimit, OrderLimitSigning, OrderSigning, PieceHash, PieceHashSigning,
};
use storj_rpc::Identity;

use crate::{Error, Result};

/// Piece hash algorithm selected from the satellite (`WithPieceHashAlgo`).
///
/// Proto default is SHA-256 (enum 0). Go's `GetPieceHashAlgo` default is
/// BLAKE3; the client default matches that and is overridden per segment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum PieceHashAlgo {
    /// `orders.PieceHashAlgorithm_SHA256`.
    Sha256,
    /// `orders.PieceHashAlgorithm_BLAKE3`.
    #[default]
    Blake3,
}

impl PieceHashAlgo {
    /// Decode a protobuf enum value. Unknown values are treated as SHA-256
    /// (proto zero-value).
    #[must_use]
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Blake3,
            _ => Self::Sha256,
        }
    }

    /// Protobuf enum discriminant.
    #[must_use]
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Sha256 => 0,
            Self::Blake3 => 1,
        }
    }

    /// Incremental hasher for this algorithm.
    #[must_use]
    pub fn hasher(self) -> PieceHasher {
        PieceHasher::new(self)
    }
}

/// Incremental SHA-256 or BLAKE3 hasher (K18).
pub enum PieceHasher {
    /// SHA-256 (32-byte digest).
    Sha256(Sha256),
    /// BLAKE3 (32-byte digest). Boxed because `blake3::Hasher` is ~2 KiB.
    Blake3(Box<blake3::Hasher>),
}

impl PieceHasher {
    /// Start a hasher for `algo`.
    #[must_use]
    pub fn new(algo: PieceHashAlgo) -> Self {
        match algo {
            PieceHashAlgo::Sha256 => Self::Sha256(Sha256::new()),
            PieceHashAlgo::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Blake3(h) => {
                h.update(data);
            }
        }
    }

    /// 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Blake3(h) => h.finalize().as_bytes().to_vec(),
        }
    }
}

/// Ed25519 piece private key (Go `storj.PiecePrivateKey`, 64-byte form).
#[derive(Clone)]
pub struct PiecePrivateKey(SigningKey);

/// Ed25519 piece public key (Go `storj.PiecePublicKey`, 32 bytes).
#[derive(Clone, Copy)]
pub struct PiecePublicKey(VerifyingKey);

impl PiecePrivateKey {
    /// Generate a new key pair.
    #[must_use]
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// Parse a 32-byte seed or 64-byte seed||public Go key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            32 => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| Error::PieceKey)?;
                Ok(Self(SigningKey::from_bytes(&seed)))
            }
            64 => {
                let pair: [u8; 64] = bytes.try_into().map_err(|_| Error::PieceKey)?;
                let sk = SigningKey::from_keypair_bytes(&pair).map_err(|_| Error::PieceKey)?;
                Ok(Self(sk))
            }
            _ => Err(Error::PieceKey),
        }
    }

    /// Corresponding public key.
    #[must_use]
    pub fn public(&self) -> PiecePublicKey {
        PiecePublicKey(self.0.verifying_key())
    }

    /// 64-byte seed||public (Go `PiecePrivateKey.Bytes`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_keypair_bytes()
    }

    /// Ed25519 sign of `data` (no prehash).
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.0.sign(data).to_bytes().to_vec()
    }
}

impl PiecePublicKey {
    /// Parse a 32-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::PieceKey)?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|_| Error::PieceKey)?;
        Ok(Self(vk))
    }

    /// 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify an Ed25519 signature over `data`.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let sig = EdSignature::from_slice(signature).map_err(|_| Error::PieceKey)?;
        self.0.verify(data, &sig).map_err(|_| Error::OrderSignature)
    }
}

/// Protobuf bytes signed by the satellite (signature field omitted).
pub fn encode_order_limit(limit: &OrderLimit) -> Vec<u8> {
    OrderLimitSigning {
        serial_number: limit.serial_number.clone(),
        satellite_id: limit.satellite_id.clone(),
        deprecated_uplink_id: limit.deprecated_uplink_id.clone(),
        uplink_public_key: limit.uplink_public_key.clone(),
        storage_node_id: limit.storage_node_id.clone(),
        piece_id: limit.piece_id.clone(),
        limit: limit.limit,
        action: limit.action,
        piece_expiration: limit.piece_expiration,
        order_expiration: limit.order_expiration,
        order_creation: limit.order_creation,
        encrypted_metadata_key_id: limit.encrypted_metadata_key_id.clone(),
        encrypted_metadata: limit.encrypted_metadata.clone(),
        satellite_signature: Vec::new(),
        deprecated_satellite_address: limit.deprecated_satellite_address.clone(),
    }
    .encode_to_vec()
}

/// Protobuf bytes signed by the uplink (signature field omitted).
pub fn encode_order(order: &Order) -> Vec<u8> {
    OrderSigning {
        serial_number: order.serial_number.clone(),
        amount: order.amount,
        uplink_signature: Vec::new(),
    }
    .encode_to_vec()
}

/// Protobuf bytes signed by the uplink or storage node (signature omitted).
pub fn encode_piece_hash(hash: &PieceHash) -> Vec<u8> {
    PieceHashSigning {
        piece_id: hash.piece_id.clone(),
        hash: hash.hash.clone(),
        piece_size: hash.piece_size,
        timestamp: hash.timestamp,
        signature: Vec::new(),
        hash_algorithm: hash.hash_algorithm,
    }
    .encode_to_vec()
}

/// Sign `limit` with the satellite CA key (Go `SignOrderLimit`).
pub fn sign_order_limit(limit: &mut OrderLimit, satellite: &Identity) -> Result<()> {
    let bytes = encode_order_limit(limit);
    limit.satellite_signature = satellite.hash_and_sign(&bytes)?;
    Ok(())
}

/// Verify the satellite ECDSA signature on `limit`.
pub fn verify_order_limit(limit: &OrderLimit, satellite_ca_der: &[u8]) -> Result<()> {
    let bytes = encode_order_limit(limit);
    storj_rpc::hash_and_verify(satellite_ca_der, &bytes, &limit.satellite_signature)
        .map_err(|_| Error::OrderLimitSignature)
}

/// Sign `order` with the piece private key (Go `SignUplinkOrder`).
pub fn sign_order(order: &mut Order, key: &PiecePrivateKey) -> Result<()> {
    let bytes = encode_order(order);
    order.uplink_signature = key.sign(&bytes);
    Ok(())
}

/// Verify an uplink Ed25519 signature on `order`.
pub fn verify_order(order: &Order, key: &PiecePublicKey) -> Result<()> {
    let bytes = encode_order(order);
    key.verify(&bytes, &order.uplink_signature)
        .map_err(|_| Error::OrderSignature)
}

/// Sign `hash` with the piece private key (Go `SignUplinkPieceHash`).
pub fn sign_piece_hash_uplink(hash: &mut PieceHash, key: &PiecePrivateKey) -> Result<()> {
    let bytes = encode_piece_hash(hash);
    hash.signature = key.sign(&bytes);
    Ok(())
}

/// Verify an uplink Ed25519 signature on `hash`.
pub fn verify_piece_hash_uplink(hash: &PieceHash, key: &PiecePublicKey) -> Result<()> {
    let bytes = encode_piece_hash(hash);
    key.verify(&bytes, &hash.signature)
        .map_err(|_| Error::PieceHashSignature)
}

/// Sign `hash` with the storage-node CA key (Go `SignPieceHash`).
pub fn sign_piece_hash_node(hash: &mut PieceHash, node: &Identity) -> Result<()> {
    let bytes = encode_piece_hash(hash);
    hash.signature = node.hash_and_sign(&bytes)?;
    Ok(())
}

/// Verify a storage-node ECDSA signature on `hash`.
pub fn verify_piece_hash_node(hash: &PieceHash, node_ca_der: &[u8]) -> Result<()> {
    let bytes = encode_piece_hash(hash);
    storj_rpc::hash_and_verify(node_ca_der, &bytes, &hash.signature)
        .map_err(|_| Error::PieceHashSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use storj_proto::orders::PieceAction;
    use storj_rpc::Identity;

    fn now_ts() -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }
    }

    fn sample_limit(sat: &Identity, piece_pub: &[u8]) -> OrderLimit {
        OrderLimit {
            serial_number: vec![7; 16],
            satellite_id: sat.node_id().as_bytes().to_vec(),
            deprecated_uplink_id: Vec::new(),
            uplink_public_key: piece_pub.to_vec(),
            storage_node_id: vec![2; 32],
            piece_id: vec![3; 32],
            limit: 4096,
            action: PieceAction::Put as i32,
            piece_expiration: Some(now_ts()),
            order_expiration: Some(now_ts()),
            order_creation: Some(now_ts()),
            encrypted_metadata_key_id: Vec::new(),
            encrypted_metadata: Vec::new(),
            satellite_signature: Vec::new(),
            deprecated_satellite_address: None,
        }
    }

    #[test]
    fn order_limit_sign_verify_and_tamper() {
        let sat = Identity::generate().unwrap();
        let piece = PiecePrivateKey::generate();
        let mut limit = sample_limit(&sat, &piece.public().to_bytes());
        sign_order_limit(&mut limit, &sat).unwrap();
        verify_order_limit(&limit, sat.ca_der().as_ref()).unwrap();

        let mut tampered = limit.clone();
        tampered.limit += 1;
        assert!(matches!(
            verify_order_limit(&tampered, sat.ca_der().as_ref()),
            Err(Error::OrderLimitSignature)
        ));

        let other = Identity::generate().unwrap();
        assert!(matches!(
            verify_order_limit(&limit, other.ca_der().as_ref()),
            Err(Error::OrderLimitSignature)
        ));
    }

    #[test]
    fn uplink_order_and_piece_hash_ed25519() {
        let key = PiecePrivateKey::generate();
        let mut order = Order {
            serial_number: vec![1; 16],
            amount: 256,
            uplink_signature: Vec::new(),
        };
        sign_order(&mut order, &key).unwrap();
        verify_order(&order, &key.public()).unwrap();
        order.amount = 1;
        assert!(verify_order(&order, &key.public()).is_err());

        let mut hash = PieceHash {
            piece_id: vec![9; 32],
            hash: vec![8; 32],
            piece_size: 16,
            timestamp: Some(now_ts()),
            signature: Vec::new(),
            hash_algorithm: PieceHashAlgo::Blake3.to_i32(),
        };
        sign_piece_hash_uplink(&mut hash, &key).unwrap();
        verify_piece_hash_uplink(&hash, &key.public()).unwrap();
        hash.piece_size = 0;
        assert!(matches!(
            verify_piece_hash_uplink(&hash, &key.public()),
            Err(Error::PieceHashSignature)
        ));
    }

    #[test]
    fn node_piece_hash_ecdsa() {
        let node = Identity::generate().unwrap();
        let mut hash = PieceHash {
            piece_id: vec![1; 32],
            hash: vec![2; 32],
            piece_size: 8,
            timestamp: Some(now_ts()),
            signature: Vec::new(),
            hash_algorithm: PieceHashAlgo::Sha256.to_i32(),
        };
        sign_piece_hash_node(&mut hash, &node).unwrap();
        verify_piece_hash_node(&hash, node.ca_der().as_ref()).unwrap();
        let other = Identity::generate().unwrap();
        assert!(matches!(
            verify_piece_hash_node(&hash, other.ca_der().as_ref()),
            Err(Error::PieceHashSignature)
        ));
    }

    #[test]
    fn sha256_and_blake3_digests_differ() {
        let data = b"piece-bytes";
        let mut sha = PieceHashAlgo::Sha256.hasher();
        sha.update(data);
        let mut blake = PieceHashAlgo::Blake3.hasher();
        blake.update(data);
        let a = sha.finalize();
        let b = blake.finalize();
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b);
        assert_eq!(PieceHashAlgo::default(), PieceHashAlgo::Blake3);
        assert_eq!(PieceHashAlgo::from_i32(0), PieceHashAlgo::Sha256);
        assert_eq!(PieceHashAlgo::from_i32(1), PieceHashAlgo::Blake3);
    }

    #[test]
    fn encode_omits_signature_fields() {
        let mut order = Order {
            serial_number: vec![1; 16],
            amount: 1,
            uplink_signature: vec![0xaa; 64],
        };
        let encoded = encode_order(&order);
        let round = OrderSigning::decode(encoded.as_slice()).unwrap();
        assert!(round.uplink_signature.is_empty());
        order.uplink_signature.clear();
        sign_order(&mut order, &PiecePrivateKey::generate()).unwrap();
        assert_eq!(order.uplink_signature.len(), 64);
    }
}
