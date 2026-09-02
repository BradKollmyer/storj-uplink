//! Version-2 macaroon codec, HMAC-SHA256 caveat chain, and `APIKey.Restrict`.
//!
//! Wire format matches [`storj.io/common/macaroon`](https://pkg.go.dev/storj.io/common/macaroon):
//! packets are `uvarint type || uvarint length || data` (EOS is type 0 with no
//! length). `head` is HMAC-SHA256-chained with each first-party caveat to
//! produce `tail`.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;

use crate::base58::{GRANT_VERSION, check_decode, check_encode};
use crate::grant::Error;
use crate::pb;

type HmacSha256 = Hmac<Sha256>;

/// Binary version. Go `macaroon` const `version`.
pub const VERSION: u8 = 2;

const FIELD_EOS: u32 = 0;
const FIELD_LOCATION: u32 = 1;
const FIELD_IDENTIFIER: u32 = 2;
const FIELD_VERIFICATION_ID: u32 = 4;
const FIELD_SIGNATURE: u32 = 6;

const MAX_UVARINT: u64 = 0x7fff_ffff;
const TAIL_LEN: usize = 32;

/// Version-2 Storj macaroon (head, first-party caveats, HMAC tail).
#[derive(Clone, Eq, PartialEq)]
pub struct Macaroon {
    head: Vec<u8>,
    caveats: Vec<Vec<u8>>,
    tail: [u8; TAIL_LEN],
}

impl fmt::Debug for Macaroon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Macaroon")
            .field("head", &"[REDACTED]")
            .field("caveats", &self.caveats.len())
            .field("tail", &"[REDACTED]")
            .finish()
    }
}

impl Macaroon {
    /// Unrestricted macaroon from identifier `head` and project `secret`.
    ///
    /// `tail = HMAC-SHA256(secret, head)`.
    pub fn from_parts(head: Vec<u8>, secret: &[u8]) -> Self {
        let tail = sign(secret, &head);
        Self {
            head,
            caveats: Vec::new(),
            tail,
        }
    }

    /// Parse binary version-2 macaroon (Go `ParseMacaroon`).
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 2 {
            return Err(Error::new("empty macaroon"));
        }
        if data[0] != VERSION {
            return Err(Error::new("invalid macaroon version"));
        }
        let mut rest = &data[1..];

        let (after_header, header) = parse_section(rest)?;
        rest = after_header;
        let header = strip_location(header);
        if header.len() != 1 || header[0].field_type != FIELD_IDENTIFIER {
            return Err(Error::new("invalid macaroon header"));
        }
        let head = header[0].data.clone();

        let mut caveats = Vec::new();
        loop {
            let (after, section) = parse_section(rest)?;
            rest = after;
            if section.is_empty() {
                break;
            }
            let section = strip_location(section);
            if section.is_empty() || section[0].field_type != FIELD_IDENTIFIER {
                return Err(Error::new("no Identifier in caveat"));
            }
            let cav = section[0].data.clone();
            match section.len() {
                1 => caveats.push(cav),
                2 if section[1].field_type == FIELD_VERIFICATION_ID => caveats.push(cav),
                2 => return Err(Error::new("invalid field found in caveat")),
                _ => return Err(Error::new("extra fields found in caveat")),
            }
        }

        let (_, sig) = parse_packet(rest)?;
        if sig.field_type != FIELD_SIGNATURE {
            return Err(Error::new("unexpected field found instead of signature"));
        }
        if sig.data.len() != TAIL_LEN {
            return Err(Error::new("signature has unexpected length"));
        }
        let mut tail = [0u8; TAIL_LEN];
        tail.copy_from_slice(&sig.data);

        Ok(Self {
            head,
            caveats,
            tail,
        })
    }

    /// Serialize to version-2 binary (Go `Macaroon.Serialize`).
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(VERSION);
        serialize_packet(
            &mut data,
            Packet {
                field_type: FIELD_IDENTIFIER,
                data: &self.head,
            },
        );
        data.push(FIELD_EOS as u8);
        for cav in &self.caveats {
            serialize_packet(
                &mut data,
                Packet {
                    field_type: FIELD_IDENTIFIER,
                    data: cav,
                },
            );
            data.push(FIELD_EOS as u8);
        }
        data.push(FIELD_EOS as u8);
        serialize_packet(
            &mut data,
            Packet {
                field_type: FIELD_SIGNATURE,
                data: &self.tail,
            },
        );
        data
    }

    /// Append a first-party caveat and HMAC-chain `tail` (Go `AddFirstPartyCaveat`).
    pub fn add_first_party_caveat(&self, caveat: &[u8]) -> Self {
        let mut out = self.clone();
        out.tail = sign(&out.tail, caveat);
        out.caveats.push(caveat.to_vec());
        out
    }

    /// Recompute the HMAC chain from `secret` and compare `tail`.
    pub fn validate(&self, secret: &[u8]) -> bool {
        ct_eq(&self.derive_tail(secret), &self.tail)
    }

    /// Ancestor tails up to and including the current tail (Go `Tails`).
    pub fn tails(&self, secret: &[u8]) -> Vec<[u8; TAIL_LEN]> {
        let mut tails = Vec::with_capacity(self.caveats.len() + 1);
        let mut tail = sign(secret, &self.head);
        tails.push(tail);
        for cav in &self.caveats {
            tail = sign(&tail, cav);
            tails.push(tail);
        }
        tails
    }

    /// Root identifier (copy of `head`).
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// Current HMAC tail.
    pub fn tail(&self) -> &[u8; TAIL_LEN] {
        &self.tail
    }

    /// First-party caveat payloads (protobuf `Caveat` bytes for API keys).
    pub fn caveats(&self) -> &[Vec<u8>] {
        &self.caveats
    }

    /// Number of caveats.
    pub fn caveat_len(&self) -> usize {
        self.caveats.len()
    }

    fn derive_tail(&self, secret: &[u8]) -> [u8; TAIL_LEN] {
        let mut tail = sign(secret, &self.head);
        for cav in &self.caveats {
            tail = sign(&tail, cav);
        }
        tail
    }
}

/// Macaroon-backed Storj API key (Go `macaroon.APIKey`).
#[derive(Clone, Eq, PartialEq)]
pub struct ApiKey {
    mac: Macaroon,
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("head", &"[REDACTED]")
            .field("tail", &"[REDACTED]")
            .field("caveats", &self.mac.caveat_len())
            .finish()
    }
}

impl ApiKey {
    /// Unrestricted API key from identifier and project secret (Go `FromParts`).
    pub fn from_parts(head: Vec<u8>, secret: &[u8]) -> Self {
        Self {
            mac: Macaroon::from_parts(head, secret),
        }
    }

    /// Parse a Base58Check (version 0) API key string (Go `ParseAPIKey`).
    pub fn parse(key: &str) -> Result<Self, Error> {
        let (data, version) =
            check_decode(key).map_err(|_| Error::new("invalid api key format"))?;
        if version != GRANT_VERSION {
            return Err(Error::new("invalid api key format"));
        }
        Self::parse_raw(&data)
    }

    /// Parse raw macaroon bytes (Go `ParseRawAPIKey`).
    pub fn parse_raw(data: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            mac: Macaroon::parse(data)?,
        })
    }

    /// Base58Check-encode the macaroon (Go `APIKey.Serialize`).
    pub fn serialize(&self) -> String {
        check_encode(&self.mac.serialize(), GRANT_VERSION)
    }

    /// Raw macaroon bytes (Go `APIKey.SerializeRaw`).
    pub fn serialize_raw(&self) -> Vec<u8> {
        self.mac.serialize()
    }

    /// Attach a protobuf-encoded caveat (Go `APIKey.Restrict`).
    pub fn restrict(&self, caveat: &Caveat) -> Self {
        Self {
            mac: self.mac.add_first_party_caveat(&caveat.encode()),
        }
    }

    /// Root identifier.
    pub fn head(&self) -> &[u8] {
        self.mac.head()
    }

    /// Current tail.
    pub fn tail(&self) -> &[u8; TAIL_LEN] {
        self.mac.tail()
    }

    /// Underlying macaroon.
    pub fn macaroon(&self) -> &Macaroon {
        &self.mac
    }
}

/// Encrypted path prefix restriction (Go `Caveat_Path`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CaveatPath {
    /// Bucket name bytes.
    pub bucket: Vec<u8>,
    /// Encrypted object-key prefix.
    pub encrypted_path_prefix: Vec<u8>,
}

/// First-party caveat (Go `macaroon.Caveat`).
///
/// Action flags are **disallow** bits (inverted Permission polarity).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Caveat {
    /// Disallow downloads / object reads.
    pub disallow_reads: bool,
    /// Disallow uploads / writes.
    pub disallow_writes: bool,
    /// Disallow listing.
    pub disallow_lists: bool,
    /// Disallow deletes.
    pub disallow_deletes: bool,
    /// Disallow deprecated coarse lock action.
    pub disallow_locks: bool,
    /// Disallow put object retention.
    pub disallow_put_retention: bool,
    /// Disallow get object retention.
    pub disallow_get_retention: bool,
    /// Disallow put object legal hold.
    pub disallow_put_legal_hold: bool,
    /// Disallow get object legal hold.
    pub disallow_get_legal_hold: bool,
    /// Disallow bypass governance retention.
    pub disallow_bypass_governance_retention: bool,
    /// Disallow put bucket Object Lock configuration.
    pub disallow_put_bucket_object_lock_configuration: bool,
    /// Disallow get bucket Object Lock configuration.
    pub disallow_get_bucket_object_lock_configuration: bool,
    /// Disallow put bucket notification configuration.
    pub disallow_put_bucket_notification_configuration: bool,
    /// Disallow get bucket notification configuration.
    pub disallow_get_bucket_notification_configuration: bool,
    /// If non-empty, access must match at least one prefix.
    pub allowed_paths: Vec<CaveatPath>,
    /// Not valid after this time.
    pub not_after: Option<SystemTime>,
    /// Not valid before this time.
    pub not_before: Option<SystemTime>,
    /// Max TTL for newly uploaded objects.
    pub max_object_ttl: Option<Duration>,
    /// Random bytes so identical restrictions still chain uniquely.
    pub nonce: Vec<u8>,
}

impl Caveat {
    /// Invert Permission allow-bits into DISALLOW flags (Go `grant.Restrict`).
    ///
    /// Notification configuration is not on [`Permission`] (same as uplink
    /// `Permission`); grant.Restrict therefore always sets those DISALLOW bits.
    pub fn from_permission(permission: &Permission) -> Self {
        Self {
            disallow_reads: !permission.allow_download,
            disallow_writes: !permission.allow_upload,
            disallow_lists: !permission.allow_list,
            disallow_deletes: !permission.allow_delete,
            disallow_locks: !permission.allow_lock,
            disallow_put_retention: !permission.allow_put_object_retention,
            disallow_get_retention: !permission.allow_get_object_retention,
            disallow_put_legal_hold: !permission.allow_put_object_legal_hold,
            disallow_get_legal_hold: !permission.allow_get_object_legal_hold,
            disallow_bypass_governance_retention: !permission.allow_bypass_governance_retention,
            disallow_put_bucket_object_lock_configuration: !permission
                .allow_put_bucket_object_lock_configuration,
            disallow_get_bucket_object_lock_configuration: !permission
                .allow_get_bucket_object_lock_configuration,
            disallow_put_bucket_notification_configuration: true,
            disallow_get_bucket_notification_configuration: true,
            allowed_paths: Vec::new(),
            not_after: permission.not_after,
            not_before: permission.not_before,
            max_object_ttl: permission.max_object_ttl,
            nonce: Vec::new(),
        }
    }

    /// Protobuf-encode (Go `picobuf.Marshal`).
    pub fn encode(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    /// Protobuf-decode (Go `ParseCaveat`).
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let p = pb::Caveat::decode(data)
            .map_err(|e| Error::new(format!("invalid caveat format: {e}")))?;
        Ok(Self::from_proto(p))
    }

    fn to_proto(&self) -> pb::Caveat {
        pb::Caveat {
            disallow_reads: self.disallow_reads,
            disallow_writes: self.disallow_writes,
            disallow_lists: self.disallow_lists,
            disallow_deletes: self.disallow_deletes,
            disallow_locks: self.disallow_locks,
            disallow_put_retention: self.disallow_put_retention,
            disallow_get_retention: self.disallow_get_retention,
            disallow_put_legal_hold: self.disallow_put_legal_hold,
            disallow_get_legal_hold: self.disallow_get_legal_hold,
            allowed_paths: self
                .allowed_paths
                .iter()
                .map(|p| pb::CaveatPath {
                    bucket: p.bucket.clone(),
                    encrypted_path_prefix: p.encrypted_path_prefix.clone(),
                })
                .collect(),
            disallow_bypass_governance_retention: self.disallow_bypass_governance_retention,
            disallow_put_bucket_object_lock_configuration: self
                .disallow_put_bucket_object_lock_configuration,
            disallow_get_bucket_object_lock_configuration: self
                .disallow_get_bucket_object_lock_configuration,
            disallow_put_bucket_notification_configuration: self
                .disallow_put_bucket_notification_configuration,
            disallow_get_bucket_notification_configuration: self
                .disallow_get_bucket_notification_configuration,
            not_after: self.not_after.map(timestamp_from_system),
            not_before: self.not_before.map(timestamp_from_system),
            max_object_ttl: self.max_object_ttl.map(duration_from_std),
            nonce: self.nonce.clone(),
        }
    }

    fn from_proto(p: pb::Caveat) -> Self {
        Self {
            disallow_reads: p.disallow_reads,
            disallow_writes: p.disallow_writes,
            disallow_lists: p.disallow_lists,
            disallow_deletes: p.disallow_deletes,
            disallow_locks: p.disallow_locks,
            disallow_put_retention: p.disallow_put_retention,
            disallow_get_retention: p.disallow_get_retention,
            disallow_put_legal_hold: p.disallow_put_legal_hold,
            disallow_get_legal_hold: p.disallow_get_legal_hold,
            disallow_bypass_governance_retention: p.disallow_bypass_governance_retention,
            disallow_put_bucket_object_lock_configuration: p
                .disallow_put_bucket_object_lock_configuration,
            disallow_get_bucket_object_lock_configuration: p
                .disallow_get_bucket_object_lock_configuration,
            disallow_put_bucket_notification_configuration: p
                .disallow_put_bucket_notification_configuration,
            disallow_get_bucket_notification_configuration: p
                .disallow_get_bucket_notification_configuration,
            allowed_paths: p
                .allowed_paths
                .into_iter()
                .map(|p| CaveatPath {
                    bucket: p.bucket,
                    encrypted_path_prefix: p.encrypted_path_prefix,
                })
                .collect(),
            not_after: p.not_after.and_then(system_from_timestamp),
            not_before: p.not_before.and_then(system_from_timestamp),
            max_object_ttl: p.max_object_ttl.and_then(std_from_duration),
            nonce: p.nonce,
        }
    }
}

/// Permission allow-bits for [`Caveat::from_permission`] (Go `grant.Permission`).
///
/// Does **not** expose bucket-notification allows (uplink `Permission` same).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Permission {
    /// Download object content and metadata.
    pub allow_download: bool,
    /// Create buckets and upload objects.
    pub allow_upload: bool,
    /// List buckets / objects.
    pub allow_list: bool,
    /// Delete buckets / objects.
    pub allow_delete: bool,
    /// Deprecated coarse lock bit.
    pub allow_lock: bool,
    /// Put object retention.
    pub allow_put_object_retention: bool,
    /// Get object retention.
    pub allow_get_object_retention: bool,
    /// Put object legal hold.
    pub allow_put_object_legal_hold: bool,
    /// Get object legal hold.
    pub allow_get_object_legal_hold: bool,
    /// Bypass governance-mode retention.
    pub allow_bypass_governance_retention: bool,
    /// Put bucket Object Lock configuration.
    pub allow_put_bucket_object_lock_configuration: bool,
    /// Get bucket Object Lock configuration.
    pub allow_get_bucket_object_lock_configuration: bool,
    /// Not valid before this time.
    pub not_before: Option<SystemTime>,
    /// Not valid after this time.
    pub not_after: Option<SystemTime>,
    /// Max TTL for newly uploaded objects.
    pub max_object_ttl: Option<Duration>,
}

impl Permission {
    /// Matches Go `uplink.FullPermission()` (no `allow_lock`, no notifications).
    pub fn full() -> Self {
        Self {
            allow_download: true,
            allow_upload: true,
            allow_list: true,
            allow_delete: true,
            allow_put_object_retention: true,
            allow_get_object_retention: true,
            allow_put_object_legal_hold: true,
            allow_get_object_legal_hold: true,
            allow_bypass_governance_retention: true,
            allow_put_bucket_object_lock_configuration: true,
            allow_get_bucket_object_lock_configuration: true,
            ..Self::default()
        }
    }

    /// Download + list.
    pub fn read_only() -> Self {
        Self {
            allow_download: true,
            allow_list: true,
            ..Self::default()
        }
    }

    /// Upload + delete.
    pub fn write_only() -> Self {
        Self {
            allow_upload: true,
            allow_delete: true,
            ..Self::default()
        }
    }
}

struct Packet<'a> {
    field_type: u32,
    data: &'a [u8],
}

struct OwnedPacket {
    field_type: u32,
    data: Vec<u8>,
}

fn sign(secret: &[u8], data: &[u8]) -> [u8; TAIL_LEN] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn append_uvarint(buf: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        buf.push((x as u8) | 0x80);
        x >>= 7;
    }
    buf.push(x as u8);
}

fn parse_uvarint(data: &[u8]) -> Result<(&[u8], u64), Error> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &b) in data.iter().enumerate() {
        if i >= 10 {
            return Err(Error::new("varint error"));
        }
        value |= u64::from(b & 0x7f) << shift;
        if b < 0x80 {
            if value > MAX_UVARINT {
                return Err(Error::new("varint error"));
            }
            return Ok((&data[i + 1..], value));
        }
        shift += 7;
    }
    Err(Error::new("varint error"))
}

fn serialize_packet(buf: &mut Vec<u8>, p: Packet<'_>) {
    append_uvarint(buf, u64::from(p.field_type));
    append_uvarint(buf, p.data.len() as u64);
    buf.extend_from_slice(p.data);
}

fn parse_packet(data: &[u8]) -> Result<(&[u8], OwnedPacket), Error> {
    let (data, ft) = parse_uvarint(data)?;
    let field_type = ft as u32;
    if field_type == FIELD_EOS {
        return Ok((
            data,
            OwnedPacket {
                field_type,
                data: Vec::new(),
            },
        ));
    }
    let (data, pack_len) = parse_uvarint(data)?;
    let pack_len = pack_len as usize;
    if pack_len > data.len() {
        return Err(Error::new("out of bounds"));
    }
    let (payload, rest) = data.split_at(pack_len);
    Ok((
        rest,
        OwnedPacket {
            field_type,
            data: payload.to_vec(),
        },
    ))
}

fn parse_section(mut data: &[u8]) -> Result<(&[u8], Vec<OwnedPacket>), Error> {
    let mut prev_field: i64 = -1;
    let mut packets = Vec::new();
    loop {
        if data.is_empty() {
            return Err(Error::new("section extends past end of buffer"));
        }
        let (rest, p) = parse_packet(data)?;
        if p.field_type == FIELD_EOS {
            return Ok((rest, packets));
        }
        if i64::from(p.field_type) <= prev_field {
            return Err(Error::new("fields out of order"));
        }
        prev_field = i64::from(p.field_type);
        packets.push(p);
        data = rest;
    }
}

fn strip_location(mut section: Vec<OwnedPacket>) -> Vec<OwnedPacket> {
    if section
        .first()
        .is_some_and(|p| p.field_type == FIELD_LOCATION)
    {
        section.remove(0);
    }
    section
}

fn timestamp_from_system(t: SystemTime) -> pb::Timestamp {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => pb::Timestamp {
            seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        },
        Err(e) => {
            let d = e.duration();
            let mut seconds = -i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            let mut nanos = -(i32::try_from(d.subsec_nanos()).unwrap_or(0));
            if nanos < 0 {
                seconds -= 1;
                nanos += 1_000_000_000;
            }
            pb::Timestamp { seconds, nanos }
        }
    }
}

fn system_from_timestamp(ts: pb::Timestamp) -> Option<SystemTime> {
    let nanos = u64::try_from(ts.nanos.max(0)).ok()?;
    if ts.seconds >= 0 {
        let secs = u64::try_from(ts.seconds).ok()?;
        UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))?
            .checked_add(Duration::from_nanos(nanos))
    } else {
        let secs = u64::try_from(-ts.seconds).ok()?;
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs))?
            .checked_add(Duration::from_nanos(nanos))
    }
}

fn duration_from_std(d: Duration) -> pb::Duration {
    pb::Duration {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
    }
}

fn std_from_duration(d: pb::Duration) -> Option<Duration> {
    if d.seconds < 0 {
        return None;
    }
    let secs = u64::try_from(d.seconds).ok()?;
    let nanos = u64::try_from(d.nanos.max(0)).ok()?;
    Some(Duration::from_secs(secs) + Duration::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: [u8; 32] = [0x11; 32];
    const SECRET: [u8; 32] = [0x22; 32];
    const NONCE: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

    // Produced by Go `macaroon.FromParts` / `APIKey.Restrict` (storj.io/common @ d38275a).
    const UNRESTRICTED_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100000620f0926e6c10f7df4255267f188f709515131b530a341cde14415129209b7ef42a";
    const UNRESTRICTED_B58: &str = "13Yqd9dreACaeh7e67NTXebS2dLajE9yP4YkC8GJQNKSkf4tYGGYNRSsmBoG1KTckmXLqrJcEQwW9R1S1CjX9mTiuPAqY4SmAQn1NVD";
    const UNRESTRICTED_TAIL: &str =
        "f0926e6c10f7df4255267f188f709515131b530a341cde14415129209b7ef42a";

    const EMPTY_CAVEAT_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100020000000620c544403d850ff41ce7b959ece302e8bde1a86b33c37e38c44b85602ac8506f1e";
    const READONLY_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100020b10012001f20104aabbccdd000006208e7477ab11f901c5bd31619b3a06022b47809474ede6b9dd4b491bfbc46c33d3";
    const READONLY_PROTO: &str = "10012001f20104aabbccdd";
    const WRITEONLY_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100020b08011801f201040102030400000620a1c6f6378fd6665eb89127dc547965e2fd963a0ff34d8399c8dd98b4672fe06c";
    const TIMED_RAW: &str = "02022011111111111111111111111111111111111111111111111111111111111111110002271001a201060880a4a7da06aa010b0880e2cfaa0610959aef3ab201040880a305f20104deadbeef00000620064c2f1b1b8b4d4afbe7027498803f09b4695c09f12dff6cc05a9414286a30ce";
    const TIMED_PROTO: &str =
        "1001a201060880a4a7da06aa010b0880e2cfaa0610959aef3ab201040880a305f20104deadbeef";
    const PATHED_RAW: &str = "0202201111111111111111111111111111111111111111111111111111111111111111000219200152100a036170701209656e632d7573657231f20102000100000620e5ced1581472aac01ab69672cb2cb7bc5534812c8561374d808e8960562cea82";
    const PATHED_PROTO: &str = "200152100a036170701209656e632d7573657231f201020001";
    const FULLDISALLOW_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100022008011001180120012801300138014001480158016001680170017801f20101ff00000620f03068bc676fb7ccf26084f89b50203308551999cd0be4c0302eefd60516a3a7";
    const CHAINED_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100020b10012001f20104aabbccdd0002061801f2010111000006201561275522e65ccbd217adee5806e16732e5903b8f6e5fa9f372bb68582b4813";

    const SHARE_READONLY_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100021f100120012801300138014001480158016001680170017801f20104aabbccdd00000620cda11665a5bb3a4336ee40d0cc3c4aecd71b4475135ab8e03a9ebf817fae5141";
    const SHARE_READONLY_PROTO: &str =
        "100120012801300138014001480158016001680170017801f20104aabbccdd";
    const SHARE_FULL_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100020d280170017801f20104aabbccdd000006204510974ec08111c370f97b637444e109764f815835abd1e7511d53560574f268";
    const SHARE_FULL_PROTO: &str = "280170017801f20104aabbccdd";
    const SHARE_WRITEONLY_RAW: &str = "020220111111111111111111111111111111111111111111111111111111111111111100021f080118012801300138014001480158016001680170017801f20104aabbccdd00000620ee13691abeb1aae837dedaf1a18dbc4b691fa866110c1ec3923186f1512a9d17";

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn unrestricted() -> ApiKey {
        ApiKey::from_parts(HEAD.to_vec(), &SECRET)
    }

    #[test]
    fn from_parts_matches_go_unrestricted() {
        let key = unrestricted();
        assert_eq!(hex::encode(key.serialize_raw()), UNRESTRICTED_RAW);
        assert_eq!(key.serialize(), UNRESTRICTED_B58);
        assert_eq!(hex::encode(key.tail()), UNRESTRICTED_TAIL);
        assert!(key.macaroon().validate(&SECRET));
        assert!(!key.macaroon().validate(&[0x00; 32]));
    }

    #[test]
    fn parse_serialize_roundtrip_go_bytes() {
        for raw in [
            UNRESTRICTED_RAW,
            EMPTY_CAVEAT_RAW,
            READONLY_RAW,
            WRITEONLY_RAW,
            TIMED_RAW,
            PATHED_RAW,
            FULLDISALLOW_RAW,
            CHAINED_RAW,
        ] {
            let mac = Macaroon::parse(&hex(raw)).unwrap();
            assert_eq!(hex::encode(mac.serialize()), raw);
            let key = ApiKey::parse_raw(&hex(raw)).unwrap();
            assert_eq!(hex::encode(key.serialize_raw()), raw);
            assert!(key.macaroon().validate(&SECRET));
        }
    }

    #[test]
    fn parse_api_key_base58() {
        let key = ApiKey::parse(UNRESTRICTED_B58).unwrap();
        assert_eq!(hex::encode(key.serialize_raw()), UNRESTRICTED_RAW);
        assert_eq!(
            ApiKey::parse("!!!not-base58!!!").unwrap_err().message(),
            "invalid api key format"
        );
    }

    #[test]
    fn parse_rejects_bad_version_and_empty() {
        assert_eq!(
            Macaroon::parse(&[]).unwrap_err().message(),
            "empty macaroon"
        );
        assert_eq!(
            Macaroon::parse(&[1]).unwrap_err().message(),
            "empty macaroon"
        );
        assert_eq!(
            Macaroon::parse(&[1, 2]).unwrap_err().message(),
            "invalid macaroon version"
        );
    }

    #[test]
    fn go_fuzz_corpus_roundtrip() {
        // storj.io/common/macaroon FuzzParseMacaroon seeds.
        let unrestricted = [
            0x2, 0x2, 0x20, 0xfb, 0x22, 0xe5, 0x50, 0x30, 0x5, 0xca, 0x60, 0x5, 0xc5, 0x4a, 0x5d,
            0x5, 0x1c, 0x4c, 0xa0, 0x95, 0x58, 0x45, 0xfe, 0x77, 0x44, 0xd0, 0x11, 0xdd, 0x69, 0x9,
            0xa1, 0x46, 0x5, 0x23, 0x6e, 0x0, 0x0, 0x6, 0x20, 0x5b, 0x50, 0x2a, 0xcd, 0xc3, 0x64,
            0x69, 0xca, 0xeb, 0xbe, 0xf6, 0xa3, 0x6, 0x74, 0x8f, 0x9c, 0xc3, 0xd, 0x47, 0xfd, 0xd9,
            0xd1, 0xd9, 0xb9, 0xd, 0x8d, 0x18, 0xe9, 0xf9, 0x5a, 0x6f, 0x7,
        ];
        let with_cav1 = [
            0x2, 0x2, 0x20, 0x10, 0xaf, 0x1a, 0xc3, 0xd9, 0xc9, 0x73, 0x46, 0x3b, 0x14, 0xab, 0x42,
            0x1, 0x45, 0x67, 0x7, 0xb4, 0x8f, 0xdb, 0x67, 0x4b, 0x56, 0xb9, 0xdc, 0x41, 0x3c, 0x11,
            0x6, 0x3c, 0xfc, 0xa8, 0xb9, 0x0, 0x2, 0x4, 0x63, 0x61, 0x76, 0x31, 0x0, 0x0, 0x6,
            0x20, 0x9f, 0x83, 0x86, 0xe1, 0x24, 0xeb, 0xae, 0xcf, 0xb8, 0x64, 0xf1, 0x6e, 0x76,
            0x40, 0x94, 0xd0, 0xee, 0x9e, 0xad, 0x83, 0x7e, 0x9d, 0x32, 0xb8, 0xc1, 0xf8, 0x4f,
            0xbd, 0xa4, 0x3f, 0x97, 0x7a,
        ];
        for raw in [unrestricted.as_slice(), with_cav1.as_slice()] {
            let mac = Macaroon::parse(raw).unwrap();
            assert_eq!(mac.serialize(), raw);
        }
        let cav = Macaroon::parse(&with_cav1).unwrap();
        assert_eq!(cav.caveats(), &[b"cav1".to_vec()]);
    }

    #[test]
    fn restrict_empty_caveat_matches_go() {
        let key = unrestricted().restrict(&Caveat::default());
        assert_eq!(hex::encode(key.serialize_raw()), EMPTY_CAVEAT_RAW);
        assert_eq!(key.macaroon().caveats(), &[Vec::<u8>::new()]);
    }

    #[test]
    fn restrict_readonly_matches_go_apikey() {
        let cav = Caveat {
            disallow_writes: true,
            disallow_deletes: true,
            nonce: NONCE.to_vec(),
            ..Caveat::default()
        };
        assert_eq!(hex::encode(cav.encode()), READONLY_PROTO);
        let key = unrestricted().restrict(&cav);
        assert_eq!(hex::encode(key.serialize_raw()), READONLY_RAW);
        let reparsed = ApiKey::parse(&key.serialize()).unwrap();
        assert_eq!(reparsed.serialize_raw(), key.serialize_raw());
    }

    #[test]
    fn restrict_writeonly_and_chained_match_go() {
        let first = Caveat {
            disallow_reads: true,
            disallow_lists: true,
            nonce: vec![0x01, 0x02, 0x03, 0x04],
            ..Caveat::default()
        };
        let key = unrestricted().restrict(&first);
        assert_eq!(hex::encode(key.serialize_raw()), WRITEONLY_RAW);

        let readonly = unrestricted().restrict(&Caveat {
            disallow_writes: true,
            disallow_deletes: true,
            nonce: NONCE.to_vec(),
            ..Caveat::default()
        });
        let chained = readonly.restrict(&Caveat {
            disallow_lists: true,
            nonce: vec![0x11],
            ..Caveat::default()
        });
        assert_eq!(hex::encode(chained.serialize_raw()), CHAINED_RAW);
        assert_eq!(chained.macaroon().caveat_len(), 2);
    }

    #[test]
    fn restrict_timed_matches_go() {
        let cav = Caveat {
            disallow_writes: true,
            not_after: Some(UNIX_EPOCH + Duration::from_secs(1_800_000_000)),
            not_before: Some(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789)),
            max_object_ttl: Some(Duration::from_secs(24 * 60 * 60)),
            nonce: vec![0xde, 0xad, 0xbe, 0xef],
            ..Caveat::default()
        };
        assert_eq!(hex::encode(cav.encode()), TIMED_PROTO);
        let key = unrestricted().restrict(&cav);
        assert_eq!(hex::encode(key.serialize_raw()), TIMED_RAW);

        let decoded = Caveat::decode(&hex(TIMED_PROTO)).unwrap();
        assert!(decoded.disallow_writes);
        assert_eq!(
            decoded.not_before,
            Some(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789))
        );
        assert_eq!(decoded.max_object_ttl, Some(Duration::from_secs(86_400)));
    }

    #[test]
    fn restrict_path_prefix_matches_go() {
        let cav = Caveat {
            disallow_deletes: true,
            allowed_paths: vec![CaveatPath {
                bucket: b"app".to_vec(),
                encrypted_path_prefix: b"enc-user1".to_vec(),
            }],
            nonce: vec![0x00, 0x01],
            ..Caveat::default()
        };
        assert_eq!(hex::encode(cav.encode()), PATHED_PROTO);
        let key = unrestricted().restrict(&cav);
        assert_eq!(hex::encode(key.serialize_raw()), PATHED_RAW);
    }

    #[test]
    fn restrict_all_disallow_flags_matches_go() {
        let cav = Caveat {
            disallow_reads: true,
            disallow_writes: true,
            disallow_lists: true,
            disallow_deletes: true,
            disallow_locks: true,
            disallow_put_retention: true,
            disallow_get_retention: true,
            disallow_put_legal_hold: true,
            disallow_get_legal_hold: true,
            disallow_bypass_governance_retention: true,
            disallow_put_bucket_object_lock_configuration: true,
            disallow_get_bucket_object_lock_configuration: true,
            disallow_put_bucket_notification_configuration: true,
            disallow_get_bucket_notification_configuration: true,
            nonce: vec![0xff],
            ..Caveat::default()
        };
        let key = unrestricted().restrict(&cav);
        assert_eq!(hex::encode(key.serialize_raw()), FULLDISALLOW_RAW);
    }

    #[test]
    fn permission_polarity_matches_go_grant_restrict() {
        let mut ro = Caveat::from_permission(&Permission::read_only());
        assert!(!ro.disallow_reads && !ro.disallow_lists);
        assert!(ro.disallow_writes && ro.disallow_deletes);
        assert!(ro.disallow_locks);
        assert!(ro.disallow_put_retention);
        assert!(ro.disallow_put_bucket_notification_configuration);
        ro.nonce = NONCE.to_vec();
        assert_eq!(hex::encode(ro.encode()), SHARE_READONLY_PROTO);
        assert_eq!(
            hex::encode(unrestricted().restrict(&ro).serialize_raw()),
            SHARE_READONLY_RAW
        );

        let mut full = Caveat::from_permission(&Permission::full());
        assert!(!full.disallow_reads && !full.disallow_writes);
        assert!(full.disallow_locks, "FullPermission does not set AllowLock");
        assert!(!full.disallow_put_retention);
        assert!(full.disallow_put_bucket_notification_configuration);
        full.nonce = NONCE.to_vec();
        assert_eq!(hex::encode(full.encode()), SHARE_FULL_PROTO);
        assert_eq!(
            hex::encode(unrestricted().restrict(&full).serialize_raw()),
            SHARE_FULL_RAW
        );

        let mut wo = Caveat::from_permission(&Permission::write_only());
        wo.nonce = NONCE.to_vec();
        assert_eq!(
            hex::encode(unrestricted().restrict(&wo).serialize_raw()),
            SHARE_WRITEONLY_RAW
        );
    }

    #[test]
    fn add_first_party_caveat_hmac_chain() {
        let mac = Macaroon::from_parts(HEAD.to_vec(), &SECRET);
        let mac = mac.add_first_party_caveat(b"cav1");
        assert_eq!(mac.caveats(), &[b"cav1".to_vec()]);
        assert!(mac.validate(&SECRET));
        let tails = mac.tails(&SECRET);
        assert_eq!(tails.len(), 2);
        assert_eq!(&tails[1], mac.tail());
    }

    #[test]
    fn debug_redacts_secrets() {
        let s = format!("{:?}", unrestricted());
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("111111"));
    }
}
