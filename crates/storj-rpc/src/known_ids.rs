//! Known satellite NodeIDs copied from `storj.io/common/rpc/known_ids.go`.
//!
//! Do not add more entries: new satellites must embed the NodeID in the URL.

use crate::identity::{IdentityError, NodeId, NodeUrl};

/// US1 / us-central-1 / mars (same NodeID).
const US1: &str = "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S";
/// AP1 / asia-east-1 / saturn.
const AP1: &str = "121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6";
/// EU1 / europe-west-1 / jupiter.
const EU1: &str = "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs";
/// satellite.stefan-benten.de.
const STEFAN: &str = "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW";
/// saltlake.tardigrade.io.
const SALTLAKE: &str = "1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE";

/// Host and `host:port` keys, matching Go `knownNodeIDs` after `ParseNodeURL`.
const KNOWN: &[(&str, &str)] = &[
    ("us-central-1.tardigrade.io:7777", US1),
    ("us-central-1.tardigrade.io", US1),
    ("mars.tardigrade.io:7777", US1),
    ("mars.tardigrade.io", US1),
    ("asia-east-1.tardigrade.io:7777", AP1),
    ("asia-east-1.tardigrade.io", AP1),
    ("saturn.tardigrade.io:7777", AP1),
    ("saturn.tardigrade.io", AP1),
    ("europe-west-1.tardigrade.io:7777", EU1),
    ("europe-west-1.tardigrade.io", EU1),
    ("jupiter.tardigrade.io:7777", EU1),
    ("jupiter.tardigrade.io", EU1),
    ("satellite.stefan-benten.de:7777", STEFAN),
    ("satellite.stefan-benten.de", STEFAN),
    ("saltlake.tardigrade.io:7777", SALTLAKE),
    ("saltlake.tardigrade.io", SALTLAKE),
];

/// Look up a well-known NodeID for `address` (`rpc.KnownNodeID`).
///
/// Tries the full address, then the host if `address` is `host:port`.
#[must_use]
pub fn known_node_id(address: &str) -> Option<NodeId> {
    lookup(address).or_else(|| split_host_port(address).and_then(|(host, _)| lookup(host)))
}

fn lookup(address: &str) -> Option<NodeId> {
    KNOWN.iter().find_map(|(k, id)| {
        (*k == address).then(|| NodeId::from_string(id).expect("static KnownNodeID"))
    })
}

/// Parse `id@host:port` or a host-only address, filling KnownNodeID when needed.
///
/// Host-only unknown satellites (e.g. `us1.storj.io:7777`) error with
/// `"node id is required in satelliteNodeURL"`.
pub fn parse_node_url(s: &str) -> Result<NodeUrl, IdentityError> {
    let node = parse_node_url_raw(s)?;
    if node.id.is_zero() {
        if let Some(id) = known_node_id(&node.address) {
            return Ok(NodeUrl {
                id,
                address: node.address,
            });
        }
        return Err(IdentityError::NodeIdRequired);
    }
    Ok(node)
}

fn parse_node_url_raw(s: &str) -> Result<NodeUrl, IdentityError> {
    if s.is_empty() {
        return Ok(NodeUrl {
            id: NodeId::ZERO,
            address: String::new(),
        });
    }

    let s = if let Some(rest) = s.strip_prefix("storj://") {
        rest
    } else if let Some(idx) = s.find("://") {
        return Err(IdentityError::NodeUrl(format!(
            "unknown scheme {:?}",
            &s[..idx]
        )));
    } else {
        s
    };

    let (id_part, rest) = match s.split_once('@') {
        Some((id, rest)) => (Some(id), rest),
        None => (None, s),
    };
    let address = rest.split_once('?').map(|(a, _)| a).unwrap_or(rest);

    let id = match id_part {
        Some(p) if !p.is_empty() => {
            NodeId::from_string(p).map_err(|e| IdentityError::NodeUrl(e.to_string()))?
        }
        _ => NodeId::ZERO,
    };

    Ok(NodeUrl {
        id,
        address: address.to_string(),
    })
}

fn split_host_port(address: &str) -> Option<(&str, &str)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        return Some((host, port));
    }
    address.rsplit_once(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_known_tardigrade() {
        let url = parse_node_url("us-central-1.tardigrade.io:7777").unwrap();
        assert_eq!(url.id.to_string(), US1);
        assert_eq!(url.address, "us-central-1.tardigrade.io:7777");
        assert_eq!(
            parse_node_url("mars.tardigrade.io").unwrap().id.to_string(),
            US1
        );
        assert_eq!(
            parse_node_url("asia-east-1.tardigrade.io:7777")
                .unwrap()
                .id
                .to_string(),
            AP1
        );
        assert_eq!(
            parse_node_url("europe-west-1.tardigrade.io:7777")
                .unwrap()
                .id
                .to_string(),
            EU1
        );
        assert_eq!(
            parse_node_url("saltlake.tardigrade.io:7777")
                .unwrap()
                .id
                .to_string(),
            SALTLAKE
        );
    }

    #[test]
    fn host_only_unknown_us1_storj_io() {
        let err = parse_node_url("us1.storj.io:7777").unwrap_err();
        assert!(matches!(err, IdentityError::NodeIdRequired));
        assert_eq!(err.to_string(), "node id is required in satelliteNodeURL");
        assert!(known_node_id("us1.storj.io:7777").is_none());
        assert!(known_node_id("us1.storj.io").is_none());
    }

    #[test]
    fn full_node_url_us1_storj_io() {
        let raw = format!("{US1}@us1.storj.io:7777");
        let url = parse_node_url(&raw).unwrap();
        assert_eq!(url.id.to_string(), US1);
        assert_eq!(url.address, "us1.storj.io:7777");
        assert_eq!(url.to_string(), raw);
    }

    #[test]
    fn known_node_id_splits_host_port() {
        assert_eq!(
            known_node_id("us-central-1.tardigrade.io:9999")
                .unwrap()
                .to_string(),
            US1
        );
    }
}
