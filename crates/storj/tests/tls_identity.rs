use storj::{Config, ErrorKind, Project, TlsIdentity, TransportMode};
use storj_test::MockSatellite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DUMP: &str = include_str!("../../storj-rpc/testdata/go-identity.pem");
fn parts() -> (&'static str, String, &'static str) {
    let (chain, keys) = DUMP.split_once("-----BEGIN PRIVATE KEY-----").unwrap();
    let (leaf, ca) = keys.split_once("-----END PRIVATE KEY-----").unwrap();
    (
        chain,
        format!("-----BEGIN PRIVATE KEY-----{leaf}-----END PRIVATE KEY-----"),
        ca,
    )
}

#[test]
fn identity_is_validated_as_a_pair_and_config_debug_redacts_pem() {
    let (chain, key, ca_key) = parts();
    let identity = TlsIdentity::from_pem(chain, &key).unwrap();
    assert_eq!(
        identity.node_id(),
        "123tRdwfDZbVeCxX117eztrC2GLZP3hPWixgAphjoQoCoW7V51G"
    );
    assert_eq!(identity, TlsIdentity::from_pem(chain, &key).unwrap());
    let config = Config {
        tls_identity: Some(identity),
        ..Default::default()
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("BEGIN"));
    assert!(!debug.contains(key.lines().nth(1).unwrap()));
    for (chain, key) in [
        ("", key.as_str()),
        (chain, ""),
        (chain, "garbage"),
        (chain, ca_key),
        (chain, &format!("{key}\n{key}")),
    ] {
        let error = TlsIdentity::from_pem(chain, key).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidTlsIdentity);
        assert!(!error.is_retryable());
    }
    let leaf = format!(
        "{}-----END CERTIFICATE-----",
        chain.split_once("-----END CERTIFICATE-----").unwrap().0
    );
    assert!(TlsIdentity::from_pem(&leaf, &key).is_err());
    assert!(TlsIdentity::from_pem(&chain.replace("MIIBYj", "NIIBYj"), &key).is_err());
}

#[tokio::test]
async fn supplied_identity_is_presented_to_satellite_and_storage_nodes_over_tls_and_quic() {
    let (chain, key, _) = parts();
    let identity = TlsIdentity::from_pem(chain, &key).unwrap();
    let expected: storj_rpc::NodeId = identity.node_id().parse().unwrap();
    for mode in [TransportMode::Tcp, TransportMode::Quic] {
        let mock = MockSatellite::start_with_quic(mode == TransportMode::Quic).await;
        let config = Config {
            tls_identity: Some(identity.clone()),
            transport: mode,
            ..Default::default()
        };
        let project = Project::open_with_config(&mock.access(), config.clone())
            .await
            .unwrap();
        let (a, b, c) = tokio::join!(
            project.ensure_bucket("identity"),
            project.ensure_bucket("parallel-a"),
            project.ensure_bucket("parallel-b")
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        let body = vec![9; 128 * 1024];
        let mut upload = project
            .upload_object("identity", "data", Default::default())
            .await
            .unwrap();
        upload.write_all(&body).await.unwrap();
        upload.commit().await.unwrap();
        let mut download = project
            .download_object("identity", "data", Default::default())
            .await
            .unwrap();
        let mut got = Vec::new();
        download.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, body);
        download.close().await.unwrap();
        project.close().await.unwrap();
        // A fresh project and new connections must keep the configured identity.
        let reopened = Project::open_with_config(&mock.access(), config)
            .await
            .unwrap();
        reopened.stat_object("identity", "data").await.unwrap();
        let peers = mock.tls_client_node_ids();
        assert!(peers.len() >= 2);
        assert!(peers.iter().all(|id| *id == expected));
        let sn_peers: Vec<_> = mock
            .storage_nodes()
            .iter()
            .flat_map(|sn| sn.tls_client_node_ids())
            .collect();
        assert!(sn_peers.len() >= 4);
        assert!(sn_peers.iter().all(|id| *id == expected));
    }
}
