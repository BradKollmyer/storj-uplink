//! Local Go listener compatibility; ignored so normal builds never need Go.
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    time::Duration,
};
use storj_rpc::transport::{TransportMode, dial};
use storj_rpc::{Conn, Identity, Kind, Packet};

#[tokio::test]
#[ignore = "requires Go; run with --ignored"]
async fn quic_stream_interoperates_with_storj_go_listener() {
    let helper_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/interop");
    let dir = std::env::temp_dir().join(format!(
        "storj-quic-interop-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let binary = dir.join(if cfg!(windows) {
        "quic-server.exe"
    } else {
        "quic-server"
    });
    assert!(
        Command::new("go")
            .current_dir(helper_dir)
            .args(["build", "-o"])
            .arg(&binary)
            .arg("./quic-server")
            .status()
            .unwrap()
            .success()
    );
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        Command::new(binary)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let node = storj_rpc::parse_node_url(line.trim()).unwrap();
    let identity = Identity::generate().unwrap();
    let io = dial(
        &identity,
        node.id,
        &node.address,
        TransportMode::Quic,
        Duration::from_secs(5),
        None,
    )
    .await
    .unwrap();
    assert!(!io.peer_cert.is_empty());
    let mut conn = Conn::new(io).with_timeout(Duration::from_secs(5));
    // Repeated messages reuse the same QUIC stream and exceed a single frame.
    for stream_id in 1..=3 {
        let packet = Packet {
            stream_id,
            message_id: 1,
            control: false,
            kind: Kind::MESSAGE,
            data: vec![stream_id as u8; 128 * 1024],
        };
        conn.write_packet(&packet).await.unwrap();
        let echoed = conn.read_packet().await.unwrap();
        assert_eq!(echoed, packet);
    }
    drop(conn);
}
