//! Requires only a local Go toolchain; no credentials or live Storj services.
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires Go; run with --ignored"]
async fn noise_interoperates_with_go_both_ciphers_and_maximum_records() {
    let dir = std::env::temp_dir().join(format!(
        "storj-noise-interop-{}-{}",
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
        "noise-server.exe"
    } else {
        "noise-server"
    });
    assert!(
        Command::new("go")
            .current_dir(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/interop")
            )
            .args(["build", "-o"])
            .arg(&binary)
            .arg("./noise-server")
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
    for (protocol, early, fast) in [
        (1, false, false),
        (2, false, false),
        (1, true, false),
        (2, true, false),
        (1, true, true),
        (2, true, true),
    ] {
        let mut child = Child(
            Command::new(&binary)
                .arg(protocol.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let (address, key) = line.trim().split_once(' ').unwrap();
        let key = hex::decode(key).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = storj_rpc::transport::dial_noise_with_options(
                address,
                protocol,
                &key,
                Duration::from_secs(5),
                &storj_rpc::transport::ConnectionOptions {
                    network: storj::NetworkOptions {
                        noise_early_data: early,
                        tcp_fast_open: fast,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                fast,
            )
            .await
            .unwrap();
            assert!(stream.peer_cert.is_empty());
            assert_eq!(stream.kind, storj::TransportKind::Noise);
            for i in 1..=3 {
                let payload = vec![i as u8; 256 * 1024 + i];
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut echoed = vec![0; payload.len()];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            }
        })
        .await
        .unwrap();
        assert!(child.0.wait().unwrap().success());
    }
}
