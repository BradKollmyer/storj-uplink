use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use storj::{
    Config, Operation, Outcome, Project, Telemetry, TelemetryEvent, TransportKind, TransportMode,
};
use storj_test::MockSatellite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn observer(mode: TransportMode) -> (Config, Arc<Mutex<Vec<TelemetryEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    (
        Config {
            transport: mode,
            telemetry: Some(Telemetry::new(move |e| sink.lock().unwrap().push(e))),
            dial_timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        },
        events,
    )
}

#[tokio::test]
async fn quic_remote_upload_download_and_multipart() {
    for mode in [TransportMode::Quic, TransportMode::Auto] {
        let mock = MockSatellite::start_with_quic(true).await;
        let (config, events) = observer(mode);
        let project = Project::open_with_config(&mock.access(), config)
            .await
            .unwrap();
        project.ensure_bucket("quic").await.unwrap();
        let body = vec![42; 128 * 1024]; // Remote pieces, not an inline-only test.
        let mut upload = project
            .upload_object("quic", "data", Default::default())
            .await
            .unwrap();
        upload.write_all(&body).await.unwrap();
        upload.commit().await.unwrap();
        assert_eq!(mock.remote_segment_count(), 1);
        let mut download = project
            .download_object("quic", "data", Default::default())
            .await
            .unwrap();
        let mut got = Vec::new();
        download.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, body);
        download.close().await.unwrap();

        let info = project
            .begin_upload("quic", "multipart", Default::default())
            .await
            .unwrap();
        let mut part = project
            .upload_part("quic", "multipart", &info.upload_id, 1)
            .await
            .unwrap();
        part.write_all(&body).await.unwrap();
        part.commit().await.unwrap();
        project
            .commit_upload("quic", "multipart", &info.upload_id, Default::default())
            .await
            .unwrap();
        let mut download = project
            .download_object("quic", "multipart", Default::default())
            .await
            .unwrap();
        let mut got = Vec::new();
        download.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, body);
        drop(download);

        let events = events.lock().unwrap();
        let mut operations = Vec::new();
        let mut connections = 0;
        for event in events.iter() {
            match event {
                TelemetryEvent::Connection {
                    transport,
                    outcome: Outcome::Success,
                    ..
                } => {
                    assert_eq!(*transport, TransportKind::Quic);
                    connections += 1;
                }
                TelemetryEvent::Transfer {
                    operation,
                    bytes,
                    elapsed,
                    first_byte,
                    outcome,
                    transport_mode,
                } => {
                    assert_eq!(*bytes, body.len() as u64);
                    assert_eq!(*outcome, Outcome::Success);
                    assert_eq!(*transport_mode, mode);
                    assert!(first_byte.is_some_and(|d| d <= *elapsed));
                    operations.push(*operation);
                }
                _ => {}
            }
        }
        assert!(
            connections >= 5,
            "satellite and multiple storage nodes must use QUIC"
        );
        assert_eq!(
            operations,
            [
                Operation::Upload,
                Operation::Download,
                Operation::UploadPart,
                Operation::Download
            ]
        );
    }
}

#[tokio::test]
async fn auto_falls_back_to_tcp_and_telemetry_counts_range_errors_and_cancellation() {
    let mock = MockSatellite::start().await;
    let (config, events) = observer(TransportMode::Auto);
    let project = Project::open_with_config(&mock.access(), config)
        .await
        .unwrap();
    project.ensure_bucket("telemetry").await.unwrap();
    let mut upload = project
        .upload_object("telemetry", "ok", Default::default())
        .await
        .unwrap();
    upload.write_all(b"0123456789").await.unwrap();
    upload.commit().await.unwrap();
    let mut download = project
        .download_object(
            "telemetry",
            "ok",
            storj::DownloadOptions {
                offset: 2,
                length: 3,
            },
        )
        .await
        .unwrap();
    let mut got = [0; 3];
    download.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"234");
    drop(download); // Full requested range is successful even without a final EOF read.

    let mut upload = project
        .upload_object("telemetry", "drop", Default::default())
        .await
        .unwrap();
    upload.write_all(b"drop").await.unwrap();
    drop(upload);
    let download = project
        .download_object("telemetry", "ok", Default::default())
        .await
        .unwrap();
    drop(download); // Never consumed.
    let mut upload = project
        .upload_object("telemetry", "fail", Default::default())
        .await
        .unwrap();
    upload.write_all(b"fail").await.unwrap();
    mock.fail_next_commit_object();
    assert!(upload.commit().await.is_err());
    assert!(
        project
            .download_object("telemetry", "missing", Default::default())
            .await
            .is_err()
    );
    let mut upload = project
        .upload_object("telemetry", "abort", Default::default())
        .await
        .unwrap();
    upload.write_all(b"abort").await.unwrap();
    upload.abort().await.unwrap();

    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        TelemetryEvent::Connection {
            transport: TransportKind::Tcp,
            outcome: Outcome::Success,
            ..
        }
    )));
    let transfers: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::Transfer {
                operation,
                bytes,
                outcome,
                ..
            } => Some((*operation, *bytes, *outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(
        transfers,
        [
            (Operation::Upload, 10, Outcome::Success),
            (Operation::Download, 3, Outcome::Success),
            (Operation::Upload, 4, Outcome::Cancelled),
            (Operation::Download, 0, Outcome::Cancelled),
            (Operation::Upload, 4, Outcome::Error),
            (Operation::Download, 0, Outcome::Error),
            (Operation::Upload, 5, Outcome::Cancelled),
        ]
    );
}

#[tokio::test]
async fn telemetry_panics_do_not_break_transfers() {
    let mock = MockSatellite::start().await;
    let config = Config {
        telemetry: Some(Telemetry::new(|_| panic!("observer failed"))),
        ..Default::default()
    };
    let project = Project::open_with_config(&mock.access(), config)
        .await
        .unwrap();
    project.ensure_bucket("observer").await.unwrap();
    let upload = project
        .upload_object("observer", "empty", Default::default())
        .await
        .unwrap();
    upload.commit().await.unwrap();
}

#[tokio::test]
async fn remote_read_failure_emits_one_error_and_empty_transfers_succeed() {
    let mock = MockSatellite::start_with_quic(true).await;
    let (config, events) = observer(TransportMode::Quic);
    let project = Project::open_with_config(&mock.access(), config)
        .await
        .unwrap();
    project.ensure_bucket("errors").await.unwrap();
    let upload = project
        .upload_object("errors", "empty", Default::default())
        .await
        .unwrap();
    upload.commit().await.unwrap();
    let download = project
        .download_object("errors", "empty", Default::default())
        .await
        .unwrap();
    download.close().await.unwrap();
    let mut upload = project
        .upload_object("errors", "remote", Default::default())
        .await
        .unwrap();
    upload.write_all(&vec![7; 128 * 1024]).await.unwrap();
    upload.commit().await.unwrap();
    for i in 0..mock.storage_nodes().len() {
        mock.fail_sn_download(i).await;
    }
    let mut download = project
        .download_object("errors", "remote", Default::default())
        .await
        .unwrap();
    let mut body = Vec::new();
    assert!(download.read_to_end(&mut body).await.is_err());
    drop(download);
    let events = events.lock().unwrap();
    let downloads: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::Transfer {
                operation: Operation::Download,
                bytes,
                first_byte,
                outcome,
                ..
            } => Some((*bytes, *first_byte, *outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(
        downloads,
        [(0, None, Outcome::Success), (0, None, Outcome::Error)]
    );
}

struct FailingIo;
impl tokio::io::AsyncRead for FailingIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("source read failed")))
    }
}
impl tokio::io::AsyncWrite for FailingIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("destination flush failed")))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn copy_helpers_report_source_and_destination_failures() {
    let mock = MockSatellite::start().await;
    let (config, events) = observer(TransportMode::Tcp);
    let project = Project::open_with_config(&mock.access(), config)
        .await
        .unwrap();
    project.ensure_bucket("copy").await.unwrap();
    assert!(
        project
            .upload_from("copy", "source-fails", FailingIo, Default::default())
            .await
            .is_err()
    );
    project
        .upload_from("copy", "ok", &b"hello"[..], Default::default())
        .await
        .unwrap();
    assert!(
        project
            .download_to("copy", "ok", FailingIo, Default::default())
            .await
            .is_err()
    );
    let events = events.lock().unwrap();
    let transfers: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::Transfer {
                operation,
                bytes,
                outcome,
                ..
            } => Some((*operation, *bytes, *outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(
        transfers,
        [
            (Operation::Upload, 0, Outcome::Error),
            (Operation::Upload, 5, Outcome::Success),
            (Operation::Download, 5, Outcome::Error)
        ]
    );
}
