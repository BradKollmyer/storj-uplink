use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use storj::{Config, DiagnosticRange, Operation, Outcome, Project, Telemetry, TelemetryEvent};
use storj_test::MockSatellite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn diagnostics_report_ranges_context_and_exclude_idle_time() {
    let mock = MockSatellite::start().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let project = Project::open_with_config(
        &mock.access(),
        Config {
            telemetry: Some(Telemetry::new(move |e| sink.lock().unwrap().push(e))),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    project.ensure_bucket("diagnostics").await.unwrap();
    let mut upload = project
        .upload_object("diagnostics", "private-object-key", Default::default())
        .await
        .unwrap();
    upload.write_all(b"0123456789").await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    upload.commit().await.unwrap();
    let mut download = project
        .download_object(
            "diagnostics",
            "private-object-key",
            storj::DownloadOptions {
                offset: -3,
                length: -1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    download.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"789");
    tokio::time::sleep(Duration::from_millis(30)).await;
    download.close().await.unwrap();
    let events = events.lock().unwrap();
    let mut transfers = 0;
    for event in events.iter() {
        if let TelemetryEvent::Transfer {
            operation,
            elapsed,
            diagnostics,
            outcome,
            ..
        } = event
        {
            transfers += 1;
            assert_eq!(*outcome, Outcome::Success);
            assert!(*elapsed >= diagnostics.working_time + Duration::from_millis(25));
            assert_eq!(diagnostics.satellite, mock.node_url());
            assert_eq!(diagnostics.os, std::env::consts::OS);
            assert_eq!(diagnostics.architecture, std::env::consts::ARCH);
            assert!(diagnostics.cpu_count.is_none_or(|n| n > 0));
            assert_eq!(diagnostics.expires, Some(false));
            assert_eq!(diagnostics.object_size, Some(10));
            assert_eq!(diagnostics.error_kind, None);
            assert_eq!(diagnostics.retryable, None);
            if *operation == Operation::Download {
                assert_eq!(
                    diagnostics.requested_range,
                    Some(DiagnosticRange {
                        offset: -3,
                        length: -1
                    })
                );
                assert_eq!(
                    diagnostics.resolved_range,
                    Some(DiagnosticRange {
                        offset: 7,
                        length: 3
                    })
                );
            } else {
                assert_eq!(diagnostics.requested_range, None);
            }
        }
        assert!(!format!("{event:?}").contains("private-object-key"));
    }
    assert_eq!(transfers, 2);
}

#[tokio::test]
async fn failed_initialization_keeps_unknown_size_and_reports_only_error_kind() {
    let mock = MockSatellite::start().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let project = Project::open_with_config(
        &mock.access(),
        Config {
            telemetry: Some(Telemetry::new(move |e| sink.lock().unwrap().push(e))),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    project.ensure_bucket("diagnostics").await.unwrap();
    let error = project
        .download_object(
            "diagnostics",
            "secret-missing-object",
            storj::DownloadOptions {
                offset: 5,
                length: 10,
                ..Default::default()
            },
        )
        .await
        .err()
        .unwrap();
    let events = events.lock().unwrap();
    let transfers: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, TelemetryEvent::Transfer { .. }))
        .collect();
    assert_eq!(transfers.len(), 1);
    let TelemetryEvent::Transfer {
        diagnostics,
        outcome,
        ..
    } = transfers[0]
    else {
        unreachable!()
    };
    assert_eq!(*outcome, Outcome::Error);
    assert_eq!(diagnostics.error_kind, Some(error.kind().to_string()));
    assert_eq!(diagnostics.retryable, Some(error.is_retryable()));
    assert_eq!(diagnostics.object_size, None);
    assert_eq!(diagnostics.resolved_range, None);
    assert_eq!(
        diagnostics.requested_range,
        Some(DiagnosticRange {
            offset: 5,
            length: 10
        })
    );
    assert!(!format!("{diagnostics:?}").contains("secret-missing-object"));
}
