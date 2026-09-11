use crate::{DiagnosticRange, Error, Operation, Outcome, TelemetryEvent, TransferDiagnostics};
use std::time::Instant;
use storj_rpc::transport::ConnectionOptions;

/// Owns one terminal event, including when its future/handle is dropped.
pub(crate) struct Transfer {
    options: ConnectionOptions,
    operation: Operation,
    start: Instant,
    bytes: u64,
    first_byte: Option<std::time::Duration>,
    finished: bool,
    work_started: Option<Instant>,
    pub(crate) diagnostics: TransferDiagnostics,
}
impl Transfer {
    pub(crate) fn new(
        operation: Operation,
        options: &ConnectionOptions,
        satellite: String,
    ) -> Self {
        let now = Instant::now();
        let mut diagnostics = TransferDiagnostics::default();
        if options.telemetry.is_some() {
            static CPUS: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
            diagnostics.cpu_count =
                *CPUS.get_or_init(|| std::thread::available_parallelism().ok().map(usize::from));
            diagnostics.satellite = satellite;
        }
        Self {
            options: options.clone(),
            operation,
            start: now,
            bytes: 0,
            first_byte: None,
            finished: false,
            work_started: Some(now),
            diagnostics,
        }
    }
    pub(crate) fn begin_work(&mut self) {
        if !self.finished {
            self.work_started.get_or_insert_with(Instant::now);
        }
    }
    pub(crate) fn end_work(&mut self) {
        if let Some(start) = self.work_started.take() {
            self.diagnostics.working_time = self
                .diagnostics
                .working_time
                .saturating_add(start.elapsed());
        }
    }
    pub(crate) fn download_request(&mut self, offset: i64, length: i64) {
        self.diagnostics.requested_range = Some(DiagnosticRange { offset, length });
    }
    pub(crate) fn download_info(&mut self, info: &crate::Object) {
        self.diagnostics.object_size = u64::try_from(info.system.content_length).ok();
        self.diagnostics.expires = Some(info.system.expires.is_some());
        if let Some(range) = self.diagnostics.requested_range
            && let Ok((offset, length)) = storj_uplink::download::resolve_range(
                range.offset,
                range.length,
                info.system.content_length,
            )
        {
            self.diagnostics.resolved_range = Some(DiagnosticRange { offset, length });
        }
    }
    pub(crate) fn fail(&mut self, error: &Error) {
        if self.finished {
            return;
        }
        self.diagnostics.error_kind = Some(error.kind().to_string());
        self.diagnostics.retryable = Some(error.is_retryable());
        self.finish(Outcome::Error);
    }
    pub(crate) fn fail_io(&mut self, error: &std::io::Error) {
        self.fail(&Error::from(std::io::Error::from(error.kind())));
    }
    pub(crate) fn add_bytes(&mut self, count: usize) {
        if count > 0 {
            self.first_byte.get_or_insert_with(|| self.start.elapsed());
            self.bytes = self.bytes.saturating_add(count as u64);
        }
    }
    pub(crate) fn finish(&mut self, outcome: Outcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.end_work();
        if outcome == Outcome::Success && self.operation != Operation::Download {
            self.diagnostics.object_size = Some(self.bytes);
        }
        if let Some(observer) = &self.options.telemetry {
            observer.emit(TelemetryEvent::Transfer {
                operation: self.operation,
                bytes: self.bytes,
                elapsed: self.start.elapsed(),
                first_byte: self.first_byte,
                outcome,
                transport_mode: self.options.mode,
                diagnostics: Box::new(self.diagnostics.clone()),
            });
        }
    }
}
impl Drop for Transfer {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}
