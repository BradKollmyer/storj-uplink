use crate::{Operation, Outcome, TelemetryEvent};
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
}
impl Transfer {
    pub(crate) fn new(operation: Operation, options: &ConnectionOptions) -> Self {
        Self {
            options: options.clone(),
            operation,
            start: Instant::now(),
            bytes: 0,
            first_byte: None,
            finished: false,
        }
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
        if let Some(observer) = &self.options.telemetry {
            observer.emit(TelemetryEvent::Transfer {
                operation: self.operation,
                bytes: self.bytes,
                elapsed: self.start.elapsed(),
                first_byte: self.first_byte,
                outcome,
                transport_mode: self.options.mode,
            });
        }
    }
}
impl Drop for Transfer {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}
