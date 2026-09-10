//! Opt-in application telemetry. No network exporter is installed.

use crate::transport::{TransportKind, TransportMode};
use std::{fmt, sync::Arc, time::Duration};

/// Operation measured by a transfer event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// A complete object upload, including commit.
    Upload,
    /// A requested object range read by the caller.
    Download,
    /// One multipart part, including its commit.
    UploadPart,
}

/// Terminal outcome. Dropped unfinished transfers are cancelled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The operation completed successfully.
    Success,
    /// The operation returned an error, including a timeout.
    Error,
    /// The operation was aborted/dropped, or a competing transport won.
    Cancelled,
}

/// Telemetry deliberately excludes credentials, bucket names, keys and error text.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TelemetryEvent {
    /// One connection attempt, including unsuccessful candidates in Auto mode.
    Connection {
        /// Wire transport attempted (not necessarily selected).
        transport: TransportKind,
        /// Time spent on this candidate, including name resolution.
        elapsed: Duration,
        /// Authentication succeeded, failed, or the attempt was cancelled.
        outcome: Outcome,
    },
    /// One logical transfer. Bytes are plaintext accepted/written or delivered/read.
    Transfer {
        /// Upload, download, or multipart part.
        operation: Operation,
        /// Plaintext bytes accepted from the writer or delivered to the reader.
        bytes: u64,
        /// Time since the public operation was started, including initialization.
        elapsed: Duration,
        /// Time to the first nonzero write/read, or `None` if no bytes moved.
        first_byte: Option<Duration>,
        /// Final result; emitted once per transfer.
        outcome: Outcome,
        /// Configured policy. Connection events identify actual transports.
        transport_mode: TransportMode,
    },
}

/// Cloneable callback. Called synchronously; callbacks must be fast and nonblocking.
/// Panics are isolated so an observer cannot fail an operation (with unwind builds).
#[derive(Clone)]
pub struct Telemetry(Arc<dyn Fn(TelemetryEvent) + Send + Sync>);
impl Telemetry {
    /// Register a local observer. Clones share the callback; equality compares
    /// callback identity. Calls may run concurrently on different runtime threads.
    pub fn new(callback: impl Fn(TelemetryEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(callback))
    }
    /// Deliver an event, isolating callback panics when unwinding is enabled.
    pub fn emit(&self, event: TelemetryEvent) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.0)(event)));
    }
}
impl fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Telemetry(..)")
    }
}
impl PartialEq for Telemetry {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Telemetry {}
