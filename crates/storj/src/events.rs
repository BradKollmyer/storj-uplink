//! Opt-in application telemetry. No network exporter is installed.

use crate::network::{TransportKind, TransportMode};
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

/// Download range, in plaintext bytes. Requested ranges can contain negative
/// offsets/lengths; resolved ranges are clamped to the object and nonnegative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticRange {
    pub offset: i64,
    pub length: i64,
}

/// Additional local diagnostics, without object paths, credentials or error text.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TransferDiagnostics {
    /// Time inside initialization/control futures and read/write operations.
    /// An I/O operation remains active from first poll until Ready or transfer
    /// termination; abandoning just its future is not observable by AsyncRead/Write.
    pub working_time: Duration,
    pub requested_range: Option<DiagnosticRange>,
    pub resolved_range: Option<DiagnosticRange>,
    pub object_size: Option<u64>,
    /// Canonical satellite NodeID@address, never an access grant.
    pub satellite: String,
    pub os: &'static str,
    pub architecture: &'static str,
    pub cpu_count: Option<usize>,
    /// Whether object expiration is set, when known.
    pub expires: Option<bool>,
    /// Public error kind only, not the error's message or source chain.
    pub error_kind: Option<String>,
    pub retryable: Option<bool>,
}
impl Default for TransferDiagnostics {
    fn default() -> Self {
        Self {
            working_time: Duration::ZERO,
            requested_range: None,
            resolved_range: None,
            object_size: None,
            satellite: String::new(),
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            cpu_count: None,
            expires: None,
            error_kind: None,
            retryable: None,
        }
    }
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
        /// Working time, range, environment and sanitized failure details.
        diagnostics: Box<TransferDiagnostics>,
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

impl Telemetry {
    pub(crate) fn to_rpc(&self) -> storj_rpc::telemetry::Telemetry {
        let observer = self.clone();
        storj_rpc::telemetry::Telemetry::new(move |event| {
            use storj_rpc::{telemetry as rpc, transport::TransportKind as Kind};
            if let rpc::TelemetryEvent::Connection {
                transport,
                elapsed,
                outcome,
            } = event
            {
                observer.emit(TelemetryEvent::Connection {
                    transport: match transport {
                        Kind::Tcp => TransportKind::Tcp,
                        Kind::Quic => TransportKind::Quic,
                        Kind::Noise => TransportKind::Noise,
                    },
                    elapsed,
                    outcome: match outcome {
                        rpc::Outcome::Success => Outcome::Success,
                        rpc::Outcome::Error => Outcome::Error,
                        rpc::Outcome::Cancelled => Outcome::Cancelled,
                    },
                });
            }
        })
    }
}
