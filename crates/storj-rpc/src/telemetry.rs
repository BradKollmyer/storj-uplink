//! Opt-in application telemetry. No network exporter is installed.

use crate::transport::TransportKind;
use std::{fmt, sync::Arc, time::Duration};

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

/// One low-level connection attempt. Transfer events belong to the facade.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TelemetryEvent {
    Connection {
        transport: TransportKind,
        elapsed: Duration,
        outcome: Outcome,
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
