//! Public transport and TCP options, independent of implementation crates.

/// Connection selection. Auto starts TCP after a 250 ms QUIC head start,
/// or immediately if QUIC fails; the first authenticated connection wins.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportMode {
    /// TCP with NodeID-pinned TLS; no UDP traffic.
    Tcp,
    /// QUIC with NodeID-pinned TLS 1.3; no TCP fallback.
    Quic,
    /// Prefer QUIC, allowing TCP/TLS to race after 250 ms.
    Auto,
    /// Noise for replay-safe storage-node RPCs with a satellite-advertised key.
    /// Uses TCP/TLS for metadata and nodes without Noise support. An advertised
    /// key that fails authentication is an error, with no TLS downgrade.
    #[default]
    Noise,
}

/// Actual wire transport selected for a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// TCP with TLS.
    Tcp,
    /// QUIC over UDP.
    Quic,
    /// TCP with Noise IK, authenticated by a satellite-advertised public key.
    Noise,
}

/// TCP performance controls. Unsupported platform/kernel options are ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkOptions {
    /// Put the first transport write in the Noise IK handshake. The current
    /// piece RPC path flushes after DRPC INVOKE, so the order limit and first
    /// piece request are sent after the handshake, not as early data.
    pub noise_early_data: bool,
    /// Race Fast Open against ordinary TCP only for nodes advertising support
    /// and capacity to suppress at least two identical handshakes.
    pub tcp_fast_open: bool,
    /// Request Lower Effort DSCP on Linux TCP sockets, matching Go.
    pub background_qos: bool,
    /// Optional Linux TCP congestion controller; unavailable controllers are ignored.
    pub congestion_control: Option<String>,
}
impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            noise_early_data: true,
            tcp_fast_open: true,
            background_qos: true,
            congestion_control: None,
        }
    }
}

impl TransportMode {
    pub(crate) fn to_rpc(self) -> storj_rpc::transport::TransportMode {
        use storj_rpc::transport::TransportMode as Rpc;
        match self {
            Self::Tcp => Rpc::Tcp,
            Self::Quic => Rpc::Quic,
            Self::Auto => Rpc::Auto,
            Self::Noise => Rpc::Noise,
        }
    }
}
impl NetworkOptions {
    pub(crate) fn to_rpc(&self) -> storj_rpc::transport::NetworkOptions {
        storj_rpc::transport::NetworkOptions {
            noise_early_data: self.noise_early_data,
            tcp_fast_open: self.tcp_fast_open,
            background_qos: self.background_qos,
            congestion_control: self.congestion_control.clone(),
        }
    }
}
