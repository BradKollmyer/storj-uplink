//! Best-effort TCP socket policy. Unsupported QoS flags never fail a dial.
use crate::transport::NetworkOptions;
use std::{io, net::SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

pub(crate) fn socket(addr: SocketAddr, options: &NetworkOptions) -> io::Result<TcpSocket> {
    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_nodelay(true)?;
    #[cfg(target_os = "linux")]
    {
        let sock = socket2::SockRef::from(&socket);
        if options.background_qos {
            // RFC 8622 Lower Effort DSCP = 1, leaving ECN bits untouched.
            if addr.is_ipv6() {
                let _ = sock.set_tclass_v6(1 << 2);
            } else {
                let _ = sock.set_tos_v4(1 << 2);
            }
        }
        if let Some(controller) = &options.congestion_control {
            let _ = sock.set_tcp_congestion(controller.as_bytes());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = options;
    Ok(socket)
}

pub(crate) async fn connect(address: &str, options: &NetworkOptions) -> io::Result<TcpStream> {
    use futures_util::{StreamExt, stream::FuturesUnordered};
    let mut candidates = FuturesUnordered::new();
    for (i, addr) in tokio::net::lookup_host(address).await?.enumerate() {
        candidates.push(async move {
            if i > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(250).saturating_mul(i as u32))
                    .await;
            }
            socket(addr, options)?.connect(addr).await
        });
    }
    let mut last = io::Error::other("address resolved to no endpoints");
    while let Some(result) = candidates.next().await {
        match result {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}
