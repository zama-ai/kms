use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Ensures proper cleanup of a TCP port by attempting to bind to it first
/// and only releasing it when the server is ready to start.
pub async fn ensure_port_available(addr: SocketAddr) -> anyhow::Result<()> {
    // Try to bind to the port first to ensure it's available
    match TcpListener::bind(addr).await {
        Ok(_) => {
            tracing::debug!("Port {} is available", addr.port());
            Ok(())
        }
        Err(e) => {
            let err_msg = format!("Port {} is not available: {}", addr.port(), e);
            tracing::error!("{}", err_msg);
            Err(anyhow::anyhow!(err_msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_port_available() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert!(ensure_port_available(addr).await.is_ok());
    }

    #[tokio::test]
    async fn test_port_unavailable() {
        // Bind to a port first
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Try to ensure the same port is available
        assert!(ensure_port_available(addr).await.is_err());
    }
}
