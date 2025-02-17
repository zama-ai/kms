use std::net::IpAddr;
use tokio::net::TcpListener;

/// Find [`n`] free ports in the range [from, to). Returns a vector (TcpListeners,port).
pub(crate) async fn get_listeners_random_free_ports(
    host: &IpAddr,
    n: usize,
) -> anyhow::Result<Vec<(TcpListener, u16)>> {
    let mut listeners_and_ports = Vec::new();
    for _ in 0..n {
        let listener = get_listener_free_tcp(host).await?;
        let port = listener.local_addr().unwrap().port();
        listeners_and_ports.push((listener, port));
    }
    Ok(listeners_and_ports)
}

/// Uses port 0 to let the OS give us a free Tcp port
async fn get_listener_free_tcp(host: &IpAddr) -> tokio::io::Result<TcpListener> {
    let socket_addr = std::net::SocketAddr::new(*host, 0);
    TcpListener::bind(socket_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_random_free_ports() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 10).await.unwrap();

        assert_eq!(listeners.len(), 10);
    }
}
