use std::net::IpAddr;

use tokio::net::{TcpListener, UdpSocket};

#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
fn seq_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static ID: AtomicU16 = AtomicU16::new(0);
    ID.fetch_add(1, Ordering::SeqCst)
}

#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
/// Find [`n`] free ports in the range [from, to). Returns a vector of random ports.
pub(crate) async fn random_free_ports(
    from: u16,
    to: u16,
    host: &IpAddr,
    n: usize,
) -> anyhow::Result<Vec<u16>> {
    use itertools::Itertools;
    use std::collections::HashSet;

    if from >= to {
        return Err(anyhow::anyhow!("from {} >= to {}", from, to));
    }

    if from < 1024 {
        return Err(anyhow::anyhow!("port range is too low"));
    }

    let tries = 3 * (to - from);
    let mut ports = HashSet::new();
    for _ in 0..n {
        let mut pushed = false;
        for _ in 0..tries {
            let port = seq_id() % (to - from) + from;
            if !ports.contains(&port) && is_free(port, host).await {
                ports.insert(port);
                pushed = true;
                break;
            }
        }

        if !pushed {
            return Err(anyhow::anyhow!(
                "failed find to free port after {} tries",
                tries
            ));
        }
    }
    Ok(ports.into_iter().collect_vec())
}

pub(crate) async fn is_free(port: u16, host: &IpAddr) -> bool {
    is_free_tcp(port, host).await && is_free_udp(port, host).await
}

async fn is_free_tcp(port: u16, host: &IpAddr) -> bool {
    let socket_addr = std::net::SocketAddr::new(*host, port);
    let result = TcpListener::bind(socket_addr).await;
    result.is_ok()
}

async fn is_free_udp(port: u16, host: &IpAddr) -> bool {
    let socket_addr = std::net::SocketAddr::new(*host, port);
    let result = UdpSocket::bind(socket_addr).await;
    result.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_random_free_ports() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let ports = random_free_ports(31000, 40000, &ip_addr, 10).await.unwrap();

        let port_set: HashSet<u16> = HashSet::from_iter(ports.into_iter());
        assert_eq!(port_set.len(), 10);

        for port in port_set {
            assert!((31000..40000).contains(&port));
        }
    }

    #[tokio::test]
    async fn test_used_port() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let addr = std::net::SocketAddr::new(ip_addr, 40001);
        let _listener = tokio::net::TcpListener::bind(addr).await;

        let ports = random_free_ports(40001, 40003, &ip_addr, 1).await.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], 40002);
    }
}
