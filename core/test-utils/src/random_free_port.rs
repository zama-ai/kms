use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use tokio::net::TcpListener;

/// Tracks all ports handed out across concurrent calls to prevent duplicates.
/// Ports are never removed since this is test-only code and the caller
/// is not guaranteed to use the port immediately after receiving it.
static ALLOCATED_PORTS: LazyLock<Mutex<HashSet<u16>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

const MAX_PORT_RETRIES: usize = 200;

/// Find [`n`] free TCP ports on the given host by binding to port 0 and letting the OS
/// assign ephemeral ports. Returns a vector of `(TcpListener, port)` pairs.
///
/// Safe for concurrent use: uses a global set to ensure no two calls
/// ever return the same port, even if the TcpListener is later dropped.
pub async fn get_listeners_random_free_ports(
    host: &IpAddr,
    n: usize,
) -> anyhow::Result<Vec<(TcpListener, u16)>> {
    let mut listeners_and_ports = Vec::new();
    for _ in 0..n {
        let mut retries = 0;
        let (listener, port) = loop {
            let listener = get_listener_free_tcp(host).await?;
            let port = listener.local_addr().unwrap().port();
            let mut allocated = ALLOCATED_PORTS.lock().unwrap();
            if allocated.insert(port) {
                break (listener, port);
            }
            // Port was already handed out, retry
            // We do not handout duplicate ports because the caller
            // may not use the port the moment it gets handed out
            drop(allocated);
            drop(listener);
            retries += 1;
            anyhow::ensure!(
                retries < MAX_PORT_RETRIES,
                "failed to find a unique free port after {MAX_PORT_RETRIES} retries"
            );
        };
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

    #[tokio::test]
    async fn test_random_free_ports_concurrent() {
        use std::collections::HashSet;

        let ip_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let num_tasks = 10;
        let ports_per_task = 5;

        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            handles.push(tokio::spawn(async move {
                get_listeners_random_free_ports(&ip_addr, ports_per_task)
                    .await
                    .unwrap()
            }));
        }

        let mut all_ports = HashSet::new();
        for handle in handles {
            let listeners = handle.await.unwrap();
            assert_eq!(listeners.len(), ports_per_task);
            for (_, port) in &listeners {
                assert!(
                    all_ports.insert(*port),
                    "duplicate port {port} found across concurrent calls"
                );
            }
        }
        assert_eq!(all_ports.len(), num_tasks * ports_per_task);
    }
}
