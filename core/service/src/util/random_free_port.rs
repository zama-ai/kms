cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        use std::net::IpAddr;
        use tokio::net::TcpListener;

        fn is_reserved_test_port(port: u16) -> bool {
            matches!(
                port,
                9646..=9649 | 50001..=50006 | 50051 | 50100 | 50200 | 50300 | 50400 | 50500 | 50600
            )
        }

        /// Find [`n`] free ports in the range [from, to). Returns a vector (TcpListeners,port).
        pub(crate) async fn get_listeners_random_free_ports(
            host: &IpAddr,
            n: usize,
        ) -> anyhow::Result<Vec<(TcpListener, u16)>> {
            let mut listeners_and_ports = Vec::with_capacity(n);
            while listeners_and_ports.len() < n {
                let listener = get_listener_free_tcp(host).await?;
                let port = listener.local_addr().unwrap().port();
                if is_reserved_test_port(port) {
                    drop(listener);
                    continue;
                }
                listeners_and_ports.push((listener, port));
            }
            Ok(listeners_and_ports)
        }

        /// Uses port 0 to let the OS give us a free Tcp port
        async fn get_listener_free_tcp(host: &IpAddr) -> tokio::io::Result<TcpListener> {
            let socket_addr = std::net::SocketAddr::new(*host, 0);
            TcpListener::bind(socket_addr).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserved_test_ports() {
        for port in [9646, 9649, 50001, 50006, 50051, 50100, 50200, 50600] {
            assert!(is_reserved_test_port(port));
        }

        for port in [9645, 9650, 50000, 50007, 50050, 50052, 50099, 50101, 50601] {
            assert!(!is_reserved_test_port(port));
        }
    }

    #[tokio::test]
    async fn test_random_free_ports() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 10).await.unwrap();

        assert_eq!(listeners.len(), 10);
        assert!(listeners
            .iter()
            .all(|(_, port)| !is_reserved_test_port(*port)));
    }
}
