//! VSOCK-side session management for `vsocktun`.
//!
//! This module owns the parent/enclave control plane for the outer transport:
//! serving enclave bootstrap configuration, creating the shard streams,
//! grouping them into one logical session, and validating that both sides agree
//! on the shard layout and framing mode.

use crate::RESOLV_CONF_PATH;
use crate::protocol::{BootstrapRequest, BootstrapResponse, Hello, InitialRequest};
use anyhow::{Context, Result, anyhow, bail};
use std::fs;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncRead;
use tokio::time::{Instant, timeout};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

#[derive(Debug)]
enum SessionShard<T> {
    Inserted,
    IgnoredUnrelated(T),
}

#[derive(Debug)]
enum AcceptedSocket {
    Bootstrap,
    Hello { hello: Hello, socket: VsockStream },
}

/// The set of VSOCK streams that make up one logical tunnel session.
pub(crate) struct SessionSockets {
    /// Identifier shared by every shard in this assembled session.
    pub(crate) session_id: u64,
    /// One connected VSOCK stream per shard, ordered by shard index.
    pub(crate) shards: Vec<VsockStream>,
}

/// Parent-side acceptor that assembles individually accepted VSOCK streams into
/// one complete multi-shard tunnel session.
pub(crate) struct ParentSessionAcceptor {
    listener: VsockListener,
    queue_count: usize,
    accept_timeout: Duration,
    raw_tun_frames: bool,
    parent_tun_address: String,
    enclave_tun_address: String,
    mtu: Option<u32>,
}

impl ParentSessionAcceptor {
    /// Binds the parent-side listener used by enclaves to open tunnel shards.
    ///
    /// The acceptor keeps just enough configuration to reject sessions whose
    /// shard count or framing mode does not match the already-created local TUN
    /// device.
    pub(crate) fn bind(
        vsock_port: u32,
        queue_count: usize,
        accept_timeout: Duration,
        raw_tun_frames: bool,
        parent_tun_address: String,
        enclave_tun_address: String,
        mtu: Option<u32>,
    ) -> Result<Self> {
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))
            .with_context(|| format!("failed to listen on VSOCK port {vsock_port}"))?;

        Ok(Self {
            listener,
            queue_count,
            accept_timeout,
            raw_tun_frames,
            parent_tun_address,
            enclave_tun_address,
            mtu,
        })
    }

    /// Accepts a full tunnel session by collecting one stream per shard.
    ///
    /// The parent observes shard connections one stream at a time, so it uses
    /// the handshake header on each connection to group related shards, reject
    /// duplicates, and restart assembly if a newer reconnect attempt overtakes a
    /// partial older one.
    pub(crate) async fn accept_session(&self) -> Result<SessionSockets> {
        let (first_socket, first_hello) = loop {
            match self
                .accept_initial_socket(
                    self.accept_timeout,
                    "accept first shard connection",
                    "read first shard session header",
                )
                .await?
            {
                AcceptedSocket::Bootstrap => continue,
                AcceptedSocket::Hello { hello, socket } => break (socket, hello),
            }
        };
        tracing::debug!(
            session_id = first_hello.session_id,
            shard = first_hello.shard,
            expected_shards = self.queue_count,
            "vsocktun(parent): accepted first shard"
        );

        validate_hello(first_hello, self.queue_count, self.raw_tun_frames)?;

        let mut session_id = first_hello.session_id;
        let mut shards = empty_shard_slots(self.queue_count);
        shards[usize::from(first_hello.shard)] = Some(first_socket);

        let mut deadline = Instant::now() + self.accept_timeout;
        while shards.iter().any(Option::is_none) {
            if Instant::now() >= deadline {
                bail!(
                    "timed out while waiting for {} vsock shards for session {}",
                    self.queue_count,
                    session_id,
                );
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let (hello, socket) = match self
                .accept_initial_socket(
                    remaining,
                    "accept additional shard connection",
                    "read shard session header",
                )
                .await?
            {
                AcceptedSocket::Bootstrap => continue,
                AcceptedSocket::Hello { hello, socket } => (hello, socket),
            };

            if let SessionShard::IgnoredUnrelated(socket) =
                record_session_shard(&mut shards, session_id, hello, socket, self.raw_tun_frames)?
            {
                tracing::info!(
                    abandoned_session_id = session_id,
                    restarted_session_id = hello.session_id,
                    shard = hello.shard,
                    "vsocktun(parent): abandoning partial session after newer session arrived"
                );
                validate_hello(hello, self.queue_count, self.raw_tun_frames)?;
                session_id = hello.session_id;
                shards = empty_shard_slots(self.queue_count);
                shards[usize::from(hello.shard)] = Some(socket);
                deadline = Instant::now() + self.accept_timeout;
                continue;
            }

            let assembled = shards.iter().filter(|socket| socket.is_some()).count();
            tracing::debug!(
                session_id = hello.session_id,
                shard = hello.shard,
                assembled,
                total_shards = self.queue_count,
                "vsocktun(parent): accepted shard"
            );
        }

        tracing::debug!(
            session_id,
            shards = self.queue_count,
            "vsocktun(parent): assembled session"
        );

        Ok(SessionSockets {
            session_id,
            shards: collect_shards(shards)?,
        })
    }

    async fn accept_initial_socket(
        &self,
        accept_timeout: Duration,
        accept_action: &str,
        read_action: &str,
    ) -> Result<AcceptedSocket> {
        let mut socket = timeout(accept_timeout, self.listener.accept())
            .await
            .with_context(|| format!("timed out while waiting to {accept_action}"))?
            .map(|(stream, _addr)| stream)
            .with_context(|| format!("failed to {accept_action}"))?;

        match read_initial_request_with_timeout(&mut socket, accept_timeout, read_action).await? {
            InitialRequest::Bootstrap(_request) => {
                let response = self
                    .build_bootstrap_response()
                    .context("failed to prepare enclave bootstrap response")?;
                response
                    .write_to_async(&mut socket)
                    .await
                    .context("failed to send enclave bootstrap response")?;
                tracing::debug!(
                    queues = self.queue_count,
                    tun_address = %self.parent_tun_address,
                    enclave_tun_address = %self.enclave_tun_address,
                    "vsocktun(parent): served enclave bootstrap"
                );
                Ok(AcceptedSocket::Bootstrap)
            }
            InitialRequest::Hello(hello) => Ok(AcceptedSocket::Hello { hello, socket }),
        }
    }

    fn build_bootstrap_response(&self) -> Result<BootstrapResponse> {
        let parent_gateway = parse_tun_gateway(&self.parent_tun_address).with_context(|| {
            format!(
                "failed to parse parent tunnel address '{}'",
                self.parent_tun_address
            )
        })?;
        let resolv_conf = rewrite_resolv_conf_for_gateway(
            &fs::read(RESOLV_CONF_PATH).with_context(|| {
                format!("failed to read parent resolv.conf from '{RESOLV_CONF_PATH}'")
            })?,
            parent_gateway,
        )?;

        Ok(BootstrapResponse {
            parent_tun_address: self.parent_tun_address.clone(),
            enclave_tun_address: self.enclave_tun_address.clone(),
            queues: u16::try_from(self.queue_count)
                .context("queue count exceeds bootstrap range")?,
            mtu: self.mtu,
            resolv_conf,
        })
    }
}

/// Enclave-side connector that opens all shard streams for one logical tunnel
/// session.
///
/// The enclave dials the parent once per shard and immediately sends the
/// per-shard handshake so the parent can place each stream into the right slot.
pub(crate) async fn connect_session(
    parent_cid: u32,
    vsock_port: u32,
    queue_count: usize,
    raw_tun_frames: bool,
) -> Result<SessionSockets> {
    let session_id = generate_session_id();
    let mut shards = Vec::with_capacity(queue_count);

    for shard in 0..queue_count {
        let mut socket = VsockStream::connect(VsockAddr::new(parent_cid, vsock_port))
            .await
            .with_context(|| {
                format!(
                    "failed to connect shard {shard} to parent CID {parent_cid} on VSOCK port {vsock_port}",
                )
            })?;
        Hello::new(
            session_id,
            u16::try_from(queue_count).context("queue count exceeds handshake range")?,
            u16::try_from(shard).context("shard index exceeds handshake range")?,
            raw_tun_frames,
        )
        .write_to_async(&mut socket)
        .await
        .with_context(|| format!("failed to send handshake for shard {shard}"))?;
        tracing::debug!(
            session_id,
            shard,
            parent_cid,
            vsock_port,
            "vsocktun(enclave): connected shard"
        );

        shards.push(socket);
    }

    tracing::debug!(
        session_id,
        shards = queue_count,
        "vsocktun(enclave): opened all shards"
    );

    Ok(SessionSockets { session_id, shards })
}

/// Enclave-side bootstrap request that fetches tunnel configuration from the
/// parent before the local TUN device exists.
pub(crate) async fn fetch_bootstrap_config(
    parent_cid: u32,
    vsock_port: u32,
) -> Result<BootstrapResponse> {
    let mut socket = VsockStream::connect(VsockAddr::new(parent_cid, vsock_port))
        .await
        .with_context(|| {
            format!(
                "failed to connect bootstrap channel to parent CID {parent_cid} on VSOCK port {vsock_port}",
            )
        })?;
    BootstrapRequest::new()
        .write_to_async(&mut socket)
        .await
        .context("failed to send bootstrap request")?;
    let response = BootstrapResponse::read_from_async(&mut socket)
        .await
        .context("failed to read bootstrap response")?;

    tracing::debug!(
        parent_cid,
        vsock_port,
        queues = response.queues,
        tun_address = %response.enclave_tun_address,
        parent_tun_address = %response.parent_tun_address,
        "vsocktun(enclave): received bootstrap configuration"
    );

    Ok(response)
}

fn collect_shards(shards: Vec<Option<VsockStream>>) -> Result<Vec<VsockStream>> {
    let mut sockets = Vec::with_capacity(shards.len());
    for (shard, socket) in shards.into_iter().enumerate() {
        let socket = socket.ok_or_else(|| anyhow!("missing socket for shard {shard}"))?;
        sockets.push(socket);
    }
    Ok(sockets)
}

fn empty_shard_slots(queue_count: usize) -> Vec<Option<VsockStream>> {
    let mut slots = Vec::with_capacity(queue_count);
    slots.resize_with(queue_count, || None);
    slots
}

fn generate_session_id() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ u64::from(std::process::id())
}

async fn read_initial_request_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout_duration: Duration,
    action: &str,
) -> Result<InitialRequest> {
    timeout(timeout_duration, InitialRequest::read_from_async(reader))
        .await
        .with_context(|| format!("timed out while {action}"))?
        .with_context(|| format!("failed to {action}"))
}

fn parse_tun_gateway(value: &str) -> Result<Ipv4Addr> {
    let address = value
        .split_once('/')
        .map(|(address, _prefix)| address)
        .unwrap_or(value);
    address
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 gateway address '{address}'"))
}

fn rewrite_resolv_conf_for_gateway(contents: &[u8], gateway: Ipv4Addr) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(contents).context("parent resolv.conf is not valid UTF-8")?;
    let mut rewritten = String::with_capacity(text.len());
    let mut replaced_nameserver = false;

    for segment in text.split_inclusive('\n') {
        let (line, newline) = if let Some(line) = segment.strip_suffix('\n') {
            (line, "\n")
        } else {
            (segment, "")
        };
        let trimmed = line.trim_start();
        if let Some(first) = trimmed.split_whitespace().next()
            && first == "nameserver"
        {
            rewritten.push_str(&format!("nameserver {gateway}{newline}"));
            replaced_nameserver = true;
            continue;
        }

        rewritten.push_str(line);
        rewritten.push_str(newline);
    }

    if !replaced_nameserver {
        bail!("parent resolv.conf does not contain any nameserver entries");
    }

    Ok(rewritten.into_bytes())
}

fn record_session_shard<T>(
    shards: &mut [Option<T>],
    assembling_session_id: u64,
    hello: Hello,
    socket: T,
    expected_raw_tun_frames: bool,
) -> Result<SessionShard<T>> {
    if hello.session_id != assembling_session_id {
        return Ok(SessionShard::IgnoredUnrelated(socket));
    }

    validate_hello(hello, shards.len(), expected_raw_tun_frames)?;
    let slot = &mut shards[usize::from(hello.shard)];
    if slot.is_some() {
        bail!(
            "received duplicate shard {} for session {}",
            hello.shard,
            hello.session_id,
        );
    }
    *slot = Some(socket);
    Ok(SessionShard::Inserted)
}

fn validate_hello(hello: Hello, queue_count: usize, expected_raw_tun_frames: bool) -> Result<()> {
    if usize::from(hello.queues) != queue_count {
        bail!(
            "peer requested {} queues but this side expects {}",
            hello.queues,
            queue_count,
        );
    }

    if usize::from(hello.shard) >= queue_count {
        bail!(
            "peer requested shard {} but this side only has {} queues",
            hello.shard,
            queue_count,
        );
    }

    if hello.supports_raw_tun_frames() != expected_raw_tun_frames {
        tracing::warn!(
            peer_raw_tun_frames = hello.supports_raw_tun_frames(),
            expected_raw_tun_frames,
            "vsocktun(parent): rejecting session because peer TUN offload framing does not match local capability"
        );
        bail!(
            "peer raw-tun-frame transport is {} but this side expects it to be {}",
            if hello.supports_raw_tun_frames() {
                "enabled"
            } else {
                "disabled"
            },
            if expected_raw_tun_frames {
                "enabled"
            } else {
                "disabled"
            },
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AcceptedSocket, Hello, InitialRequest, ParentSessionAcceptor, SessionShard,
        fetch_bootstrap_config, parse_tun_gateway, read_initial_request_with_timeout,
        record_session_shard, rewrite_resolv_conf_for_gateway, validate_hello,
    };
    use anyhow::Result;
    use std::net::Ipv4Addr;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{self, AsyncWriteExt};
    use tokio::runtime::Builder;
    use tokio::time::Duration;

    fn test_runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should be created")
    }

    #[test]
    fn read_initial_request_timeout_is_enforced() {
        // Both bootstrap requests and shard handshakes share the listener, so a
        // stalled first message still needs a hard timeout.
        test_runtime().block_on(async {
            let (_writer, mut reader) = io::duplex(Hello::ENCODED_LEN);
            let err = read_initial_request_with_timeout(
                &mut reader,
                Duration::from_millis(5),
                "read shard session header",
            )
            .await
            .expect_err("stalled hello should time out");

            assert!(
                err.to_string()
                    .contains("timed out while read shard session header")
            );
        });
    }

    #[test]
    fn read_initial_request_decodes_hello_before_timeout() {
        // This keeps the shared timeout wrapper compatible with the existing
        // shard handshake path.
        test_runtime().block_on(async {
            let (mut writer, mut reader) = io::duplex(Hello::ENCODED_LEN);
            let expected = Hello::new(7, 2, 1, true);
            writer
                .write_all(&expected.encode())
                .await
                .expect("hello bytes should be written");

            let decoded = read_initial_request_with_timeout(
                &mut reader,
                Duration::from_millis(50),
                "read shard session header",
            )
            .await
            .expect("hello should decode before timeout");

            assert_eq!(decoded, InitialRequest::Hello(expected));
        });
    }

    #[test]
    fn rewrites_resolv_conf_nameservers_to_tunnel_gateway() -> Result<()> {
        // The enclave should receive a ready-to-install resolver file and no
        // longer needs a separate side channel plus shell rewrite step.
        let rewritten = rewrite_resolv_conf_for_gateway(
            b"search svc.cluster.local\nnameserver 1.1.1.1\nnameserver\t8.8.8.8\noptions ndots:5\n",
            Ipv4Addr::new(10, 118, 0, 1),
        )?;

        assert_eq!(
            std::str::from_utf8(&rewritten).expect("rewritten resolv.conf should stay UTF-8"),
            "search svc.cluster.local\nnameserver 10.118.0.1\nnameserver 10.118.0.1\noptions ndots:5\n",
        );
        Ok(())
    }

    #[test]
    fn parses_gateway_address_from_cidr() -> Result<()> {
        // Bootstrap route setup needs the parent IP without losing the prefix on
        // the full tunnel address string that the enclave still uses for TUN setup.
        assert_eq!(
            parse_tun_gateway("10.118.0.1/24")?,
            Ipv4Addr::new(10, 118, 0, 1)
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires VSOCK loopback support"]
    fn bootstrap_round_trip_over_vsock_loopback() -> Result<()> {
        // This isolates the new bootstrap protocol from TUN setup so we can
        // verify that parent and enclave can exchange tunnel config on the real
        // VSOCK transport before packet-forwarding sessions start.
        let port = 20_000
            + ((process::id() + SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos())
                % 20_000);

        test_runtime().block_on(async {
            let acceptor = ParentSessionAcceptor::bind(
                port,
                1,
                Duration::from_secs(2),
                true,
                "10.118.0.1/24".to_owned(),
                "10.118.0.2/24".to_owned(),
                Some(1500),
            )?;
            let (accepted, response) = tokio::join!(
                acceptor.accept_initial_socket(
                    Duration::from_secs(2),
                    "accept bootstrap connection",
                    "read bootstrap request",
                ),
                fetch_bootstrap_config(1, port),
            );

            assert!(matches!(accepted?, AcceptedSocket::Bootstrap));
            let response = response?;
            assert_eq!(response.parent_tun_address, "10.118.0.1/24");
            assert_eq!(response.enclave_tun_address, "10.118.0.2/24");
            assert_eq!(response.queues, 1);
            assert_eq!(response.mtu, Some(1500));
            assert!(
                std::str::from_utf8(&response.resolv_conf)
                    .expect("rewritten resolv.conf should stay UTF-8")
                    .contains("nameserver 10.118.0.1"),
                "bootstrap resolver payload should target the parent TUN gateway"
            );
            Ok(())
        })
    }

    #[test]
    fn record_session_shard_ignores_unrelated_sessions() -> Result<()> {
        // Reconnects can interleave on the listener, so this verifies assembly of
        // one session does not accidentally consume a shard from another one.
        let mut shards = vec![None];
        let disposition =
            record_session_shard(&mut shards, 9, Hello::new(10, 1, 0, true), 42_u8, true)?;

        assert!(matches!(disposition, SessionShard::IgnoredUnrelated(42)));
        assert!(shards[0].is_none());
        Ok(())
    }

    #[test]
    fn record_session_shard_rejects_duplicates() {
        // Duplicate shard indexes would wire two streams to the same TUN queue,
        // so the acceptor must fail loudly instead of guessing.
        let mut shards = vec![Some(11_u8)];
        let err = record_session_shard(&mut shards, 9, Hello::new(9, 1, 0, true), 42_u8, true)
            .expect_err("duplicate shard should be rejected");

        assert!(err.to_string().contains("duplicate shard 0"));
    }

    #[test]
    fn validate_hello_rejects_wrong_queue_count() {
        // This keeps both endpoints from building different shard topologies for
        // what they think is the same logical tunnel session.
        let err = validate_hello(Hello::new(1, 2, 0, true), 1, true)
            .expect_err("queue mismatch should be rejected");

        assert!(err.to_string().contains("peer requested 2 queues"));
    }

    #[test]
    fn validate_hello_rejects_out_of_range_shard() {
        // Shard indexes must map to real queue slots; otherwise later packet I/O
        // would address nonexistent queues.
        let err = validate_hello(Hello::new(1, 2, 2, true), 2, true)
            .expect_err("out-of-range shard should be rejected");

        assert!(err.to_string().contains("peer requested shard 2"));
    }

    #[test]
    fn validate_hello_rejects_raw_tun_frame_mismatch() {
        // The relay must agree on whether framed payloads contain virtio-net
        // headers, or one side would misparse every forwarded packet.
        let err = validate_hello(Hello::new(1, 2, 1, false), 2, true)
            .expect_err("capability mismatch should be rejected");

        assert!(err.to_string().contains("raw-tun-frame transport"));
    }
}
