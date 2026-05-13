//! VSOCK-side session management for `vsocktun`.
//!
//! This module owns the parent/enclave control plane for the outer transport:
//! creating the shard streams, grouping them into one logical session, and
//! validating that both sides agree on the shard layout.

use crate::protocol::Hello;
use anyhow::{Context, Result, anyhow, bail};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{Instant, timeout};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

/// The set of VSOCK streams that make up one logical tunnel session.
pub(crate) struct SessionSockets {
    pub(crate) session_id: u64,
    pub(crate) shards: Vec<VsockStream>,
}

/// Parent-side acceptor that assembles individually accepted VSOCK streams into
/// one complete multi-shard tunnel session.
pub(crate) struct ParentSessionAcceptor {
    listener: VsockListener,
    queue_count: usize,
    accept_timeout: Duration,
}

impl ParentSessionAcceptor {
    /// Binds the parent-side listener used by enclaves to open tunnel shards.
    pub(crate) fn bind(
        vsock_port: u32,
        queue_count: usize,
        accept_timeout: Duration,
    ) -> Result<Self> {
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))
            .with_context(|| format!("failed to listen on VSOCK port {vsock_port}"))?;

        Ok(Self {
            listener,
            queue_count,
            accept_timeout,
        })
    }

    /// Accepts a full tunnel session by collecting one stream per shard.
    pub(crate) async fn accept_session(&self) -> Result<SessionSockets> {
        let mut first_socket = self
            .listener
            .accept()
            .await
            .map(|(stream, _addr)| stream)
            .context("failed to accept first shard connection")?;
        let first_hello = Hello::read_from_async(&mut first_socket)
            .await
            .context("failed to read first shard session header")?;

        validate_hello(first_hello, self.queue_count)?;

        let mut shards = empty_shard_slots(self.queue_count);
        shards[usize::from(first_hello.shard)] = Some(first_socket);

        let deadline = Instant::now() + self.accept_timeout;
        while shards.iter().any(Option::is_none) {
            if Instant::now() >= deadline {
                bail!(
                    "timed out while waiting for {} vsock shards for session {}",
                    self.queue_count,
                    first_hello.session_id,
                );
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut socket = timeout(remaining, self.listener.accept())
                .await
                .context("timed out while waiting for additional shard connections")?
                .map(|(stream, _addr)| stream)
                .context("failed to accept additional shard connection")?;
            let hello = Hello::read_from_async(&mut socket)
                .await
                .context("failed to read shard session header")?;

            if hello.session_id != first_hello.session_id {
                continue;
            }

            validate_hello(hello, self.queue_count)?;
            let slot = &mut shards[usize::from(hello.shard)];
            if slot.is_some() {
                bail!(
                    "received duplicate shard {} for session {}",
                    hello.shard,
                    hello.session_id,
                );
            }
            *slot = Some(socket);
        }

        Ok(SessionSockets {
            session_id: first_hello.session_id,
            shards: collect_shards(shards)?,
        })
    }
}

/// Enclave-side connector that opens all shard streams for one logical tunnel
/// session.
pub(crate) async fn connect_session(
    parent_cid: u32,
    vsock_port: u32,
    queue_count: usize,
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
        Hello {
            session_id,
            queues: u16::try_from(queue_count).context("queue count exceeds handshake range")?,
            shard: u16::try_from(shard).context("shard index exceeds handshake range")?,
        }
        .write_to_async(&mut socket)
        .await
        .with_context(|| format!("failed to send handshake for shard {shard}"))?;

        shards.push(socket);
    }

    Ok(SessionSockets { session_id, shards })
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

fn validate_hello(hello: Hello, queue_count: usize) -> Result<()> {
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

    Ok(())
}
