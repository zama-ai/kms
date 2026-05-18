//! VSOCK-side session management for `vsocktun`.
//!
//! This module owns the parent/enclave control plane for the outer transport:
//! creating the shard streams, grouping them into one logical session, and
//! validating that both sides agree on the shard layout.

use crate::protocol::Hello;
use anyhow::{Context, Result, anyhow, bail};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncRead;
use tokio::time::{Instant, timeout};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

#[derive(Debug)]
enum SessionShard<T> {
    Inserted,
    IgnoredUnrelated(T),
}

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
        let first_hello = read_hello_with_timeout(
            &mut first_socket,
            self.accept_timeout,
            "read first shard session header",
        )
        .await?;
        tracing::debug!(
            session_id = first_hello.session_id,
            shard = first_hello.shard,
            expected_shards = self.queue_count,
            "vsocktun(parent): accepted first shard"
        );

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
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!(
                    "timed out while waiting for {} vsock shards for session {}",
                    self.queue_count,
                    first_hello.session_id,
                );
            }
            let hello =
                read_hello_with_timeout(&mut socket, remaining, "read shard session header")
                    .await?;

            if let SessionShard::IgnoredUnrelated(_socket) =
                record_session_shard(&mut shards, first_hello.session_id, hello, socket)?
            {
                tracing::debug!(
                    assembling_session_id = first_hello.session_id,
                    ignored_session_id = hello.session_id,
                    shard = hello.shard,
                    "vsocktun(parent): ignoring shard from unrelated session"
                );
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
            session_id = first_hello.session_id,
            shards = self.queue_count,
            "vsocktun(parent): assembled session"
        );

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

async fn read_hello_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout_duration: Duration,
    action: &str,
) -> Result<Hello> {
    timeout(timeout_duration, Hello::read_from_async(reader))
        .await
        .with_context(|| format!("timed out while {action}"))?
        .with_context(|| format!("failed to {action}"))
}

fn record_session_shard<T>(
    shards: &mut [Option<T>],
    assembling_session_id: u64,
    hello: Hello,
    socket: T,
) -> Result<SessionShard<T>> {
    if hello.session_id != assembling_session_id {
        return Ok(SessionShard::IgnoredUnrelated(socket));
    }

    validate_hello(hello, shards.len())?;
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

#[cfg(test)]
mod tests {
    use super::{
        Hello, SessionShard, read_hello_with_timeout, record_session_shard, validate_hello,
    };
    use anyhow::Result;
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
    fn read_hello_timeout_is_enforced() {
        test_runtime().block_on(async {
            let (_writer, mut reader) = io::duplex(Hello::ENCODED_LEN);
            let err = read_hello_with_timeout(
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
    fn read_hello_succeeds_before_timeout() {
        test_runtime().block_on(async {
            let (mut writer, mut reader) = io::duplex(Hello::ENCODED_LEN);
            let expected = Hello {
                session_id: 7,
                queues: 2,
                shard: 1,
            };
            writer
                .write_all(&expected.encode())
                .await
                .expect("hello bytes should be written");

            let decoded = read_hello_with_timeout(
                &mut reader,
                Duration::from_millis(50),
                "read shard session header",
            )
            .await
            .expect("hello should decode before timeout");

            assert_eq!(decoded, expected);
        });
    }

    #[test]
    fn record_session_shard_ignores_unrelated_sessions() -> Result<()> {
        let mut shards = vec![None];
        let disposition = record_session_shard(
            &mut shards,
            9,
            Hello {
                session_id: 10,
                queues: 1,
                shard: 0,
            },
            42_u8,
        )?;

        assert!(matches!(disposition, SessionShard::IgnoredUnrelated(42)));
        assert!(shards[0].is_none());
        Ok(())
    }

    #[test]
    fn record_session_shard_rejects_duplicates() {
        let mut shards = vec![Some(11_u8)];
        let err = record_session_shard(
            &mut shards,
            9,
            Hello {
                session_id: 9,
                queues: 1,
                shard: 0,
            },
            42_u8,
        )
        .expect_err("duplicate shard should be rejected");

        assert!(err.to_string().contains("duplicate shard 0"));
    }

    #[test]
    fn validate_hello_rejects_wrong_queue_count() {
        let err = validate_hello(
            Hello {
                session_id: 1,
                queues: 2,
                shard: 0,
            },
            1,
        )
        .expect_err("queue mismatch should be rejected");

        assert!(err.to_string().contains("peer requested 2 queues"));
    }

    #[test]
    fn validate_hello_rejects_out_of_range_shard() {
        let err = validate_hello(
            Hello {
                session_id: 1,
                queues: 2,
                shard: 2,
            },
            2,
        )
        .expect_err("out-of-range shard should be rejected");

        assert!(err.to_string().contains("peer requested shard 2"));
    }
}
