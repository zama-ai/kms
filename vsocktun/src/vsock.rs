use crate::protocol::Hello;
use crate::sys;
use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) struct SessionSockets {
    pub(crate) session_id: u64,
    pub(crate) shards: Vec<File>,
}

pub(crate) struct ParentSessionAcceptor {
    listener: sys::Listener,
    queue_count: usize,
    accept_timeout: Duration,
}

impl ParentSessionAcceptor {
    pub(crate) fn bind(
        vsock_port: u32,
        queue_count: usize,
        accept_timeout: Duration,
    ) -> Result<Self> {
        let backlog = i32::try_from(queue_count.saturating_mul(2))
            .context("queue count is too large to use as a VSOCK listen backlog")?;
        let listener = sys::Listener::bind_vsock(vsock_port, backlog)
            .with_context(|| format!("failed to listen on VSOCK port {vsock_port}"))?;

        Ok(Self {
            listener,
            queue_count,
            accept_timeout,
        })
    }

    pub(crate) fn accept_session(&self) -> Result<SessionSockets> {
        let mut first_socket = self
            .listener
            .accept()
            .context("failed to accept first shard connection")?;
        let first_hello = Hello::read_from(&mut first_socket)
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
            wait_for_listener(&self.listener, remaining)
                .context("timed out while waiting for additional shard connections")?;

            let mut socket = self
                .listener
                .accept()
                .context("failed to accept additional shard connection")?;
            let hello =
                Hello::read_from(&mut socket).context("failed to read shard session header")?;

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

pub(crate) fn connect_session(
    parent_cid: u32,
    vsock_port: u32,
    queue_count: usize,
) -> Result<SessionSockets> {
    let session_id = generate_session_id();
    let mut shards = Vec::with_capacity(queue_count);

    for shard in 0..queue_count {
        let mut socket = sys::connect_vsock(parent_cid, vsock_port).with_context(|| {
            format!(
                "failed to connect shard {shard} to parent CID {parent_cid} on VSOCK port {vsock_port}",
            )
        })?;

        Hello {
            session_id,
            queues: u16::try_from(queue_count).context("queue count exceeds handshake range")?,
            shard: u16::try_from(shard).context("shard index exceeds handshake range")?,
        }
        .write_to(&mut socket)
        .with_context(|| format!("failed to send handshake for shard {shard}"))?;

        shards.push(socket);
    }

    Ok(SessionSockets { session_id, shards })
}

fn collect_shards(shards: Vec<Option<File>>) -> Result<Vec<File>> {
    let mut sockets = Vec::with_capacity(shards.len());
    for (shard, socket) in shards.into_iter().enumerate() {
        let socket = socket.ok_or_else(|| anyhow!("missing socket for shard {shard}"))?;
        sockets.push(socket);
    }
    Ok(sockets)
}

fn empty_shard_slots(queue_count: usize) -> Vec<Option<File>> {
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

fn wait_for_listener(listener: &sys::Listener, timeout: Duration) -> Result<()> {
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut fds = [sys::PollFd {
        fd: listener.as_raw_fd(),
        events: sys::POLLIN,
        revents: 0,
    }];
    sys::poll_once(&mut fds, timeout_ms)?;
    if fds[0].revents & sys::POLLIN == 0 {
        bail!("listener did not become readable before the session deadline");
    }
    Ok(())
}
