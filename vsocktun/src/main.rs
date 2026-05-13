//! `vsocktun` is a point-to-point packet relay between a Linux TUN device and
//! a set of VSOCK connections.
//!
//! The relay is organized around two concepts:
//! - a *session*, which is one logical tunnel between enclave and parent
//! - a set of *shards*, where each shard pairs one TUN queue with one VSOCK
//!   stream so independent inner flows do not all contend on one ordered outer
//!   transport

mod protocol;
mod tun;
mod vsock;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use protocol::{FrameReader, OutgoingBuffer};
use std::fmt::Arguments;
use std::io;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use tokio_vsock::{OwnedReadHalf, OwnedWriteHalf, VsockStream};
use tracing::Level;
use tun::{Ipv4Cidr, TunDevice};
use tun_rs::{AsyncDevice, SyncDevice};
use vsock::{ParentSessionAcceptor, SessionSockets, connect_session};

const MAX_TUN_FRAME_BYTES: usize = 1024 * 1024;

fn log_level_from_count(count: u8) -> Level {
    match count {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    }
}

#[derive(Parser, Debug)]
#[command(name = "vsocktun")]
#[command(about = "Multi-queue TUN to VSOCK relay")]
struct Cli {
    /// Verbosity level (-v for shard/session logs, -vv for packet flow logs)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    Parent(ParentArgs),
    Enclave(EnclaveArgs),
}

/// Common tunnel parameters shared by both ends of the relay.
///
/// The surrounding shell scripts still own addressing, routing, NAT, and DNS.
/// `vsocktun` only needs enough information to create the local TUN queues and
/// connect them to the matching VSOCK session.
#[derive(Args, Debug, Clone)]
struct CommonArgs {
    #[arg(long)]
    tun_name: String,
    #[arg(long)]
    tun_address: String,
    #[arg(long)]
    vsock_port: u32,
    #[arg(long, default_value_t = 8)]
    queues: u16,
    #[arg(long)]
    mtu: Option<u32>,
    #[arg(long, default_value_t = 4)]
    tokio_worker_threads: usize,
}

#[derive(Args, Debug)]
struct ParentArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long, default_value_t = 5)]
    session_timeout_secs: u64,
}

#[derive(Args, Debug)]
struct EnclaveArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long, default_value_t = 3)]
    parent_cid: u32,
    #[arg(long, default_value_t = 1_000)]
    reconnect_delay_ms: u64,
}

#[derive(Debug)]
struct WorkerOutcome {
    shard: usize,
    result: Result<()>,
}

/// Identifies which half of a shard finished first so the other half can be
/// cancelled and drained cleanly.
enum DirectionTask {
    SocketToTun,
    TunToSocket,
}

#[derive(Clone, Copy, Debug)]
struct ShardLogContext {
    role: &'static str,
    session_id: u64,
    shard: usize,
}

impl ShardLogContext {
    fn debug(self, args: Arguments<'_>) {
        tracing::debug!(
            role = self.role,
            session_id = self.session_id,
            shard = self.shard,
            "{args}"
        );
    }

    fn trace(self, args: Arguments<'_>) {
        tracing::trace!(
            role = self.role,
            session_id = self.session_id,
            shard = self.shard,
            "{args}"
        );
    }
}

impl Cli {
    fn tokio_worker_threads(&self) -> usize {
        match &self.mode {
            Mode::Parent(args) => args.common.tokio_worker_threads,
            Mode::Enclave(args) => args.common.tokio_worker_threads,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let worker_threads = cli.tokio_worker_threads();
    if worker_threads == 0 {
        bail!("--tokio-worker-threads must be at least one");
    }

    tracing_subscriber::fmt()
        .with_max_level(log_level_from_count(cli.verbose))
        .with_target(false)
        .without_time()
        .init();

    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("vsocktun")
        .enable_all()
        .build()
        .context("failed to build Tokio runtime for vsocktun")?;

    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    match cli.mode {
        Mode::Parent(args) => run_parent(args).await,
        Mode::Enclave(args) => run_enclave(args).await,
    }
}

/// Parent-side entry point.
///
/// The parent creates the local TUN device once, then repeatedly accepts new
/// tunnel sessions from enclaves over VSOCK. Each accepted session reuses that
/// same TUN interface but gets a fresh set of queue handles.
async fn run_parent(args: ParentArgs) -> Result<()> {
    let common = ParsedCommon::parse(args.common)?;
    let tun = TunDevice::create(
        &common.tun_name,
        &common.tun_address,
        common.queues,
        common.mtu,
    )
    .with_context(|| format!("failed to create TUN interface '{}'", common.tun_name))?;
    tracing::debug!(
        tun_name = %common.tun_name,
        tun_address = %common.tun_address.address(),
        prefix_len = common.tun_address.prefix_len(),
        queues = common.queues,
        mtu = ?common.mtu,
        tokio_worker_threads = common.tokio_worker_threads,
        "vsocktun(parent): configured tunnel"
    );
    let acceptor = ParentSessionAcceptor::bind(
        common.vsock_port,
        tun.queue_count(),
        Duration::from_secs(args.session_timeout_secs),
    )?;

    tracing::info!(
        vsock_port = common.vsock_port,
        queues = tun.queue_count(),
        tun_name = %common.tun_name,
        "vsocktun(parent): listening for tunnel sessions"
    );

    loop {
        match acceptor.accept_session().await {
            Ok(session) => {
                tracing::info!(
                    session_id = session.session_id,
                    shards = session.shards.len(),
                    "vsocktun(parent): established session"
                );
                if let Err(err) = run_session("parent", &tun, session).await {
                    tracing::error!(error = %err, "vsocktun(parent): session ended with error");
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "vsocktun(parent): failed to accept session");
            }
        }
    }
}

/// Enclave-side entry point.
///
/// The enclave creates its local TUN device once and then repeatedly attempts
/// to establish a complete multi-shard session to the parent. Reconnect policy
/// lives here so shard workers can stay focused on packet forwarding.
async fn run_enclave(args: EnclaveArgs) -> Result<()> {
    let common = ParsedCommon::parse(args.common)?;
    let tun = TunDevice::create(
        &common.tun_name,
        &common.tun_address,
        common.queues,
        common.mtu,
    )
    .with_context(|| format!("failed to create TUN interface '{}'", common.tun_name))?;
    let reconnect_delay = Duration::from_millis(args.reconnect_delay_ms);
    tracing::debug!(
        tun_name = %common.tun_name,
        tun_address = %common.tun_address.address(),
        prefix_len = common.tun_address.prefix_len(),
        queues = common.queues,
        mtu = ?common.mtu,
        tokio_worker_threads = common.tokio_worker_threads,
        "vsocktun(enclave): configured tunnel"
    );

    tracing::info!(
        parent_cid = args.parent_cid,
        vsock_port = common.vsock_port,
        queues = tun.queue_count(),
        tun_name = %common.tun_name,
        "vsocktun(enclave): dialing parent"
    );

    loop {
        match connect_session(args.parent_cid, common.vsock_port, tun.queue_count()).await {
            Ok(session) => {
                tracing::info!(
                    session_id = session.session_id,
                    shards = session.shards.len(),
                    "vsocktun(enclave): established session"
                );
                if let Err(err) = run_session("enclave", &tun, session).await {
                    tracing::error!(error = %err, "vsocktun(enclave): session ended with error");
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "vsocktun(enclave): failed to connect session");
            }
        }

        tracing::info!(
            reconnect_delay_ms = reconnect_delay.as_millis(),
            "vsocktun(enclave): reconnecting"
        );
        sleep(reconnect_delay).await;
    }
}

/// Runs one logical tunnel session across all configured shards.
///
/// A session supervisor fans out one worker per shard, waits for the first
/// failure, and then broadcasts cancellation so no shard outlives the session.
async fn run_session(role: &'static str, tun: &TunDevice, session: SessionSockets) -> Result<()> {
    let session_id = session.session_id;
    let max_tun_frame_bytes = tun.max_frame_bytes();
    let tun_queues = tun
        .clone_queues()
        .context("failed to clone TUN queues for session")?;
    if tun_queues.len() != session.shards.len() {
        bail!(
            "session {} has {} shard sockets but {} TUN queues",
            session.session_id,
            session.shards.len(),
            tun_queues.len(),
        );
    }
    tracing::debug!(
        role,
        session_id,
        shards = tun_queues.len(),
        "vsocktun: starting session"
    );

    let (cancel_tx, _) = watch::channel(false);
    let mut tasks = JoinSet::new();

    for (shard, (tun_queue, socket)) in tun_queues.into_iter().zip(session.shards).enumerate() {
        tracing::debug!(role, session_id, shard, "vsocktun: spawning shard worker");
        let shard_log = ShardLogContext {
            role,
            session_id,
            shard,
        };
        let cancel_rx = cancel_tx.subscribe();
        tasks.spawn(async move {
            WorkerOutcome {
                shard,
                result: pump_shard(shard_log, tun_queue, socket, max_tun_frame_bytes, cancel_rx)
                    .await,
            }
        });
    }

    let mut first_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(outcome) => {
                if let Err(err) = outcome.result
                    && first_error.is_none()
                {
                    tracing::debug!(
                        role,
                        session_id,
                        shard = outcome.shard,
                        "vsocktun: cancelling session after shard failure"
                    );
                    let _ = cancel_tx.send(true);
                    first_error = Some(anyhow!("shard {} failed: {err:#}", outcome.shard));
                }
            }
            Err(err) => {
                if first_error.is_none() {
                    tracing::debug!(
                        role,
                        session_id,
                        "vsocktun: cancelling session after worker task failure"
                    );
                    let _ = cancel_tx.send(true);
                    first_error = Some(anyhow!("vsocktun worker task failed: {err}"));
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    tracing::debug!(role, session_id, "vsocktun: session completed cleanly");

    Ok(())
}

/// Runs both packet directions for one shard.
///
/// Each shard is one independently scheduled lane in the tunnel. It combines a
/// single TUN queue with a single VSOCK stream and treats both directions as a
/// unit for lifecycle and error handling.
async fn pump_shard(
    shard_log: ShardLogContext,
    tun_queue: SyncDevice,
    socket: VsockStream,
    max_tun_frame_bytes: usize,
    mut session_cancelled: watch::Receiver<bool>,
) -> Result<()> {
    if *session_cancelled.borrow() {
        return Ok(());
    }

    shard_log.debug(format_args!("starting"));

    let tun_queue =
        Arc::new(AsyncDevice::new(tun_queue).with_context(|| {
            format!("failed to make TUN queue {} asynchronous", shard_log.shard)
        })?);
    let socket_frame_bytes = MAX_TUN_FRAME_BYTES.max(max_tun_frame_bytes);
    let (socket_reader, socket_writer) = socket.into_split();
    let (local_cancel_tx, _) = watch::channel(false);

    let socket_to_tun = forward_socket_to_tun(
        shard_log,
        socket_reader,
        Arc::clone(&tun_queue),
        socket_frame_bytes,
        local_cancel_tx.subscribe(),
    );
    let tun_to_socket = forward_tun_to_socket(
        shard_log,
        Arc::clone(&tun_queue),
        socket_writer,
        socket_frame_bytes,
        local_cancel_tx.subscribe(),
    );
    tokio::pin!(socket_to_tun);
    tokio::pin!(tun_to_socket);

    let first = tokio::select! {
        changed = session_cancelled.changed() => {
            match changed {
                Ok(()) if *session_cancelled.borrow() => {
                    shard_log.debug(format_args!("received session cancellation"));
                    let _ = local_cancel_tx.send(true);
                    let _ = (&mut socket_to_tun).await;
                    let _ = (&mut tun_to_socket).await;
                    return Ok(());
                }
                Ok(()) | Err(_) => {
                    let _ = local_cancel_tx.send(true);
                    let _ = (&mut socket_to_tun).await;
                    let _ = (&mut tun_to_socket).await;
                    return Ok(());
                }
            }
        }
        result = &mut socket_to_tun => (DirectionTask::SocketToTun, result),
        result = &mut tun_to_socket => (DirectionTask::TunToSocket, result),
    };

    let _ = local_cancel_tx.send(true);
    let second = match first.0 {
        DirectionTask::SocketToTun => (&mut tun_to_socket).await,
        DirectionTask::TunToSocket => (&mut socket_to_tun).await,
    };

    shard_log.debug(format_args!("stopping"));

    match (first.1, second) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Moves framed packets from the shard's VSOCK stream into the matching TUN
/// queue.
///
/// This direction is intentionally agnostic to the inner TCP or gRPC protocol;
/// it only restores packet boundaries established by the tunnel framing.
async fn forward_socket_to_tun(
    shard_log: ShardLogContext,
    mut socket_reader: OwnedReadHalf,
    tun_queue: Arc<AsyncDevice>,
    max_tun_frame_bytes: usize,
    mut cancelled: watch::Receiver<bool>,
) -> Result<()> {
    let mut frame_reader = FrameReader::new(max_tun_frame_bytes);

    loop {
        if *cancelled.borrow() {
            return Ok(());
        }

        let packet = tokio::select! {
            changed = cancelled.changed() => {
                match changed {
                    Ok(()) if *cancelled.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            result = frame_reader.read_packet_async(&mut socket_reader) => {
                result.with_context(|| format!("failed to read framed packet on shard {}", shard_log.shard))?
            }
        };

        let Some(packet) = packet else {
            continue;
        };
        let packet_len = packet.len();

        let mut pending_tun_write = OutgoingBuffer::raw(packet);
        loop {
            if *cancelled.borrow() {
                return Ok(());
            }

            let finished = tokio::select! {
                changed = cancelled.changed() => {
                    match changed {
                        Ok(()) if *cancelled.borrow() => return Ok(()),
                        Ok(()) => continue,
                        Err(_) => return Ok(()),
                    }
                }
                result = write_to_tun(&mut pending_tun_write, tun_queue.as_ref()) => {
                    result.with_context(|| format!("failed to inject packet into TUN queue {}", shard_log.shard))?
                }
            };

            if finished {
                shard_log.trace(format_args!("forwarded {packet_len} bytes vsock->tun"));
                break;
            }
        }
    }
}

/// Moves packets from the shard's TUN queue into the matching VSOCK stream.
///
/// The TUN device may surface offloaded or coalesced traffic, so this path is
/// responsible for preserving whatever packet representation the local kernel
/// exposes rather than normalizing it back to one frame per inner segment.
async fn forward_tun_to_socket(
    shard_log: ShardLogContext,
    tun_queue: Arc<AsyncDevice>,
    mut socket_writer: OwnedWriteHalf,
    max_tun_frame_bytes: usize,
    mut cancelled: watch::Receiver<bool>,
) -> Result<()> {
    let mut tun_buf = vec![0_u8; max_tun_frame_bytes];

    loop {
        if *cancelled.borrow() {
            return Ok(());
        }

        let read = tokio::select! {
            changed = cancelled.changed() => {
                match changed {
                    Ok(()) if *cancelled.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            result = tun_queue.recv(&mut tun_buf) => {
                result.with_context(|| format!("failed to read packet from TUN queue {}", shard_log.shard))?
            }
        };

        if read == 0 {
            bail!("TUN queue {} closed unexpectedly", shard_log.shard);
        }

        let mut pending_socket_write =
            OutgoingBuffer::framed(&tun_buf[..read]).with_context(|| {
                format!("failed to frame TUN packet from queue {}", shard_log.shard)
            })?;
        loop {
            if *cancelled.borrow() {
                return Ok(());
            }

            let finished = tokio::select! {
                changed = cancelled.changed() => {
                    match changed {
                        Ok(()) if *cancelled.borrow() => return Ok(()),
                        Ok(()) => continue,
                        Err(_) => return Ok(()),
                    }
                }
                result = pending_socket_write.write_to_async(&mut socket_writer) => {
                    result.with_context(|| format!("failed to forward packet on VSOCK shard {}", shard_log.shard))?
                }
            };

            if finished {
                shard_log.trace(format_args!("forwarded {read} bytes tun->vsock"));
                break;
            }
        }
    }
}

/// Best-effort write helper for the TUN side of a shard.
///
/// The caller retains ownership of the pending packet buffer so partial writes
/// can resume without rebuilding framing state.
async fn write_to_tun(buffer: &mut OutgoingBuffer, tun_queue: &AsyncDevice) -> io::Result<bool> {
    let bytes = &buffer.bytes[buffer.written..];
    match tun_queue.send(bytes).await {
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "failed to make forward progress while writing packet to TUN",
        )),
        Ok(written) => {
            buffer.written += written;
            Ok(buffer.written == buffer.bytes.len())
        }
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
struct ParsedCommon {
    tun_name: String,
    tun_address: Ipv4Cidr,
    vsock_port: u32,
    queues: usize,
    mtu: Option<u32>,
    tokio_worker_threads: usize,
}

impl ParsedCommon {
    /// Parses CLI parameters into the validated runtime configuration used by
    /// both parent and enclave session setup.
    fn parse(args: CommonArgs) -> Result<Self> {
        if args.queues == 0 {
            bail!("--queues must be at least one");
        }

        Ok(Self {
            tun_name: args.tun_name,
            tun_address: Ipv4Cidr::parse(&args.tun_address)
                .with_context(|| format!("failed to parse --tun-address '{}'", args.tun_address))?,
            vsock_port: args.vsock_port,
            queues: usize::from(args.queues),
            mtu: args.mtu,
            tokio_worker_threads: args.tokio_worker_threads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Mode, log_level_from_count};
    use clap::Parser;
    use tracing::Level;

    #[test]
    fn parses_single_verbose_flag() {
        let cli = Cli::try_parse_from([
            "vsocktun",
            "-v",
            "parent",
            "--tun-name",
            "vsocktun",
            "--tun-address",
            "10.118.0.1/24",
            "--vsock-port",
            "2100",
        ])
        .expect("CLI should parse with one verbose flag");

        assert_eq!(cli.verbose, 1);
        assert!(matches!(cli.mode, Mode::Parent(_)));
    }

    #[test]
    fn parses_double_verbose_flag() {
        let cli = Cli::try_parse_from([
            "vsocktun",
            "-vv",
            "enclave",
            "--parent-cid",
            "3",
            "--tun-name",
            "vsocktun",
            "--tun-address",
            "10.118.0.2/24",
            "--vsock-port",
            "2100",
        ])
        .expect("CLI should parse with two verbose flags");

        assert_eq!(cli.verbose, 2);
        assert!(matches!(cli.mode, Mode::Enclave(_)));
    }

    #[test]
    fn maps_verbose_levels_to_expected_outputs() {
        assert_eq!(log_level_from_count(0), Level::INFO);
        assert_eq!(log_level_from_count(1), Level::DEBUG);
        assert_eq!(log_level_from_count(2), Level::TRACE);
        assert_eq!(log_level_from_count(7), Level::TRACE);
    }
}
