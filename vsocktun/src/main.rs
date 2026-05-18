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
#[cfg(test)]
use std::collections::VecDeque;
use std::fmt::Arguments;
use std::future::Future;
use std::io;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use tokio::runtime::Builder;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use tokio_vsock::{OwnedReadHalf, OwnedWriteHalf, VsockStream};
use tracing::Level;
use tun::{Ipv4Cidr, TunDevice};
use tun_rs::{AsyncDevice, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
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

struct WorkerOutcome<ReturnedQueue> {
    shard: usize,
    returned_queue: ReturnedQueue,
    result: Result<()>,
}

struct SupervisedWorkersOutcome<ReturnedQueue> {
    returned_queues: Vec<Option<ReturnedQueue>>,
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

#[cfg(test)]
#[derive(Default)]
struct TestFlowCounters {
    parent_tun_to_vsock_packets: u64,
    parent_vsock_to_tun_packets: u64,
    enclave_tun_to_vsock_packets: u64,
    enclave_vsock_to_tun_packets: u64,
    parent_tun_to_vsock_samples: VecDeque<String>,
    parent_vsock_to_tun_samples: VecDeque<String>,
    enclave_tun_to_vsock_samples: VecDeque<String>,
    enclave_vsock_to_tun_samples: VecDeque<String>,
}

#[cfg(test)]
static TEST_FLOW_COUNTERS: OnceLock<Mutex<TestFlowCounters>> = OnceLock::new();

#[cfg(test)]
fn reset_test_flow_counters() {
    *TEST_FLOW_COUNTERS
        .get_or_init(|| Mutex::new(TestFlowCounters::default()))
        .lock()
        .expect("test flow counters mutex should not be poisoned") = TestFlowCounters::default();
}

#[cfg(test)]
fn test_flow_summary() -> String {
    let counters = TEST_FLOW_COUNTERS
        .get_or_init(|| Mutex::new(TestFlowCounters::default()))
        .lock()
        .expect("test flow counters mutex should not be poisoned");
    format!(
        "parent_tun_to_vsock_packets={}, parent_vsock_to_tun_packets={}, enclave_tun_to_vsock_packets={}, enclave_vsock_to_tun_packets={}, parent_tun_to_vsock_samples={:?}, parent_vsock_to_tun_samples={:?}, enclave_tun_to_vsock_samples={:?}, enclave_vsock_to_tun_samples={:?}",
        counters.parent_tun_to_vsock_packets,
        counters.parent_vsock_to_tun_packets,
        counters.enclave_tun_to_vsock_packets,
        counters.enclave_vsock_to_tun_packets,
        counters.parent_tun_to_vsock_samples,
        counters.parent_vsock_to_tun_samples,
        counters.enclave_tun_to_vsock_samples,
        counters.enclave_vsock_to_tun_samples,
    )
}

#[cfg(test)]
fn push_sample(samples: &mut VecDeque<String>, summary: String) {
    if samples.len() == 4 {
        let _ = samples.pop_front();
    }
    samples.push_back(summary);
}

#[cfg(test)]
fn record_test_tun_to_vsock(role: &'static str, packet: &[u8]) {
    let mut counters = TEST_FLOW_COUNTERS
        .get_or_init(|| Mutex::new(TestFlowCounters::default()))
        .lock()
        .expect("test flow counters mutex should not be poisoned");
    let summary = packet_summary(packet);
    match role {
        "parent" => {
            counters.parent_tun_to_vsock_packets += 1;
            push_sample(&mut counters.parent_tun_to_vsock_samples, summary);
        }
        "enclave" => {
            counters.enclave_tun_to_vsock_packets += 1;
            push_sample(&mut counters.enclave_tun_to_vsock_samples, summary);
        }
        _ => {}
    }
}

#[cfg(test)]
fn record_test_vsock_to_tun(role: &'static str, packet: &[u8]) {
    let mut counters = TEST_FLOW_COUNTERS
        .get_or_init(|| Mutex::new(TestFlowCounters::default()))
        .lock()
        .expect("test flow counters mutex should not be poisoned");
    let summary = packet_summary(packet);
    match role {
        "parent" => {
            counters.parent_vsock_to_tun_packets += 1;
            push_sample(&mut counters.parent_vsock_to_tun_samples, summary);
        }
        "enclave" => {
            counters.enclave_vsock_to_tun_packets += 1;
            push_sample(&mut counters.enclave_vsock_to_tun_samples, summary);
        }
        _ => {}
    }
}

#[cfg(test)]
fn packet_summary(packet: &[u8]) -> String {
    if packet.len() < 20 {
        return format!("short(len={})", packet.len());
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return format!("ip_version={} len={}", version, packet.len());
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return format!("bad_ihl={} len={}", ihl, packet.len());
    }
    let src = format!(
        "{}.{}.{}.{}",
        packet[12], packet[13], packet[14], packet[15]
    );
    let dst = format!(
        "{}.{}.{}.{}",
        packet[16], packet[17], packet[18], packet[19]
    );
    match packet[9] {
        17 if packet.len() >= ihl + 8 => {
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            format!(
                "udp {}:{} -> {}:{} len={}",
                src,
                src_port,
                dst,
                dst_port,
                packet.len()
            )
        }
        1 if packet.len() >= ihl + 2 => {
            let icmp_type = packet[ihl];
            let icmp_code = packet[ihl + 1];
            format!(
                "icmp {} -> {} type={} code={} len={}",
                src,
                dst,
                icmp_type,
                icmp_code,
                packet.len()
            )
        }
        proto => format!("proto={} {} -> {} len={}", proto, src, dst, packet.len()),
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
        Mode::Parent(args) => run_parent(args, std::future::pending()).await,
        Mode::Enclave(args) => run_enclave(args, std::future::pending()).await,
    }
}

/// Parent-side entry point.
///
/// The parent creates the local TUN device once, then repeatedly accepts new
/// tunnel sessions from enclaves over VSOCK. Each accepted session reuses that
/// same TUN interface but gets a fresh set of queue handles.
async fn run_parent<Shutdown>(args: ParentArgs, shutdown: Shutdown) -> Result<()>
where
    Shutdown: Future<Output = ()>,
{
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

    tokio::pin!(shutdown);
    loop {
        match tokio::select! {
            _ = shutdown.as_mut() => return Ok(()),
            session = acceptor.accept_session() => session,
        } {
            Ok(session) => {
                tracing::info!(
                    session_id = session.session_id,
                    shards = session.shards.len(),
                    "vsocktun(parent): established session"
                );
                let session_result = tokio::select! {
                    _ = shutdown.as_mut() => return Ok(()),
                    result = run_session("parent", &tun, session) => result,
                };
                if let Err(err) = session_result {
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
async fn run_enclave<Shutdown>(args: EnclaveArgs, shutdown: Shutdown) -> Result<()>
where
    Shutdown: Future<Output = ()>,
{
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

    let queue_count = tun.queue_count();
    tokio::pin!(shutdown);
    loop {
        match tokio::select! {
            _ = shutdown.as_mut() => return Ok(()),
            session = connect_session(args.parent_cid, common.vsock_port, queue_count) => session,
        } {
            Ok(session) => {
                tracing::info!(
                    session_id = session.session_id,
                    shards = session.shards.len(),
                    "vsocktun(enclave): established session"
                );
                let session_result = tokio::select! {
                    _ = shutdown.as_mut() => return Ok(()),
                    result = run_session("enclave", &tun, session) => result,
                };
                if let Err(err) = session_result {
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
        tokio::select! {
            _ = shutdown.as_mut() => return Ok(()),
            _ = sleep(reconnect_delay) => {}
        }
    }
}

/// Runs one logical tunnel session across all configured shards.
///
/// A session supervisor fans out one worker per shard, waits for the first
/// failure, and then broadcasts cancellation so no shard outlives the session.
async fn run_session(role: &'static str, tun: &TunDevice, session: SessionSockets) -> Result<()> {
    let session_id = session.session_id;
    let max_tun_frame_bytes = tun.max_frame_bytes();
    let mut tun_queues = tun
        .take_queues()
        .context("failed to take TUN queues for session")?;
    let tun_queue_count = tun_queues.len();
    if tun_queues.len() != session.shards.len() {
        tun.restore_queues(tun_queues);
        bail!(
            "session {} has {} shard sockets but {} TUN queues",
            session.session_id,
            session.shards.len(),
            tun_queue_count,
        );
    }
    tracing::debug!(
        role,
        session_id,
        shards = tun_queues.len(),
        "vsocktun: starting session"
    );

    let work_items = tun_queues.drain(..).zip(session.shards).collect::<Vec<_>>();
    let SupervisedWorkersOutcome {
        returned_queues,
        result,
    } =
        supervise_session_workers(
            role,
            session_id,
            work_items,
            |shard, (tun_queue, socket), cancel_rx| {
                let shard_log = ShardLogContext {
                    role,
                    session_id,
                    shard,
                };
                async move {
                    pump_shard(shard_log, tun_queue, socket, max_tun_frame_bytes, cancel_rx).await
                }
            },
        )
        .await;

    let restored_queues = returned_queues
        .into_iter()
        .enumerate()
        .map(|(shard, queue)| {
            queue.ok_or_else(|| anyhow!("missing returned TUN queue for shard {shard}"))
        })
        .collect::<Result<Vec<_>>>()?;
    tun.restore_queues(restored_queues);

    result?;

    tracing::debug!(role, session_id, "vsocktun: session completed cleanly");

    Ok(())
}

async fn supervise_session_workers<WorkItem, ReturnedQueue, SpawnWorker, WorkerFuture>(
    role: &'static str,
    session_id: u64,
    work_items: Vec<WorkItem>,
    mut spawn_worker: SpawnWorker,
) -> SupervisedWorkersOutcome<ReturnedQueue>
where
    WorkItem: Send + 'static,
    ReturnedQueue: Send + 'static,
    SpawnWorker: FnMut(usize, WorkItem, watch::Receiver<bool>) -> WorkerFuture,
    WorkerFuture: Future<Output = (ReturnedQueue, Result<()>)> + Send + 'static,
{
    let (cancel_tx, _) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let mut returned_queues = std::iter::repeat_with(|| None)
        .take(work_items.len())
        .collect::<Vec<Option<ReturnedQueue>>>();

    for (shard, work_item) in work_items.into_iter().enumerate() {
        tracing::debug!(role, session_id, shard, "vsocktun: spawning shard worker");
        let cancel_rx = cancel_tx.subscribe();
        let worker = spawn_worker(shard, work_item, cancel_rx);
        tasks.spawn(async move {
            let (returned_queue, result) = worker.await;
            WorkerOutcome {
                shard,
                returned_queue,
                result,
            }
        });
    }

    let mut first_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(outcome) => {
                returned_queues[outcome.shard] = Some(outcome.returned_queue);
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

    SupervisedWorkersOutcome {
        returned_queues,
        result: first_error.map_or_else(|| Ok(()), Err),
    }
}

/// Runs both packet directions for one shard.
///
/// Each shard is one independently scheduled lane in the tunnel. It combines a
/// single TUN queue with a single VSOCK stream and treats both directions as a
/// unit for lifecycle and error handling.
async fn pump_shard(
    shard_log: ShardLogContext,
    tun_queue: AsyncDevice,
    socket: VsockStream,
    max_tun_frame_bytes: usize,
    mut session_cancelled: watch::Receiver<bool>,
) -> (AsyncDevice, Result<()>) {
    if *session_cancelled.borrow() {
        return (tun_queue, Ok(()));
    }

    shard_log.debug(format_args!("starting"));

    let socket_frame_bytes = MAX_TUN_FRAME_BYTES.max(max_tun_frame_bytes);
    let (socket_reader, socket_writer) = socket.into_split();
    let (local_cancel_tx, _) = watch::channel(false);

    let result = {
        // Both directions only need a shared borrow of the queue. Keeping ownership in this
        // worker guarantees the session supervisor can recover the queue even when one direction
        // exits with an error.
        let socket_to_tun = forward_socket_to_tun(
            shard_log,
            socket_reader,
            &tun_queue,
            socket_frame_bytes,
            local_cancel_tx.subscribe(),
        );
        let tun_to_socket = forward_tun_to_socket(
            shard_log,
            &tun_queue,
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
                        None
                    }
                    Ok(()) | Err(_) => {
                        let _ = local_cancel_tx.send(true);
                        let _ = (&mut socket_to_tun).await;
                        let _ = (&mut tun_to_socket).await;
                        None
                    }
                }
            }
            result = &mut socket_to_tun => Some((DirectionTask::SocketToTun, result)),
            result = &mut tun_to_socket => Some((DirectionTask::TunToSocket, result)),
        };

        if let Some(first) = first {
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
        } else {
            Ok(())
        }
    };
    (tun_queue, result)
}

/// Moves framed packets from the shard's VSOCK stream into the matching TUN
/// queue.
///
/// This direction is intentionally agnostic to the inner TCP or gRPC protocol;
/// it only restores packet boundaries established by the tunnel framing.
async fn forward_socket_to_tun(
    shard_log: ShardLogContext,
    mut socket_reader: OwnedReadHalf,
    tun_queue: &AsyncDevice,
    max_tun_frame_bytes: usize,
    mut cancelled: watch::Receiver<bool>,
) -> Result<()> {
    let mut frame_reader = FrameReader::new(max_tun_frame_bytes);
    let tun_offload = tun_queue.tcp_gso() || tun_queue.udp_gso();

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

        if tun_offload {
            let mut pending_tun_write = OutgoingBuffer::raw({
                let mut tun_packet = vec![0_u8; VIRTIO_NET_HDR_LEN];
                tun_packet.extend_from_slice(&packet);
                tun_packet
            });
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
                    result = write_to_tun(&mut pending_tun_write, tun_queue) => {
                        result.with_context(|| format!("failed to inject packet into TUN queue {}", shard_log.shard))?
                    }
                };

                if finished {
                    shard_log.trace(format_args!("forwarded {packet_len} bytes vsock->tun"));
                    #[cfg(test)]
                    record_test_vsock_to_tun(shard_log.role, &packet);
                    break;
                }
            }
            continue;
        }

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
                result = write_to_tun(&mut pending_tun_write, tun_queue) => {
                    result.with_context(|| format!("failed to inject packet into TUN queue {}", shard_log.shard))?
                }
            };

            if finished {
                shard_log.trace(format_args!("forwarded {packet_len} bytes vsock->tun"));
                #[cfg(test)]
                record_test_vsock_to_tun(
                    shard_log.role,
                    &pending_tun_write.bytes[VIRTIO_NET_HDR_LEN..],
                );
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
    tun_queue: &AsyncDevice,
    mut socket_writer: OwnedWriteHalf,
    max_tun_frame_bytes: usize,
    mut cancelled: watch::Receiver<bool>,
) -> Result<()> {
    let tun_offload = tun_queue.tcp_gso() || tun_queue.udp_gso();
    let mut tun_buf = vec![0_u8; max_tun_frame_bytes];
    let mut tun_packet_bufs = (0..IDEAL_BATCH_SIZE)
        .map(|_| vec![0_u8; max_tun_frame_bytes])
        .collect::<Vec<_>>();
    let mut tun_packet_sizes = vec![0_usize; IDEAL_BATCH_SIZE];

    loop {
        if *cancelled.borrow() {
            return Ok(());
        }

        let packets = tokio::select! {
            changed = cancelled.changed() => {
                match changed {
                    Ok(()) if *cancelled.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            result = async {
                if tun_offload {
                    tun_queue
                        .recv_multiple(&mut tun_buf, &mut tun_packet_bufs, &mut tun_packet_sizes, 0)
                        .await
                } else {
                    tun_queue.recv(&mut tun_buf).await.map(|read| {
                        tun_packet_sizes[0] = read;
                        1
                    })
                }
            } => {
                result.with_context(|| format!("failed to read packet from TUN queue {}", shard_log.shard))?
            }
        };

        if packets == 0 || tun_packet_sizes[0] == 0 {
            bail!("TUN queue {} closed unexpectedly", shard_log.shard);
        }

        for packet_index in 0..packets {
            let packet_len = tun_packet_sizes[packet_index];
            let packet = if tun_offload {
                &tun_packet_bufs[packet_index][..packet_len]
            } else {
                &tun_buf[..packet_len]
            };
            let mut pending_socket_write = OutgoingBuffer::framed(packet).with_context(|| {
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
                    shard_log.trace(format_args!("forwarded {packet_len} bytes tun->vsock"));
                    #[cfg(test)]
                    record_test_tun_to_vsock(shard_log.role, packet);
                    break;
                }
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
    use super::{
        Cli, Mode, SupervisedWorkersOutcome, log_level_from_count, supervise_session_workers,
    };
    use anyhow::{Result, anyhow};
    use clap::Parser;
    use tokio::runtime::Builder;
    use tracing::Level;

    struct TestQueuePool<T> {
        queues: Option<Vec<T>>,
    }

    impl<T> TestQueuePool<T> {
        fn new(queues: Vec<T>) -> Self {
            Self {
                queues: Some(queues),
            }
        }

        fn take(&mut self) -> Vec<T> {
            self.queues
                .take()
                .expect("test queue pool should have queues available")
        }

        fn restore(&mut self, queues: Vec<T>) {
            let previous = self.queues.replace(queues);
            assert!(
                previous.is_none(),
                "test queue pool should not overwrite already-available queues"
            );
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should be created")
    }

    #[cfg(target_os = "linux")]
    mod integration_tests {
        use super::super::{
            CommonArgs, EnclaveArgs, ParentArgs, reset_test_flow_counters, run_enclave, run_parent,
            test_flow_summary,
        };
        use anyhow::{Context, Result, anyhow, bail};
        use etherparse::{NetSlice, SlicedPacket, TransportSlice};
        use netns_rs::NetNs;
        use nix::sys::socket::{
            AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType, recv, setsockopt, socket,
            sockopt,
        };
        use std::ffi::OsString;
        use std::net::{Ipv4Addr, SocketAddrV4};
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::pin::pin;
        use std::process::{self, Command};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::{self, Receiver as StdReceiver};
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::io::unix::AsyncFd;
        use tokio::net::UdpSocket;
        use tokio::runtime::Builder;
        use tokio::sync::oneshot;
        use tokio::time::{Duration, Instant, sleep};

        const TEST_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
        const TEST_RETRY_DELAY: Duration = Duration::from_millis(50);
        const REQUEST_PORT: u16 = 41_000;
        const REPLY_PORT: u16 = 41_001;
        const REQUEST_PAYLOAD: &[u8] = b"enclave-to-parent-through-vsocktun";
        const REPLY_PAYLOAD: &[u8] = b"parent-to-enclave-through-vsocktun";

        #[derive(Clone, Debug)]
        struct TestConfig {
            enclave_ns_name: String,
            parent_tun_name: String,
            enclave_tun_name: String,
            parent_ip: Ipv4Addr,
            enclave_ip: Ipv4Addr,
            vsock_port: u32,
        }

        // Owns the persistent namespaces created for the test so partial setup and normal drop
        // both clean them up through netns-rs.
        struct NetNamespaceGuard {
            namespaces: Vec<NetNs>,
        }

        // Captures raw IPv4 packets on one TUN interface so the test can prove traffic crossed
        // the relay instead of only checking that user-space UDP sockets exchanged bytes.
        struct PacketCapture {
            socket: AsyncFd<OwnedFd>,
            interface_name: String,
        }

        struct ExpectedCapturedPacket<'a> {
            src_ip: Ipv4Addr,
            dst_ip: Ipv4Addr,
            dst_port: u16,
            payload: &'a [u8],
        }

        struct ParsedUdpPacket<'a> {
            src_ip: Ipv4Addr,
            dst_ip: Ipv4Addr,
            dst_port: u16,
            payload: &'a [u8],
        }

        impl TestConfig {
            fn new() -> Self {
                let pid = process::id() as u16;
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as u16;
                let token = pid ^ nanos;
                let subnet_octet = 1 + (token % 250) as u8;

                Self {
                    enclave_ns_name: format!("vstens{token:04x}"),
                    parent_tun_name: format!("vstp{token:04x}"),
                    enclave_tun_name: format!("vste{token:04x}"),
                    parent_ip: Ipv4Addr::new(10, 254, subnet_octet, 1),
                    enclave_ip: Ipv4Addr::new(10, 254, subnet_octet, 2),
                    vsock_port: 20_000 + u32::from(token % 20_000),
                }
            }
        }

        fn parent_args(config: &TestConfig) -> ParentArgs {
            ParentArgs {
                common: CommonArgs {
                    tun_name: config.parent_tun_name.clone(),
                    tun_address: format!("{}/24", config.parent_ip),
                    vsock_port: config.vsock_port,
                    queues: 1,
                    mtu: Some(1500),
                    tokio_worker_threads: 1,
                },
                session_timeout_secs: 5,
            }
        }

        fn enclave_args(config: &TestConfig) -> EnclaveArgs {
            EnclaveArgs {
                common: CommonArgs {
                    tun_name: config.enclave_tun_name.clone(),
                    tun_address: format!("{}/24", config.enclave_ip),
                    vsock_port: config.vsock_port,
                    queues: 1,
                    mtu: Some(1500),
                    tokio_worker_threads: 1,
                },
                // Use the Linux VSOCK loopback CID so the test reaches the parent listener on
                // the same host after entering the enclave network namespace.
                parent_cid: 1,
                reconnect_delay_ms: TEST_RETRY_DELAY.as_millis() as u64,
            }
        }

        impl PacketCapture {
            fn bind(interface_name: &str) -> Result<Self> {
                let socket = socket(
                    AddressFamily::Packet,
                    SockType::Datagram,
                    SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
                    Some(SockProtocol::EthIp),
                )
                .context("failed to create packet capture socket")?;
                setsockopt(
                    &socket,
                    sockopt::BindToDevice,
                    &OsString::from(interface_name),
                )
                .with_context(|| {
                    format!("failed to bind packet capture socket to interface '{interface_name}'",)
                })?;

                Ok(Self {
                    socket: AsyncFd::new(socket).with_context(|| {
                        format!(
                            "failed to register packet capture socket for interface '{interface_name}'",
                        )
                    })?,
                    interface_name: interface_name.to_owned(),
                })
            }

            async fn recv_matching(self, expected: ExpectedCapturedPacket<'_>) -> Result<()> {
                let mut buf = [0_u8; 4096];

                loop {
                    let mut readiness = self.socket.readable().await.with_context(|| {
                        format!(
                            "failed while waiting for packet capture readiness on '{}'",
                            self.interface_name,
                        )
                    })?;
                    let read = match readiness.try_io(|fd| {
                        recv(fd.get_ref().as_raw_fd(), &mut buf, MsgFlags::empty())
                            .map_err(std::io::Error::from)
                    }) {
                        Ok(result) => result.with_context(|| {
                            format!(
                                "failed to receive packet from capture socket on '{}'",
                                self.interface_name,
                            )
                        })?,
                        Err(_would_block) => continue,
                    };
                    let packet = &buf[..read];
                    let Some(parsed) = ParsedUdpPacket::parse(packet) else {
                        continue;
                    };
                    if parsed.src_ip == expected.src_ip
                        && parsed.dst_ip == expected.dst_ip
                        && parsed.dst_port == expected.dst_port
                        && parsed.payload == expected.payload
                    {
                        return Ok(());
                    }
                }
            }
        }

        impl<'a> ParsedUdpPacket<'a> {
            fn parse(packet: &'a [u8]) -> Option<Self> {
                let sliced = SlicedPacket::from_ip(packet).ok()?;
                let ipv4 = match sliced.net? {
                    NetSlice::Ipv4(ipv4) => ipv4,
                    NetSlice::Ipv6(_) | NetSlice::Arp(_) => return None,
                };
                let udp = match sliced.transport? {
                    TransportSlice::Udp(udp) => udp,
                    TransportSlice::Icmpv4(_)
                    | TransportSlice::Icmpv6(_)
                    | TransportSlice::Tcp(_) => return None,
                };

                Some(Self {
                    src_ip: ipv4.header().source_addr(),
                    dst_ip: ipv4.header().destination_addr(),
                    dst_port: udp.destination_port(),
                    payload: udp.payload(),
                })
            }
        }

        impl NetNamespaceGuard {
            fn new(names: &[&str]) -> Result<Self> {
                let mut guard = Self {
                    namespaces: Vec::with_capacity(names.len()),
                };
                for name in names {
                    let namespace = NetNs::new(name)
                        .with_context(|| format!("failed to create network namespace '{name}'"))?;
                    namespace
                        .run(|_| run_ip_command(["link", "set", "lo", "up"]))
                        .with_context(|| {
                            format!(
                                "failed to run loopback setup inside network namespace '{name}'",
                            )
                        })?
                        .with_context(|| {
                            format!("failed to bring loopback up in network namespace '{name}'")
                        })?;
                    guard.namespaces.push(namespace);
                }

                Ok(guard)
            }
        }

        impl Drop for NetNamespaceGuard {
            fn drop(&mut self) {
                for namespace in self.namespaces.drain(..) {
                    let _ = namespace.remove();
                }
            }
        }

        fn run_ip_command<const N: usize>(args: [&str; N]) -> Result<()> {
            let output = Command::new("ip")
                .args(args)
                .output()
                .context("failed to launch ip command")?;
            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("ip {} failed: {stderr}", args.join(" "));
        }

        fn bind_socket_to_device(socket: &std::net::UdpSocket, interface_name: &str) -> Result<()> {
            setsockopt(
                socket,
                sockopt::BindToDevice,
                &OsString::from(interface_name),
            )
            .with_context(|| format!("failed to bind UDP socket to interface '{interface_name}'"))
        }

        async fn wait_for_device_bound_udp_socket(
            bind_addr: SocketAddrV4,
            interface_name: &str,
        ) -> Result<UdpSocket> {
            let deadline = Instant::now() + TEST_WAIT_TIMEOUT;
            loop {
                match std::net::UdpSocket::bind(bind_addr) {
                    Ok(socket) => {
                        bind_socket_to_device(&socket, interface_name)?;
                        socket
                            .set_nonblocking(true)
                            .context("failed to set UDP socket nonblocking mode")?;
                        return UdpSocket::from_std(socket)
                            .context("failed to convert UDP socket into Tokio socket");
                    }
                    Err(err) if Instant::now() < deadline => {
                        let _ = err;
                        sleep(TEST_RETRY_DELAY).await;
                    }
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("timed out while binding UDP socket on {bind_addr}")
                        });
                    }
                }
            }
        }

        async fn wait_for_packet_capture(interface_name: &str) -> Result<PacketCapture> {
            let deadline = Instant::now() + TEST_WAIT_TIMEOUT;
            loop {
                match PacketCapture::bind(interface_name) {
                    Ok(capture) => return Ok(capture),
                    Err(err) if Instant::now() < deadline => {
                        let _ = err;
                        sleep(TEST_RETRY_DELAY).await;
                    }
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!(
                                "timed out while preparing packet capture on interface '{interface_name}'",
                            )
                        });
                    }
                }
            }
        }

        fn wait_for_worker_ready(ready_rx: StdReceiver<Result<()>>, name: &str) -> Result<()> {
            ready_rx
                .recv_timeout(TEST_WAIT_TIMEOUT)
                .map_err(|err| anyhow!("timed out while waiting for {name} setup: {err}"))??;
            Ok(())
        }

        // The enclave side needs its own network namespace. If both tunnel endpoints live in the
        // initial namespace, Linux short-circuits traffic addressed to another local interface IP
        // and the packet never traverses the relay. Each worker runs inside its namespace before
        // starting the real parent/enclave entry point so the test exercises the same setup path
        // as production without moving live interfaces or sockets across namespaces.
        fn run_test_worker<F>(name: &str, namespace_name: Option<&str>, future: F) -> Result<()>
        where
            F: std::future::Future<Output = Result<()>>,
        {
            if let Some(namespace_name) = namespace_name {
                let namespace = NetNs::get(namespace_name).with_context(|| {
                    format!("failed to open network namespace '{namespace_name}'")
                })?;
                return namespace.run(|_| {
                    let runtime = Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .with_context(|| format!("failed to build {name} test runtime"))?;

                    runtime.block_on(future)
                })
                .with_context(|| {
                    format!(
                        "failed to run {name} test worker in network namespace '{namespace_name}'",
                    )
                })?;
            }

            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .with_context(|| format!("failed to build {name} test runtime"))?;

            runtime.block_on(future)
        }

        #[test]
        #[ignore = "requires /dev/net/tun, VSOCK loopback support, CAP_NET_ADMIN, and iproute2 network namespaces (usually root)"]
        fn relays_packets_between_parent_and_enclave_tuns() -> Result<()> {
            // End-to-end shape of the test:
            // 1. Start a parent-side vsocktun worker in the initial network namespace.
            // 2. Start an enclave-side worker in a separate namespace so Linux cannot shortcut
            //    packets addressed to another local interface IP.
            // 3. Send a UDP request from the enclave TUN toward the parent, require the parent
            //    TUN capture to observe it, then send a UDP reply back and require the enclave
            //    TUN capture to observe that reply.
            reset_test_flow_counters();
            let config = TestConfig::new();
            let _namespaces = NetNamespaceGuard::new(&[&config.enclave_ns_name])?;

            let (parent_ready_tx, parent_ready_rx) = mpsc::channel();
            let (enclave_ready_tx, enclave_ready_rx) = mpsc::channel();
            let (parent_start_tx, parent_start_rx) = oneshot::channel();
            let (enclave_start_tx, enclave_start_rx) = oneshot::channel();
            let (parent_stop_tx, parent_stop_rx) = oneshot::channel();
            let mut parent_stop_tx = Some(parent_stop_tx);
            let (enclave_stop_tx, enclave_stop_rx) = oneshot::channel();
            let mut enclave_stop_tx = Some(enclave_stop_tx);
            let (enclave_completed_tx, enclave_completed_rx) = mpsc::channel::<Result<()>>();
            let reply_sent = Arc::new(AtomicBool::new(false));

            let parent_config = config.clone();
            let parent_reply_sent = Arc::clone(&reply_sent);
            let parent_thread = thread::spawn(move || {
                run_test_worker("parent", None, async move {
                    // Keep the destination UDP port open before vsocktun starts so the test can
                    // attribute failures to the relay path rather than an ICMP port-unreachable.
                    let receiver_socket = std::net::UdpSocket::bind(SocketAddrV4::new(
                        Ipv4Addr::UNSPECIFIED,
                        REQUEST_PORT,
                    ))
                    .with_context(|| {
                        format!(
                            "failed to bind parent UDP socket on 0.0.0.0:{}",
                            REQUEST_PORT
                        )
                    })?;
                    receiver_socket
                        .set_nonblocking(true)
                        .context("failed to set parent UDP socket nonblocking mode")?;
                    let _receiver = UdpSocket::from_std(receiver_socket)
                        .context("failed to convert parent UDP socket into Tokio socket")?;
                    let shutdown = async move {
                        let _ = parent_stop_rx.await;
                    };
                    let mut run_future = pin!(run_parent(parent_args(&parent_config), shutdown));
                    // Wait until the parent TUN exists and can be monitored before allowing the
                    // enclave side to start sending traffic.
                    let request_capture = tokio::select! {
                        capture = wait_for_packet_capture(&parent_config.parent_tun_name) => capture?,
                        result = &mut run_future => {
                            match result {
                                Ok(()) => bail!("parent entry point exited before test setup completed"),
                                Err(err) => Err(err).context("parent entry point failed before test setup completed")?,
                            }
                        }
                    };
                    // Replies are injected from a UDP socket bound to the parent TUN interface so
                    // the reverse direction exercises the same packet relay path back to enclave.
                    let sender = tokio::select! {
                        sender = wait_for_device_bound_udp_socket(
                            SocketAddrV4::new(parent_config.parent_ip, 0),
                            &parent_config.parent_tun_name,
                        ) => sender?,
                        result = &mut run_future => {
                            match result {
                                Ok(()) => bail!("parent entry point exited before reply socket setup completed"),
                                Err(err) => Err(err).context("parent entry point failed before reply socket setup completed")?,
                            }
                        }
                    };
                    parent_ready_tx
                        .send(Ok(()))
                        .map_err(|_| anyhow!("parent readiness receiver dropped"))?;
                    parent_start_rx
                        .await
                        .map_err(|_| anyhow!("parent start signal dropped"))?;

                    // The request only counts once it shows up on the parent TUN capture with the
                    // expected tunnel source/destination IPs, UDP port, and payload.
                    let mut request_capture =
                        pin!(request_capture.recv_matching(ExpectedCapturedPacket {
                            src_ip: parent_config.enclave_ip,
                            dst_ip: parent_config.parent_ip,
                            dst_port: REQUEST_PORT,
                            payload: REQUEST_PAYLOAD,
                        }));

                    tokio::select! {
                        result = &mut request_capture => {
                            result.context("failed to capture enclave request on parent TUN")?
                        }
                        result = &mut run_future => {
                            match result {
                                Ok(()) => bail!("parent entry point exited before enclave request"),
                                Err(err) => Err(err).context("parent entry point failed before enclave request")?,
                            }
                        }
                    };

                    sender
                        .send_to(
                            REPLY_PAYLOAD,
                            SocketAddrV4::new(parent_config.enclave_ip, REPLY_PORT),
                        )
                        .await
                        .context("failed to send parent reply")?;
                    parent_reply_sent.store(true, Ordering::SeqCst);

                    match run_future.await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            Err(err).context("parent entry point failed before test shutdown")
                        }
                    }
                })
            });
            let enclave_config = config.clone();
            let enclave_reply_sent = Arc::clone(&reply_sent);
            let enclave_namespace = enclave_config.enclave_ns_name.clone();
            let enclave_thread = thread::spawn(move || {
                run_test_worker("enclave", Some(enclave_namespace.as_str()), async move {
                    // Keep the enclave reply port open for the same reason as the parent side:
                    // we want relay failures, not missing listeners, to decide the test outcome.
                    let receiver_socket = std::net::UdpSocket::bind(SocketAddrV4::new(
                        Ipv4Addr::UNSPECIFIED,
                        REPLY_PORT,
                    ))
                    .with_context(|| {
                        format!(
                            "failed to bind enclave UDP socket on 0.0.0.0:{}",
                            REPLY_PORT
                        )
                    })?;
                    receiver_socket
                        .set_nonblocking(true)
                        .context("failed to set enclave UDP socket nonblocking mode")?;
                    let _receiver = UdpSocket::from_std(receiver_socket)
                        .context("failed to convert enclave UDP socket into Tokio socket")?;
                    let shutdown = async move {
                        let _ = enclave_stop_rx.await;
                    };
                    let mut run_future = pin!(run_enclave(enclave_args(&enclave_config), shutdown));
                    // Wait until the enclave TUN exists and can be monitored before triggering
                    // the request/reply exchange.
                    let reply_capture = tokio::select! {
                        capture = wait_for_packet_capture(&enclave_config.enclave_tun_name) => capture?,
                        result = &mut run_future => {
                            match result {
                                Ok(()) => bail!("enclave entry point exited before test setup completed"),
                                Err(err) => Err(err).context("enclave entry point failed before test setup completed")?,
                            }
                        }
                    };
                    let sender = tokio::select! {
                        sender = wait_for_device_bound_udp_socket(
                            SocketAddrV4::new(enclave_config.enclave_ip, 0),
                            &enclave_config.enclave_tun_name,
                        ) => sender?,
                        result = &mut run_future => {
                            match result {
                                Ok(()) => bail!("enclave entry point exited before request socket setup completed"),
                                Err(err) => Err(err).context("enclave entry point failed before request socket setup completed")?,
                            }
                        }
                    };
                    enclave_ready_tx
                        .send(Ok(()))
                        .map_err(|_| anyhow!("enclave readiness receiver dropped"))?;
                    enclave_start_rx
                        .await
                        .map_err(|_| anyhow!("enclave start signal dropped"))?;

                    let mut reply_capture =
                        pin!(reply_capture.recv_matching(ExpectedCapturedPacket {
                            src_ip: enclave_config.parent_ip,
                            dst_ip: enclave_config.enclave_ip,
                            dst_port: REPLY_PORT,
                            payload: REPLY_PAYLOAD,
                        }));

                    let deadline = Instant::now() + TEST_WAIT_TIMEOUT;
                    let destination = SocketAddrV4::new(enclave_config.parent_ip, REQUEST_PORT);

                    // Retry the request until the reply appears on the enclave TUN capture. This
                    // keeps the test robust against startup races while still requiring a real
                    // round trip through parent<->VSOCK<->enclave.
                    loop {
                        sender
                            .send_to(REQUEST_PAYLOAD, destination)
                            .await
                            .with_context(|| {
                                format!("failed to send enclave request to {destination}")
                            })?;

                        let wait_result = tokio::select! {
                            result = &mut reply_capture => {
                                result.context("failed to capture parent reply on enclave TUN")?;
                                Some(())
                            }
                            result = &mut run_future => {
                                match result {
                                    Ok(()) => bail!("enclave entry point exited before parent reply"),
                                    Err(err) => Err(err).context("enclave entry point failed before parent reply")?,
                                }
                            }
                            _ = sleep(TEST_RETRY_DELAY) => None,
                        };

                        if wait_result.is_some() {
                            enclave_completed_tx
                                .send(Ok(()))
                                .map_err(|_| anyhow!("enclave completion receiver dropped"))?;
                            break;
                        }

                        if Instant::now() >= deadline {
                            bail!(
                                "timed out while waiting for parent reply on enclave side; parent_reply_send_completed={}",
                                enclave_reply_sent.load(Ordering::SeqCst)
                            );
                        }
                    }

                    match run_future.await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            Err(err).context("enclave entry point failed before test shutdown")
                        }
                    }
                })
            });

            let parent_ready = wait_for_worker_ready(parent_ready_rx, "parent");
            let enclave_ready = wait_for_worker_ready(enclave_ready_rx, "enclave");
            let ready_result = parent_ready.and(enclave_ready);

            // Only release traffic once both workers reported that their TUN devices and helper
            // sockets are ready; otherwise an early packet could race the setup and fail spuriously.
            if ready_result.is_ok() {
                let _ = parent_start_tx.send(());
                let _ = enclave_start_tx.send(());
            } else {
                drop(parent_start_tx);
                drop(enclave_start_tx);
                let _ = parent_stop_tx.take();
                let _ = enclave_stop_tx.take();
            }

            let enclave_completed = enclave_completed_rx.recv_timeout(TEST_WAIT_TIMEOUT);
            if let Some(parent_stop_tx) = parent_stop_tx.take() {
                let _ = parent_stop_tx.send(());
            }
            if let Some(enclave_stop_tx) = enclave_stop_tx.take() {
                let _ = enclave_stop_tx.send(());
            }

            let enclave_result = enclave_thread
                .join()
                .map_err(|_| anyhow!("enclave worker thread panicked"))?;
            let parent_result = parent_thread
                .join()
                .map_err(|_| anyhow!("parent worker thread panicked"))?;

            // Collapse all asynchronous failures into one final error so the ignored test is
            // debuggable when someone runs it manually on a suitably privileged host.
            let mut errors = Vec::new();
            if let Err(err) = ready_result {
                errors.push(format!("readiness failed: {err:#}"));
            }
            if let Err(err) = enclave_result {
                errors.push(format!("enclave worker failed: {err:#}"));
            }
            if let Err(err) = parent_result {
                errors.push(format!("parent worker failed: {err:#}"));
            }
            match enclave_completed {
                Ok(Ok(())) => {}
                Ok(Err(err)) => errors.push(format!("enclave completion failed: {err:#}")),
                Err(err) => errors.push(format!("enclave completion wait failed: {err}")),
            }
            if !errors.is_empty() {
                errors.push(format!("flow summary: {}", test_flow_summary()));
                bail!(errors.join("\n\n"));
            }

            Ok(())
        }
    }

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

    #[test]
    fn session_supervisor_restores_all_queues_after_worker_error() -> Result<()> {
        let mut queue_pool = TestQueuePool::new(vec![10_u8, 20_u8]);
        let work_items = queue_pool.take();

        let SupervisedWorkersOutcome {
            returned_queues,
            result,
        } = test_runtime().block_on(supervise_session_workers(
            "test",
            42,
            work_items,
            |shard, queue, mut cancelled| async move {
                if shard == 0 {
                    (queue, Err(anyhow!("synthetic shard failure")))
                } else {
                    cancelled
                        .changed()
                        .await
                        .expect("cancellation should reach sibling worker");
                    assert!(
                        *cancelled.borrow(),
                        "sibling worker should observe cancellation"
                    );
                    (queue, Ok(()))
                }
            },
        ));

        let restored_queues = returned_queues
            .into_iter()
            .enumerate()
            .map(|(shard, queue)| {
                queue.ok_or_else(|| anyhow!("missing returned test queue for shard {shard}"))
            })
            .collect::<Result<Vec<_>>>()?;
        queue_pool.restore(restored_queues);

        assert_eq!(queue_pool.take(), vec![10_u8, 20_u8]);

        let err = result.expect_err("worker failure should surface from the supervisor");
        assert!(err.to_string().contains("shard 0 failed"));
        Ok(())
    }
}
