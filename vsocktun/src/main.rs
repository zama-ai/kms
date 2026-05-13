mod protocol;
mod tun;
mod vsock;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use protocol::{FrameReader, OutgoingBuffer};
use std::io;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use tokio_vsock::{OwnedReadHalf, OwnedWriteHalf, VsockStream};
use tun::{Ipv4Cidr, TunDevice};
use tun_rs::{AsyncDevice, SyncDevice};
use vsock::{ParentSessionAcceptor, SessionSockets, connect_session};

const MAX_TUN_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "vsocktun")]
#[command(about = "Multi-queue TUN to VSOCK relay")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    Parent(ParentArgs),
    Enclave(EnclaveArgs),
}

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

enum DirectionTask {
    SocketToTun,
    TunToSocket,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    match cli.mode {
        Mode::Parent(args) => run_parent(args).await,
        Mode::Enclave(args) => run_enclave(args).await,
    }
}

async fn run_parent(args: ParentArgs) -> Result<()> {
    let common = ParsedCommon::parse(args.common)?;
    let tun = TunDevice::create(
        &common.tun_name,
        &common.tun_address,
        common.queues,
        common.mtu,
    )
    .with_context(|| format!("failed to create TUN interface '{}'", common.tun_name))?;
    let acceptor = ParentSessionAcceptor::bind(
        common.vsock_port,
        tun.queue_count(),
        Duration::from_secs(args.session_timeout_secs),
    )?;

    eprintln!(
        "vsocktun(parent): listening on VSOCK port {} with {} queue(s) on {}",
        common.vsock_port,
        tun.queue_count(),
        common.tun_name,
    );

    loop {
        match acceptor.accept_session().await {
            Ok(session) => {
                eprintln!(
                    "vsocktun(parent): established session {} with {} shard connection(s)",
                    session.session_id,
                    session.shards.len(),
                );
                if let Err(err) = run_session(&tun, session).await {
                    eprintln!("vsocktun(parent): session ended with error: {err:#}");
                }
            }
            Err(err) => {
                eprintln!("vsocktun(parent): failed to accept session: {err:#}");
            }
        }
    }
}

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

    eprintln!(
        "vsocktun(enclave): dialing parent CID {} on VSOCK port {} with {} queue(s) on {}",
        args.parent_cid,
        common.vsock_port,
        tun.queue_count(),
        common.tun_name,
    );

    loop {
        match connect_session(args.parent_cid, common.vsock_port, tun.queue_count()).await {
            Ok(session) => {
                eprintln!(
                    "vsocktun(enclave): established session {} with {} shard connection(s)",
                    session.session_id,
                    session.shards.len(),
                );
                if let Err(err) = run_session(&tun, session).await {
                    eprintln!("vsocktun(enclave): session ended with error: {err:#}");
                }
            }
            Err(err) => {
                eprintln!("vsocktun(enclave): failed to connect session: {err:#}");
            }
        }

        eprintln!(
            "vsocktun(enclave): reconnecting in {} ms",
            reconnect_delay.as_millis(),
        );
        sleep(reconnect_delay).await;
    }
}

async fn run_session(tun: &TunDevice, session: SessionSockets) -> Result<()> {
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

    let (cancel_tx, _) = watch::channel(false);
    let mut tasks = JoinSet::new();

    for (shard, (tun_queue, socket)) in tun_queues.into_iter().zip(session.shards).enumerate() {
        let cancel_rx = cancel_tx.subscribe();
        tasks.spawn(async move {
            WorkerOutcome {
                shard,
                result: pump_shard(shard, tun_queue, socket, max_tun_frame_bytes, cancel_rx).await,
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
                    let _ = cancel_tx.send(true);
                    first_error = Some(anyhow!("shard {} failed: {err:#}", outcome.shard));
                }
            }
            Err(err) => {
                if first_error.is_none() {
                    let _ = cancel_tx.send(true);
                    first_error = Some(anyhow!("vsocktun worker task failed: {err}"));
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    Ok(())
}

async fn pump_shard(
    shard: usize,
    tun_queue: SyncDevice,
    socket: VsockStream,
    max_tun_frame_bytes: usize,
    mut session_cancelled: watch::Receiver<bool>,
) -> Result<()> {
    if *session_cancelled.borrow() {
        return Ok(());
    }

    let tun_queue = Arc::new(
        AsyncDevice::new(tun_queue)
            .with_context(|| format!("failed to make TUN queue {shard} asynchronous"))?,
    );
    let socket_frame_bytes = MAX_TUN_FRAME_BYTES.max(max_tun_frame_bytes);
    let (socket_reader, socket_writer) = socket.into_split();
    let (local_cancel_tx, _) = watch::channel(false);

    let socket_to_tun = forward_socket_to_tun(
        shard,
        socket_reader,
        Arc::clone(&tun_queue),
        socket_frame_bytes,
        local_cancel_tx.subscribe(),
    );
    let tun_to_socket = forward_tun_to_socket(
        shard,
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

    match (first.1, second) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn forward_socket_to_tun(
    shard: usize,
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
                result.with_context(|| format!("failed to read framed packet on shard {shard}"))?
            }
        };

        let Some(packet) = packet else {
            continue;
        };

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
                    result.with_context(|| format!("failed to inject packet into TUN queue {shard}"))?
                }
            };

            if finished {
                break;
            }
        }
    }
}

async fn forward_tun_to_socket(
    shard: usize,
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
                result.with_context(|| format!("failed to read packet from TUN queue {shard}"))?
            }
        };

        if read == 0 {
            bail!("TUN queue {shard} closed unexpectedly");
        }

        let mut pending_socket_write = OutgoingBuffer::framed(&tun_buf[..read])
            .with_context(|| format!("failed to frame TUN packet from queue {shard}"))?;
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
                    result.with_context(|| format!("failed to forward packet on VSOCK shard {shard}"))?
                }
            };

            if finished {
                break;
            }
        }
    }
}

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
}

impl ParsedCommon {
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
        })
    }
}
