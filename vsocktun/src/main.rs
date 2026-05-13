mod protocol;
mod sys;
mod tun;
mod vsock;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use protocol::{FrameReader, OutgoingBuffer};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;
use tun::{Ipv4Cidr, TunDevice};
use vsock::{ParentSessionAcceptor, SessionSockets, connect_session};

const POLL_TIMEOUT_MS: i32 = 200;
const MAX_TUN_PACKET_BYTES: usize = u16::MAX as usize;

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
    #[arg(long, default_value_t = 1)]
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    match cli.mode {
        Mode::Parent(args) => run_parent(args),
        Mode::Enclave(args) => run_enclave(args),
    }
}

fn run_parent(args: ParentArgs) -> Result<()> {
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
        match acceptor.accept_session() {
            Ok(session) => {
                eprintln!(
                    "vsocktun(parent): established session {} with {} shard connection(s)",
                    session.session_id,
                    session.shards.len(),
                );
                if let Err(err) = run_session("parent", &tun, session) {
                    eprintln!("vsocktun(parent): session ended with error: {err:#}");
                }
            }
            Err(err) => {
                eprintln!("vsocktun(parent): failed to accept session: {err:#}");
            }
        }
    }
}

fn run_enclave(args: EnclaveArgs) -> Result<()> {
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
        match connect_session(args.parent_cid, common.vsock_port, tun.queue_count()) {
            Ok(session) => {
                eprintln!(
                    "vsocktun(enclave): established session {} with {} shard connection(s)",
                    session.session_id,
                    session.shards.len(),
                );
                if let Err(err) = run_session("enclave", &tun, session) {
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
        thread::sleep(reconnect_delay);
    }
}

fn run_session(role: &str, tun: &TunDevice, session: SessionSockets) -> Result<()> {
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

    let cancelled = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(session.shards.len());

    for (shard, (tun_queue, socket)) in tun_queues.into_iter().zip(session.shards).enumerate() {
        let cancelled = Arc::clone(&cancelled);
        let role = role.to_owned();
        let builder = thread::Builder::new().name(format!("vsocktun-{role}-shard-{shard}"));
        let handle = builder
            .spawn(move || WorkerOutcome {
                shard,
                result: pump_shard(shard, tun_queue, socket, cancelled),
            })
            .with_context(|| format!("failed to spawn worker thread for shard {shard}"))?;
        handles.push(handle);
    }

    let mut first_error = None;
    for handle in handles {
        let outcome = handle
            .join()
            .map_err(|_| anyhow!("vsocktun worker thread panicked"))?;
        if let Err(err) = outcome.result
            && first_error.is_none()
        {
            first_error = Some(anyhow!("shard {} failed: {err:#}", outcome.shard));
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    Ok(())
}

fn pump_shard(
    shard: usize,
    mut tun_queue: File,
    mut socket: File,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    let result = pump_shard_inner(shard, &mut tun_queue, &mut socket, &cancelled);
    if result.is_err() {
        cancelled.store(true, Ordering::Relaxed);
    }
    result
}

fn pump_shard_inner(
    shard: usize,
    tun_queue: &mut File,
    socket: &mut File,
    cancelled: &Arc<AtomicBool>,
) -> Result<()> {
    sys::set_nonblocking(tun_queue)
        .with_context(|| format!("failed to make TUN queue {shard} nonblocking"))?;
    sys::set_nonblocking(socket)
        .with_context(|| format!("failed to make VSOCK shard {shard} nonblocking"))?;

    let tun_fd = tun_queue.as_raw_fd();
    let socket_fd = socket.as_raw_fd();
    let mut tun_buf = vec![0_u8; MAX_TUN_PACKET_BYTES];
    let mut socket_reader = FrameReader::new();
    let mut pending_tun_write: Option<OutgoingBuffer> = None;
    let mut pending_socket_write: Option<OutgoingBuffer> = None;

    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }

        let mut made_progress = false;

        if pending_tun_write.is_none()
            && let Some(packet) = socket_reader
                .read_packet(socket)
                .with_context(|| format!("failed to read framed packet on shard {shard}"))?
        {
            pending_tun_write = Some(OutgoingBuffer::raw(packet));
            made_progress = true;
        }

        if let Some(buffer) = pending_tun_write.as_mut() {
            let finished = buffer
                .write_to(tun_queue)
                .with_context(|| format!("failed to inject packet into TUN queue {shard}"))?;
            made_progress |= finished;
            if finished {
                pending_tun_write = None;
            }
        }

        if pending_socket_write.is_none() {
            match tun_queue.read(&mut tun_buf) {
                Ok(0) => {
                    bail!("TUN queue {shard} closed unexpectedly");
                }
                Ok(read) => {
                    pending_socket_write =
                        Some(OutgoingBuffer::framed(&tun_buf[..read]).with_context(|| {
                            format!("failed to frame TUN packet from queue {shard}")
                        })?);
                    made_progress = true;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("failed to read packet from TUN queue {shard}"));
                }
            }
        }

        if let Some(buffer) = pending_socket_write.as_mut() {
            let finished = buffer
                .write_to(socket)
                .with_context(|| format!("failed to forward packet on VSOCK shard {shard}"))?;
            made_progress |= finished;
            if finished {
                pending_socket_write = None;
            }
        }

        if made_progress {
            continue;
        }

        let mut fds = [
            sys::PollFd {
                fd: tun_fd,
                events: poll_events(pending_socket_write.is_none(), pending_tun_write.is_some()),
                revents: 0,
            },
            sys::PollFd {
                fd: socket_fd,
                events: poll_events(pending_tun_write.is_none(), pending_socket_write.is_some()),
                revents: 0,
            },
        ];

        sys::poll_once(&mut fds, POLL_TIMEOUT_MS)
            .with_context(|| format!("failed to poll shard {shard}"))?;

        if fds
            .iter()
            .any(|fd| fd.revents & (sys::POLLERR | sys::POLLHUP) != 0)
        {
            bail!("detected hangup on shard {shard}");
        }
    }
}

fn poll_events(readable: bool, writable: bool) -> i16 {
    let mut events = 0;
    if readable {
        events |= sys::POLLIN;
    }
    if writable {
        events |= sys::POLLOUT;
    }
    events
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
