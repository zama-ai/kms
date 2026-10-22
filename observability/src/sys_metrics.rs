use crate::diag_metrics::DIAG;
use crate::metrics::METRICS;
use std::{
    cmp::max,
    collections::HashMap,
    ffi::OsStr,
    fs,
    time::{Duration, Instant},
};
use sysinfo::{
    MINIMUM_CPU_UPDATE_INTERVAL, Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};

/// Comma-separated names of other processes whose CPU usage is exported as
/// `kms_named_process_cpu_usage{process}` (default: the enclave network relay and the socat
/// proxies, which share the VM with `kms-server` inside a Nitro enclave).
pub const SYS_METRICS_PROCESSES_ENV: &str = "KMS_SYS_METRICS_PROCESSES";
const DEFAULT_SYS_METRICS_PROCESSES: &str = "vsocktun,socat,dnsproxy";

/// Thread-name prefix of the rayon compute pool (set in `thread-handles`).
pub const RAYON_THREAD_NAME_PREFIX: &str = "mpc-rayon";
/// Thread-name prefix of the tokio workers (tokio's default name is `tokio-runtime-worker`).
const TOKIO_THREAD_NAME_PREFIX: &str = "tokio";
const THREAD_POOLS: [&str; 3] = ["tokio", "rayon", "other"];

pub fn start_sys_metrics_collection(refresh_interval: Duration) -> anyhow::Result<()> {
    // Only fail for info we'll actually poll later on
    let mut system = sysinfo::System::new_with_specifics(RefreshKind::everything());

    let num_cpus = system.cpus().len();
    // Set this info once and for all
    METRICS.record_total_cpus(num_cpus as u64);
    let total_ram = system.total_memory();
    METRICS.record_total_memory(total_ram);
    let free_ram = system.free_memory();
    tracing::info!(
        "Starting system metrics collection...\n Running on {} CPUs. Total memory: {} bytes, Free memory: {} bytes.",
        num_cpus,
        total_ram,
        free_ram
    );

    let mut networks = sysinfo::Networks::new_with_refreshed_list();
    let named_processes = named_processes_from_env();
    tracing::info!(
        "Diagnostic system metrics: thread pools {:?}, named processes {:?}",
        THREAD_POOLS,
        named_processes
    );

    tokio::spawn(async move {
        let mut last_rx_bytes = 0u64;
        let mut last_tx_bytes = 0u64;
        let mut net_stats = ProcNetStats::default();
        let mut last_sample = Instant::now();
        // Ensure CPU averate is accurate by sleeping initially as recommended by sysinfo documentation
        tokio::time::sleep(MINIMUM_CPU_UPDATE_INTERVAL).await;
        loop {
            // Refresh to be able to get accurate reading
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::everything(),
            );
            // Update CPU metrics
            let cpus_load_avg = System::load_average().one / num_cpus as f64;
            tracing::debug!("CPU Load Average over all cores within 1 min {cpus_load_avg}");
            METRICS.record_cpu_load(cpus_load_avg);

            let runtime_metrics = tokio::runtime::Handle::current().metrics();
            METRICS.record_tokio_alive_tasks(runtime_metrics.num_alive_tasks());
            METRICS.record_tokio_global_queue_depth(runtime_metrics.global_queue_depth());

            let now = Instant::now();
            let elapsed = now.duration_since(last_sample).as_secs_f64();
            last_sample = now;

            if let Ok(pid) = sysinfo::get_current_pid() {
                if let Some(process) = system.process(pid) {
                    METRICS.record_process_memory_usage(process.memory());
                    // CPU usage is a percentage (0.0 to 100.0) per core
                    METRICS.record_process_cpu_usage(process.cpu_usage() as f64);
                    DIAG.record_process_sample(
                        process.start_time(),
                        process.run_time(),
                        process.cpu_usage() as f64 / 100.0 * elapsed,
                    );
                }
                record_thread_pool_cpu(&system, pid, elapsed);
            } else {
                tracing::error!(
                    "Could not get current PID and hence cannot refresh process CPU usage for accurate reading. This may lead to inaccurate CPU usage metrics."
                );
            }
            record_named_process_cpu(&system, &named_processes);

            // Update memory metrics
            METRICS.record_memory_usage(system.used_memory());

            // Update network metrics
            networks.refresh(true);
            let (total_tx, total_rx) = networks.iter().fold((0u64, 0u64), |(tx, rx), net| {
                (tx + net.1.total_transmitted(), rx + net.1.total_received())
            });
            let tx_delta = total_tx - last_tx_bytes;
            let rx_delta = total_rx - last_rx_bytes;

            METRICS.increment_network_rx_counter(rx_delta);
            METRICS.increment_network_tx_counter(tx_delta);

            last_rx_bytes = total_rx;
            last_tx_bytes = total_tx;

            // Interface drops and TCP (re)transmissions, straight from procfs
            net_stats.sample();

            // Update file descriptor count
            // TODO this only works on Linux, need alternative for other OSes
            let entries = get_file_descriptor_count();
            METRICS.record_open_file_descriptors(entries);

            // Update task count
            let task_count = get_task_count(&system);
            METRICS.record_tasks(task_count);

            // Update socat task count
            let socat_count = get_socat_task_count(&system);
            METRICS.record_socat_tasks(socat_count);

            // Update socat file descriptor count
            let socat_count = get_socat_file_descriptor_count(&system);
            METRICS.record_socat_file_descriptors(socat_count);

            // Ensure we sleep at least the time needed to accurately update CPU usage, as recommended by sysinfo documentation
            tokio::time::sleep(max(refresh_interval, MINIMUM_CPU_UPDATE_INTERVAL)).await;
        }
    });

    Ok(())
    //  todo add socat tasks as well
}

/// Names of the other processes to watch, from [`SYS_METRICS_PROCESSES_ENV`].
fn named_processes_from_env() -> Vec<String> {
    let raw = std::env::var(SYS_METRICS_PROCESSES_ENV)
        .unwrap_or_else(|_| DEFAULT_SYS_METRICS_PROCESSES.to_string());
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Classify a thread by name into the pool it belongs to.
fn thread_pool_of(name: &str) -> &'static str {
    if name.starts_with(TOKIO_THREAD_NAME_PREFIX) {
        "tokio"
    } else if name.starts_with(RAYON_THREAD_NAME_PREFIX) {
        "rayon"
    } else {
        "other"
    }
}

/// Export the CPU usage of this process' threads grouped by pool (tokio workers, the rayon
/// compute pool, everything else). The process leader itself is skipped because sysinfo reports
/// the whole process' usage on it.
fn record_thread_pool_cpu(system: &System, pid: Pid, elapsed_secs: f64) {
    let mut by_pool: HashMap<&'static str, f64> = HashMap::new();
    if let Some(process) = system.process(pid)
        && let Some(tasks) = process.tasks()
    {
        for tid in tasks {
            if *tid == pid {
                continue;
            }
            if let Some(task) = system.process(*tid) {
                let name = task.name().to_string_lossy();
                *by_pool.entry(thread_pool_of(&name)).or_default() += task.cpu_usage() as f64;
            }
        }
    }
    for pool in THREAD_POOLS {
        let percent = by_pool.get(pool).copied().unwrap_or(0.0);
        DIAG.record_thread_pool_cpu(pool, percent);
        DIAG.add_thread_pool_cpu_seconds(pool, percent / 100.0 * elapsed_secs);
    }
}

/// Export the summed CPU usage of every process whose name matches one of `names`.
fn record_named_process_cpu(system: &System, names: &[String]) {
    for name in names {
        let percent: f64 = named_processes(system, name)
            .map(|process| process.cpu_usage() as f64)
            .sum();
        DIAG.record_named_process_cpu(name, percent);
    }
}

fn named_processes<'a>(
    system: &'a System,
    name: &'a str,
) -> impl Iterator<Item = &'a sysinfo::Process> {
    system
        .processes_by_exact_name(OsStr::new(name))
        // Linux exposes task records in this map too. The leader already includes their CPU.
        .filter(|process| process.thread_kind().is_none())
}

/// Deltas of `/proc/net/dev` drop counters and `/proc/net/snmp` TCP segment counters.
#[derive(Default)]
struct ProcNetStats {
    iface_drops: HashMap<String, (u64, u64)>,
    tcp: HashMap<String, u64>,
}

impl ProcNetStats {
    fn sample(&mut self) {
        match fs::read_to_string("/proc/net/dev") {
            Ok(contents) => self.sample_net_dev(&contents),
            Err(e) => tracing::debug!("cannot read /proc/net/dev: {e}"),
        }
        match fs::read_to_string("/proc/net/snmp") {
            Ok(contents) => self.sample_snmp(&contents),
            Err(e) => tracing::debug!("cannot read /proc/net/snmp: {e}"),
        }
    }

    fn sample_net_dev(&mut self, contents: &str) {
        for (iface, rx_drop, tx_drop) in parse_net_dev_drops(contents) {
            let last = self
                .iface_drops
                .entry(iface.clone())
                .or_insert((rx_drop, tx_drop));
            DIAG.add_net_iface_dropped(&iface, "rx", rx_drop.saturating_sub(last.0));
            DIAG.add_net_iface_dropped(&iface, "tx", tx_drop.saturating_sub(last.1));
            *last = (rx_drop, tx_drop);
        }
    }

    fn sample_snmp(&mut self, contents: &str) {
        for (name, kind) in [
            ("InSegs", "in"),
            ("OutSegs", "out"),
            ("RetransSegs", "retrans"),
        ] {
            if let Some(value) = parse_snmp_tcp_field(contents, name) {
                let last = self.tcp.entry(name.to_string()).or_insert(value);
                DIAG.add_tcp_segs(kind, value.saturating_sub(*last));
                *last = value;
            }
        }
    }
}

/// `(iface, rx_dropped, tx_dropped)` for each interface line of `/proc/net/dev`.
fn parse_net_dev_drops(contents: &str) -> Vec<(String, u64, u64)> {
    contents
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (iface, rest) = line.split_once(':')?;
            let fields: Vec<u64> = rest
                .split_whitespace()
                .map(|field| field.parse::<u64>().unwrap_or(0))
                .collect();
            // rx: bytes packets errs drop fifo frame compressed multicast | tx: bytes packets errs drop ...
            if fields.len() < 12 {
                return None;
            }
            Some((iface.trim().to_string(), fields[3], fields[11]))
        })
        .collect()
}

/// Value of column `field` of the `Tcp:` rows of `/proc/net/snmp`.
fn parse_snmp_tcp_field(contents: &str, field: &str) -> Option<u64> {
    let mut lines = contents.lines().filter(|line| line.starts_with("Tcp:"));
    let header = lines.next()?;
    let values = lines.next()?;
    let index = header.split_whitespace().position(|name| name == field)?;
    values.split_whitespace().nth(index)?.parse().ok()
}

/// Get the number of open file descriptors for the current process
/// TODO this only works on Linux, need alternative for other OSes
fn get_file_descriptor_count() -> u64 {
    let pid = match sysinfo::get_current_pid() {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!(
                "Could not get current PID and hence cannot evaluate file descriptors. Using 0 by default. Error was: {e}"
            );
            return 0;
        }
    };
    let entries = fs::read_dir(format!("/proc/{pid}/fd")).map(|res| res.count())
        .unwrap_or_else(|e| {
            tracing::error!("Failed to read /proc/{pid}/fd with error and hence cannot get file descriptor count. Defaulting to 0. Error was: {e}");
            0
        });
    entries as u64
}

/// Get the number of tasks for the current process
/// TODO this only works on Linux, need alternative for other OSes
fn get_task_count(system: &sysinfo::System) -> u64 {
    let pid = match sysinfo::get_current_pid() {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!(
                "Could not get current PID and hence cannot evaluate amount of tasks. Using 0 by default. Error was: {e}"
            );
            return 0;
        }
    };
    let process = match system.process(pid) {
        Some(process) => process,
        None => {
            tracing::error!(
                "Could not get current process info from sysinfo and hence cannot evaluate amount of tasks. Using 0 by default"
            );
            return 0;
        }
    };
    match process.tasks() {
        Some(tasks) => tasks.len() as u64,
        None => {
            tracing::error!(
                "System does not appear to be Linux and hence cannot get the amount of tasks. Using 0 by default"
            );
            0
        }
    }
}

/// Get the number of running socat tasks
/// TODO this only works on Linux, need alternative for other OSes
fn get_socat_task_count(system: &sysinfo::System) -> u64 {
    let mut count = 0;
    for process in system.processes_by_name(OsStr::new("socat")) {
        let entries = match process.tasks() {
            Some(tasks) => tasks.len() as u64,
            None => {
                tracing::error!(
                    "System does not appear to be Linux and hence cannot get the amount of socat tasks. Using 0 by default"
                );
                0
            }
        };
        count += entries;
    }
    count
}

/// Get the number of running socat file descriptors
/// TODO this only works on Linux, need alternative for other OSes
fn get_socat_file_descriptor_count(system: &sysinfo::System) -> u64 {
    let mut count = 0;
    for process in system.processes_by_name(OsStr::new("socat")) {
        let pid = process.pid();
        let entries= fs::read_dir(format!("/proc/{pid}/fd")).map(|res| res.count())
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to read /proc/{pid}/fd with error and hence cannot get file descriptor count. Defaulting to 0. Error was: {e}");
                    0
                });
        count += entries as u64;
    }
    count
}

/// Tests are only compatible with Linux
#[cfg(target_os = "linux")]
#[cfg(test)]
pub(crate) mod tests {
    use std::{
        thread::{self, sleep},
        time::Duration,
    };
    use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, RefreshKind};

    #[test]
    fn test_file_descriptor_count() {
        // Ensure that there is an open file
        let temp_dir = tempfile::tempdir().unwrap();
        let _file = std::fs::File::create(temp_dir.path().join("test_fd.txt")).unwrap();
        let count = super::get_file_descriptor_count();
        assert!(count > 0, "File descriptor count should be greater than 0");
    }

    #[test]
    fn test_task_count() {
        // Ensure that there is at least one thread spawned
        thread::spawn(|| {
            sleep(Duration::from_secs(10));
        });
        sleep(Duration::from_secs(1));
        let specifics = RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing())
            .with_memory(MemoryRefreshKind::nothing().with_ram())
            .with_processes(ProcessRefreshKind::everything());
        let system = sysinfo::System::new_with_specifics(specifics);
        let task_count = super::get_task_count(&system);
        assert!(task_count > 0, "Task count should be greater than 0");
    }

    #[test]
    fn test_parse_net_dev_drops() {
        let sample = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\nvsocktun: 5000 50 0 7 0 0 0 0 6000 60 0 3 0 0 0 0\n";
        let drops = super::parse_net_dev_drops(sample);
        assert_eq!(
            drops,
            vec![("lo".to_string(), 0, 0), ("vsocktun".to_string(), 7, 3)]
        );
    }

    #[test]
    fn test_parse_snmp_tcp_field() {
        let sample = "Ip: Forwarding DefaultTTL\nIp: 1 64\nTcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\nTcp: 1 200 120000 -1 10 20 0 0 5 1234 5678 42 0 0 0\n";
        assert_eq!(super::parse_snmp_tcp_field(sample, "InSegs"), Some(1234));
        assert_eq!(super::parse_snmp_tcp_field(sample, "OutSegs"), Some(5678));
        assert_eq!(super::parse_snmp_tcp_field(sample, "RetransSegs"), Some(42));
        assert_eq!(super::parse_snmp_tcp_field(sample, "Nope"), None);
    }

    #[test]
    fn test_thread_pool_of() {
        assert_eq!(super::thread_pool_of("tokio-runtime-worker"), "tokio");
        assert_eq!(super::thread_pool_of("tokio-rt-worker"), "tokio");
        assert_eq!(super::thread_pool_of("mpc-rayon-7"), "rayon");
        assert_eq!(super::thread_pool_of("kms-server"), "other");
    }

    #[test]
    fn named_processes_excludes_matching_worker_threads() {
        let pid = sysinfo::get_current_pid().unwrap();
        let mut system = sysinfo::System::new_all();
        let name = system
            .process(pid)
            .unwrap()
            .name()
            .to_string_lossy()
            .into_owned();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let worker = thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                ready_tx.send(()).unwrap();
                stop_rx.recv().unwrap();
            })
            .unwrap();
        ready_rx.recv().unwrap();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        let all = system
            .processes_by_exact_name(std::ffi::OsStr::new(&name))
            .count();
        let leaders: Vec<_> = super::named_processes(&system, &name).collect();
        stop_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(leaders.iter().any(|process| process.pid() == pid));
        assert!(all > leaders.len(), "matching worker must not count twice");
    }
}
