use crate::metrics::METRICS;
use std::{ffi::OsStr, fs, time::Duration};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, System};

pub fn start_sys_metrics_collection(refresh_interval: Duration) -> anyhow::Result<()> {
    // Only fail for info we'll actually poll later on
    let specifics = RefreshKind::nothing()
        .with_cpu(CpuRefreshKind::nothing())
        .with_memory(MemoryRefreshKind::nothing().with_ram())
        .with_processes(ProcessRefreshKind::nothing().with_memory());
    let mut system = sysinfo::System::new_with_specifics(specifics);

    let num_cpus = system.cpus().len();

    // Get current process PID for process-specific memory tracking
    let current_pid = sysinfo::get_current_pid().ok();
    if current_pid.is_none() {
        tracing::warn!("Could not get current PID for process memory tracking");
    }

    let total_ram = system.total_memory();
    let free_ram = system.free_memory();
    tracing::info!("Starting system metrics collection...\n Running on {} CPUs. Total memory: {} bytes, Free memory: {} bytes.",
        num_cpus, total_ram, free_ram);

    let mut networks = sysinfo::Networks::new_with_refreshed_list();

    tokio::spawn(async move {
        let mut last_rx_bytes = 0u64;
        let mut last_tx_bytes = 0u64;
        loop {
            // Update CPU metrics
            system.refresh_specifics(specifics);
            let cpus_load_avg = System::load_average().one / num_cpus as f64;

            tracing::debug!("CPU Load Average within 1 min {cpus_load_avg}");

            METRICS.record_cpu_load(cpus_load_avg);

            // Update memory metrics (total system memory)
            METRICS.record_memory_usage(system.used_memory());

            // Update process-specific memory (more accurate for cross-party comparison)
            if let Some(pid) = current_pid {
                if let Some(process) = system.process(pid) {
                    METRICS.record_process_memory(process.memory());
                } else {
                    tracing::debug!("Could not find process {:?} for memory tracking", pid);
                }
            }

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

            tokio::time::sleep(refresh_interval).await;
        }
    });

    Ok(())
    //  todo add socat tasks as well
}

/// Get the number of open file descriptors for the current process
/// TODO this only works on Linux, need alternative for other OSes
fn get_file_descriptor_count() -> u64 {
    let pid = match sysinfo::get_current_pid() {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!("Could not get current PID and hence cannot evaluate file descriptors. Using 0 by default. Error was: {e}");
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
            tracing::error!("Could not get current PID and hence cannot evaluate amount of tasks. Using 0 by default. Error was: {e}");
            return 0;
        }
    };
    let process = match system.process(pid) {
        Some(process) => process,
        None => {
            tracing::error!("Could not get current process info from sysinfo and hence cannot evaluate amount of tasks. Using 0 by default");
            return 0;
        }
    };
    match process.tasks() {
        Some(tasks) => tasks.len() as u64,
        None => {
            tracing::error!(
                "System does not appear to be Linux and hence cannot get the amount of tasks. Using 0 by default");
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
                "System does not appear to be Linux and hence cannot get the amount of socat tasks. Using 0 by default");
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
}
