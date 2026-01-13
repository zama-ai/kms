use crate::metrics::METRICS;
use std::{ffi::OsStr, fs, time::Duration};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, System};

pub fn start_sys_metrics_collection(refresh_interval: Duration) -> anyhow::Result<()> {
    // Only fail for info we'll actually poll later on
    let specifics = RefreshKind::nothing()
        .with_cpu(CpuRefreshKind::nothing())
        .with_memory(MemoryRefreshKind::nothing().with_ram())
        .with_processes(ProcessRefreshKind::nothing().with_memory().with_cpu());
    let mut system = sysinfo::System::new_with_specifics(specifics);

    let num_cpus = system.cpus().len() as f64;

    let total_ram = system.total_memory();
    let free_ram = system.free_memory();

    tracing::info!("Starting system metrics collection...\n Running on {} CPUs. Total memory: {} bytes, Free memory: {} bytes.",
        num_cpus,  total_ram, free_ram);

    let mut networks = sysinfo::Networks::new_with_refreshed_list();

    let current_pid = sysinfo::get_current_pid().ok();
    if current_pid.is_none() {
        tracing::warn!("Could not get current PID for process memory tracking");
    }

    tokio::spawn(async move {
        let mut last_rx_bytes = 0u64;
        let mut last_tx_bytes = 0u64;
        loop {
            // Update CPU metrics
            system.refresh_specifics(specifics);
            let cpus_load_avg = System::load_average().one / num_cpus;

            tracing::debug!("CPU Load Average within 1 min {cpus_load_avg}");

            METRICS.record_cpu_load(cpus_load_avg);

            // Update memory metrics
            let memory_usage = system.used_memory();
            if memory_usage != 0 {
                METRICS.record_memory_usage(memory_usage);
            } else {
                tracing::warn!("sysinfo is reporting 0 memory usage")
            }

            // Update process-specific memory (more accurate for cross-party comparison)
            if let Some(pid) = current_pid {
                if let Some(process) = system.process(pid) {
                    METRICS.record_process_memory(process.memory());
                } else {
                    tracing::warn!("Could not find process {:?} for memory tracking", pid);
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
            let fd_count = get_file_descriptor_count();
            METRICS.record_open_file_descriptors(fd_count);

            // Update thread count
            let thread_count = get_thread_count(&system);
            METRICS.record_threads(thread_count);

            // Update socat process count
            let socat_count = get_socat_count(&system);
            METRICS.record_socat_processes(socat_count);

            tokio::time::sleep(refresh_interval).await;
        }
    });

    Ok(())
}

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

/// Get the number of child threads for the current process
/// TODO this only works on Linux, need alternative for other OSes
fn get_thread_count(system: &sysinfo::System) -> u64 {
    let pid = match sysinfo::get_current_pid() {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!("Could not get current PID and hence cannot evaluate amount of child threads. Using 0 by default. Error was: {e}");
            return 0;
        }
    };
    let process = match system.process(pid) {
        Some(process) => process,
        None => {
            tracing::error!("Could not get current process info from sysinfo and hence cannot evaluate amount of child threads. Using 0 by default");
            return 0;
        }
    };
    match process.tasks() {
        Some(tasks) => tasks.len() as u64,
        None => {
            tracing::error!(
                "System does not appear to be Linux and hence cannot get the amount of child threads. Using 0 by default");
            0
        }
    }
}

/// Get the number of running socat file descriptors
/// TODO this only works on Linux, need alternative for other OSes
fn get_socat_count(system: &sysinfo::System) -> u64 {
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
