use crate::metrics::METRICS;
use std::{fs, time::Duration};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

pub fn start_sys_metrics_collection(refresh_interval: Duration) -> anyhow::Result<()> {
    // Only fail for info we'll actually poll later on
    let specifics = RefreshKind::nothing()
        .with_cpu(CpuRefreshKind::nothing())
        .with_memory(MemoryRefreshKind::nothing().with_ram());
    let mut system = sysinfo::System::new_with_specifics(specifics);

    let num_cpus = system.cpus().len();

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

            // Update file descriptor count
            let entries = fs::read_dir("/proc/self/fd").map(|res| res.count())
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to read /proc/self/fd with error and hence cannot get file descriptor count. Defaulting to 0. Erro was: {e}");
                    0
                });
            METRICS.record_open_file_descriptors(entries as u64);
            tokio::time::sleep(refresh_interval).await;
        }
    });

    Ok(())
}
