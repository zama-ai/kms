//! Diagnostic metrics for the DKG-preprocessing investigation.
//!
//! Everything here is additive to [`crate::metrics::METRICS`]: a second set of Prometheus
//! series, registered in the same default registry (so they appear on the usual `/metrics`
//! endpoint) with the same `kms_` prefix and the same const-labels. They are kept apart from
//! [`crate::metrics::CoreMetrics`] so that the bench instrumentation can be reviewed, kept or
//! dropped as one unit.
//!
//! These metrics add timing, synchronization, and label-lookup overhead. Compare identical
//! instrumentation in both arms and measure its overhead before attributing small differences.
//!
//! Series:
//!
//! - `kms_dkg_phase_duration_microseconds_total{phase}` and
//!   `kms_dkg_phase_observations_total{phase}` — cumulative wall time and count of each phase of
//!   a preprocessing batch (see [`DkgPhase`]). These measure elapsed session time, including
//!   queue and scheduler delays; they do not measure CPU consumption or a critical path.
//! - `kms_optimistic_reconstruct_total{site,outcome}` — whether the optimistic Shamir
//!   reconstruction was taken (`hit`), declined on its eligibility check (`declined`), found the
//!   shares inconsistent (`inconsistent`), or the decoder also failed (`failed`). `disabled`
//!   counts values sent directly to the decoder by the runtime control.
//! - `kms_c2c_send_rpc_duration_ms{size_bucket}` — histogram of the core-to-core `send_value`
//!   RPC, from dequeue by the sender task to the peer's ack, by message size.
//! - `kms_c2c_sender_queued_messages` — messages currently waiting in the per-(session, peer)
//!   sender queues, summed over all of them.
//! - `kms_thread_pool_cpu_usage{pool}` — CPU of this process' threads grouped by pool
//!   (`tokio`, `rayon`, `main`, `other`); 100 = one core, like `kms_process_cpu_usage`.
//! - `kms_named_process_cpu_usage{process}` — CPU of other processes in the same VM/container
//!   (inside a Nitro enclave: the enclave-side `vsocktun` relay), from `KMS_SYS_METRICS_PROCESSES`.
//! - `kms_net_iface_dropped_total{iface,dir}` — `/proc/net/dev` drop counters per interface.
//! - `kms_tcp_segs_total{kind}` — `/proc/net/snmp` TCP `InSegs`, `OutSegs`, `RetransSegs`.

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, Opts,
};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::metrics::MetricsConfig;

/// Measured phases of one preprocessing batch of the nSmall DKG offline phase.
///
/// These are elapsed-time phases, including scheduler and queue delays. Broadcast and opening
/// phases include local work and communication. The last two are whole-batch envelopes.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum DkgPhase {
    /// PRSS/PRZS draws and the local arithmetic that turns them into the `d` vector.
    Prss,
    /// Round 1 of the reliable broadcast: serialise and hand the `d` vector to the sender tasks.
    BcastSend,
    /// From the round-1 send until every peer's contribution was received.
    BcastRecv,
    /// From the echo send until every peer's echo was received and tallied.
    BcastEchoWait,
    /// The `1 + t` hash-only vote rounds.
    BcastVotes,
    /// Reconstruction of the opened `d` values (optimistic path or decoder).
    ReconsD,
    /// `mult_list`: the ε/ρ open round, including its local arithmetic.
    MultOpen,
    /// `open_list(v)`: the last open round.
    OpenV,
    /// The local `solve`/`invert` pass that turns opened values into bits.
    Solve,
    /// Time a producer spends blocked handing a finished batch to the aggregator.
    AggregatorSend,
    /// Whole triple batch (`next_triple_batch`), i.e. `Prss + Bcast* + ReconsD`.
    TripleBatch,
    /// Whole bit batch (`gen_bits_even`), i.e. `MultOpen + OpenV + Solve`.
    BitBatch,
}

impl DkgPhase {
    pub const COUNT: usize = 12;
    pub const LABELS: [&'static str; Self::COUNT] = [
        "prss",
        "bcast_send",
        "bcast_recv",
        "bcast_echo_wait",
        "bcast_votes",
        "recons_d",
        "mult_open",
        "open_v",
        "solve",
        "aggregator_send",
        "triple_batch",
        "bit_batch",
    ];

    pub fn label(self) -> &'static str {
        Self::LABELS[self as usize]
    }
}

/// Outcome of one optimistic reconstruction attempt (label values of
/// `kms_optimistic_reconstruct_total`).
pub mod optimistic_outcome {
    pub const HIT: &str = "hit";
    pub const DECLINED: &str = "declined";
    pub const INCONSISTENT: &str = "inconsistent";
    pub const FAILED: &str = "failed";
    /// The runtime control bypassed the optimistic path.
    pub const DISABLED: &str = "disabled";
}

/// Buckets (ms) for the core-to-core RPC histogram: from sub-millisecond acks of hash-sized
/// messages up to multi-minute stalls behind the network timeout.
const RPC_BUCKETS_MS: &[f64] = &[
    1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0,
    30_000.0, 60_000.0, 120_000.0, 300_000.0,
];

/// Size-bucket label of a core-to-core message, so that the RPC latency of 32-byte votes and of
/// 8 MB echo batches is not averaged together.
pub fn size_bucket(bytes: usize) -> &'static str {
    match bytes {
        0..=4_096 => "le_4k",
        4_097..=65_536 => "le_64k",
        65_537..=1_048_576 => "le_1m",
        1_048_577..=16_777_216 => "le_16m",
        _ => "gt_16m",
    }
}

#[derive(Debug, Clone)]
pub struct DiagMetrics {
    dkg_phase_duration_counters: [IntCounter; DkgPhase::COUNT],
    dkg_phase_observation_counters: [IntCounter; DkgPhase::COUNT],
    optimistic_reconstruct_counter: IntCounterVec,
    c2c_send_rpc_histogram: HistogramVec,
    c2c_sender_queued_gauge: IntGauge,
    thread_pool_cpu_gauge: GaugeVec,
    named_process_cpu_gauge: GaugeVec,
    net_iface_dropped_counter: IntCounterVec,
    tcp_segs_counter: IntCounterVec,
    thread_pool_cpu_seconds_counter: CounterVec,
    generated_items_counter: IntCounterVec,
    detail_duration_counter: CounterVec,
    detail_observation_counter: IntCounterVec,
    process_start_time_gauge: Gauge,
    process_uptime_gauge: Gauge,
    process_cpu_seconds_counter: Counter,
}

/// Global instance; built on first use with the same prefix and const-labels as
/// [`crate::metrics::METRICS`] and registered in the default Prometheus registry.
pub static DIAG: LazyLock<DiagMetrics> =
    LazyLock::new(|| DiagMetrics::new(&MetricsConfig::from_env(), prometheus::default_registry()));

impl DiagMetrics {
    fn new(config: &MetricsConfig, registry: &prometheus::Registry) -> Self {
        let prefix = &config.prefix;
        let const_labels: HashMap<String, String> = config.labels.clone().into_iter().collect();
        let opts = |name: String, help: &'static str| {
            Opts::new(name, help).const_labels(const_labels.clone())
        };
        let hist_opts = |name: String, help: &'static str| {
            HistogramOpts::new(name, help).const_labels(const_labels.clone())
        };

        let dkg_phase_duration_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_dkg_phase_duration_microseconds_total"),
                "Cumulative wall-clock time spent in each phase of a DKG preprocessing batch",
            ),
            &["phase"],
        )
        .expect("failed to create dkg phase duration counter");
        registry
            .register(Box::new(dkg_phase_duration_counter.clone()))
            .expect("failed to register dkg phase duration counter");
        let dkg_phase_duration_counters = std::array::from_fn(|index| {
            dkg_phase_duration_counter.with_label_values(&[DkgPhase::LABELS[index]])
        });

        let dkg_phase_observation_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_dkg_phase_observations_total"),
                "Number of observed DKG preprocessing batch phases",
            ),
            &["phase"],
        )
        .expect("failed to create dkg phase observation counter");
        registry
            .register(Box::new(dkg_phase_observation_counter.clone()))
            .expect("failed to register dkg phase observation counter");
        let dkg_phase_observation_counters = std::array::from_fn(|index| {
            dkg_phase_observation_counter.with_label_values(&[DkgPhase::LABELS[index]])
        });

        let optimistic_reconstruct_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_optimistic_reconstruct_total"),
                "Outcomes of the optimistic Shamir reconstruction, per call site",
            ),
            &["site", "outcome"],
        )
        .expect("failed to create optimistic reconstruct counter");
        registry
            .register(Box::new(optimistic_reconstruct_counter.clone()))
            .expect("failed to register optimistic reconstruct counter");
        for site in ["robust_open", "d_values", "unspecified"] {
            for outcome in ["hit", "declined", "inconsistent", "failed", "disabled"] {
                optimistic_reconstruct_counter.with_label_values(&[site, outcome]);
            }
        }

        let c2c_send_rpc_histogram = HistogramVec::new(
            hist_opts(
                format!("{prefix}_c2c_send_rpc_duration_ms"),
                "Core-to-core send_value RPC duration, from dequeue to the peer's ack",
            )
            .buckets(RPC_BUCKETS_MS.to_vec()),
            &["size_bucket"],
        )
        .expect("failed to create c2c send rpc histogram");
        registry
            .register(Box::new(c2c_send_rpc_histogram.clone()))
            .expect("failed to register c2c send rpc histogram");
        for bucket in ["le_4k", "le_64k", "le_1m", "le_16m", "gt_16m"] {
            c2c_send_rpc_histogram.with_label_values(&[bucket]);
        }

        let c2c_sender_queued_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_c2c_sender_queued_messages"),
            "Messages waiting in the per-(session, peer) core-to-core sender queues",
        ))
        .expect("failed to create c2c sender queued gauge");
        registry
            .register(Box::new(c2c_sender_queued_gauge.clone()))
            .expect("failed to register c2c sender queued gauge");

        let thread_pool_cpu_gauge = GaugeVec::new(
            opts(
                format!("{prefix}_thread_pool_cpu_usage"),
                "CPU usage of this process' threads grouped by pool (100 = one core)",
            ),
            &["pool"],
        )
        .expect("failed to create thread pool cpu gauge");
        registry
            .register(Box::new(thread_pool_cpu_gauge.clone()))
            .expect("failed to register thread pool cpu gauge");

        let thread_pool_cpu_seconds_counter = CounterVec::new(
            opts(
                format!("{prefix}_thread_pool_cpu_seconds_total"),
                "Cumulative CPU seconds of this process' threads grouped by pool",
            ),
            &["pool"],
        )
        .expect("failed to create thread pool cpu seconds counter");
        registry
            .register(Box::new(thread_pool_cpu_seconds_counter.clone()))
            .expect("failed to register thread pool cpu seconds counter");
        for pool in ["tokio", "rayon", "other"] {
            thread_pool_cpu_gauge.with_label_values(&[pool]);
            thread_pool_cpu_seconds_counter.with_label_values(&[pool]);
        }

        let named_process_cpu_gauge = GaugeVec::new(
            opts(
                format!("{prefix}_named_process_cpu_usage"),
                "CPU usage of other named processes on the same host/VM (100 = one core)",
            ),
            &["process"],
        )
        .expect("failed to create named process cpu gauge");
        registry
            .register(Box::new(named_process_cpu_gauge.clone()))
            .expect("failed to register named process cpu gauge");

        let net_iface_dropped_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_net_iface_dropped_total"),
                "Packets dropped per network interface and direction (/proc/net/dev)",
            ),
            &["iface", "dir"],
        )
        .expect("failed to create net iface dropped counter");
        registry
            .register(Box::new(net_iface_dropped_counter.clone()))
            .expect("failed to register net iface dropped counter");

        let tcp_segs_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_tcp_segs_total"),
                "TCP segments in, out and retransmitted (/proc/net/snmp)",
            ),
            &["kind"],
        )
        .expect("failed to create tcp segs counter");
        registry
            .register(Box::new(tcp_segs_counter.clone()))
            .expect("failed to register tcp segs counter");
        for kind in ["in", "out", "retrans"] {
            tcp_segs_counter.with_label_values(&[kind]);
        }

        let generated_items_counter = IntCounterVec::new(
            opts(format!("{prefix}_dkg_generated_items_total"), "Completed batches of final preprocessing items, counted before aggregator delivery"),
            &["kind"],
        ).expect("failed to create generated items counter");
        registry
            .register(Box::new(generated_items_counter.clone()))
            .expect("failed to register generated items counter");
        for kind in ["bits", "triples"] {
            generated_items_counter.with_label_values(&[kind]);
        }
        let detail_duration_counter = CounterVec::new(
            opts(format!("{prefix}_dkg_detail_duration_seconds_total"), "Elapsed time of nested diagnostic operations; not additive with DKG phase durations"),
            &["operation"],
        ).expect("failed to create detail duration counter");
        registry
            .register(Box::new(detail_duration_counter.clone()))
            .expect("failed to register detail duration counter");
        let detail_observation_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_dkg_detail_observations_total"),
                "Completed nested diagnostic operations",
            ),
            &["operation"],
        )
        .expect("failed to create detail observation counter");
        registry
            .register(Box::new(detail_observation_counter.clone()))
            .expect("failed to register detail observation counter");
        for operation in [
            "rayon_queue",
            "rayon_execute",
            "broadcast_serialize",
            "echo_serialize",
            "echo_receive_wait",
            "echo_tally",
            "echo_hash",
        ] {
            detail_duration_counter.with_label_values(&[operation]);
            detail_observation_counter.with_label_values(&[operation]);
        }
        let process_start_time_gauge = Gauge::with_opts(opts(
            format!("{prefix}_process_start_time_seconds"),
            "Process start time since the Unix epoch",
        ))
        .expect("failed to create process start time gauge");
        registry
            .register(Box::new(process_start_time_gauge.clone()))
            .expect("failed to register process start time gauge");
        let process_uptime_gauge = Gauge::with_opts(opts(
            format!("{prefix}_process_uptime_seconds"),
            "Elapsed seconds since this process started",
        ))
        .expect("failed to create process uptime gauge");
        registry
            .register(Box::new(process_uptime_gauge.clone()))
            .expect("failed to register process uptime gauge");
        let process_cpu_seconds_counter = Counter::with_opts(opts(
            format!("{prefix}_process_cpu_seconds_total"),
            "Process CPU seconds integrated from sampled process CPU usage",
        ))
        .expect("failed to create process CPU seconds counter");
        registry
            .register(Box::new(process_cpu_seconds_counter.clone()))
            .expect("failed to register process CPU seconds counter");

        Self {
            dkg_phase_duration_counters,
            dkg_phase_observation_counters,
            optimistic_reconstruct_counter,
            c2c_send_rpc_histogram,
            c2c_sender_queued_gauge,
            thread_pool_cpu_gauge,
            named_process_cpu_gauge,
            net_iface_dropped_counter,
            tcp_segs_counter,
            thread_pool_cpu_seconds_counter,
            generated_items_counter,
            detail_duration_counter,
            detail_observation_counter,
            process_start_time_gauge,
            process_uptime_gauge,
            process_cpu_seconds_counter,
        }
    }

    /// Record one execution of `phase`.
    pub fn observe_dkg_phase(&self, phase: DkgPhase, duration: Duration) {
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.dkg_phase_duration_counters[phase as usize].inc_by(micros);
        self.dkg_phase_observation_counters[phase as usize].inc();
    }

    /// Time `phase` until the returned guard is dropped.
    pub fn time_dkg_phase(&self, phase: DkgPhase) -> DkgPhaseGuard<'_> {
        DkgPhaseGuard {
            metrics: self,
            phase,
            start: Instant::now(),
        }
    }

    /// Cumulative `(phase, microseconds, observations)` for every phase, for log lines.
    pub fn dkg_phase_snapshot(&self) -> Vec<(&'static str, u64, u64)> {
        (0..DkgPhase::COUNT)
            .map(|index| {
                (
                    DkgPhase::LABELS[index],
                    self.dkg_phase_duration_counters[index].get(),
                    self.dkg_phase_observation_counters[index].get(),
                )
            })
            .collect()
    }

    /// Count `n` optimistic reconstruction outcomes at `site` (see [`optimistic_outcome`]).
    pub fn increment_optimistic_reconstruct(&self, site: &str, outcome: &str, n: u64) {
        if n == 0 {
            return;
        }
        self.optimistic_reconstruct_counter
            .with_label_values(&[site, outcome])
            .inc_by(n);
    }

    /// Count completed final items of `kind`; internal triples consumed by bit generation are excluded.
    pub fn add_generated_items(&self, kind: &str, count: usize) {
        self.generated_items_counter
            .with_label_values(&[kind])
            .inc_by(count as u64);
    }

    /// Record a nested operation separately from the exclusive phase breakdown.
    pub fn observe_detail(&self, operation: &str, duration: Duration) {
        self.detail_duration_counter
            .with_label_values(&[operation])
            .inc_by(duration.as_secs_f64());
        self.detail_observation_counter
            .with_label_values(&[operation])
            .inc();
    }

    /// Time a nested operation without adding it to the exclusive phase breakdown.
    pub fn time_detail(&self, operation: &'static str) -> DetailGuard<'_> {
        DetailGuard {
            metrics: self,
            operation,
            start: Instant::now(),
        }
    }

    /// Export process identity, uptime, and CPU consumed during the sample interval.
    pub fn record_process_sample(&self, start_time: u64, uptime: u64, cpu_seconds: f64) {
        self.process_start_time_gauge.set(start_time as f64);
        self.process_uptime_gauge.set(uptime as f64);
        if cpu_seconds > 0.0 {
            self.process_cpu_seconds_counter.inc_by(cpu_seconds);
        }
    }

    /// Record one core-to-core `send_value` RPC of `bytes` bytes that took `duration`.
    pub fn observe_c2c_send_rpc(&self, bytes: usize, duration: Duration) {
        self.c2c_send_rpc_histogram
            .with_label_values(&[size_bucket(bytes)])
            .observe(duration.as_secs_f64() * 1_000.0);
    }

    /// Adjust the number of messages waiting in the sender queues by `delta`.
    pub fn add_c2c_sender_queued(&self, delta: i64) {
        self.c2c_sender_queued_gauge.add(delta);
    }

    /// Record the CPU usage (100 = one core) of the threads of `pool`.
    pub fn record_thread_pool_cpu(&self, pool: &str, percent: f64) {
        self.thread_pool_cpu_gauge
            .with_label_values(&[pool])
            .set(percent);
    }

    /// Add `seconds` of CPU time consumed by the threads of `pool` since the last sample.
    pub fn add_thread_pool_cpu_seconds(&self, pool: &str, seconds: f64) {
        if seconds > 0.0 {
            self.thread_pool_cpu_seconds_counter
                .with_label_values(&[pool])
                .inc_by(seconds);
        }
    }

    /// Record the CPU usage (100 = one core) of all processes named `process`.
    pub fn record_named_process_cpu(&self, process: &str, percent: f64) {
        self.named_process_cpu_gauge
            .with_label_values(&[process])
            .set(percent);
    }

    /// Add `delta` dropped packets for `iface` in direction `dir` (`rx` or `tx`).
    pub fn add_net_iface_dropped(&self, iface: &str, dir: &str, delta: u64) {
        self.net_iface_dropped_counter
            .with_label_values(&[iface, dir])
            .inc_by(delta);
    }

    /// Add `delta` TCP segments of `kind` (`in`, `out`, `retrans`).
    pub fn add_tcp_segs(&self, kind: &str, delta: u64) {
        self.tcp_segs_counter
            .with_label_values(&[kind])
            .inc_by(delta);
    }
}

/// Records elapsed time for one nested diagnostic operation.
pub struct DetailGuard<'a> {
    metrics: &'a DiagMetrics,
    operation: &'static str,
    start: Instant,
}

impl Drop for DetailGuard<'_> {
    fn drop(&mut self) {
        self.metrics
            .observe_detail(self.operation, self.start.elapsed());
    }
}

/// RAII guard that records a [`DkgPhase`] duration when dropped.
pub struct DkgPhaseGuard<'a> {
    metrics: &'a DiagMetrics,
    phase: DkgPhase,
    start: Instant,
}

impl DkgPhaseGuard<'_> {
    /// Record now and consume the guard, returning the measured duration.
    pub fn finish(self) -> Duration {
        let duration = self.start.elapsed();
        self.metrics.observe_dkg_phase(self.phase, duration);
        std::mem::forget(self);
        duration
    }
}

impl Drop for DkgPhaseGuard<'_> {
    fn drop(&mut self) {
        self.metrics
            .observe_dkg_phase(self.phase, self.start.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_have_one_label_each() {
        assert_eq!(DkgPhase::LABELS.len(), DkgPhase::COUNT);
        assert_eq!(DkgPhase::BitBatch as usize, DkgPhase::COUNT - 1);
    }

    #[test]
    fn size_buckets_are_monotone() {
        assert_eq!(size_bucket(0), "le_4k");
        assert_eq!(size_bucket(4_096), "le_4k");
        assert_eq!(size_bucket(4_097), "le_64k");
        assert_eq!(size_bucket(1_000_000), "le_1m");
        assert_eq!(size_bucket(8_320_000), "le_16m");
        assert_eq!(size_bucket(100_000_000), "gt_16m");
    }

    #[test]
    fn registers_in_a_fresh_registry_and_counts() {
        let registry = prometheus::Registry::new();
        let diag = DiagMetrics::new(&MetricsConfig::default(), &registry);
        diag.observe_dkg_phase(DkgPhase::Prss, Duration::from_millis(3));
        {
            let _guard = diag.time_dkg_phase(DkgPhase::Solve);
        }
        diag.increment_optimistic_reconstruct("d_values", optimistic_outcome::HIT, 5);
        diag.observe_c2c_send_rpc(8_320_000, Duration::from_millis(120));
        diag.add_c2c_sender_queued(3);
        diag.add_c2c_sender_queued(-3);
        diag.record_thread_pool_cpu("tokio", 950.0);
        diag.add_net_iface_dropped("vsocktun", "rx", 2);
        diag.add_tcp_segs("retrans", 7);
        diag.add_generated_items("bits", 10_000);
        diag.add_generated_items("triples", 500);
        diag.observe_detail("rayon_queue", Duration::from_millis(15));
        {
            let _guard = diag.time_detail("echo_tally");
        }
        diag.record_process_sample(1_000, 20, 2.5);
        diag.record_process_sample(1_000, 21, -1.0);
        assert_eq!(
            diag.generated_items_counter
                .with_label_values(&["bits"])
                .get(),
            10_000
        );
        assert_eq!(
            diag.generated_items_counter
                .with_label_values(&["triples"])
                .get(),
            500
        );
        assert_eq!(
            diag.detail_duration_counter
                .with_label_values(&["rayon_queue"])
                .get(),
            0.015
        );
        assert_eq!(
            diag.detail_observation_counter
                .with_label_values(&["echo_tally"])
                .get(),
            1
        );
        assert_eq!(diag.process_start_time_gauge.get(), 1_000.0);
        assert_eq!(diag.process_uptime_gauge.get(), 21.0);
        assert_eq!(diag.process_cpu_seconds_counter.get(), 2.5);
        let snapshot = diag.dkg_phase_snapshot();
        let prss = snapshot
            .iter()
            .find(|(label, _, _)| *label == "prss")
            .expect("prss phase present");
        assert_eq!(prss.1, 3_000);
        assert_eq!(prss.2, 1);
        let solve = snapshot
            .iter()
            .find(|(label, _, _)| *label == "solve")
            .expect("solve phase present");
        assert_eq!(solve.2, 1);
        assert!(!registry.gather().is_empty());
    }

    #[test]
    fn zero_activity_series_are_exported_before_first_work() {
        let registry = prometheus::Registry::new();
        let diag = DiagMetrics::new(&MetricsConfig::default(), &registry);
        diag.add_net_iface_dropped("vsocktun", "rx", 0);
        let families = registry.gather();
        for (suffix, expected) in [
            ("dkg_generated_items_total", 2),
            ("c2c_send_rpc_duration_ms", 5),
            ("thread_pool_cpu_seconds_total", 3),
            ("tcp_segs_total", 3),
            ("net_iface_dropped_total", 1),
            ("optimistic_reconstruct_total", 15),
        ] {
            let family = families
                .iter()
                .find(|family| family.name().ends_with(suffix))
                .unwrap();
            assert_eq!(family.get_metric().len(), expected, "{suffix}");
        }
    }
}
