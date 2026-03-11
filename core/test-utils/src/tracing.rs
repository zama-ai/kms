use std::{
    cmp::Reverse,
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use comfy_table::{presets::UTF8_FULL_CONDENSED, CellAlignment, ContentArrangement, Table};
use tracing::{span, Subscriber};
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::Context, prelude::*, registry::LookupSpan, EnvFilter, Layer,
};

/// Convenience function to set up a tracing subscriber with two [`Layer`]s:
///
/// - A **fmt layer** that respects `RUST_LOG`'s filtering features.
/// - A **timing layer** ([`TimingLayer`]) that sees *all* spans regardless of `RUST_LOG`.
///
/// This function can safely be called many times; calls after the first are cheap clones.
///
/// Returns a [`TimingHandle`].
///
/// # Example
/// ```rust,ignore
/// let timing = test_utils::setup_test_tracing();
/// // ... run test ...
/// timing.print_summary();
/// ```
///
/// NOTE: To see the timing summary, pass  `--nocapture` to the test runner.
pub fn setup_test_tracing() -> TimingHandle {
    static HANDLE: OnceLock<TimingHandle> = OnceLock::new();

    HANDLE
        .get_or_init(|| {
            let timing_layer = TimingLayer::new();
            let handle = timing_layer.handle();

            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                );

            let _ = tracing_subscriber::registry()
                .with(fmt_layer)
                .with(timing_layer)
                .try_init();

            handle
        })
        .clone()
}

/// Per-span timing data stored in the span's extensions.
struct SpanTiming {
    /// When the span was created.
    created_at: Instant,
    /// Accumulated time spent actively between span entry/exit.
    busy: Duration,
    /// Timestamp of the most recent `on_enter`.
    last_entered: Option<Instant>,
}

/// Key for aggregating spans: name + target (typically the module path).
#[derive(Clone, PartialEq, Eq, Hash)]
struct SpanKey {
    name: String,
    target: String,
}

/// Aggregated timing data for all spans sharing the same name and target.
///
/// Mirrors the private `Timings` struct in `tracing_subscriber`.
#[derive(Default)]
struct AggregatedTiming {
    /// Total duration for all calls and all spans.
    total: Duration,
    /// Active execution time inside spans.
    busy: Duration,
    /// Time spent in an open span, but waiting (typically during async .awaits).
    idle: Duration,
    /// Call count.
    count: u64,
}

type Timings = Arc<Mutex<HashMap<SpanKey, AggregatedTiming>>>;

/// A `tracing` [`Layer`] that collects span timings and prints a sorted summary.
///
/// For most use cases, prefer [`setup_test_tracing`] which handles the subscriber
/// setup correctly.
///
/// # Manual usage
///
/// ```rust,ignore
/// use test_utils::TimingLayer;
/// use tracing_subscriber::prelude::*;
///
/// let timing_layer = TimingLayer::new();
/// let timing_handle = timing_layer.handle();
///
/// // NOTE: attach EnvFilter to the fmt layer only, not the registry,
/// // otherwise the timing layer won't see filtered-out spans.
/// let fmt_layer = tracing_subscriber::fmt::layer()
///     .with_filter(tracing_subscriber::EnvFilter::new("info"));
///
/// let _ = tracing_subscriber::registry()
///     .with(fmt_layer)
///     .with(timing_layer)
///     .try_init();
///
/// // ... run your test ...
/// timing_handle.print_summary();
/// ```
///
/// Example output:
///
/// ```ignore
///   Span Timing Summary (23 more spans not shown)
///
/// ┌───────────────────────────┬───────────────────────────────────────────────────────────┬──────────┬──────────┬──────────┬───────┐
/// │ Span                      ┆ Target                                                    ┆    Total ┆     Busy ┆     Idle ┆ Calls │
/// ╞═══════════════════════════╪═══════════════════════════════════════════════════════════╪══════════╪══════════╪══════════╪═══════╡
/// │ Connection                ┆ h2::proto::connection                                     ┆  863.98s ┆  23.19ms ┆  863.95s ┆    48 │
/// │ server_handshake          ┆ h2::server                                                ┆  431.96s ┆   3.05ms ┆  431.95s ┆    24 │
/// │ grpc_request              ┆ observability::telemetry                                  ┆   57.38s ┆   51.62s ┆    5.76s ┆    12 │
/// │ new_custodian_context     ┆ kms_lib::engine::threshold::endpoint                      ┆   53.47s ┆   51.62s ┆    1.85s ┆     4 │
/// │ Create servers/clients    ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆   37.15s ┆  26.21ms ┆   37.13s ┆     1 │
/// │ Run new custodian context ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆   13.51s ┆   1.39ms ┆   13.51s ┆     1 │
/// │ Shut down                 ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆    4.71s ┆ 128.25ms ┆    4.58s ┆     4 │
/// │ Run CRS                   ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆    2.63s ┆    2.14s ┆ 494.80ms ┆     1 │
/// │ insecure_crs_gen          ┆ kms_lib::engine::threshold::endpoint                      ┆    1.96s ┆  40.79ms ┆    1.92s ┆     4 │
/// │ get_crs_gen_result        ┆ kms_lib::engine::threshold::endpoint                      ┆    1.95s ┆     25µs ┆    1.95s ┆     4 │
/// │ PRSS.Init (robust)        ┆ threshold_execution::small_execution::prss                ┆ 368.62ms ┆   6.63ms ┆ 361.99ms ┆    16 │
/// │ VSS                       ┆ threshold_execution::large_execution::vss                 ┆ 339.04ms ┆   5.42ms ┆ 333.62ms ┆    16 │
/// │ poll                      ┆ h2::proto::connection                                     ┆ 281.79ms ┆ 280.97ms ┆    824µs ┆  2496 │
/// │ Purge backup              ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆ 120.10ms ┆    720µs ┆ 119.38ms ┆     1 │
/// │ Syn-Bcast-Corrupt         ┆ threshold_execution::communication::broadcast             ┆  77.38ms ┆   2.74ms ┆  74.64ms ┆    16 │
/// │ Syn-Bcast                 ┆ threshold_execution::communication::broadcast             ┆  77.10ms ┆   5.26ms ┆  71.84ms ┆    16 │
/// │ Purge crs request         ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆  47.08ms ┆  16.23ms ┆  30.85ms ┆     1 │
/// │ Purge new custodian req   ┆ kms_lib::client::tests::threshold::custodian_backup_tests ┆  42.72ms ┆   4.19ms ┆  38.52ms ┆     1 │
/// │ pop_frame                 ┆ h2::proto::streams::prioritize                            ┆  34.68ms ┆  33.65ms ┆   1.03ms ┆  4665 │
/// │ FramedRead::poll_next     ┆ h2::codec::framed_read                                    ┆  34.11ms ┆  32.89ms ┆   1.21ms ┆  5221 │
/// └───────────────────────────┴───────────────────────────────────────────────────────────┴──────────┴──────────┴──────────┴───────┘
/// ```
pub struct TimingLayer {
    timings: Timings,
    top_n: usize,
}

/// A cheaply-cloneable handle to a [`TimingLayer`]'s collected timings.
///
/// Grab one via [`TimingLayer::handle`] *before* passing the layer to the subscriber,
/// then call [`print_summary`](TimingHandle::print_summary) whenever you want.
#[derive(Clone)]
pub struct TimingHandle {
    timings: Timings,
    top_n: usize,
}

impl TimingLayer {
    /// Create a new timing summary layer that will print the top 20 spans by total time.
    // FFS Clippy
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            timings: Arc::new(Mutex::new(HashMap::new())),
            top_n: 20,
        }
    }

    /// Set how many spans to include in the summary.
    pub fn top_n(mut self, n: usize) -> Self {
        self.top_n = n;
        self
    }

    /// Get a handle that can print the summary at any time.
    ///
    /// Call this *before* passing the layer to the subscriber (which consumes it).
    pub fn handle(&self) -> TimingHandle {
        TimingHandle {
            timings: Arc::clone(&self.timings),
            top_n: self.top_n,
        }
    }
}

impl TimingHandle {
    /// Print the summary to stderr and clear collected timings.
    pub fn print_summary(&self) {
        print_summary_impl(&self.timings, self.top_n);
        self.timings.lock().unwrap().clear();
    }
}

fn print_summary_impl(timings: &Timings, top_n: usize) {
    let timings = timings
        .lock()
        .expect("The timings lock is only held for printing");
    if timings.is_empty() {
        return;
    }

    let mut entries: Vec<_> = timings.iter().collect();
    entries.sort_by_key(|(_, timing)| Reverse(timing.total));

    let mut table = Table::new();
    let headers = vec!["Span", "Target", "Total", "Busy", "Idle", "Calls"];
    let col_count = headers.len();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(headers);

    // Right-align the numeric columns (Total=2, Busy=3, Idle=4, Calls=5).
    for col in 2..col_count {
        table
            .column_mut(col)
            .expect("column exists")
            .set_cell_alignment(CellAlignment::Right);
    }

    for (key, agg) in entries.iter().take(top_n) {
        table.add_row(vec![
            key.name.clone(),
            key.target.clone(),
            format_duration(agg.total),
            format_duration(agg.busy),
            format_duration(agg.idle),
            agg.count.to_string(),
        ]);
    }

    let shown = entries.len().min(top_n);
    if entries.len() > shown {
        eprintln!(
            "\n  Span Timing Summary ({} more spans not shown)\n",
            entries.len() - shown
        );
    } else {
        eprintln!("\n  Span Timing Summary\n");
    }
    eprintln!("{table}\n");
}

impl<S> Layer<S> for TimingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            extensions.insert(SpanTiming {
                created_at: Instant::now(),
                busy: Duration::ZERO,
                last_entered: None,
            });
        }
    }

    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(timing) = extensions.get_mut::<SpanTiming>() {
                timing.last_entered = Some(Instant::now());
            }
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(timing) = extensions.get_mut::<SpanTiming>() {
                if let Some(entered) = timing.last_entered.take() {
                    timing.busy += entered.elapsed();
                }
            }
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            let extensions = span.extensions();
            if let Some(timing) = extensions.get::<SpanTiming>() {
                let total = timing.created_at.elapsed();
                let busy = timing.busy;
                let idle = total.saturating_sub(busy);
                let key = SpanKey {
                    name: span.name().to_string(),
                    target: span.metadata().target().to_string(),
                };

                let mut timings = self.timings.lock().unwrap();
                let entry = timings.entry(key).or_default();
                entry.total += total;
                entry.busy += busy;
                entry.idle += idle;
                entry.count += 1;
            }
        }
    }
}

fn format_duration(d: Duration) -> String {
    let total_us = d.as_micros();
    if total_us < 1_000 {
        format!("{}µs", total_us)
    } else if total_us < 1_000_000 {
        format!("{:.2}ms", total_us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", total_us as f64 / 1_000_000.0)
    }
}
