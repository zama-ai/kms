use crate::checks::{HealthCheckResult, HealthStatus};
use anyhow::Result;
use kms_grpc::kms::v1::BandwidthBenchmarkResponse;
use std::fmt::Write;

pub fn print_result(result: HealthCheckResult, format: &crate::OutputFormat) -> Result<()> {
    match format {
        crate::OutputFormat::Text => print_text(&result),
        crate::OutputFormat::Json => print_json(&result),
    }
}

fn print_text(result: &HealthCheckResult) -> Result<()> {
    let mut output = String::with_capacity(2048); // Pre-allocate for typical output size

    writeln!(output, "\n[KMS HEALTH CHECK REPORT]")?;
    writeln!(output, "{}", "=".repeat(50))?;

    // Overall status
    match result.overall_health {
        HealthStatus::Optimal => writeln!(
            output,
            "\n[EXCELLENT] Overall Status: Optimal - All nodes online"
        )?,
        HealthStatus::Healthy => writeln!(
            output,
            "\n[OK] Overall Status: Healthy - Sufficient majority"
        )?,
        HealthStatus::Degraded => writeln!(
            output,
            "\n[WARN] Overall Status: Degraded - Reduced fault tolerance or missing key material"
        )?,
        HealthStatus::Unhealthy => writeln!(
            output,
            "\n[ERROR] Overall Status: Unhealthy - Critical issues"
        )?,
    }

    // Config validation
    if let Some(config) = &result.config_valid {
        writeln!(output, "\n[CONFIG]:")?;
        if config.valid {
            writeln!(output, "  [OK] Valid {} config", config.config_type)?;
            writeln!(output, "  [OK] Storage: {}", config.storage_type)?;
        } else {
            writeln!(output, "  [FAIL] Invalid configuration:")?;
            for error in &config.errors {
                writeln!(output, "  [FAIL] {}", error)?;
            }
        }
    }

    // Connectivity
    if let Some(conn) = &result.connectivity {
        writeln!(output, "\n[CORE SERVICE CONNECTIVITY]:")?;
        if conn.reachable {
            writeln!(output, "  [OK] Reachable (latency: {}ms)", conn.latency_ms)?;
        } else {
            writeln!(
                output,
                "  [FAIL] Cannot connect: {}",
                conn.error.as_ref().unwrap_or(&"Unknown".to_string())
            )?;
        }
    }

    // Key material
    if let Some(keys) = &result.key_material {
        writeln!(output, "\n[KEY MATERIAL]:")?;
        if keys.available {
            writeln!(output, "  [OK] FHE Keys: {}", keys.fhe_key_ids.len())?;
            if !keys.fhe_key_ids.is_empty() {
                for key_id in &keys.fhe_key_ids {
                    writeln!(output, "       - {}", key_id)?;
                }
            }
            writeln!(output, "  [OK] CRS: {}", keys.crs_ids.len())?;
            if !keys.crs_ids.is_empty() {
                for key_id in &keys.crs_ids {
                    writeln!(output, "       - {}", key_id)?;
                }
            }
            writeln!(
                output,
                "  [OK] Preprocessing: {}",
                keys.preprocessing_key_ids.len()
            )?;
            if !keys.preprocessing_key_ids.is_empty() {
                for key_id in &keys.preprocessing_key_ids {
                    writeln!(output, "       - {}", key_id)?;
                }
            }
            writeln!(output, "  [OK] Storage: {}", keys.storage_backend)?;
        } else {
            writeln!(output, "  [FAIL] Key material unavailable")?;
        }
    }

    // Operator key
    if let Some(op_key) = &result.operator_key {
        writeln!(output, "\n[OPERATOR KEY]:")?;
        if op_key.available {
            writeln!(output, "  [OK] Available ({} bytes)", op_key.public_key_len)?;
            if let Some(hex) = &op_key.public_key_hex {
                // Display first 32 and last 32 chars of hex for readability
                if hex.len() > 64 {
                    writeln!(
                        output,
                        "  [OK] Hex: {}...{}",
                        &hex[..32],
                        &hex[hex.len() - 32..]
                    )?;
                } else {
                    writeln!(output, "  [OK] Hex: {}", hex)?;
                }
            }
        } else {
            writeln!(
                output,
                "  [FAIL] Not available: {}",
                op_key.error.as_ref().unwrap_or(&"Unknown".to_string())
            )?;
        }
    }

    // Peer status for threshold for each of the contexts
    if let Some(contexts) = &result.context_info {
        for context in contexts {
            writeln!(
                output,
                "\n[CONTEXT {}]:",
                context
                    .context_id
                    .clone()
                    .map(|c| c.request_id)
                    .unwrap_or_else(|| "UNKNOWN".to_string())
            )?;
            let self_info = &context.self_node_info;
            writeln!(output, "\n  [NODE INFO]:")?;
            writeln!(output, "    Type: {}", self_info.node_type)?;
            if self_info.node_type == "threshold" {
                writeln!(output, "    Party ID: {}", self_info.my_party_id)?;
                writeln!(
                    output,
                    "    Threshold: {} required",
                    self_info.threshold_required
                )?;
                writeln!(output, "    Nodes Reachable: {}", self_info.nodes_reachable)?;
            }

            writeln!(output, "\n  [PEER STATUS]:")?;
            let reachable = context.peers_status.iter().filter(|p| p.reachable).count();
            writeln!(
                output,
                "    {} of {} peers reachable",
                reachable,
                context.peers_status.len()
            )?;

            for peer in &context.peers_status {
                if peer.reachable {
                    writeln!(
                        output,
                        "    [OK] Party {} @ {} ({}ms)",
                        peer.peer_id, peer.endpoint, peer.latency_ms
                    )?;
                } else {
                    writeln!(
                        output,
                        "    [FAIL] Party {} @ {}",
                        peer.peer_id, peer.endpoint
                    )?;
                    writeln!(
                        output,
                        "           Error: {}",
                        peer.error.as_ref().unwrap_or(&"Unreachable".to_string())
                    )?;
                }
            }
            writeln!(output, "\n  {}", context.recommendation)?;
        }
    }

    // Recommendations
    if !result.recommendations.is_empty() {
        writeln!(output, "\n[INFO]:")?;
        for rec in &result.recommendations {
            writeln!(output, "  {}", rec)?;
        }
    }

    writeln!(output, "\n{}", "=".repeat(50))?;

    // Single write to stdout
    print!("{}", output);
    Ok(())
}

fn print_json(result: &HealthCheckResult) -> Result<()> {
    let json = serde_json::to_string_pretty(&result)?;
    println!("{}", json);
    Ok(())
}

pub fn print_bandwidth_benchmark_text(
    duration: u64,
    num_sessions: u32,
    payload_size: u32,
    connections_per_peer: u32,
    results: Vec<(String, BandwidthBenchmarkResponse)>,
) -> Result<()> {
    let oneshot = duration == 0;
    let mut output = String::with_capacity(4096);
    writeln!(output, "\n[KMS BANDWIDTH BENCHMARK]")?;
    writeln!(output, "{}", "=".repeat(78))?;
    if oneshot {
        writeln!(
            output,
            "Benchmark type:      One-shot (single payload per session)"
        )?;
    } else {
        writeln!(
            output,
            "Benchmark type:      Duration-based ({} seconds)",
            duration
        )?;
    }
    writeln!(output, "Parallel sessions:   {}", num_sessions)?;
    writeln!(output, "Payload per session: {} bytes", payload_size)?;
    writeln!(
        output,
        "Connections / peer:  {}",
        connections_per_peer.max(1)
    )?;

    for (endpoint, result) in results {
        writeln!(output, "\n{}", "-".repeat(78))?;
        writeln!(output, "Endpoint: {}", endpoint)?;
        writeln!(output, "Peers:    {}", result.peers_info.len())?;
        writeln!(output, "{}", "-".repeat(78))?;
        writeln!(
            output,
            "{:>7}  {:<24}  {:>12}  {:>8}  {:>10}",
            "Peer", "Address", "Sent (MiB)", "Secs", "MiB/s"
        )?;
        writeln!(output, "{}", "-".repeat(78))?;

        let mut total_bytes_sent: u64 = 0;
        let mut max_duration_secs: u64 = 0;

        for peer in &result.peers_info {
            total_bytes_sent = total_bytes_sent.saturating_add(peer.bytes_sent);
            max_duration_secs = max_duration_secs.max(peer.duration);

            let sent_mib = peer.bytes_sent as f64 / (1024.0 * 1024.0);
            let throughput_mib_per_sec = if peer.duration == 0 {
                0.0
            } else {
                sent_mib / (peer.duration as f64)
            };

            writeln!(
                output,
                "{:>7}  {:<24}  {:>12.2}  {:>8}  {:>10.2}",
                peer.peer_id, peer.endpoint, sent_mib, peer.duration, throughput_mib_per_sec
            )?;

            if let Some(latency) = &peer.latency {
                writeln!(output, "         latency(ms) avg: {}", latency.average,)?;
                writeln!(
                    output,
                    "                     p50/p90/p99: {}/{}/{}",
                    latency.p50, latency.p90, latency.p99,
                )?;
                writeln!(
                    output,
                    "                     slowest/fastest: {}/{}",
                    latency.slowest, latency.fastest
                )?;
            }
        }

        let total_mib = total_bytes_sent as f64 / (1024.0 * 1024.0);
        let aggregate_mib_per_sec = if max_duration_secs == 0 {
            0.0
        } else {
            total_mib / (max_duration_secs as f64)
        };
        writeln!(output, "{}", "-".repeat(78))?;
        writeln!(
            output,
            "Summary: total {:.2} MiB in ~{}s, aggregate {:.2} MiB/s",
            total_mib, max_duration_secs, aggregate_mib_per_sec
        )?;
    }

    writeln!(output, "\n{}", "=".repeat(78))?;
    print!("{}", output);
    Ok(())
}

/// JSON-formatted equivalent of [`print_bandwidth_benchmark_text`].
///
/// Emits a single pretty-printed JSON document to stdout containing the
/// same configuration, per-peer measurements, and per-endpoint summary
/// statistics. The shape is intentionally machine-friendly (no padding,
/// fully explicit unit suffixes in field names) so downstream tooling can
/// parse it with `jq` or `serde_json` directly.
///
/// All MiB values are computed with a 1024 × 1024 divisor (matching the
/// text formatter). Throughput fields are 0.0 when the relevant duration
/// is 0 (one-shot mode), since per-second rates are not meaningful in
/// that case.
pub fn print_bandwidth_benchmark_json(
    duration: u64,
    num_sessions: u32,
    payload_size: u32,
    connections_per_peer: u32,
    results: Vec<(String, BandwidthBenchmarkResponse)>,
) -> Result<()> {
    let oneshot = duration == 0;

    let endpoints: Vec<serde_json::Value> = results
        .into_iter()
        .map(|(endpoint, result)| {
            let mut total_bytes_sent: u64 = 0;
            let mut max_duration_secs: u64 = 0;

            let peers: Vec<serde_json::Value> = result
                .peers_info
                .iter()
                .map(|peer| {
                    total_bytes_sent = total_bytes_sent.saturating_add(peer.bytes_sent);
                    max_duration_secs = max_duration_secs.max(peer.duration);

                    let sent_mib = peer.bytes_sent as f64 / (1024.0 * 1024.0);
                    let throughput_mib_per_sec = if peer.duration == 0 {
                        0.0
                    } else {
                        sent_mib / (peer.duration as f64)
                    };

                    let latency = peer.latency.as_ref().map(|l| {
                        serde_json::json!({
                            "average_ms": l.average,
                            "p50_ms": l.p50,
                            "p90_ms": l.p90,
                            "p99_ms": l.p99,
                            "slowest_ms": l.slowest,
                            "fastest_ms": l.fastest,
                        })
                    });

                    serde_json::json!({
                        "peer_id": peer.peer_id,
                        "endpoint": peer.endpoint,
                        "bytes_sent": peer.bytes_sent,
                        "duration_secs": peer.duration,
                        "throughput_mib_per_sec": throughput_mib_per_sec,
                        "latency": latency,
                    })
                })
                .collect();

            let total_mib = total_bytes_sent as f64 / (1024.0 * 1024.0);
            let aggregate_mib_per_sec = if max_duration_secs == 0 {
                0.0
            } else {
                total_mib / (max_duration_secs as f64)
            };

            serde_json::json!({
                "endpoint": endpoint,
                "num_peers": peers.len(),
                "peers": peers,
                "summary": {
                    "total_bytes_sent": total_bytes_sent,
                    "total_mib": total_mib,
                    "duration_secs": max_duration_secs,
                    "aggregate_mib_per_sec": aggregate_mib_per_sec,
                },
            })
        })
        .collect();

    let report = serde_json::json!({
        "config": {
            "benchmark_type": if oneshot { "oneshot" } else { "duration" },
            "duration_secs": duration,
            "num_sessions": num_sessions,
            "payload_size_bytes": payload_size,
            "connections_per_peer": connections_per_peer.max(1),
        },
        "endpoints": endpoints,
    });

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
