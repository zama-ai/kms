use crate::checks::{HealthCheckResult, HealthStatus};
use anyhow::Result;
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
