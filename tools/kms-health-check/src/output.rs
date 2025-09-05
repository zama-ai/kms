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
        HealthStatus::Healthy => writeln!(output, "\n[OK] Overall Status: Healthy")?,
        HealthStatus::Degraded => writeln!(output, "\n[WARN] Overall Status: Degraded")?,
        HealthStatus::Unhealthy => writeln!(output, "\n[ERROR] Overall Status: Unhealthy")?,
    }

    // Node info
    if let Some(node_info) = &result.node_info {
        writeln!(output, "\n[NODE INFO]:")?;
        writeln!(output, "  Type: {}", node_info.node_type)?;
        if node_info.node_type == "threshold" {
            writeln!(output, "  Party ID: {}", node_info.my_party_id)?;
            writeln!(
                output,
                "  Threshold: {} required",
                node_info.threshold_required
            )?;
            writeln!(output, "  Nodes Reachable: {}", node_info.nodes_reachable)?;
        }
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
        writeln!(output, "\n[CONNECTIVITY]:")?;
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
            writeln!(output, "  [OK] CRS Keys: {}", keys.crs_ids.len())?;
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

    // Peer status for threshold
    if let Some(peers) = &result.peer_status {
        writeln!(output, "\n[PEER STATUS]:")?;
        let reachable = peers.iter().filter(|p| p.reachable).count();
        writeln!(output, "  {} of {} peers reachable", reachable, peers.len())?;

        for peer in peers {
            if peer.reachable {
                writeln!(
                    output,
                    "  [OK] Party {} @ {} ({}ms)",
                    peer.peer_id, peer.endpoint, peer.latency_ms
                )?;

                // Display key material in consistent format with host
                writeln!(output, "       FHE Keys: {}", peer.fhe_key_ids.len())?;
                for key_id in &peer.fhe_key_ids {
                    writeln!(output, "         - {}", key_id)?;
                }

                writeln!(output, "       CRS Keys: {}", peer.crs_ids.len())?;
                for key_id in &peer.crs_ids {
                    writeln!(output, "         - {}", key_id)?;
                }

                writeln!(
                    output,
                    "       Preprocessing: {}",
                    peer.preprocessing_key_ids.len()
                )?;
                for key_id in &peer.preprocessing_key_ids {
                    writeln!(output, "         - {}", key_id)?;
                }

                if !peer.storage_info.is_empty() {
                    writeln!(output, "       Storage: {}", peer.storage_info)?;
                }
            } else {
                writeln!(
                    output,
                    "  [FAIL] Party {} @ {}",
                    peer.peer_id, peer.endpoint
                )?;
                writeln!(
                    output,
                    "         Error: {}",
                    peer.error.as_ref().unwrap_or(&"Unreachable".to_string())
                )?;
            }
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
