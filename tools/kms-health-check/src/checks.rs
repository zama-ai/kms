use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::config::{self};
use crate::grpc_client::GrpcHealthClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub overall_health: HealthStatus,
    pub config_valid: Option<ConfigValidation>,
    pub connectivity: Option<ConnectivityCheck>,
    pub key_material: Option<KeyMaterialCheck>,
    pub operator_key: Option<OperatorKeyCheck>,
    pub peer_status: Option<Vec<PeerStatus>>,
    pub node_info: Option<NodeInfo>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub peer_id: u32, // Party ID for threshold mode
    pub endpoint: String,
    pub reachable: bool,
    pub latency_ms: u32,
    pub fhe_keys: usize,
    pub crs_keys: usize,
    pub preprocessing_keys: usize,
    pub storage_info: String, // Storage backend info from peer
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_type: String,       // "threshold" or "centralized"
    pub my_party_id: u32,        // Only meaningful for threshold
    pub threshold_required: u32, // Minimum nodes needed
    pub nodes_reachable: u32,    // Currently reachable nodes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigValidation {
    pub valid: bool,
    pub config_type: String,
    pub storage_type: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityCheck {
    pub reachable: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterialCheck {
    pub available: bool,
    pub fhe_keys: usize,
    pub crs_keys: usize,
    pub preprocessing_keys: usize,
    pub storage_backend: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorKeyCheck {
    pub available: bool,
    pub public_key_len: usize,
    pub public_key_hex: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Validate configuration file only
pub async fn run_config_validation(config_path: &str) -> anyhow::Result<HealthCheckResult> {
    let mut result = HealthCheckResult {
        config_valid: None,
        connectivity: None,
        key_material: None,
        operator_key: None,
        peer_status: None,
        node_info: None,
        overall_health: HealthStatus::Healthy,
        recommendations: Vec::new(),
    };

    match config::parse_config(Path::new(config_path)).await {
        Ok(config_type) => {
            let (type_str, storage_type) = match &config_type {
                config::KmsConfig::Centralized(c) => {
                    ("centralized", c.storage.storage_type.clone())
                }
                config::KmsConfig::Threshold(t) => (
                    "threshold",
                    t.storage
                        .as_ref()
                        .map(|s| s.storage_type.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                ),
            };

            result.config_valid = Some(ConfigValidation {
                valid: true,
                config_type: type_str.to_string(),
                storage_type: storage_type.clone(),
                errors: Vec::new(),
            });

            println!("\n[INFO]:");
            println!("  [OK] Valid {} config", type_str);
            println!("  [OK] Storage: {}", storage_type);

            if type_str == "threshold" {
                if let config::KmsConfig::Threshold(t) = &config_type {
                    // Report listen address for validation
                    println!(
                        "  [OK] Listen address: {}:{}",
                        t.listen_address, t.listen_port
                    );

                    // Validate threshold setting
                    // threshold = max number of malicious/offline nodes tolerated
                    // min_nodes = 2*threshold + 1 = total_nodes - threshold (for MPC operations)
                    if let Some(threshold) = t.threshold {
                        let total_nodes = t.peers.len(); // peers list includes self
                        let min_nodes_required = 2 * threshold + 1;
                        let min_nodes = total_nodes.saturating_sub(threshold);

                        if total_nodes < min_nodes_required {
                            result.overall_health = HealthStatus::Unhealthy;
                            result.recommendations.push(format!(
                                "Config error: {} nodes defined but threshold={} requires at least {} nodes (2t+1)",
                                total_nodes, threshold, min_nodes_required
                            ));
                        } else {
                            println!(
                                "  [OK] Threshold: {} (requires {} of {} nodes for MPC)",
                                threshold, min_nodes, total_nodes
                            );
                        }
                    }

                    // Validate peer addresses
                    println!("  [OK] {} peers configured:", t.peers.len());
                    for peer in &t.peers {
                        println!(
                            "      - Peer {} at {}:{}",
                            peer.party_id, peer.address, peer.port
                        );
                    }

                    result.recommendations.push(format!(
                        "Config defines {} peers for threshold KMS at {}:{}",
                        t.peers.len(),
                        t.listen_address,
                        t.listen_port
                    ));
                }
            }
        }
        Err(e) => {
            result.config_valid = Some(ConfigValidation {
                valid: false,
                config_type: "unknown".to_string(),
                storage_type: "unknown".to_string(),
                errors: vec![e.to_string()],
            });
            result.overall_health = HealthStatus::Unhealthy;
            result
                .recommendations
                .push("Fix configuration errors before deployment".to_string());
            println!("  [FAIL] Invalid configuration:");
        }
    }

    Ok(result)
}

// Helper function to check connectivity
async fn check_connectivity(
    client: &GrpcHealthClient,
    endpoint: &str,
) -> (ConnectivityCheck, bool) {
    match client.test_connectivity().await {
        Ok(latency) => {
            tracing::debug!(
                "Successfully connected to {} in {}ms",
                endpoint,
                latency.as_millis()
            );
            (
                ConnectivityCheck {
                    reachable: true,
                    latency_ms: latency.as_millis() as u64,
                    error: None,
                },
                true,
            )
        }
        Err(e) => {
            tracing::warn!("Failed to connect to {}: {}", endpoint, e);
            (
                ConnectivityCheck {
                    reachable: false,
                    latency_ms: 0,
                    error: Some(format!("Failed to connect to {}: {}", endpoint, e)),
                },
                false,
            )
        }
    }
}

// Helper function to process health status response
fn process_health_status(
    health_status: &kms_grpc::kms::v1::HealthStatusResponse,
    result: &mut HealthCheckResult,
) {
    // Set key material from health status response
    let total_keys = health_status.my_fhe_keys + health_status.my_crs_keys;
    result.key_material = Some(KeyMaterialCheck {
        available: true,
        fhe_keys: health_status.my_fhe_keys as usize,
        crs_keys: health_status.my_crs_keys as usize,
        preprocessing_keys: health_status.my_preprocessing_keys as usize,
        storage_backend: health_status.my_storage_info.clone(),
        error: None,
    });

    if total_keys == 0 {
        result.overall_health = HealthStatus::Degraded;
        result
            .recommendations
            .push("No keys found - run key generation".to_string());
    }

    // Set node info from health response
    result.node_info = Some(NodeInfo {
        node_type: health_status.node_type.clone(),
        my_party_id: health_status.my_party_id,
        threshold_required: health_status.threshold_required,
        nodes_reachable: health_status.nodes_reachable,
    });

    // Set peer status from health response
    if !health_status.peers.is_empty() {
        let mut peer_statuses = Vec::new();
        for peer in &health_status.peers {
            peer_statuses.push(PeerStatus {
                peer_id: peer.peer_id,
                endpoint: peer.endpoint.clone(),
                reachable: peer.reachable,
                latency_ms: peer.latency_ms,
                fhe_keys: peer.fhe_keys as usize,
                crs_keys: peer.crs_keys as usize,
                preprocessing_keys: peer.preprocessing_keys as usize,
                storage_info: peer.storage_info.clone(),
                error: if peer.error.is_empty() {
                    None
                } else {
                    Some(peer.error.clone())
                },
            });
        }
        result.peer_status = Some(peer_statuses);

        // Check threshold requirements if applicable
        if health_status.node_type == "threshold" && health_status.threshold_required > 0 {
            if health_status.nodes_reachable < health_status.threshold_required {
                result.overall_health = HealthStatus::Unhealthy;
                result.recommendations.push(format!(
                    "Critical: Only {} nodes reachable, but {} required for threshold operations",
                    health_status.nodes_reachable, health_status.threshold_required
                ));
            } else if health_status.nodes_reachable < health_status.peers.len() as u32 + 1 {
                result.overall_health = HealthStatus::Degraded;
                result.recommendations.push(format!(
                    "Some peers unreachable: {}/{} peers responding",
                    health_status.nodes_reachable - 1,
                    health_status.peers.len()
                ));
            }
        }
    }

    // Set overall health based on server's assessment
    match health_status.status.as_str() {
        "unhealthy" => result.overall_health = HealthStatus::Unhealthy,
        "degraded" => {
            if result.overall_health != HealthStatus::Unhealthy {
                result.overall_health = HealthStatus::Degraded;
            }
        }
        _ => {} // Keep current status
    }
}

// Helper function to check key material (fallback when health status not available)
async fn check_key_material_fallback(client: &GrpcHealthClient, result: &mut HealthCheckResult) {
    match client.get_key_material_availability().await {
        Ok(material) => {
            let total_keys = material.fhe_key_ids.len() + material.crs_ids.len();
            result.key_material = Some(KeyMaterialCheck {
                available: true,
                fhe_keys: material.fhe_key_ids.len(),
                crs_keys: material.crs_ids.len(),
                preprocessing_keys: material.preprocessing_ids.len(),
                storage_backend: material.storage_info.clone(),
                error: None,
            });

            if total_keys == 0 {
                result.overall_health = HealthStatus::Degraded;
                result
                    .recommendations
                    .push("No keys found - run key generation".to_string());
            }
        }
        Err(e) => {
            result.key_material = Some(KeyMaterialCheck {
                fhe_keys: 0,
                crs_keys: 0,
                preprocessing_keys: 0,
                storage_backend: String::new(),
                available: false,
                error: Some(e.to_string()),
            });
            result.overall_health = HealthStatus::Degraded;
            result
                .recommendations
                .push(format!("Key material check failed: {}", e));
        }
    }
}

// Helper function to check operator key
async fn check_operator_key(client: &GrpcHealthClient, result: &mut HealthCheckResult) {
    match client.get_operator_public_key().await {
        Ok(key) => {
            result.operator_key = Some(OperatorKeyCheck {
                available: true,
                public_key_len: key.public_key.len(),
                public_key_hex: Some(hex::encode(&key.public_key)),
                error: None,
            });
        }
        Err(e) => {
            result.operator_key = Some(OperatorKeyCheck {
                available: false,
                public_key_len: 0,
                public_key_hex: None,
                error: Some(e.to_string()),
            });
            // Not critical enough to degrade health
        }
    }
}

/// Check live KMS instance
pub async fn check_live(
    endpoint: &str,
    _config_path: Option<&Path>,
) -> anyhow::Result<HealthCheckResult> {
    let mut result = HealthCheckResult {
        config_valid: None,
        connectivity: None,
        key_material: None,
        operator_key: None,
        peer_status: None,
        node_info: None,
        overall_health: HealthStatus::Healthy,
        recommendations: Vec::new(),
    };

    let client = GrpcHealthClient::new(endpoint);

    // Test connectivity
    let (connectivity, is_reachable) = check_connectivity(&client, endpoint).await;
    result.connectivity = Some(connectivity);

    if !is_reachable {
        result.overall_health = HealthStatus::Unhealthy;
        result
            .recommendations
            .push(format!("Cannot connect to KMS at {}", endpoint));
        return Ok(result);
    }

    // Try to get comprehensive health status first (includes peer health)
    match client.get_health_status().await {
        Ok(health_status) => {
            process_health_status(&health_status, &mut result);
        }
        Err(_) => {
            // Fall back to basic key material check if health status RPC not available
            check_key_material_fallback(&client, &mut result).await;
        }
    }

    // Check operator public key
    check_operator_key(&client, &mut result).await;

    if result.recommendations.is_empty() && result.overall_health == HealthStatus::Healthy {
        result
            .recommendations
            .push("All health checks passed".to_string());
    }

    Ok(result)
}

/// Run full check (config + live)
pub async fn run_full_check(
    config_path: Option<&str>,
    endpoint: &str,
) -> anyhow::Result<HealthCheckResult> {
    let mut result = check_live(endpoint, config_path.map(Path::new)).await?;

    // If we have config, parse it to get peer information
    if let Some(config_path) = config_path {
        let config_result = run_config_validation(config_path).await?;
        result.config_valid = config_result.config_valid;
    }

    // Merge recommendations
    if let Some(config_validation) = &result.config_valid {
        if !config_validation.valid {
            result.overall_health = HealthStatus::Unhealthy;
            result
                .recommendations
                .insert(0, "Configuration validation failed".to_string());
        }
    }

    Ok(result)
}
