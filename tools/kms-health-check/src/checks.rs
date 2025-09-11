use anyhow::Result;
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
    pub fhe_key_ids: Vec<String>,
    pub crs_ids: Vec<String>,
    pub preprocessing_key_ids: Vec<String>,
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
    pub fhe_key_ids: Vec<String>,
    pub crs_ids: Vec<String>,
    pub preprocessing_key_ids: Vec<String>,
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
    Optimal,   // All nodes online and reachable
    Healthy,   // Sufficient 2/3 majority but not all nodes
    Degraded,  // Above minimum threshold but below 2/3
    Unhealthy, // Insufficient nodes for operations
}

/// Validate configuration file only
pub async fn run_config_validation(config_path: &str) -> Result<HealthCheckResult> {
    let mut result = HealthCheckResult {
        config_valid: None,
        connectivity: None,
        key_material: None,
        operator_key: None,
        peer_status: None,
        node_info: None,
        overall_health: HealthStatus::Optimal,
        recommendations: Vec::new(),
    };

    match config::parse_config(Path::new(config_path)).await {
        Ok(config_type) => {
            let (type_str, storage_type) = if config_type.threshold.is_some() {
                // Threshold KMS mode
                let storage_info = config_type
                    .private_vault
                    .as_ref()
                    .map(|v| format!("{:?}", v.storage))
                    .unwrap_or_else(|| "unknown".to_string());
                ("threshold", storage_info)
            } else {
                // Centralized KMS mode
                let storage_info = config_type
                    .private_vault
                    .as_ref()
                    .map(|v| format!("{:?}", v.storage))
                    .unwrap_or_else(|| "unknown".to_string());
                ("centralized", storage_info)
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
                if let Some(threshold_conf) = &config_type.threshold {
                    // Report listen address for validation
                    println!(
                        "  [OK] Listen address: {}:{}",
                        config_type.service.listen_address, config_type.service.listen_port
                    );

                    // Validate threshold setting - consistent with server-side health logic
                    // threshold = max number of malicious/offline nodes tolerated
                    // For Byzantine fault tolerance, need 2/3 majority for healthy status
                    let threshold = threshold_conf.threshold;
                    let total_nodes = threshold_conf.peers.as_ref().map_or(0, |p| p.len()); // peers list includes self

                    // Ensure we have positive node count
                    if total_nodes == 0 {
                        result.overall_health = HealthStatus::Unhealthy;
                        result
                            .recommendations
                            .push("Config error: No nodes defined in peers list".to_string());
                        return Ok(result);
                    }

                    let min_nodes_required = threshold as usize + 1; // Need t+1 nodes for threshold operations
                    let min_nodes_for_healthy = (2 * total_nodes) / 3 + 1; // 2/3 majority for Byzantine fault tolerance

                    if total_nodes < min_nodes_required {
                        result.overall_health = HealthStatus::Unhealthy;
                        result.recommendations.push(format!(
                            "Config error: {} nodes defined but threshold={} requires at least {} nodes (t+1)",
                            total_nodes, threshold, min_nodes_required
                        ));
                    } else {
                        println!("  [OK] Threshold: {} - Node requirements:", threshold);
                        println!(
                            "      - {} of {} nodes minimum for threshold operations (t+1)",
                            min_nodes_required, total_nodes
                        );
                        println!(
                            "      - {} of {} nodes for healthy status (2/3 majority)",
                            min_nodes_for_healthy, total_nodes
                        );
                        println!(
                            "      - {} of {} nodes for optimal status (all nodes online)",
                            total_nodes, total_nodes
                        );
                        println!("      (!!!)  Operational recommendation: All {} nodes should be online for best performance", total_nodes);
                    }

                    // Validate peer addresses
                    if let Some(peers) = &threshold_conf.peers {
                        println!("  [OK] {} peers configured:", peers.len());
                        for peer in peers {
                            println!(
                                "      - Peer {} at {}:{}",
                                peer.party_id, peer.address, peer.port
                            );
                        }

                        result.recommendations.push(format!(
                            "Config defines {} peers for threshold KMS at {}:{}",
                            peers.len(),
                            threshold_conf.listen_address,
                            threshold_conf.listen_port
                        ));
                    } else {
                        println!("  [WARN] No peers configured in peers list");
                        result.recommendations.push(format!(
                            "Config defines 0 peers for threshold KMS at {}:{}",
                            threshold_conf.listen_address, threshold_conf.listen_port
                        ));
                    }

                    result.recommendations.push(format!(
                        "OPERATIONAL: Monitor that all {} nodes remain online. While {} nodes provide healthy status, having all nodes online ensures optimal performance and fault tolerance",
                        total_nodes, min_nodes_for_healthy
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
async fn process_health_status(
    health_status: &kms_grpc::kms::v1::HealthStatusResponse,
    result: &mut HealthCheckResult,
) {
    // Set key material from health status response
    let total_keys = health_status.my_fhe_key_ids.len() + health_status.my_crs_ids.len();

    // Use detailed key IDs from health status response
    let key_material = KeyMaterialCheck {
        available: true,
        fhe_key_ids: health_status.my_fhe_key_ids.clone(),
        crs_ids: health_status.my_crs_ids.clone(),
        preprocessing_key_ids: health_status.my_preprocessing_key_ids.clone(),
        storage_backend: health_status.my_storage_info.clone(),
        error: None,
    };

    result.key_material = Some(key_material);

    if total_keys == 0 {
        result.overall_health = HealthStatus::Degraded;
        result
            .recommendations
            .push("No keys found - run key generation".to_string());
    }

    // Set node info from health response
    let node_type_str = match health_status.node_type {
        1 => "centralized",
        2 => "threshold",
        _ => "unknown",
    };
    result.node_info = Some(NodeInfo {
        node_type: node_type_str.to_string(),
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
                fhe_key_ids: peer.fhe_key_ids.clone(),
                crs_ids: peer.crs_ids.clone(),
                preprocessing_key_ids: peer.preprocessing_key_ids.clone(),
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
        if health_status.node_type == 2 && health_status.threshold_required > 0 {
            // NODE_TYPE_THRESHOLD - match the four-tier system from endpoint.rs
            let total_nodes = health_status.peers.len() as u32 + 1; // peers + self (response excludes self)

            let min_nodes_for_healthy = (2 * total_nodes) / 3 + 1; // 2/3 majority + 1

            if health_status.nodes_reachable >= total_nodes {
                // All nodes online - optimal status
                result.recommendations.push(format!(
                    "Optimal: All {} nodes online and reachable",
                    total_nodes
                ));
            } else if health_status.nodes_reachable >= min_nodes_for_healthy {
                // Sufficient 2/3 majority but not all nodes - healthy but should investigate
                result.overall_health = HealthStatus::Degraded;
                result.recommendations.push(format!(
                    "Healthy but not optimal: {}/{} nodes reachable (sufficient majority but {} nodes offline)",
                    health_status.nodes_reachable, total_nodes, total_nodes - health_status.nodes_reachable
                ));
                result.recommendations.push(format!(
                    "(!!!)  INVESTIGATE: Even with healthy status, explore why {} nodes are offline. Check peer connectivity, network issues, or node failures to restore optimal fault tolerance.",
                    total_nodes - health_status.nodes_reachable
                ));
            } else if health_status.nodes_reachable > health_status.threshold_required {
                // Above minimum threshold but below 2/3 - degraded
                result.overall_health = HealthStatus::Degraded;
                result.recommendations.push(format!(
                    "Degraded: {}/{} nodes reachable (above threshold {} but below healthy majority {})",
                    health_status.nodes_reachable, total_nodes, health_status.threshold_required, min_nodes_for_healthy
                ));
            } else {
                // Below threshold - unhealthy
                result.overall_health = HealthStatus::Unhealthy;
                result.recommendations.push(format!(
                    "Critical: Only {} nodes reachable, but {} required for threshold operations",
                    health_status.nodes_reachable, health_status.threshold_required
                ));
            }
        }
    }

    // Set overall health based on server's assessment using direct 4-tier mapping
    // Only override if server status is worse than what we determined locally
    let server_status = match health_status.status {
        1 => HealthStatus::Optimal,   // HEALTH_STATUS_OPTIMAL
        2 => HealthStatus::Healthy,   // HEALTH_STATUS_HEALTHY
        3 => HealthStatus::Degraded,  // HEALTH_STATUS_DEGRADED
        4 => HealthStatus::Unhealthy, // HEALTH_STATUS_UNHEALTHY
        _ => return,                  // Keep current status for unspecified values
    };

    // Use the worse of local assessment vs server assessment
    if is_worse_status(&server_status, &result.overall_health) {
        result.overall_health = server_status;
    }
}

// Helper function to determine if one status is worse than another
fn is_worse_status(status1: &HealthStatus, status2: &HealthStatus) -> bool {
    let status1_rank = match status1 {
        HealthStatus::Optimal => 0,
        HealthStatus::Healthy => 1,
        HealthStatus::Degraded => 2,
        HealthStatus::Unhealthy => 3,
    };

    let status2_rank = match status2 {
        HealthStatus::Optimal => 0,
        HealthStatus::Healthy => 1,
        HealthStatus::Degraded => 2,
        HealthStatus::Unhealthy => 3,
    };

    status1_rank > status2_rank
}

// Helper function to check key material (fallback when health status not available)
async fn check_key_material_fallback(client: &GrpcHealthClient, result: &mut HealthCheckResult) {
    match client.get_key_material_availability().await {
        Ok(material) => {
            let total_keys = material.fhe_key_ids.len() + material.crs_ids.len();
            result.key_material = Some(KeyMaterialCheck {
                available: true,
                fhe_key_ids: material.fhe_key_ids.clone(),
                crs_ids: material.crs_ids.clone(),
                preprocessing_key_ids: material.preprocessing_ids.clone(),
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
                available: false,
                fhe_key_ids: Vec::new(),
                crs_ids: Vec::new(),
                preprocessing_key_ids: Vec::new(),
                storage_backend: String::new(),
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
pub async fn check_live(endpoint: &str, _config_path: Option<&Path>) -> Result<HealthCheckResult> {
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
            process_health_status(&health_status, &mut result).await;
        }
        Err(_) => {
            // Fall back to basic key material check if health status RPC not available
            check_key_material_fallback(&client, &mut result).await;
        }
    }

    // Check operator public key
    check_operator_key(&client, &mut result).await;

    if result.recommendations.is_empty() && result.overall_health == HealthStatus::Optimal {
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
) -> Result<HealthCheckResult> {
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
