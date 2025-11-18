//! CLI Integration Tests - Native Execution (Docker-free)
//!
//! Verifies kms-core-client CLI tool functionality using isolated native KMS servers.
//!
//! **Default (9 tests, parallel)**:
//! - Centralized: keygen, decryption, CRS, backup/restore, custodian backup
//! - Threshold: CRS (concurrent/sequential), backup/restore, custodian backup
//!
//! **PRSS Tests (4 tests, K8s CI only, sequential)**:
//! - Threshold: keygen, preprocessing (sequential/concurrent/full)
//! - Disabled locally due to PRSS networking requirements
//! - Enable: `cargo test --features k8s_tests -- --test-threads=1`
//!
//! ## Architecture
//! - Each test uses isolated temporary directory with pre-generated material
//! - Native KMS servers (no Docker Compose)
//! - Tests run in parallel (except PRSS which requires sequential execution)
//! - CLI commands unchanged (testing actual CLI functionality)

use kms_core_client::*;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::KeyId;
use kms_lib::client::test_tools::{setup_centralized_isolated, setup_threshold_isolated, ServerHandle};
use kms_lib::consts::{ID_LENGTH, TEST_CENTRAL_KEY_ID, OTHER_CENTRAL_TEST_ID, TEST_PARAM};
use kms_lib::util::key_setup::ensure_central_keys_exist;
use kms_lib::util::key_setup::test_material_manager::TestMaterialManager;
use kms_lib::util::key_setup::test_material_spec::TestMaterialSpec;
use kms_lib::vault::storage::{file::FileStorage, Storage, StorageType};
use anyhow::Result;
use futures::future::join_all;
use serial_test::serial;
use std::collections::HashMap;
use std::fs::write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::String;
use tempfile::TempDir;

// Additional imports for custodian and threshold tests
use kms_grpc::RequestId;
use kms_lib::backup::SEED_PHRASE_DESC;
use kms_lib::conf::{Keychain, SecretSharingKeychain};
use kms_lib::consts::SIGNING_KEY_ID;
use kms_lib::util::key_setup::test_material_spec::KeyType;
use kms_lib::vault::keychain::make_keychain_proxy;
use kms_lib::vault::storage::make_storage;
use kms_lib::vault::Vault;
use std::fs::create_dir_all;
use std::process::{Command, Output};
use threshold_fhe::execution::runtime::party::Role;

// ============================================================================
// SETUP HELPERS
// ============================================================================

/// Create test material manager with workspace test-material path
fn create_test_material_manager() -> TestMaterialManager {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    TestMaterialManager::new(Some(workspace_root.join("test-material")))
}

/// Create file storage proxy for given path and type
fn create_file_storage(
    path: &Path,
    storage_type: StorageType,
    role: Option<Role>,
) -> Result<kms_lib::vault::storage::StorageProxy> {
    make_storage(
        Some(kms_lib::conf::Storage::File(kms_lib::conf::FileStorage {
            path: path.to_path_buf(),
        })),
        storage_type,
        role,
        None,
        None,
    )
}

/// Helper to setup isolated centralized KMS for CLI testing (without backup vault)
async fn setup_isolated_centralized_cli_test(test_name: &str) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, false, false).await
}

/// Helper to setup isolated centralized KMS for CLI testing with backup vault
async fn setup_isolated_centralized_cli_test_with_backup(test_name: &str) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, true, false).await
}

/// Helper to setup isolated centralized KMS for CLI testing with custodian backup vault
async fn setup_isolated_centralized_cli_test_with_custodian_backup(test_name: &str) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, true, true).await
}

/// Internal implementation for centralized CLI test setup
async fn setup_isolated_centralized_cli_test_impl(
    test_name: &str,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    let manager = create_test_material_manager();
    let mut spec = TestMaterialSpec::centralized_basic();
    spec.required_keys.insert(KeyType::ServerSigningKeys);
    let material_dir = manager.setup_test_material(&spec, test_name).await?;
    
    let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;
    
    // Regenerate central keys with correct RequestIds
    let _ = pub_storage.delete_data(&TEST_CENTRAL_KEY_ID, &PubDataType::PublicKey.to_string()).await;
    let _ = pub_storage.delete_data(&OTHER_CENTRAL_TEST_ID, &PubDataType::PublicKey.to_string()).await;
    ensure_central_keys_exist(
        &mut pub_storage,
        &mut priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        true,
        true,
    ).await;
    
    let backup_vault = if with_backup_vault {
        let backup_proxy = create_file_storage(material_dir.path(), StorageType::BACKUP, None)?;
        let keychain = if with_custodian_keychain {
            let pub_proxy = create_file_storage(material_dir.path(), StorageType::PUB, None)?;
            Some(make_keychain_proxy(
                &Keychain::SecretSharing(SecretSharingKeychain {}),
                None,
                None,
                Some(&pub_proxy),
            ).await?)
        } else {
            None
        };
        Some(Vault { storage: backup_proxy, keychain })
    } else {
        None
    };
    
    let (server, _client) = setup_centralized_isolated(
        pub_storage,
        priv_storage,
        backup_vault,
        None,
        None, // Don't pass material_dir since we already set it up above
    ).await;
    
    // Generate CLI config file pointing to local test material
    let config_path = material_dir.path().join("client_config.toml");
    let config_content = format!(
        r#"
kms_type = "centralized"
num_majority = 1
num_reconstruct = 1
fhe_params = "Test"

[storage]
pub_storage_type = "file"
priv_storage_type = "file"
client_storage_type = "file"
file_storage_path = "{}"

[[cores]]
party_id = 1
address = "localhost:{}"
s3_endpoint = "file://{}"
object_folder = "PUB"
"#,
        material_dir.path().display(),
        server.service_port,
        material_dir.path().display()
    );
    write(&config_path, config_content)?;
    
    Ok((material_dir, server, config_path))
}

/// Helper to setup isolated threshold KMS for CLI testing (without PRSS / backup vault)
async fn setup_isolated_threshold_cli_test(test_name: &str, party_count: usize) -> Result<(TempDir, HashMap<u32, ServerHandle>, PathBuf)> {
    setup_isolated_threshold_cli_test_impl(test_name, party_count, false, false, false).await
}

/// Helper to setup isolated threshold KMS for CLI testing with PRSS enabled
#[cfg(feature = "k8s_tests")]
async fn setup_isolated_threshold_cli_test_with_prss(test_name: &str, party_count: usize) -> Result<(TempDir, HashMap<u32, ServerHandle>, PathBuf)> {
    setup_isolated_threshold_cli_test_impl(test_name, party_count, true, false, false).await
}

/// Helper to setup isolated threshold KMS for CLI testing with backup vault
async fn setup_isolated_threshold_cli_test_with_backup(test_name: &str, party_count: usize) -> Result<(TempDir, HashMap<u32, ServerHandle>, PathBuf)> {
    setup_isolated_threshold_cli_test_impl(test_name, party_count, false, true, false).await
}

/// Helper to setup isolated threshold KMS for CLI testing with custodian backup vault
async fn setup_isolated_threshold_cli_test_with_custodian_backup(test_name: &str, party_count: usize) -> Result<(TempDir, HashMap<u32, ServerHandle>, PathBuf)> {
    setup_isolated_threshold_cli_test_impl(test_name, party_count, false, true, true).await
}

/// Internal implementation for threshold CLI test setup
async fn setup_isolated_threshold_cli_test_impl(
    test_name: &str,
    party_count: usize,
    run_prss: bool,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
) -> Result<(TempDir, HashMap<u32, ServerHandle>, PathBuf)> {
    let manager = create_test_material_manager();
    let mut spec = TestMaterialSpec::threshold_basic(party_count);
    spec.required_keys.insert(KeyType::ServerSigningKeys);
    let material_dir = manager.setup_test_material(&spec, test_name).await?;
    
    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    for i in 1..=party_count {
        let role = Role::indexed_from_one(i);
        pub_storages.push(FileStorage::new(Some(material_dir.path()), StorageType::PUB, Some(role))?);
        priv_storages.push(FileStorage::new(Some(material_dir.path()), StorageType::PRIV, Some(role))?);
    }
    
    let mut vaults: Vec<Option<Vault>> = Vec::new();
    for i in 1..=party_count {
        if with_backup_vault {
            let role = Role::indexed_from_one(i);
            let backup_proxy = create_file_storage(material_dir.path(), StorageType::BACKUP, Some(role))?;
            let keychain = if with_custodian_keychain {
                let pub_proxy = create_file_storage(material_dir.path(), StorageType::PUB, Some(role))?;
                Some(make_keychain_proxy(
                    &Keychain::SecretSharing(SecretSharingKeychain {}),
                    None,
                    None,
                    Some(&pub_proxy),
                ).await?)
            } else {
                None
            };
            vaults.push(Some(Vault { storage: backup_proxy, keychain }));
        } else {
            vaults.push(None);
        }
    }
    let (servers, _clients) = setup_threshold_isolated(
        (party_count / 2 + 1) as u8, // threshold
        pub_storages,
        priv_storages,
        vaults,
        run_prss, // PRSS enabled/disabled based on test requirements
        None, // rate_limiter
        None, // decryption_mode
        None, // Don't pass material_dir since we already set it up above
    ).await;
    
    // Wait for PRSS initialization if enabled
    if run_prss {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
    
    // Generate CLI config file pointing to local test material
    let config_path = material_dir.path().join("client_config.toml");
    let mut config_content = format!(
        r#"
kms_type = "threshold"
num_majority = {}
num_reconstruct = {}
fhe_params = "Test"

[storage]
pub_storage_type = "file"
priv_storage_type = "file"
client_storage_type = "file"
file_storage_path = "{}"
"#,
        (party_count / 2 + 1),
        (party_count / 2 + 1),
        material_dir.path().display()
    );
    
    // Add all server addresses
    for i in 1..=party_count {
        let server = servers.get(&(i as u32)).unwrap_or_else(|| panic!("Server {} should exist", i));
        config_content.push_str(&format!(
            r#"
[[cores]]
party_id = {}
address = "localhost:{}"
s3_endpoint = "file://{}"
object_folder = "PUB-p{}"
"#,
            i,
            server.service_port,
            material_dir.path().display(),
            i
        ));
    }
    
    write(&config_path, config_content)?;
    
    Ok((material_dir, servers, config_path))
}

// ============================================================================
// TEST UTILITIES
// ============================================================================

fn init_testing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();
}

/// Helper to run insecure key generation via CLI (isolated version)
async fn insecure_key_gen_isolated(config_path: &Path, test_path: &Path) -> Result<String> {
    let config = CmdConfig {
        file_conf: Some(config_path.to_str().unwrap().to_string()),
        command: CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing insecure key-gen");
    let key_gen_results = execute_cmd(&config, test_path).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Insecure key-gen done");

    assert_eq!(key_gen_results.len(), 1);
    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing insecure keygen"),
    };

    Ok(key_id.to_string())
}

// ============================================================================
// CLI COMMAND HELPERS
// ============================================================================

/// Helper to run CRS generation via CLI (isolated version)
async fn crs_gen_isolated(config_path: &Path, test_path: &Path, insecure_crs_gen: bool) -> Result<String> {
    let command = if insecure_crs_gen {
        CCCommand::InsecureCrsGen(CrsParameters {
            max_num_bits: 16, // Default test value
        })
    } else {
        CCCommand::CrsGen(CrsParameters {
            max_num_bits: 16, // Default test value
        })
    };

    let config = CmdConfig {
        file_conf: Some(config_path.to_str().unwrap().to_string()),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing CRS generation");
    let crs_gen_results = execute_cmd(&config, test_path).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("CRS generation done");

    assert_eq!(crs_gen_results.len(), 1);
    let crs_id = match crs_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing CRS generation"),
    };

    Ok(crs_id.to_string())
}

/// Helper to run integration test commands via CLI (isolated version)
async fn integration_test_commands_isolated(config_path: &Path, keys_folder: &Path, key_id: String) -> Result<()> {
    let key_id = KeyId::from_str(&key_id)?;
    
    let commands = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
    ];

    for command in commands {
        let config = CmdConfig {
            file_conf: Some(config_path.to_str().unwrap().to_string()),
            command,
            logs: true,
            max_iter: 200,
            expect_all_responses: true,
            download_all: false,
        };
        execute_cmd(&config, keys_folder).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    Ok(())
}

/// Helper to run backup restore via CLI (isolated version)
async fn restore_from_backup_isolated(config_path: &Path, test_path: &Path) -> Result<String> {
    let config = CmdConfig {
        file_conf: Some(config_path.to_str().unwrap().to_string()),
        command: CCCommand::BackupRestore(NoParameters {}),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing restore from backup");
    let restore_results = execute_cmd(&config, test_path).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Restore from backup done");
    
    assert_eq!(restore_results.len(), 1);
    // No backup ID is returned since restore_from_backup can also be used without custodians
    assert_eq!(restore_results.first().unwrap().0, None);
    
    Ok("".to_string())
}

/// Helper to run preprocessing and keygen via CLI (isolated version)
/// Only used by PRSS tests which are gated by k8s_tests feature
async fn real_preproc_and_keygen_isolated(config_path: &Path, test_path: &Path) -> Result<String> {
    // Step 1: Preprocessing
    let preproc_config = CmdConfig {
        file_conf: Some(config_path.to_str().unwrap().to_string()),
        command: CCCommand::PreprocKeyGen(NoParameters {}),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };
    
    println!("Doing preprocessing");
    let mut preproc_result = execute_cmd(&preproc_config, test_path).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    assert_eq!(preproc_result.len(), 1);
    let (preproc_id, _) = preproc_result.pop().unwrap();
    println!("Preprocessing done with ID {preproc_id:?}");

    // Step 2: Key generation using preprocessing result
    let keygen_config = CmdConfig {
        file_conf: Some(config_path.to_str().unwrap().to_string()),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id: preproc_id.unwrap(),
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };
    
    println!("Doing key-gen");
    let key_gen_results = execute_cmd(&keygen_config, test_path).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    Ok(key_id.to_string())
}

// ============================================================================
// CUSTODIAN HELPER FUNCTIONS
// ============================================================================

/// Native implementation: Create new custodian context using isolated config
async fn new_custodian_context_isolated(
    config_path: &Path,
    test_path: &Path,
    custodian_threshold: u32,
    setup_msg_paths: Vec<PathBuf>,
) -> String {
    let command = CCCommand::NewCustodianContext(NewCustodianContextParameters {
        threshold: custodian_threshold,
        setup_msg_paths,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing new custodian context");
    let backup_init_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("New custodian context done");
    assert_eq!(backup_init_results.len(), 1);
    let res_id = match backup_init_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing new custodian context"),
    };

    res_id.to_string()
}

/// Native implementation: Generate custodian keys using kms-custodian binary directly
async fn generate_custodian_keys_to_file(
    temp_dir: &Path,
    amount_custodians: usize,
    _threshold: bool, // Not needed for native implementation
) -> (Vec<String>, Vec<PathBuf>) {
    let mut seeds = Vec::new();
    let mut setup_msgs_paths = Vec::new();
    
    // Find the kms-custodian binary
    let custodian_bin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("kms-custodian");
    
    assert!(
        custodian_bin.exists(),
        "kms-custodian binary not found at {:?}. Run: cargo build --bin kms-custodian",
        custodian_bin
    );
    
    for cus_idx in 1..=amount_custodians {
        let cur_setup_path = temp_dir
            .join("CUSTODIAN")
            .join("setup-msg")
            .join(format!("setup-{}", cus_idx));
        
        // Ensure the dir exists
        create_dir_all(cur_setup_path.parent().unwrap()).unwrap();
        
        // Call kms-custodian binary directly (no Docker)
        let args = [
            "generate",
            "--randomness",
            "123456",
            "--custodian-role",
            &cus_idx.to_string(),
            "--custodian-name",
            &format!("skynet-{cus_idx}"),
            "--path",
            cur_setup_path.to_str().unwrap(),
        ];
        
        let cmd_output = Command::new(&custodian_bin)
            .args(args)
            .output()
            .unwrap();
        
        assert!(
            cmd_output.status.success(),
            "kms-custodian generate failed: {}",
            String::from_utf8_lossy(&cmd_output.stderr)
        );
        
        let seed_phrase = extract_seed_phrase(cmd_output);
        seeds.push(seed_phrase);
        setup_msgs_paths.push(cur_setup_path);
    }
    
    (seeds, setup_msgs_paths)
}

fn extract_seed_phrase(out: Output) -> String {
    let errors = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "Command did not execute successfully: {} : {}",
        out.status,
        errors
    );
    assert!(errors.is_empty());
    let output_string = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let seed_phrase_line = output_string
        .lines()
        .find(|line| line.contains(SEED_PHRASE_DESC));
    seed_phrase_line
        .unwrap()
        .split_at(SEED_PHRASE_DESC.len())
        .1
        .trim()
        .to_string()
}

/// Native implementation: Initialize custodian backup using isolated config
async fn custodian_backup_init_isolated(
    config_path: &Path,
    test_path: &Path,
    operator_recovery_resp_paths: Vec<PathBuf>,
) -> String {
    let init_command = CCCommand::CustodianRecoveryInit(RecoveryInitParameters {
        operator_recovery_resp_paths,
        overwrite_ephemeral_key: false,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command: init_command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing backup init");
    let backup_init_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("Backup init done");
    assert_eq!(backup_init_results.len(), 1);
    let res_id = match backup_init_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup init"),
    };

    res_id.to_string()
}

/// Native implementation: Re-encrypt custodian backups using kms-custodian binary directly
async fn custodian_reencrypt(
    temp_dir: &Path,
    amount_operators: usize,
    amount_custodians: usize,
    backup_id: RequestId,
    seeds: &[String],
    recovery_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut response_paths = Vec::new();
    
    // Find the kms-custodian binary
    let custodian_bin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("kms-custodian");
    
    assert!(
        custodian_bin.exists(),
        "kms-custodian binary not found at {:?}",
        custodian_bin
    );
    
    for operator_index in 1..=amount_operators {
        let pub_prefix = if amount_operators == 1 {
            "PUB".to_string()
        } else {
            format!("PUB-p{}", operator_index)
        };
        
        let cur_recovery_path = &recovery_paths[operator_index - 1];

        for custodian_index in 1..=amount_custodians {
            let cur_response_path = temp_dir
                .join("CUSTODIAN")
                .join("response")
                .join(backup_id.to_string())
                .join(format!(
                    "recovery-response-{}-{}",
                    operator_index, custodian_index,
                ));
            
            create_dir_all(cur_response_path.parent().unwrap()).unwrap();
            
            let verf_path = temp_dir
                .join(&pub_prefix)
                .join(PubDataType::VerfKey.to_string())
                .join(SIGNING_KEY_ID.to_string());
            
            // Call kms-custodian binary directly (no Docker)
            let args = [
                "decrypt",
                "--seed-phrase",
                &seeds[custodian_index - 1],
                "--custodian-role",
                &custodian_index.to_string(),
                "--operator-verf-key",
                verf_path.to_str().unwrap(),
                "-b",
                cur_recovery_path.to_str().unwrap(),
                "-o",
                cur_response_path.to_str().unwrap(),
            ];
            
            let cmd_output = Command::new(&custodian_bin)
                .args(args)
                .output()
                .unwrap();
            
            assert!(
                cmd_output.status.success(),
                "kms-custodian decrypt failed: {}",
                String::from_utf8_lossy(&cmd_output.stderr)
            );
            
            response_paths.push(cur_response_path);
        }
    }
    response_paths
}

/// Native implementation: Recover custodian backup using isolated config
async fn custodian_backup_recovery_isolated(
    config_path: &Path,
    test_path: &Path,
    custodian_recovery_outputs: Vec<PathBuf>,
    backup_id: RequestId,
) -> String {
    let command = CCCommand::CustodianBackupRecovery(RecoveryParameters {
        custodian_context_id: backup_id,
        custodian_recovery_outputs,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing backup recovery");
    let backup_recovery_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("Backup init recovery");
    assert_eq!(backup_recovery_results.len(), 1);
    let res_id = match backup_recovery_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup recovery"),
    };

    res_id.to_string()
}

// ============================================================================
// TESTS
/// 
/// - Uses native isolated KMS server instead of Docker container
/// - CLI commands remain unchanged (testing CLI functionality)
/// - Can now run in parallel with other tests
// ============================================================================

/// Test centralized insecure key generation via CLI
#[tokio::test]
async fn test_centralized_insecure() -> Result<()> {
    init_testing();
    
    // Setup isolated centralized KMS server
    let (material_dir, _server, config_path) = setup_isolated_centralized_cli_test("centralized_insecure").await?;
    
    // Run CLI commands against native server (use material_dir as keys_folder so CLI can access server keys)
    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen_isolated(&config_path, keys_folder).await?;
    integration_test_commands_isolated(&config_path, keys_folder, key_id).await?;
    
    Ok(())
}

/// Test centralized CRS generation via CLI
#[tokio::test]
async fn test_centralized_crsgen_secure() -> Result<()> {
    init_testing();
    
    // Setup isolated centralized KMS server
    let (material_dir, _server, config_path) = setup_isolated_centralized_cli_test("centralized_crsgen").await?;
    
    // Run CRS generation via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let crs_id = crs_gen_isolated(&config_path, keys_folder, false).await?;
    
    // Verify CRS ID format (hex string with double the length of ID_LENGTH)
    assert_eq!(crs_id.len(), ID_LENGTH * 2);
    
    Ok(())
}

/// Test centralized restore from backup via CLI (without custodians)
/// 
/// Note: This test mainly validates the CLI endpoints and content returned from KMS.
/// Full restore validation is done in service/client tests.
#[tokio::test]
async fn test_centralized_restore_from_backup() -> Result<()> {
    init_testing();
    
    // Setup isolated centralized KMS server with backup vault
    let (material_dir, _server, config_path) = setup_isolated_centralized_cli_test_with_backup("centralized_restore").await?;
    
    // Run insecure CRS generation and backup restore via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let _crs_id = crs_gen_isolated(&config_path, keys_folder, true).await?;
    let _ = restore_from_backup_isolated(&config_path, keys_folder).await?;
    
    Ok(())
}

/// Test centralized custodian backup via CLI
#[tokio::test]
async fn test_centralized_custodian_backup() -> Result<()> {
    init_testing();
    
    let amount_custodians = 5;
    let custodian_threshold = 2;
    
    // Setup isolated centralized KMS server with custodian backup vault (includes SecretSharingKeychain)
    let (material_dir, _server, config_path) = 
        setup_isolated_centralized_cli_test_with_custodian_backup("centralized_custodian").await?;
    
    let temp_path = material_dir.path();
    
    // Generate custodian keys using native kms-custodian binary
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians, false).await;
    
    // Create custodian context
    let cus_backup_id =
        new_custodian_context_isolated(&config_path, temp_path, custodian_threshold, setup_msg_paths).await;
    
    let operator_recovery_resp_path = temp_path
        .join("CUSTODIAN")
        .join("recovery")
        .join(&cus_backup_id)
        .join("central");
    
    // Ensure the dir exists
    create_dir_all(operator_recovery_resp_path.parent().unwrap())?;
    
    // Initialize custodian backup
    let init_backup_id =
        custodian_backup_init_isolated(&config_path, temp_path, vec![operator_recovery_resp_path.clone()]).await;
    assert_eq!(cus_backup_id, init_backup_id);
    
    // Re-encrypt with custodian keys
    let recovery_output_paths = custodian_reencrypt(
        temp_path,
        1,
        amount_custodians,
        init_backup_id.parse()?,
        &seeds,
        &[operator_recovery_resp_path],
    )
    .await;
    
    // Recover backup using custodian outputs
    let recovery_backup_id = custodian_backup_recovery_isolated(
        &config_path,
        temp_path,
        recovery_output_paths,
        RequestId::from_str(&cus_backup_id)?,
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);
    
    // Restore from backup
    let _ = restore_from_backup_isolated(&config_path, temp_path).await?;
    
    // Note: This test validates the CLI endpoints and content returned from KMS.
    // Full restore validation is done in service/client tests.
    
    Ok(())
}

/// Test threshold insecure key generation via CLI
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "k8s_tests"), ignore)] // Run only in K8s CI - enable locally with: cargo test --features k8s_tests -- --test-threads=1
async fn test_threshold_insecure() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (3 parties) with PRSS enabled
    #[cfg(feature = "k8s_tests")]
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test_with_prss("threshold_insecure", 3).await?;
    
    #[cfg(not(feature = "k8s_tests"))]
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("threshold_insecure", 3).await?;
    
    // Run CLI commands against native threshold servers (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen_isolated(&config_path, keys_folder).await?;
    integration_test_commands_isolated(&config_path, keys_folder, key_id).await?;
    
    Ok(())
}

/// Test threshold sequential preprocessing and keygen via CLI
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "k8s_tests"), ignore)] // Run only in K8s CI - enable locally with: cargo test --features k8s_tests -- --test-threads=1
async fn nightly_tests_threshold_sequential_preproc_keygen() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (4 parties for test context)
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("threshold_seq_preproc", 4).await?;
    
    // Run sequential preprocessing and keygen operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let key_id_1 = real_preproc_and_keygen_isolated(&config_path, keys_folder).await?;
    let key_id_2 = real_preproc_and_keygen_isolated(&config_path, keys_folder).await?;
    
    // Verify different key IDs generated
    assert_ne!(key_id_1, key_id_2);
    
    Ok(())
}

/// Test threshold concurrent preprocessing and keygen via CLI
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "k8s_tests"), ignore)] // Run only in K8s CI - enable locally with: cargo test --features k8s_tests -- --test-threads=1
async fn test_threshold_concurrent_preproc_keygen() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (4 parties for test context)
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("threshold_conc_preproc", 4).await?;
    
    // Run concurrent preprocessing and keygen operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let _ = join_all([
        real_preproc_and_keygen_isolated(&config_path, keys_folder),
        real_preproc_and_keygen_isolated(&config_path, keys_folder),
    ])
    .await;
    
    Ok(())
}

/// Test threshold sequential CRS generation via CLI
#[tokio::test]
async fn nightly_tests_threshold_sequential_crs() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (3 parties)
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("threshold_seq_crs", 3).await?;
    
    // Run sequential CRS generation operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let crs_id_1 = crs_gen_isolated(&config_path, keys_folder, false).await?;
    let crs_id_2 = crs_gen_isolated(&config_path, keys_folder, false).await?;
    
    // Verify different CRS IDs generated
    assert_ne!(crs_id_1, crs_id_2);
    
    Ok(())
}

/// Test threshold concurrent CRS generation via CLI
#[tokio::test]
async fn test_threshold_concurrent_crs() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (3 parties)
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("threshold_concurrent_crs", 3).await?;
    
    // Run concurrent CRS generation via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let res = join_all([
        crs_gen_isolated(&config_path, keys_folder, false),
        crs_gen_isolated(&config_path, keys_folder, false),
    ])
    .await;
    
    // Verify different CRS IDs generated
    assert_ne!(res[0].as_ref().unwrap(), res[1].as_ref().unwrap());
    
    Ok(())
}

/// Test threshold restore from backup via CLI (without custodians)
/// 
/// Note: This test mainly validates the CLI endpoints and content returned from KMS.
/// Full restore validation is done in service/client tests.
#[tokio::test]
async fn test_threshold_restore_from_backup() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (3 parties) with backup vaults
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_backup("threshold_restore", 3).await?;
    
    // Run insecure CRS generation and backup restore via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let _crs_id = crs_gen_isolated(&config_path, keys_folder, true).await?;
    let _ = restore_from_backup_isolated(&config_path, keys_folder).await?;
    
    Ok(())
}

/// Test threshold custodian backup via CLI
#[tokio::test]
async fn test_threshold_custodian_backup() -> Result<()> {
    init_testing();
    
    let amount_custodians = 5;
    let custodian_threshold = 2;
    let amount_operators = 4;
    
    // Setup isolated threshold KMS servers with custodian backup vaults (includes SecretSharingKeychain)
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_custodian_backup("threshold_custodian", amount_operators).await?;
    
    let temp_path = material_dir.path();
    
    // Generate custodian keys using native kms-custodian binary
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians, true).await;
    
    // Create custodian context
    let cus_backup_id =
        new_custodian_context_isolated(&config_path, temp_path, custodian_threshold, setup_msg_paths).await;
    // Paths to where the results of the backup init will be stored
    let mut operator_recovery_resp_paths = Vec::new();
    for cur_op_idx in 1..=amount_operators {
        let cur_resp_path = temp_path
            .join("CUSTODIAN")
            .join("recovery")
            .join(&cus_backup_id)
            .join(cur_op_idx.to_string());
        // Ensure the dir exists locally
        assert!(create_dir_all(cur_resp_path.parent().unwrap()).is_ok());
        operator_recovery_resp_paths.push(cur_resp_path);
    }
    
    // Initialize custodian backup
    let init_backup_id =
        custodian_backup_init_isolated(&config_path, temp_path, operator_recovery_resp_paths.clone()).await;
    assert_eq!(cus_backup_id, init_backup_id);
    
    // Re-encrypt with custodian keys
    let recovery_output_paths = custodian_reencrypt(
        temp_path,
        amount_operators,
        amount_custodians,
        init_backup_id.parse()?,
        &seeds,
        &operator_recovery_resp_paths,
    )
    .await;
    
    // Recover backup using custodian outputs
    let recovery_backup_id = custodian_backup_recovery_isolated(
        &config_path,
        temp_path,
        recovery_output_paths,
        RequestId::from_str(&cus_backup_id)?,
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);
    
    // Restore from backup
    let _ = restore_from_backup_isolated(&config_path, temp_path).await?;
    
    // Note: This test validates the CLI endpoints and content returned from KMS.
    // Full restore validation is done in service/client tests.
    
    Ok(())
}

/// Full generation test - threshold sequential preprocessing and keygen
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "k8s_tests"), ignore)] // Run only in K8s CI - enable locally with: cargo test --features k8s_tests -- --test-threads=1
async fn full_gen_tests_default_threshold_sequential_preproc_keygen() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (3 parties for default context)
    let (material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("full_gen_preproc", 3).await?;
    
    // Run sequential preprocessing and keygen operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let key_id_1 = real_preproc_and_keygen_isolated(&config_path, keys_folder).await?;
    let key_id_2 = real_preproc_and_keygen_isolated(&config_path, keys_folder).await?;
    
    // Verify different key IDs generated
    assert_ne!(key_id_1, key_id_2);
    
    Ok(())
}

/// Full generation test - threshold sequential CRS generation
#[tokio::test]
async fn full_gen_tests_default_threshold_sequential_crs() -> Result<()> {
    init_testing();
    
    // Setup isolated threshold KMS servers (3 parties for default context)
    let (_material_dir, _servers, config_path) = setup_isolated_threshold_cli_test("full_gen_crs", 3).await?;
    
    // Run sequential CRS generation operations
    let temp_dir = tempfile::tempdir()?;
    let keys_folder = temp_dir.path();
    let crs_id_1 = crs_gen_isolated(&config_path, keys_folder, false).await?;
    let crs_id_2 = crs_gen_isolated(&config_path, keys_folder, false).await?;
    
    // Verify different CRS IDs generated
    assert_ne!(crs_id_1, crs_id_2);
    
    Ok(())
}
