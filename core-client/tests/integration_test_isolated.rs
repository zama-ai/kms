//! CLI Integration Tests - Native Execution (Docker-free)
//!
//! Verifies kms-core-client CLI tool functionality using isolated native KMS servers.
//! Replaces Docker Compose-based tests with faster, more reliable native execution.
//!
//! TODO: Currently this module resembles integration_test.rs which is big and monolithic.
//! TODO: It should be split into smaller modules for better organization after the migration.
//!
//! ## Test Coverage
//!
//! **Default Tests (9 tests, parallel execution)**:
//! - Centralized (4): keygen, CRS, backup/restore, custodian backup
//! - Threshold (5): sequential CRS, concurrent CRS, Default CRS, backup/restore, custodian backup
//!
//! **PRSS Tests (7 tests, K8s CI only, sequential execution)**:
//! - Threshold: keygen, sequential preprocessing, concurrent preprocessing,
//!   Default preprocessing, MPC context init, MPC context switch, reshare
//! - Disabled locally due to PRSS networking requirements
//! - Enable: `cargo test --features k8s_tests,testing -- --test-threads=1`
//!
//! ## Architecture
//!
//! **Test Isolation:**
//! - Each test gets isolated temporary directory with pre-generated cryptographic material
//! - Native KMS servers spawned in-process (no Docker Compose)
//! - Automatic cleanup on test completion (RAII pattern via TempDir)
//! - No shared state between tests (full isolation)
//!
//! **Execution:**
//! - Default tests run in parallel for speed
//! - PRSS tests run sequentially (marked with `#[serial]`) due to network coordination
//! - CLI commands unchanged (testing actual CLI functionality)
//!
//! **Feature Flags:**
//! - `k8s_tests`: Enables PRSS tests (requires stable network environment)
//! - `testing`: Enables test helper functions (required for compilation)
//!
//! ## How Tests Execute
//!
//! Native isolated tests run KMS servers as in-process Rust processes (no Docker):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Test Function Execution                                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  1. Setup Phase                                              │
//! │     setup_isolated_centralized_cli_test("my_test")          │
//! │     ├─ Creates TempDir with isolated material               │
//! │     ├─ Spawns KMS server (native Rust process)              │
//! │     │  └─ Server listens on 127.0.0.1:54321 (dynamic port)  │
//! │     └─ Generates config file pointing to server             │
//! │                                                              │
//! │  2. CLI Command Execution                                    │
//! │     ├─ kms-core-client --config client_config.toml          │
//! │     ├─ Reads config → connects to 127.0.0.1:54321           │
//! │     └─ Sends gRPC request to running server                 │
//! │                                                              │
//! │  3. Server Processing                                        │
//! │     ├─ Receives gRPC request                                │
//! │     ├─ Performs operation (keygen, decrypt, etc.)           │
//! │     └─ Returns gRPC response                                │
//! │                                                              │
//! │  4. Test Validation                                          │
//! │     └─ assert!(output.status.success())                     │
//! │                                                              │
//! │  5. Automatic Cleanup (RAII)                                │
//! │     ├─ _server dropped → server.assert_shutdown()           │
//! │     ├─ Sends shutdown signal → server stops                 │
//! │     ├─ Verifies ports closed                                │
//! │     └─ material_dir dropped → temp directory deleted        │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Key Points:**
//! - **Native Process:** Server runs as Rust process
//! - **Dynamic Ports:** Each test gets unique port (no conflicts)
//! - **RAII Cleanup:** Server and temp dir auto-cleanup via Drop trait
//! - **Real gRPC:** CLI sends actual gRPC requests to running server
//! - **Full Isolation:** Each test completely isolated (own server, material, temp dir)
//!
//! ## Writing New Tests
//!
//! ### Centralized Test Example
//!
//! ```no_run
//! #[tokio::test]
//! async fn test_my_centralized_feature() -> Result<()> {
//!     // Setup: Returns (TempDir, ServerHandle, PathBuf)
//!     let (material_dir, _server, config_path) =
//!         setup_isolated_centralized_cli_test("my_test").await?;
//!     
//!     // Run CLI commands using config_path
//!     let output = Command::new(env!("CARGO_BIN_EXE_kms-core-client"))
//!         .args(["--config", config_path.to_str().unwrap()])
//!         .args(["your-command"])
//!         .output()?;
//!     
//!     assert!(output.status.success());
//!     Ok(())
//! }
//! ```
//!
//! ### Threshold Test Example
//!
//! ```no_run
//! #[tokio::test]
//! async fn test_my_threshold_feature() -> Result<()> {
//!     // Setup: Returns (TempDir, HashMap<u32, ServerHandle>, PathBuf)
//!     let (material_dir, _servers, config_path) =
//!         setup_isolated_threshold_cli_test_default("my_test", 4).await?;
//!     
//!     // CLI automatically communicates with all 4 parties via config
//!     // Run your test commands here
//!     Ok(())
//! }
//! ```
//!
//! **Threshold Test Execution Model:**
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Single Test Thread (tokio runtime)                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  Main Test Task                                                  │
//! │  ├─ setup_threshold_isolated(4 parties)                         │
//! │  │                                                               │
//! │  └─ Spawns 4 async tasks (tokio::spawn):                        │
//! │      ├─ Task 1: Party 1 Server (service port + MPC port)        │
//! │      ├─ Task 2: Party 2 Server (service port + MPC port)        │
//! │      ├─ Task 3: Party 3 Server (service port + MPC port)        │
//! │      └─ Task 4: Party 4 Server (service port + MPC port)        │
//! │                                                                  │
//! │  All tasks run concurrently on tokio thread pool                │
//! │  (NOT separate OS threads - async tasks!)                       │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Key Points:**
//! - Each party runs as a lightweight async task (via `tokio::spawn`)
//! - All tasks share the same tokio runtime (thread pool)
//! - Each party has unique ports: service port (gRPC) + MPC port (party communication)
//! - Real TCP communication between parties over localhost
//! - Efficient: Can run many parties without OS thread overhead
//!
//! ### PRSS Test Example
//!
//! ```no_run
//! #[tokio::test]
//! #[serial]  // Required: Sequential execution for PRSS
//! #[cfg_attr(not(feature = "k8s_tests"), ignore)]  // Required: K8s CI only
//! async fn test_my_prss_feature() -> Result<()> {
//!     // Setup with PRSS enabled
//!     let (material_dir, _servers, config_path) =
//!         setup_isolated_threshold_cli_test_with_prss("my_test", 4).await?;
//!     
//!     // Run PRSS operations (keygen, preprocessing, etc.)
//!     Ok(())
//! }
//! ```
//!
//! ## Setup Function Variants
//!
//! **Centralized:**
//! - `setup_isolated_centralized_cli_test()` - Basic setup
//! - `setup_isolated_centralized_cli_test_with_backup()` - With backup vault
//! - `setup_isolated_centralized_cli_test_with_custodian_backup()` - With custodian keychain
//!
//! **Threshold:**
//! - `setup_isolated_threshold_cli_test()` - Test FHE params (fast)
//! - `setup_isolated_threshold_cli_test_default()` - Default FHE params (production-like)
//! - `setup_isolated_threshold_cli_test_with_prss()` - With PRSS (Test params)
//! - `setup_isolated_threshold_cli_test_with_prss_default()` - With PRSS (Default production-like params)
//! - `setup_isolated_threshold_cli_test_with_backup()` - With backup vault
//! - `setup_isolated_threshold_cli_test_with_custodian_backup()` - With custodian keychain
//!
//! ## Return Values Explained
//!
//! All setup functions return a tuple with:
//! 1. `TempDir` - Isolated temporary directory (auto-cleanup on drop)
//! 2. `ServerHandle` or `HashMap<u32, ServerHandle>` - Running KMS server(s) (auto-shutdown on drop)
//! 3. `PathBuf` - Path to generated CLI config file (use with `--config` flag)
//!
//! ## Running Tests
//!
//! ```bash
//! # All tests (excluding PRSS)
//! cargo test --test integration_test_isolated --features testing
//!
//! # All tests (including PRSS, sequential)
//! cargo test --test integration_test_isolated --features k8s_tests,testing -- --test-threads=1
//!
//! # Specific test
//! cargo test --test integration_test_isolated --features testing test_centralized_insecure
//! ```

use anyhow::Result;
use futures::future::join_all;
use kms_core_client::*;
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::KeyId;
use kms_lib::client::test_tools::ServerHandle;
use kms_lib::consts::{ID_LENGTH, SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
use kms_lib::testing::prelude::*;
use serial_test::serial;
use std::collections::HashMap;
use std::fs::write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::String;
use tempfile::TempDir;

// Additional imports for custodian and threshold tests
use kms_core_client::mpc_context::create_test_context_info_from_core_config;
use kms_grpc::identifiers::EpochId;
use kms_grpc::{ContextId, RequestId};
use kms_lib::backup::SEED_PHRASE_DESC;
use std::fs::create_dir_all;
use std::process::{Command, Output};
use tfhe::safe_serialization::safe_serialize;

// Additional imports for reshare test (only needed with k8s_tests feature)
#[cfg(feature = "k8s_tests")]
use kms_lib::engine::base::{safe_serialize_hash_element_versioned, DSEP_PUBDATA_KEY};
#[cfg(feature = "k8s_tests")]
use kms_lib::util::key_setup::test_tools::{
    load_material_from_pub_storage, load_pk_from_pub_storage,
};

// ============================================================================
// CLI TEST SETUP FUNCTIONS
// ============================================================================

/// Helper to setup isolated centralized KMS for CLI testing (without backup vault)
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "centralized_insecure")
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with test material (auto-cleanup on drop)
/// * `ServerHandle` - Running KMS server (auto-shutdown on drop)
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Example
/// ```no_run
/// let (material_dir, _server, config_path) =
///     setup_isolated_centralized_cli_test("my_test").await?;
/// ```
async fn setup_isolated_centralized_cli_test(
    test_name: &str,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, false, false, FheParameter::Test).await
}

/// Helper to setup isolated centralized KMS for CLI testing with backup vault
async fn setup_isolated_centralized_cli_test_with_backup(
    test_name: &str,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, true, false, FheParameter::Test).await
}

/// Helper to setup isolated centralized KMS for CLI testing with custodian backup vault
async fn setup_isolated_centralized_cli_test_with_custodian_backup(
    test_name: &str,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, true, true, FheParameter::Test).await
}

/// Generate CLI config file for centralized KMS
///
/// Note: We generate configs dynamically (not from template files) because:
/// - Ports are dynamically allocated (random free ports per test)
/// - Paths are dynamic (unique TempDir per test)
/// - This ensures complete test isolation
///
/// See `core-client/config/client_local_centralized.toml` for the reference format.
///
/// TODO: Refactor to use `CoreClientConfig` struct with TOML serialization instead of format strings.
///
/// This would require (preliminary estimation):
/// 1. Adding a `storage` field to `CoreClientConfig` (currently only in deserialization)
/// 2. Implementing `Serialize` for the storage config section
/// 3. Using `toml::to_string()` to generate the config file
///
/// Benefits: Type-safe config generation, compile-time validation, easier maintenance.
fn generate_centralized_cli_config(
    material_dir: &TempDir,
    server: &ServerHandle,
    fhe_params: FheParameter,
) -> Result<PathBuf> {
    let config_path = material_dir.path().join("client_config.toml");
    // Canonicalize the path to resolve symlinks (e.g., /var -> /private/var on macOS)
    // This ensures the CLI client uses the same path as the FileStorage
    let canonical_path = material_dir.path().canonicalize()?;
    let config_content = format!(
        r#"
kms_type = "centralized"
num_majority = 1
num_reconstruct = 1
fhe_params = "{fhe_params:?}"

[storage]
pub_storage_type = "file"
priv_storage_type = "file"
client_storage_type = "file"
file_storage_path = "{path}"

[[cores]]
party_id = 1
address = "localhost:{port}"
s3_endpoint = "file://{path}"
object_folder = "PUB"
"#,
        fhe_params = fhe_params,
        path = canonical_path.display(),
        port = server.service_port,
    );
    write(&config_path, config_content)?;
    Ok(config_path)
}

/// Internal implementation for centralized CLI test setup
async fn setup_isolated_centralized_cli_test_impl(
    test_name: &str,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    fhe_params: FheParameter,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    // Use builder pattern with full feature support
    let mut builder = CentralizedTestEnv::builder().with_test_name(test_name);

    if with_backup_vault {
        builder = builder.with_backup_vault();
    }

    if with_custodian_keychain {
        builder = builder.with_custodian_keychain();
    }

    let env = builder.build().await?;

    // Extract components for CLI usage
    let material_dir = env.material_dir;
    let server = env.server;

    // Generate CLI config file pointing to local test material
    let config_path = generate_centralized_cli_config(&material_dir, &server, fhe_params)?;

    Ok((material_dir, server, config_path))
}

/// Helper to setup isolated threshold KMS for CLI testing (without PRSS / backup vault)
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "threshold_crs")
/// * `party_count` - Number of parties in threshold cluster (typically 4)
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with test material (auto-cleanup on drop)
/// * `HashMap<u32, ServerHandle>` - Map of running KMS servers (party_id -> ServerHandle)
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Example
/// ```no_run
/// let (material_dir, _servers, config_path) =
///     setup_isolated_threshold_cli_test("my_test", 4).await?;
/// ```
#[allow(dead_code)] // Part of test infrastructure API, kept for future use
async fn setup_isolated_threshold_cli_test(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        false,
        false,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing WITHOUT pre-loaded PRSS material.
///
/// These tests create their own MPC context and epoch from scratch.
/// The server will start with an empty epoch map, so `NewEpoch` calls won't conflict
/// with pre-loaded PRSS data.
async fn setup_isolated_threshold_cli_test_signing_only(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl_with_spec(
        test_name,
        party_count,
        false,
        false,
        false,
        FheParameter::Test,
        Some(kms_lib::testing::material::TestMaterialSpec::threshold_signing_only(party_count)),
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with PRSS enabled
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "threshold_prss_keygen")
/// * `party_count` - Number of parties in threshold cluster (typically 4)
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with PRSS material (auto-cleanup on drop)
/// * `HashMap<u32, ServerHandle>` - Map of KMS servers with PRSS initialized
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Note
/// Requires `k8s_tests` feature. Tests using this must be marked with:
/// - `#[serial]` - Sequential execution required (PRSS network coordination)
/// - `#[cfg_attr(not(feature = "k8s_tests"), ignore)]` - Only runs in K8s CI
///
/// # Example
/// ```no_run
/// #[tokio::test]
/// #[serial]
/// #[cfg_attr(not(feature = "k8s_tests"), ignore)]
/// async fn test_prss_feature() -> Result<()> {
///     let (material_dir, _servers, config_path) =
///         setup_isolated_threshold_cli_test_with_prss("my_prss_test", 4).await?;
///     // Run PRSS operations
///     Ok(())
/// }
/// ```
#[cfg(feature = "k8s_tests")]
async fn setup_isolated_threshold_cli_test_with_prss(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        true,
        false,
        false,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with backup vault
async fn setup_isolated_threshold_cli_test_with_backup(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        true,
        false,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with custodian backup vault
async fn setup_isolated_threshold_cli_test_with_custodian_backup(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        true,
        true,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with Default FHE parameters
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "threshold_default")
/// * `party_count` - Number of parties in threshold cluster (typically 4)
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with test material (auto-cleanup on drop)
/// * `HashMap<u32, ServerHandle>` - Map of running KMS servers with Default FHE params
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Note
/// Uses Default FHE parameters (production-like, slower than Test params)
///
/// # Example
/// ```no_run
/// let (material_dir, _servers, config_path) =
///     setup_isolated_threshold_cli_test_default("my_test", 4).await?;
/// ```
async fn setup_isolated_threshold_cli_test_default(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        false,
        false,
        FheParameter::Default,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with Default FHE parameters and PRSS enabled
#[cfg(feature = "k8s_tests")]
async fn setup_isolated_threshold_cli_test_with_prss_default(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        true,
        false,
        false,
        FheParameter::Default,
    )
    .await
}

/// Generate CLI config files for threshold KMS
///
/// Note: We generate configs dynamically (not from template files) because:
/// - Ports are dynamically allocated (random free ports per test)
/// - Paths are dynamic (unique TempDir per test)
/// - Party count varies between tests (4, 6, etc.)
/// - This ensures complete test isolation
///
/// See `core-client/config/client_local_threshold.toml` for the reference format.
///
/// TODO: Refactor to use `CoreClientConfig` struct with TOML serialization instead of format strings.
/// See the TODO in `generate_centralized_cli_config` for details.
fn generate_threshold_cli_config(
    material_dir: &kms_lib::testing::material::TestMaterialHandle,
    servers: &HashMap<u32, ServerHandle>,
    party_count: usize,
    fhe_params: FheParameter,
) -> Result<PathBuf> {
    let config_path = material_dir.path().join("client_config.toml");
    let majority = party_count / 2 + 1;
    let mut config_content = format!(
        r#"
kms_type = "threshold"
num_majority = {majority}
num_reconstruct = {majority}
fhe_params = "{fhe_params:?}"

[storage]
pub_storage_type = "file"
priv_storage_type = "file"
client_storage_type = "file"
file_storage_path = "{path}"
"#,
        path = material_dir.path().display()
    );

    // Create minimal server config files for each party (needed for MPC context creation)
    let threshold_value = party_count.div_ceil(3) - 1;

    for i in 1..=party_count {
        let server = servers
            .get(&(i as u32))
            .unwrap_or_else(|| panic!("Server {} should exist", i));

        let server_config_path = material_dir.path().join(format!("compose_{}.toml", i));

        // Build peer list for this party
        let mut peers_config = String::new();
        for j in 1..=party_count {
            let peer_server = servers.get(&(j as u32)).unwrap();
            let mpc_port = peer_server
                .mpc_port
                .expect("MPC port should be set for threshold server");
            peers_config.push_str(&format!(
                r#"
[[threshold.peers]]
party_id = {}
address = "127.0.0.1"
mpc_identity = "kms-core-{}.local"
port = {}
"#,
                j, j, mpc_port
            ));
        }

        // Create minimal server config with mock enclave PCR values
        // Include public_vault and aws sections for MPC context creation
        let server_config_content = format!(
            r#"
mock_enclave = true

[service]
listen_address = "127.0.0.1"
listen_port = {}
timeout_secs = 30
grpc_max_message_size = 104857600

[public_vault.storage.s3]
bucket = "kms-public"
prefix = "PUB-p{}"

[private_vault.storage.file]
path = "{}/PRIV-p{}"

[aws]
region = "us-east-1"
s3_endpoint = "http://dev-s3-mock:9000"

[threshold]
my_id = {}
threshold = {}
listen_address = "127.0.0.1"
listen_port = {}
dec_capacity = 100
min_dec_cache = 10
num_sessions_preproc = 2
decryption_mode = "NoiseFloodSmall"

[[threshold.tls.auto.trusted_releases]]
pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
{}
"#,
            server.service_port,
            i, // prefix for public_vault
            material_dir.path().display(),
            i, // PRIV-p{i}
            i, // my_id
            threshold_value,
            server.mpc_port.expect("MPC port should be set"),
            peers_config
        );

        write(&server_config_path, server_config_content)?;

        // Add core config to client config with config_path
        config_content.push_str(&format!(
            r#"
[[cores]]
party_id = {}
address = "localhost:{}"
s3_endpoint = "file://{}"
object_folder = "PUB-p{}"
private_object_folder = "PRIV-p{}"
config_path = "{}"
"#,
            i,
            server.service_port,
            material_dir.path().display(),
            i,
            i,
            server_config_path.display()
        ));
    }

    write(&config_path, config_content)?;
    Ok(config_path)
}

/// Internal implementation for threshold CLI test setup
async fn setup_isolated_threshold_cli_test_impl(
    test_name: &str,
    party_count: usize,
    run_prss: bool,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    fhe_params: FheParameter,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl_with_spec(
        test_name,
        party_count,
        run_prss,
        with_backup_vault,
        with_custodian_keychain,
        fhe_params,
        None,
    )
    .await
}

/// Internal implementation for threshold CLI test setup with optional material spec
async fn setup_isolated_threshold_cli_test_impl_with_spec(
    test_name: &str,
    party_count: usize,
    run_prss: bool,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    fhe_params: FheParameter,
    material_spec: Option<kms_lib::testing::material::TestMaterialSpec>,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    // Use builder pattern with full feature support
    let mut builder = ThresholdTestEnv::builder()
        .with_test_name(test_name)
        .with_party_count(party_count);

    if let Some(spec) = material_spec {
        builder = builder.with_material_spec(spec);
    }

    if run_prss {
        builder = builder.with_prss();
    }

    if with_backup_vault {
        builder = builder.with_backup_vault();
    }

    if with_custodian_keychain {
        builder = builder.with_custodian_keychain();
    }

    let env = builder.build().await?;

    // Extract components for CLI usage
    let material_dir = env.material_dir;
    let servers = env.servers;

    // Generate CLI config files
    let config_path =
        generate_threshold_cli_config(&material_dir, &servers, party_count, fhe_params)?;

    Ok((material_dir, servers, config_path))
}

// ============================================================================
// PARTY RESHARING SETUP
// ============================================================================

/// Setup 6 servers with per-server peer configuration for party resharing tests.
///
/// This creates:
/// - Servers 1-4 with peers [1,2,3,4] (for context 1)
/// - Servers 5-6 with peers [5,6,3,4] where 5→party1, 6→party2 (for context 2)
///
/// Returns:
/// - TestMaterialHandle with test material
/// - HashMap of server handles
/// - Config path for context 1 (servers 1,2,3,4)
/// - Config path for context 2 (servers 5,6,3,4)
///
/// TODO: add possibility for dynamic party number setup
async fn setup_party_resharing_servers(
    test_name: &str,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
    PathBuf,
)> {
    use kms_lib::conf::threshold::PeerConf;
    use kms_lib::testing::helpers::create_test_material_manager;
    use kms_lib::testing::material::TestMaterialSpec;
    use kms_lib::vault::storage::file::FileStorage;
    use kms_lib::vault::storage::StorageType;

    let manager = create_test_material_manager();

    // Setup material for 4 parties (the test uses 6 servers but operates in 4-party contexts)
    // Servers 1-4 form context 1, servers 5,6,3,4 form context 2 (party resharing)
    // Use threshold_signing_only since this test generates FHE keys dynamically
    let spec = TestMaterialSpec::threshold_signing_only(4);
    let material_dir = manager.setup_test_material_auto(&spec, test_name).await?;

    // Create storage for each of the 6 servers
    let pub_prefixes = [
        Some("PUB-p1".to_string()),
        Some("PUB-p2".to_string()),
        Some("PUB-p3".to_string()),
        Some("PUB-p4".to_string()),
        Some("PUB-p5".to_string()),
        Some("PUB-p6".to_string()),
    ];
    let priv_prefixes = [
        Some("PRIV-p1".to_string()),
        Some("PRIV-p2".to_string()),
        Some("PRIV-p3".to_string()),
        Some("PRIV-p4".to_string()),
        Some("PRIV-p5".to_string()),
        Some("PRIV-p6".to_string()),
    ];

    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    for (pub_prefix, priv_prefix) in pub_prefixes.iter().zip(&priv_prefixes) {
        pub_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PUB,
            pub_prefix.as_deref(),
        )?);
        priv_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            priv_prefix.as_deref(),
        )?);
    }

    // Ensure signing keys exist for all 6 servers
    // The test material only has keys for 4 parties, so we need to generate for servers 5-6
    use kms_lib::consts::SIGNING_KEY_ID;
    use kms_lib::util::key_setup::{
        ensure_threshold_server_signing_keys_exist, ThresholdSigningKeyConfig,
    };
    let _ = ensure_threshold_server_signing_keys_exist(
        &mut pub_storages,
        &mut priv_storages,
        &SIGNING_KEY_ID,
        true, // deterministic
        ThresholdSigningKeyConfig::AllParties((1..=6).map(|i| format!("party-{i}")).collect()),
        false, // don't skip if exists
    )
    .await;

    // Create peer configurations for party resharing:
    // - Servers 1-4: peers [1,2,3,4] (standard 4-party setup)
    // - Servers 5-6: peers [5,6,3,4] where server 5 acts as party 1, server 6 as party 2
    //   (This allows servers 5,6 to replace servers 1,2 in context 2)

    // Peers for servers 1-4 (context 1)
    let peers_1234: Vec<PeerConf> = (1..=4)
        .map(|i| PeerConf {
            party_id: i,
            address: "127.0.0.1".to_string(),
            mpc_identity: Some(format!("kms-core-{}.local", i)),
            port: 0, // Will be updated by setup_threshold_with_custom_peers
            tls_cert: None,
            verification_address: None,
        })
        .collect();

    // Peers for context 2: servers [5,6,3,4] acting as MPC parties [1,2,3,4]
    // - Server 5 (index 4) acts as MPC party 1 (replacing server 1)
    // - Server 6 (index 5) acts as MPC party 2 (replacing server 2)
    // - Server 3 (index 2) remains as MPC party 3
    // - Server 4 (index 3) remains as MPC party 4
    let peers_ctx2: Vec<PeerConf> = vec![
        PeerConf {
            party_id: 1, // MPC party 1
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-5.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
        PeerConf {
            party_id: 2, // MPC party 2
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-6.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
        PeerConf {
            party_id: 3, // MPC party 3
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-3.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
        PeerConf {
            party_id: 4, // MPC party 4
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-4.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
    ];

    // Server configs: (my_id, threshold, peers, peer_server_indices)
    // - my_id: The MPC party ID this server will act as
    // - peer_server_indices: Maps each peer (by index in peers vec) to physical server index (0-based)
    //
    // Context 1 servers (indices 0-3): peers map to servers 0,1,2,3
    // Context 2 servers (indices 4-5): peers map to servers 4,5,2,3 (party 1→server5, party 2→server6)
    let peer_indices_ctx1 = vec![0, 1, 2, 3]; // Peers 1,2,3,4 → servers 0,1,2,3
    let peer_indices_ctx2 = vec![4, 5, 2, 3]; // Peers 1,2,3,4 → servers 4,5,2,3

    let server_configs: Vec<(usize, u8, Vec<PeerConf>, Vec<usize>)> = vec![
        (1, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 1 (idx 0): party 1
        (2, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 2 (idx 1): party 2
        (3, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 3 (idx 2): party 3
        (4, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 4 (idx 3): party 4
        (1, 1, peers_ctx2.clone(), peer_indices_ctx2.clone()), // Server 5 (idx 4): party 1 in ctx2
        (2, 1, peers_ctx2.clone(), peer_indices_ctx2.clone()), // Server 6 (idx 5): party 2 in ctx2
    ];

    let vaults: Vec<Option<kms_lib::vault::Vault>> = (0..6).map(|_| None).collect();

    // Start servers with custom peer configurations
    let servers = kms_lib::client::test_tools::setup_threshold_with_custom_peers(
        server_configs,
        pub_storages,
        priv_storages,
        vaults,
        false, // run_prss - we'll do this per-context
        None,  // rate_limiter_conf
        None,  // decryption_mode
    )
    .await;

    // Generate server config files for MPC context creation (needed for PCR values)
    // These are minimal configs with mock_enclave = true and TLS auto mode
    let threshold_value = 1; // For 4 parties: threshold = 1

    // Create server configs for all 6 servers
    for server_id in 1..=6 {
        let server = servers.get(&(server_id as u32)).unwrap();
        let server_config_path = material_dir
            .path()
            .join(format!("compose_{}.toml", server_id));

        // Determine which peer list this server uses
        let (my_party_id, peers_for_config) = if server_id <= 4 {
            // Servers 1-4 use peers_1234, party_id = server_id
            (server_id, &peers_1234)
        } else {
            // Servers 5-6 use peers_ctx2, party_id = server_id - 4 (5→1, 6→2)
            (server_id - 4, &peers_ctx2)
        };

        // Build peer list for this server's config
        let mut peers_config = String::new();
        for peer in peers_for_config.iter() {
            // Find the physical server for this peer
            let peer_server_id = if server_id <= 4 {
                // Context 1: peer party_id maps directly to server_id
                peer.party_id as u32
            } else {
                // Context 2: party 1→server5, party 2→server6, party 3→server3, party 4→server4
                match peer.party_id {
                    1 => 5,
                    2 => 6,
                    3 => 3,
                    4 => 4,
                    _ => peer.party_id as u32,
                }
            };
            let peer_server = servers.get(&peer_server_id).unwrap();
            let mpc_port = peer_server.mpc_port.expect("MPC port should be set");
            peers_config.push_str(&format!(
                r#"
[[threshold.peers]]
party_id = {}
address = "127.0.0.1"
mpc_identity = "kms-core-{}.local"
port = {}
"#,
                peer.party_id, peer_server_id, mpc_port
            ));
        }

        let server_config_content = format!(
            r#"
mock_enclave = true

[service]
listen_address = "127.0.0.1"
listen_port = {}
timeout_secs = 30
grpc_max_message_size = 104857600

[public_vault.storage.s3]
bucket = "kms-public"
prefix = "PUB-p{}"

[private_vault.storage.file]
path = "{}/PRIV-p{}"

[aws]
region = "us-east-1"
s3_endpoint = "http://dev-s3-mock:9000"

[threshold]
my_id = {}
threshold = {}
listen_address = "127.0.0.1"
listen_port = {}
dec_capacity = 100
min_dec_cache = 10
num_sessions_preproc = 2
decryption_mode = "NoiseFloodSmall"

[[threshold.tls.auto.trusted_releases]]
pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
{}
"#,
            server.service_port,
            server_id, // prefix for public_vault - use server_id to match client config
            material_dir.path().display(),
            server_id,   // PRIV-p{server_id}
            my_party_id, // my_id
            threshold_value,
            server.mpc_port.expect("MPC port should be set"),
            peers_config
        );

        std::fs::write(&server_config_path, server_config_content)?;
    }

    // Generate CLI config for context 1 (servers 1,2,3,4)
    let fhe_params = FheParameter::Test;
    let config_path_1234 = material_dir.path().join("client_config_1234.toml");
    let mut config_content_1234 = format!(
        r#"
kms_type = "threshold"
num_majority = 2
num_reconstruct = 3
fhe_params = "{fhe_params:?}"
decryption_mode = "NoiseFloodSmall"

[storage]
pub_storage_type = "file"
priv_storage_type = "file"
client_storage_type = "file"
file_storage_path = "{path}"
"#,
        path = material_dir.path().display()
    );

    for i in 1..=4 {
        let server = servers.get(&(i as u32)).unwrap();
        let server_config_path = material_dir.path().join(format!("compose_{}.toml", i));
        config_content_1234.push_str(&format!(
            r#"
[[cores]]
party_id = {}
address = "localhost:{}"
s3_endpoint = "file://{}"
object_folder = "PUB-p{}"
private_object_folder = "PRIV-p{}"
config_path = "{}"
"#,
            i,
            server.service_port,
            material_dir.path().display(),
            i,
            i,
            server_config_path.display()
        ));
    }
    std::fs::write(&config_path_1234, config_content_1234)?;

    // Generate CLI config for context 2 (servers 5,6,3,4 as parties 1,2,3,4)
    let config_path_5634 = material_dir.path().join("client_config_5634.toml");
    let mut config_content_5634 = format!(
        r#"
kms_type = "threshold"
num_majority = 2
num_reconstruct = 3
fhe_params = "{fhe_params:?}"
decryption_mode = "NoiseFloodSmall"

[storage]
pub_storage_type = "file"
priv_storage_type = "file"
client_storage_type = "file"
file_storage_path = "{path}"
"#,
        path = material_dir.path().display()
    );

    // Map: MPC party_id -> physical server_id
    // Party 1 -> Server 5, Party 2 -> Server 6, Party 3 -> Server 3, Party 4 -> Server 4
    for (party_id, server_id) in [(1, 5), (2, 6), (3, 3), (4, 4)] {
        let server = servers.get(&(server_id as u32)).unwrap();
        let server_config_path = material_dir
            .path()
            .join(format!("compose_{}.toml", server_id));
        config_content_5634.push_str(&format!(
            r#"
[[cores]]
party_id = {}
address = "localhost:{}"
s3_endpoint = "file://{}"
object_folder = "PUB-p{}"
private_object_folder = "PRIV-p{}"
config_path = "{}"
"#,
            party_id, // MPC party ID (1-4)
            server.service_port,
            material_dir.path().display(),
            server_id, // Physical server ID for storage
            server_id,
            server_config_path.display()
        ));
    }
    std::fs::write(&config_path_5634, config_content_5634)?;

    Ok((material_dir, servers, config_path_1234, config_path_5634))
}

// ============================================================================
// TEST UTILITIES
// ============================================================================

fn init_testing() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
}

/// Helper to run insecure key generation via CLI (isolated version)
async fn insecure_key_gen_isolated(config_path: &Path, test_path: &Path) -> Result<String> {
    let config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing insecure key-gen");
    let key_gen_results = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
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
async fn crs_gen_isolated(
    config_path: &Path,
    test_path: &Path,
    insecure_crs_gen: bool,
) -> Result<String> {
    crs_gen_isolated_with_params(config_path, test_path, insecure_crs_gen, 2048, 200).await
}

/// CRS generation with configurable max_num_bits and max_iter.
/// Default-param tests need max_num_bits=2048 and higher max_iter for production-sized ZK ceremonies.
async fn crs_gen_isolated_with_params(
    config_path: &Path,
    test_path: &Path,
    insecure_crs_gen: bool,
    max_num_bits: u32,
    max_iter: usize,
) -> Result<String> {
    let command = if insecure_crs_gen {
        CCCommand::InsecureCrsGen(CrsParameters { max_num_bits })
    } else {
        CCCommand::CrsGen(CrsParameters { max_num_bits })
    };

    let config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command,
        logs: true,
        max_iter,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing CRS generation");
    let crs_gen_results = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("CRS generation done");

    assert_eq!(crs_gen_results.len(), 1);
    let crs_id = match crs_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing CRS generation"),
    };

    Ok(crs_id.to_string())
}

/// Helper to run integration test commands via CLI (isolated version)
///
/// Mirrors the Docker-based `integration_test_commands` in integration_test.rs:
/// - PublicDecrypt/UserDecrypt across ebool, euint8 (compressed/uncompressed), euint16, euint256
/// - Encrypt to file + PublicDecrypt/UserDecrypt from file
/// - SnS precompute variants (no_precompute_sns=false)
async fn integration_test_commands_isolated(
    config_path: &Path,
    keys_folder: &Path,
    key_id: String,
) -> Result<()> {
    let key_id = KeyId::from_str(&key_id)?;
    let ctxt_path = keys_folder.join("test_encrypt_cipher.txt");
    let ctxt_with_sns_path = keys_folder.join("test_encrypt_cipher_with_sns.txt");

    // Commands without SnS precompute (no_precompute_sns=true)
    let commands = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            no_compression: true,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 3,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 3,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xFFFF".to_string(),
            data_type: FheType::Euint16,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x96BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC4592B"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D81CE14B95D225928E4E9B5305EC4592C"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::Encrypt(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF0395689B5305EC4592D"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: Some(ctxt_path.clone()),
            inter_request_delay_ms: 0,
        }),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_path.clone(),
            batch_size: 1,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_path.clone(),
            batch_size: 1,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
        })),
    ];

    // Commands with SnS precompute (no_precompute_sns=false)
    let commands_for_sns_precompute = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 2,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x78".to_string(),
            data_type: FheType::Euint8,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 2,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F7820"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xC9BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC4592F"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: None,
            inter_request_delay_ms: 0,
        })),
        CCCommand::Encrypt(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13CA037D537E521CE14B95D225928E4E9B5305EC4592E"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: Some(ctxt_with_sns_path.clone()),
            inter_request_delay_ms: 0,
        }),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_with_sns_path.clone(),
            batch_size: 1,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_with_sns_path.clone(),
            batch_size: 1,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
        })),
    ];

    let all_commands = [commands, commands_for_sns_precompute].concat();

    for command in all_commands {
        let config = CmdConfig {
            file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
            command: command.clone(),
            logs: true,
            max_iter: 500,
            expect_all_responses: true,
            download_all: false,
        };

        let results = execute_cmd(&config, keys_folder)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Validate result count matches expected requests
        match &command {
            CCCommand::PublicDecrypt(cipher_arguments)
            | CCCommand::UserDecrypt(cipher_arguments) => {
                let num_expected_results = cipher_arguments.get_num_requests();
                assert_eq!(results.len(), num_expected_results);
            }
            _ => {}
        }

        // Also test the get result commands
        let req_id = results[0].0;

        let get_res_command = match command {
            CCCommand::PreprocKeyGen(_) => CCCommand::PreprocKeyGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::KeyGen(_) => CCCommand::KeyGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::InsecureKeyGen(_) => CCCommand::InsecureKeyGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::PublicDecrypt(_) => CCCommand::PublicDecryptResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::CrsGen(_) => CCCommand::CrsGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::InsecureCrsGen(_) => CCCommand::InsecureCrsGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            _ => CCCommand::DoNothing(NoParameters {}),
        };

        let expect_result = !matches!(&get_res_command, CCCommand::DoNothing(_));

        if expect_result {
            let config = CmdConfig {
                file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
                command: get_res_command,
                logs: true,
                max_iter: 500,
                expect_all_responses: true,
                download_all: false,
            };

            // We query result on a single request id, so should get a single result
            let mut results_bis = execute_cmd(&config, keys_folder)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            assert_eq!(results_bis.len(), 1);
            let (sid_bis, result_bis) = results_bis.remove(0);

            for (sid, result) in results {
                if sid_bis == sid {
                    assert_eq!(result_bis, result);
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

/// Helper to run backup restore via CLI (isolated version)
async fn restore_from_backup_isolated(config_path: &Path, test_path: &Path) -> Result<String> {
    let config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::BackupRestore(NoParameters {}),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing restore from backup");
    let restore_results = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Restore from backup done");

    assert_eq!(restore_results.len(), 1);
    // No backup ID is returned since restore_from_backup can also be used without custodians
    assert_eq!(restore_results.first().unwrap().0, None);

    Ok("".to_string())
}

/// Helper to run preprocessing and keygen via CLI (isolated version)
/// Only used by PRSS tests which are gated by k8s_tests feature
#[cfg(feature = "k8s_tests")]
async fn real_preproc_and_keygen_isolated(
    config_path: &Path,
    test_path: &Path,
    max_iter: usize,
) -> Result<String> {
    // Step 1: Preprocessing
    let preproc_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id: None,
            epoch_id: None,
        }),
        logs: true,
        max_iter,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing preprocessing");
    let mut preproc_result = execute_cmd(&preproc_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    assert_eq!(preproc_result.len(), 1);
    let (preproc_id, _) = preproc_result.pop().unwrap();
    println!("Preprocessing done with ID {preproc_id:?}");

    // Step 2: Key generation using preprocessing result
    let keygen_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id: preproc_id.unwrap(),
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing key-gen");
    let key_gen_results = execute_cmd(&keygen_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    Ok(key_id.to_string())
}

/// Helper to run partial preprocessing and keygen via CLI (isolated version)
/// Uses PartialPreprocKeyGen with a small percentage_offline to avoid generating
/// the full 785M bits with Default FHE params. store_dummy_preprocessing=true
/// allows keygen to proceed with the partial material.
#[cfg(feature = "k8s_tests")]
async fn real_partial_preproc_and_keygen_isolated(
    config_path: &Path,
    test_path: &Path,
    percentage_offline: u32,
    max_iter: usize,
) -> Result<String> {
    // Step 1: Partial preprocessing
    let preproc_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::PartialPreprocKeyGen(PartialKeyGenPreprocParameters {
            context_id: None,
            epoch_id: None,
            percentage_offline,
            store_dummy_preprocessing: true,
        }),
        logs: true,
        max_iter,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing partial preprocessing ({percentage_offline}%)");
    let mut preproc_result = execute_cmd(&preproc_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    assert_eq!(preproc_result.len(), 1);
    let (preproc_id, _) = preproc_result.pop().unwrap();
    println!("Partial preprocessing done with ID {preproc_id:?}");

    // Step 2: Key generation using preprocessing result
    let keygen_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id: preproc_id.unwrap(),
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing key-gen");
    let key_gen_results = execute_cmd(&keygen_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    Ok(key_id.to_string())
}

// ============================================================================
// MPC CONTEXT HELPER FUNCTIONS
// ============================================================================

/// Store MPC context to file for test
async fn store_mpc_context_in_file_isolated(
    context_path: &Path,
    config_path: &Path,
    context_id: ContextId,
) -> Result<()> {
    // Load the core client config from file
    let cc_conf: CoreClientConfig = observability::conf::Settings::builder()
        .path(config_path.to_str().unwrap())
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()?;

    let context = create_test_context_info_from_core_config(context_id, &cc_conf).await?;

    println!("Storing context {:?} to file {:?}", context, context_path);

    let mut buf = Vec::new();
    safe_serialize(&context, &mut buf, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow::anyhow!("Failed to serialize context: {}", e))?;

    tokio::fs::write(context_path, buf).await?;
    Ok(())
}

/// Create new MPC context via CLI (isolated version)
async fn new_mpc_context_isolated(
    config_path: &Path,
    context_path: &Path,
    test_path: &Path,
) -> Result<()> {
    let command = CCCommand::NewMpcContext(NewMpcContextParameters::SerializedContextPath(
        ContextPath {
            input_path: context_path.to_path_buf(),
        },
    ));

    let config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Creating new MPC context");
    let context_result = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create MPC context: {}", e))?;
    println!("MPC context created");
    assert_eq!(context_result.len(), 1);
    Ok(())
}

/// Initialize PRSS for a context via CLI (isolated version)
async fn new_prss_isolated(
    config_path: &Path,
    context_id: ContextId,
    epoch_id: EpochId,
    test_path: &Path,
) -> Result<()> {
    let command = CCCommand::NewEpoch(NewEpochParameters {
        new_epoch_id: epoch_id,
        new_context_id: context_id,
        previous_epoch_params: None,
    });

    let config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Initializing PRSS");
    let prss_result = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to initialize PRSS: {}", e))?;
    println!("PRSS initialized");
    assert_eq!(prss_result.len(), 1);
    Ok(())
}

/// Helper to run preprocessing and keygen with context/epoch via CLI (isolated version)
async fn real_preproc_and_keygen_with_context_isolated(
    config_path: &Path,
    test_path: &Path,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
) -> Result<String> {
    // Step 1: Preprocessing
    let preproc_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id,
            epoch_id,
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing preprocessing with context");
    let mut preproc_result = execute_cmd(&preproc_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do preprocessing: {}", e))?;
    assert_eq!(preproc_result.len(), 1);
    let (preproc_id, _) = preproc_result.pop().unwrap();
    println!("Preprocessing done with ID {preproc_id:?}");

    // Step 2: Key generation using preprocessing result
    let keygen_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id: preproc_id.unwrap(),
            shared_args: SharedKeyGenParameters {
                keyset_type: None,
                context_id,
                epoch_id,
            },
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing key-gen with context");
    let key_gen_results = execute_cmd(&keygen_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do keygen: {}", e))?;
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen with context"),
    };

    Ok(key_id.to_string())
}

/// Helper to run preprocessing and keygen with context/epoch via CLI (isolated version)
/// Returns both key_id and preproc_id for reshare operations
#[cfg(feature = "k8s_tests")]
async fn real_preproc_and_keygen_with_context_isolated_full(
    config_path: &Path,
    test_path: &Path,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
) -> Result<(String, String)> {
    // Step 1: Preprocessing
    let preproc_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id,
            epoch_id,
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing preprocessing with context");
    let mut preproc_result = execute_cmd(&preproc_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do preprocessing: {}", e))?;
    assert_eq!(preproc_result.len(), 1);
    let (preproc_id_opt, _) = preproc_result.pop().unwrap();
    let preproc_id = preproc_id_opt.unwrap();
    println!("Preprocessing done with ID {preproc_id:?}");

    // Step 2: Key generation using preprocessing result
    let keygen_config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id,
            shared_args: SharedKeyGenParameters {
                keyset_type: None,
                context_id,
                epoch_id,
            },
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing key-gen with context");
    let key_gen_results = execute_cmd(&keygen_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do keygen: {}", e))?;
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen with context"),
    };

    Ok((key_id.to_string(), preproc_id.to_string()))
}

/// Helper to run reshare operation via CLI (isolated version)
#[cfg(feature = "k8s_tests")]
#[allow(clippy::too_many_arguments)]
async fn reshare_isolated(
    config_path: &Path,
    test_path: &Path,
    key_id: RequestId,
    preproc_id: RequestId,
    from_context_id: Option<ContextId>,
    from_epoch_id: Option<EpochId>,
    new_epoch_id: EpochId,
    server_key_digest: String,
    public_key_digest: String,
) -> Result<Vec<(Option<RequestId>, String)>> {
    let ctx_id = from_context_id.expect("context_id required for reshare");
    let ep_id = from_epoch_id.expect("epoch_id required for reshare");
    let config = CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command: CCCommand::NewEpoch(NewEpochParameters {
            new_epoch_id,
            new_context_id: ctx_id,
            previous_epoch_params: Some(PreviousEpochParameters {
                context_id: ctx_id,
                epoch_id: ep_id,
                key_id: key_id.into(),
                preproc_id,
                server_key_digest,
                public_key_digest,
            }),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing resharing");
    let resharing_result = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do resharing: {}", e))?;
    println!("Resharing done");

    Ok(resharing_result)
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
        file_conf: Some(vec![String::from(config_path.to_str().unwrap())]),
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

        let cmd_output = Command::new(&custodian_bin).args(args).output().unwrap();

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
        file_conf: Some(vec![String::from(config_path.to_str().unwrap())]),
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

            let cmd_output = Command::new(&custodian_bin).args(args).output().unwrap();

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
        file_conf: Some(vec![String::from(config_path.to_str().unwrap())]),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing backup recovery");
    let backup_recovery_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("Backup recovery done");
    assert_eq!(backup_recovery_results.len(), 1);
    let res_id = match backup_recovery_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup recovery"),
    };

    res_id.to_string()
}

// ============================================================================
// TESTS
// ============================================================================

/// Test centralized insecure key generation via CLI
#[tokio::test]
async fn test_centralized_insecure() -> Result<()> {
    init_testing();

    // Setup isolated centralized KMS server
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test("centralized_insecure").await?;

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
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test("centralized_crsgen").await?;

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
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test_with_backup("centralized_restore").await?;

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
    let cus_backup_id = new_custodian_context_isolated(
        &config_path,
        temp_path,
        custodian_threshold,
        setup_msg_paths,
    )
    .await;

    let operator_recovery_resp_path = temp_path
        .join("CUSTODIAN")
        .join("recovery")
        .join(&cus_backup_id)
        .join("central");

    // Ensure the dir exists
    create_dir_all(operator_recovery_resp_path.parent().unwrap())?;

    // Initialize custodian backup
    let init_backup_id = custodian_backup_init_isolated(
        &config_path,
        temp_path,
        vec![operator_recovery_resp_path.clone()],
    )
    .await;
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

    // Setup isolated threshold KMS servers (4 parties) with Default FHE params
    #[cfg(feature = "k8s_tests")]
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss_default("threshold_insecure", 4).await?;

    #[cfg(not(feature = "k8s_tests"))]
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("threshold_insecure", 4).await?;

    // Run CLI commands against native threshold servers (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen_isolated(&config_path, keys_folder).await?;
    integration_test_commands_isolated(&config_path, keys_folder, key_id).await?;

    Ok(())
}

/// Nightly test - threshold sequential preprocessing and keygen with nightly parameters
#[cfg(feature = "k8s_tests")]
#[tokio::test]
#[serial] // PRSS requires sequential execution
async fn nightly_tests_threshold_sequential_preproc_keygen() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties for test context) with PRSS enabled
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("nightly_preproc", 4).await?;

    // Run sequential preprocessing and keygen operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let key_id_1 = real_preproc_and_keygen_isolated(&config_path, keys_folder, 200).await?;
    let key_id_2 = real_preproc_and_keygen_isolated(&config_path, keys_folder, 200).await?;

    // Verify different key IDs generated
    assert_ne!(key_id_1, key_id_2);

    Ok(())
}

/// Test threshold concurrent preprocessing and keygen operations
#[cfg(feature = "k8s_tests")]
#[tokio::test]
#[serial] // PRSS requires sequential execution
async fn test_threshold_concurrent_preproc_keygen() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties for test context) with PRSS enabled
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("concurrent_preproc", 4).await?;

    // Run concurrent preprocessing and keygen operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let _ = join_all([
        real_preproc_and_keygen_isolated(&config_path, keys_folder, 200),
        real_preproc_and_keygen_isolated(&config_path, keys_folder, 200),
    ])
    .await;

    Ok(())
}

/// Test threshold sequential CRS generation via CLI with production-sized params
/// Uses max_num_bits=2048 and secure ZK ceremony (same as Docker-based version)
#[tokio::test]
async fn nightly_tests_threshold_sequential_crs() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties) with Default FHE params
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("threshold_seq_crs", 4).await?;

    // Run sequential CRS generation with production-sized params (max_num_bits=2048)
    // Secure ZK ceremony with Default params can take ~17min per CRS gen
    let keys_folder = material_dir.path();
    let crs_id_1 =
        crs_gen_isolated_with_params(&config_path, keys_folder, false, 2048, 5000).await?;
    let crs_id_2 =
        crs_gen_isolated_with_params(&config_path, keys_folder, false, 2048, 5000).await?;

    // Verify different CRS IDs generated
    assert_ne!(crs_id_1, crs_id_2);

    Ok(())
}

/// Test threshold concurrent CRS generation via CLI with production-sized params
///
/// Uses insecure CRS generation because the multi-party ZK ceremony cannot handle
/// concurrent sessions — the first ceremony completes but subsequent ones get stuck
/// with networking timeouts between parties.
#[tokio::test]
async fn test_threshold_concurrent_crs() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties) with Default FHE params
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("threshold_concurrent_crs", 4).await?;

    // Run concurrent CRS generation via CLI with production-sized params (max_num_bits=2048)
    // insecure_crs_gen=true: secure ZK ceremony doesn't support concurrent sessions
    let keys_folder = material_dir.path();
    let res = join_all([
        crs_gen_isolated_with_params(&config_path, keys_folder, true, 2048, 5000),
        crs_gen_isolated_with_params(&config_path, keys_folder, true, 2048, 5000),
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

    // Setup isolated threshold KMS servers (4 parties) with backup vaults
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_backup("threshold_restore", 4).await?;

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
        setup_isolated_threshold_cli_test_with_custodian_backup(
            "threshold_custodian",
            amount_operators,
        )
        .await?;

    let temp_path = material_dir.path();

    // Generate custodian keys using native kms-custodian binary
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians, true).await;

    // Create custodian context
    let cus_backup_id = new_custodian_context_isolated(
        &config_path,
        temp_path,
        custodian_threshold,
        setup_msg_paths,
    )
    .await;
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
    let init_backup_id = custodian_backup_init_isolated(
        &config_path,
        temp_path,
        operator_recovery_resp_paths.clone(),
    )
    .await;
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

/// Full generation test - threshold sequential preprocessing and keygen with Default FHE params
/// Uses partial preprocessing (1%) with store_dummy_preprocessing to test the full pipeline
/// without generating the full 785M bits. This exercises the same code paths as full preprocessing
/// but completes in reasonable time.
#[cfg(feature = "k8s_tests")]
#[tokio::test]
#[serial] // PRSS requires sequential execution
async fn full_gen_tests_default_threshold_sequential_preproc_keygen() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties for default context) with PRSS enabled
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss_default("full_gen_preproc", 4).await?;

    // Run sequential partial preprocessing (1%) and keygen with Default FHE params
    // 1% of 785M bits ≈ 7.8M bits — manageable in CI
    let keys_folder = material_dir.path();
    let key_id_1 =
        real_partial_preproc_and_keygen_isolated(&config_path, keys_folder, 1, 5000).await?;
    let key_id_2 =
        real_partial_preproc_and_keygen_isolated(&config_path, keys_folder, 1, 5000).await?;

    // Verify different key IDs generated
    assert_ne!(key_id_1, key_id_2);

    Ok(())
}

/// Full generation test - threshold sequential CRS generation with production-sized params
/// Uses max_num_bits=2048 and secure ZK ceremony (same as Docker-based version)
#[tokio::test]
async fn full_gen_tests_default_threshold_sequential_crs() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties for default context) with Default FHE params
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("full_gen_crs", 4).await?;

    // Run sequential CRS generation with production-sized params (max_num_bits=2048)
    // Secure ZK ceremony with Default params can take ~17min per CRS gen
    let keys_folder = material_dir.path();
    let crs_id_1 =
        crs_gen_isolated_with_params(&config_path, keys_folder, false, 2048, 5000).await?;
    let crs_id_2 =
        crs_gen_isolated_with_params(&config_path, keys_folder, false, 2048, 5000).await?;

    // Verify different CRS IDs generated
    assert_ne!(crs_id_1, crs_id_2);

    Ok(())
}

/// Test threshold MPC context initialization and PRSS setup
///
/// This test verifies the complete MPC context lifecycle:
/// 1. Create and store MPC context to file
/// 2. Initialize new MPC context in KMS servers
/// 3. Initialize PRSS for the context
/// 4. Run preprocessing and keygen using the context and PRSS
///
/// Note: This test starts from uninitialized threshold KMS servers (no PRSS or context)
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "k8s_tests"), ignore)] // Run only in K8s CI - enable locally with: cargo test --features k8s_tests -- --test-threads=1
async fn test_threshold_mpc_context_init() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties) WITHOUT PRSS initialization
    // This simulates servers that need context and PRSS setup
    // Note: 4 parties required to satisfy MPC context validation formula n = 3t + 1 (with t=1)
    // Uses signing_only spec to avoid pre-loaded PRSS conflicting with NewEpoch calls
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_signing_only("threshold_mpc_context_init", 4).await?;

    let test_path = material_dir.path();
    let context_path = material_dir.path().join("mpc_context.bin");

    // Step 1: Create and store MPC context to file
    let context_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222223333")?;
    store_mpc_context_in_file_isolated(&context_path, &config_path, context_id).await?;

    // Step 2: Initialize the new MPC context in KMS servers
    new_mpc_context_isolated(&config_path, &context_path, test_path).await?;

    // Step 3: Initialize PRSS for this context
    let epoch_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222224444")?;
    new_prss_isolated(&config_path, context_id, epoch_id, test_path).await?;

    // Step 4: Run preprocessing and keygen using the context and PRSS
    let _key_id = real_preproc_and_keygen_with_context_isolated(
        &config_path,
        test_path,
        Some(context_id),
        Some(epoch_id),
    )
    .await?;

    println!("MPC context initialization test completed successfully");
    Ok(())
}

/// Test 6-party MPC context switching with party resharing (ISOLATED, NO TLS)
///
/// **NOTE:** This is the isolated test version WITHOUT TLS for fast execution.
/// For TLS-enabled testing in K8s, see: `kubernetes_test_threshold_context::k8s_test_threshold_context_switch_6_tls`
///
/// This test validates party resharing/remapping across MPC contexts:
/// - First context: Physical servers 1,2,3,4 act as MPC parties 1,2,3,4
/// - Second context: Physical servers 5,6,3,4 act as MPC parties 1,2,3,4
/// - Servers 3 and 4 participate in BOTH contexts (continuity)
/// - Servers 5 and 6 REPLACE servers 1 and 2 in the second context
///
/// This test replicates party resharing scenario, which is critical for:
/// - Disaster recovery (replacing failed servers)
/// - Key rotation (changing physical server composition)
/// - Dynamic party management in production
///
/// **Architecture:**
/// - 6 physical servers total, each MPC context uses 4 parties (threshold=1)
/// - Servers 1-4 configured with peers [1,2,3,4]
/// - Servers 5-6 configured with peers [5,6,3,4] where 5→party1, 6→party2
///
/// **TLS Status:** Disabled (isolated test, localhost only)
/// **For TLS testing:** Use K8s version in `kubernetes_test_threshold_context.rs`
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "k8s_tests"), ignore)] // Run only in K8s CI - enable locally with: cargo test --features k8s_tests -- --test-threads=1
async fn test_threshold_mpc_context_switch_6() -> Result<()> {
    init_testing();

    // Setup 6 servers with per-server peer configuration for party resharing
    let (material_dir, servers, config_path_1234, config_path_5634) =
        setup_party_resharing_servers("threshold_context_switch_6").await?;

    let test_path = material_dir.path();

    // === CONTEXT 1: Servers 1,2,3,4 as parties 1,2,3,4 ===
    println!("\n========== CONTEXT 1 ==========");
    println!("Creating first context with servers [1, 2, 3, 4] as parties [1, 2, 3, 4]");

    let context_1_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222223333")?;
    let epoch_1_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222224444")?;
    let context_1_path = material_dir.path().join("mpc_context_1.bin");

    store_mpc_context_in_file_isolated(&context_1_path, &config_path_1234, context_1_id).await?;
    new_mpc_context_isolated(&config_path_1234, &context_1_path, test_path).await?;
    new_prss_isolated(&config_path_1234, context_1_id, epoch_1_id, test_path).await?;

    // Generate key in context 1
    let key_1_id = real_preproc_and_keygen_with_context_isolated(
        &config_path_1234,
        test_path,
        Some(context_1_id),
        Some(epoch_1_id),
    )
    .await?;
    println!(
        "✅ Context 1 (servers 1,2,3,4): Key generated: {}",
        key_1_id
    );

    // === CONTEXT 2: Servers 5,6,3,4 as parties 1,2,3,4 (party resharing) ===
    println!("\n========== CONTEXT 2 (PARTY RESHARING) ==========");
    println!("Creating second context with servers [5, 6, 3, 4] as parties [1, 2, 3, 4]");
    println!("Note: Servers 5,6 REPLACE servers 1,2 in this context");

    let context_2_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222225555")?;
    let epoch_2_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222226666")?;
    let context_2_path = material_dir.path().join("mpc_context_2.bin");

    store_mpc_context_in_file_isolated(&context_2_path, &config_path_5634, context_2_id).await?;
    new_mpc_context_isolated(&config_path_5634, &context_2_path, test_path).await?;
    new_prss_isolated(&config_path_5634, context_2_id, epoch_2_id, test_path).await?;

    // Generate key in context 2 (with reshared parties)
    let key_2_id = real_preproc_and_keygen_with_context_isolated(
        &config_path_5634,
        test_path,
        Some(context_2_id),
        Some(epoch_2_id),
    )
    .await?;
    println!(
        "✅ Context 2 (servers 5,6,3,4): Key generated: {}",
        key_2_id
    );

    // === SWITCH BACK TO CONTEXT 1 ===
    println!("\n========== SWITCH BACK TO CONTEXT 1 ==========");
    println!("Switching back to context 1 (servers 1,2,3,4)");

    let key_1b_id = real_preproc_and_keygen_with_context_isolated(
        &config_path_1234,
        test_path,
        Some(context_1_id),
        Some(epoch_1_id),
    )
    .await?;
    println!("✅ Context 1 (switched back): Key generated: {}", key_1b_id);

    // === VALIDATION ===
    println!("\n========== VALIDATION ==========");
    assert_ne!(context_1_id, context_2_id, "Context IDs must be different");
    assert_ne!(
        key_1_id, key_2_id,
        "Keys from different contexts must be different"
    );
    assert_ne!(
        key_1_id, key_1b_id,
        "Different keys in same context must be different"
    );
    assert_ne!(
        key_2_id, key_1b_id,
        "Keys from different contexts must be different"
    );

    println!("✅ Party resharing validated:");
    println!("   - Context 1: servers 1,2,3,4 as parties 1,2,3,4");
    println!("   - Context 2: servers 5,6,3,4 as parties 1,2,3,4 (5,6 replaced 1,2)");
    println!("   - Servers 3,4 participated in BOTH contexts");
    println!("   - All 3 keys are unique and isolated");
    println!("✅ 6-party MPC context switch with party resharing test completed successfully");

    // Cleanup: drop servers explicitly
    drop(servers);

    Ok(())
}

/// Test threshold reshare operation via CLI (isolated version)
///
/// This test validates the resharing workflow:
/// 1. Create and initialize MPC context
/// 2. Initialize PRSS for the context
/// 3. Run preprocessing and keygen with the context
/// 4. Download key materials (ServerKey, PublicKey)
/// 5. Compute digests of the key materials
/// 6. Execute resharing command
#[cfg(feature = "k8s_tests")]
#[tokio::test]
#[serial] // PRSS requires sequential execution
async fn test_threshold_reshare() -> Result<()> {
    init_testing();

    // Setup isolated threshold KMS servers (4 parties) WITHOUT PRSS initialization
    // This simulates servers that need context and PRSS setup
    // Uses signing_only spec to avoid pre-loaded PRSS conflicting with NewEpoch calls
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_signing_only("threshold_reshare", 4).await?;

    let test_path = material_dir.path();
    let context_path = material_dir.path().join("mpc_context.bin");

    // Step 1: Create and store MPC context to file
    let context_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222225555")?;
    store_mpc_context_in_file_isolated(&context_path, &config_path, context_id).await?;

    // Step 2: Initialize the new MPC context in KMS servers
    new_mpc_context_isolated(&config_path, &context_path, test_path).await?;

    // Step 3: Initialize PRSS for this context
    let epoch_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222226666")?;
    new_prss_isolated(&config_path, context_id, epoch_id, test_path).await?;

    // Step 4: Run preprocessing and keygen with the context (get both key_id and preproc_id)
    let (key_id_str, preproc_id_str) = real_preproc_and_keygen_with_context_isolated_full(
        &config_path,
        test_path,
        Some(context_id),
        Some(epoch_id),
    )
    .await?;

    // Step 5: Download the key materials
    let cc_conf: CoreClientConfig = observability::conf::Settings::builder()
        .path(config_path.to_str().unwrap())
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()?;

    let ids = fetch_public_elements(
        &key_id_str,
        &[PubDataType::ServerKey, PubDataType::PublicKey],
        &cc_conf,
        test_path,
        false,
    )
    .await?;

    // Step 6: Read the key materials from file and compute digests
    let key_id = RequestId::from_str(&key_id_str)?;
    // Use first party's storage prefix for reading materials
    let storage_prefix = format!("PUB-p{}", ids[0].party_id);
    let public_key =
        load_pk_from_pub_storage(Some(test_path), &key_id, Some(&storage_prefix)).await;
    let server_key: tfhe::ServerKey = load_material_from_pub_storage(
        Some(test_path),
        &key_id,
        PubDataType::ServerKey,
        Some(&storage_prefix),
    )
    .await;

    let server_key_digest = hex::encode(safe_serialize_hash_element_versioned(
        &DSEP_PUBDATA_KEY,
        &server_key,
    )?);
    let public_key_digest = hex::encode(safe_serialize_hash_element_versioned(
        &DSEP_PUBDATA_KEY,
        &public_key,
    )?);

    // Step 7: Execute resharing (must use a NEW epoch ID, different from the one created in Step 3)
    let new_epoch_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1333336666")?;
    let preproc_id = RequestId::from_str(&preproc_id_str)?;
    let resharing_result = reshare_isolated(
        &config_path,
        test_path,
        key_id,
        preproc_id,
        Some(context_id),
        Some(epoch_id),
        new_epoch_id,
        server_key_digest,
        public_key_digest,
    )
    .await?;

    println!("Resharing result: {:?}", resharing_result);
    assert_eq!(resharing_result.len(), 2);

    // The second element should be the key id
    assert_eq!(resharing_result[1].0.unwrap(), key_id);

    println!("✅ Threshold reshare test completed successfully");
    Ok(())
}
