//! Isolated threshold key generation tests
//!
//! These tests use the consolidated testing module. Each test runs
//! in its own temporary directory with pre-generated cryptographic material.
//!
//! ## Key Features
//! - No Docker dependency
//! - Each test uses isolated temporary directory
//! - Pre-generated material copied per test
//! - Native KMS servers spawned in-process
//! - Automatic cleanup via RAII (Drop trait)

#[cfg(feature = "insecure")]
use crate::client::tests::threshold::common::threshold_insecure_key_gen_isolated;
#[cfg(feature = "slow_tests")]
use crate::client::tests::threshold::common::threshold_key_gen_secure_isolated;
#[cfg(any(feature = "insecure", feature = "slow_tests"))]
use crate::client::tests::threshold::key_gen_tests::verify_keygen_responses;
#[cfg(any(feature = "insecure", feature = "slow_tests"))]
use crate::consts::TEST_PARAM;
#[cfg(feature = "slow_tests")]
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
#[cfg(feature = "insecure")]
use crate::engine::base::INSECURE_PREPROCESSING_ID;
#[cfg(feature = "slow_tests")]
use crate::testing::helpers::domain_to_msg;
use crate::testing::prelude::*;
use kms_grpc::kms::v1::FheParameter;

/// Test insecure threshold DKG with Test parameters.
///
/// Boots servers with PRSS, generates key using insecure mode,
/// verifies key generation succeeded on all parties.
///
/// **Requires:** `insecure` feature flag
/// **Run with:** `cargo test --lib --features insecure,testing test_insecure_dkg_isolated`
#[tokio::test]
#[cfg(feature = "insecure")]
async fn test_insecure_dkg_isolated() -> Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("insecure_dkg")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss() // PRSS is required for threshold key generation even in insecure mode
        .force_isolated() // Prevent writing PRSS/keygen data to shared test-material source
        .build()
        .await?;

    let key_id = derive_request_id("test_insecure_dkg_isolated")?;

    // Generate key using insecure mode
    let responses =
        threshold_insecure_key_gen_isolated(&env.clients, &key_id, FheParameter::Test).await?;

    // Reconstruct ClientKey from shares and run encrypt/decrypt sanity check
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    verify_keygen_responses(
        responses,
        Some(env.material_dir.path()),
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        &crate::dummy_domain(),
        env.clients.len(),
        None,
        false,
    )
    .await
    .expect("keygen verification failed");

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test insecure threshold DKG with Default parameters.
///
/// Generates a threshold FHE key using insecure mode with Default parameters
/// (larger keys, production-size) across 4 parties. Verifies key generation
/// succeeded on all parties.
///
/// **IMPORTANT:** Uses MaterialType::Default (production-like key sizes).
/// **Requires:**
/// - `insecure` feature flag
/// - `slow_tests` feature flag (for default material generation)
/// - Pre-generated default material: `make generate-test-material-all`
///
/// **Run with:** `cargo test --lib --features insecure,testing,slow_tests default_insecure_dkg_isolated`
#[tokio::test]
#[cfg(all(feature = "insecure", feature = "slow_tests"))]
async fn default_insecure_dkg_isolated() -> Result<()> {
    // Use Default material spec for production-like keys
    let spec = TestMaterialSpec::threshold_default(4);

    let env = ThresholdTestEnv::builder()
        .with_test_name("default_insecure_dkg")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: threshold = ⌈4/3⌉ - 1 = 1
        .with_prss() // PRSS is required for threshold key generation even in insecure mode
        .force_isolated() // Prevent writing PRSS/keygen data to shared test-material source
        .with_material_spec(spec)
        .build()
        .await?;

    let key_id = derive_request_id("default_insecure_dkg_isolated")?;

    // Use FheParameter::Default to match MaterialType::Default
    let responses =
        threshold_insecure_key_gen_isolated(&env.clients, &key_id, FheParameter::Default).await?;

    // Reconstruct ClientKey from shares and run encrypt/decrypt sanity check
    let internal_client = env
        .create_internal_client(&crate::consts::DEFAULT_PARAM, None)
        .await?;
    verify_keygen_responses(
        responses,
        Some(env.material_dir.path()),
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        &crate::dummy_domain(),
        env.clients.len(),
        None,
        false,
    )
    .await
    .expect("keygen verification failed");

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold key generation with preprocessing.
///
/// Generates a threshold FHE key using secure mode (with preprocessing) with Test parameters
/// across 4 parties. Verifies key generation succeeded on all parties.
///
/// **IMPORTANT:** Uses secure mode with preprocessing (not insecure mode).
/// **Requires:**
/// - `slow_tests` feature flag (PRSS generation at runtime)
///
/// **Note:** PRSS material is generated at runtime by `.with_prss()`
///
/// **Run with:** `cargo test --lib --features slow_tests,testing secure_threshold_keygen_isolated`
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_keygen_isolated() -> Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_threshold_keygen")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .force_isolated() // Prevent writing PRSS/keygen data to shared test-material source
        .build()
        .await?;

    let preproc_id = derive_request_id("secure_threshold_keygen_preproc")?;
    let keygen_id = derive_request_id("secure_threshold_keygen")?;

    // Run secure key generation with preprocessing
    let responses = threshold_key_gen_secure_isolated(
        &env.clients,
        &preproc_id,
        &keygen_id,
        FheParameter::Test,
        None,
        None,
        None,
        None,
    )
    .await?;

    // Reconstruct ClientKey from shares and run encrypt/decrypt sanity check
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    verify_keygen_responses(
        responses,
        Some(env.material_dir.path()),
        &internal_client,
        &preproc_id,
        &keygen_id,
        &crate::dummy_domain(),
        env.clients.len(),
        None,
        false,
    )
    .await
    .expect("keygen verification failed");

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold key generation with crash during online phase.
///
/// Simulates party 2 crashing during the online (keygen) phase. Verifies that the remaining
/// parties (1, 3, 4) can still complete key generation successfully.
///
/// **IMPORTANT:** Tests crash recovery - party 2 excluded from keygen.
/// **Requires:**
/// - `slow_tests` feature flag (PRSS generation at runtime)
///
/// **Run with:** `cargo test --lib --features slow_tests,testing secure_threshold_keygen_crash_online_isolated`
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_keygen_crash_online_isolated() -> Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_keygen_crash_online")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .force_isolated() // Prevent writing PRSS/keygen data to shared test-material source
        .build()
        .await?;

    let preproc_id = derive_request_id("secure_keygen_crash_online_preproc")?;
    let keygen_id = derive_request_id("secure_keygen_crash_online")?;

    // Run preprocessing with all parties
    let mut preproc_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let preproc_req = kms_grpc::kms::v1::KeyGenPreprocRequest {
            request_id: Some(preproc_id.into()),
            params: FheParameter::Test as i32,
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            context_id: None,
            epoch_id: None,
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete on all parties
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
                .await;
        }
        result?;
    }

    // Simulate crash: Run keygen WITHOUT party 2
    let crashed_party = 2u32;

    // Run keygen with only active parties (excluding crashed party 2)
    let mut keygen_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let keygen_req = kms_grpc::kms::v1::KeyGenRequest {
            request_id: Some(keygen_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            keyset_added_info: None,
            context_id: None,
            epoch_id: None,
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Verify key generation completed on active parties (not crashed party)
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new(keygen_id.into()))
                .await;
        }
        result?;
    }

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold key generation with crash during preprocessing.
///
/// Simulates party 3 crashing during the preprocessing phase. Verifies that the remaining
/// parties (1, 2, 4) can still complete preprocessing and key generation successfully.
///
/// **IMPORTANT:** Tests crash recovery - party 3 excluded from preprocessing and keygen.
/// **Requires:**
/// - `slow_tests` feature flag (PRSS generation at runtime)
///
/// **Run with:** `cargo test --lib --features slow_tests,testing secure_threshold_keygen_crash_preprocessing_isolated`
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_keygen_crash_preprocessing_isolated() -> Result<()> {
    let env = ThresholdTestEnv::builder()
        .with_test_name("secure_keygen_crash_preproc")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .force_isolated() // Prevent writing PRSS/keygen data to shared test-material source
        .build()
        .await?;

    let preproc_id = derive_request_id("secure_keygen_crash_preproc_preproc")?;
    let keygen_id = derive_request_id("secure_keygen_crash_preproc")?;

    // Simulate crash: Run preprocessing WITHOUT party 3
    let crashed_party = 3u32;

    // Run preprocessing with only active parties
    let mut preproc_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let preproc_req = kms_grpc::kms::v1::KeyGenPreprocRequest {
            request_id: Some(preproc_id.into()),
            params: FheParameter::Test as i32,
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            context_id: None,
            epoch_id: None,
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete on active parties
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new(preproc_id.into()))
                .await;
        }
        result?;
    }

    // Run keygen with same active parties (crashed party stays crashed)
    let mut keygen_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let keygen_req = kms_grpc::kms::v1::KeyGenRequest {
            request_id: Some(keygen_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: None,
            keyset_added_info: None,
            context_id: None,
            epoch_id: None,
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Verify key generation completed on active parties
    for client in env.all_clients_except(crashed_party) {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new(keygen_id.into()))
                .await;
        }
        result?;
    }

    for server in env.into_servers() {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test secure threshold compressed key generation from existing secret shares.
///
/// Generates a standard keyset first, then performs compressed key generation
/// reusing the existing secret key shares from the first keygen. This validates
/// the end-to-end flow of compressed keygen from existing secrets through the
/// gRPC service layer.
///
/// **Workflow:**
/// 1. Standard keygen (preprocessing + online) to produce the first keyset
/// 2. Preprocessing for compressed keygen from existing shares
/// 3. Compressed keygen from existing shares
/// 4. Verify both keygens completed on all parties using ddec
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn secure_threshold_compressed_keygen_from_existing_isolated() -> Result<()> {
    use crate::client::tests::common::compressed_from_existing_keygen_config;
    use crate::consts::DEFAULT_EPOCH_ID;

    let env = ThresholdTestEnv::builder()
        .with_test_name("compressed_from_existing_keygen")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .build()
        .await?;

    let clients = &env.clients;

    // Step 1: Standard keygen (preprocessing + online)
    let preproc_id_1 = derive_request_id("compressed_existing_preproc_1")?;
    let keygen_id_1 = derive_request_id("compressed_existing_keygen_1")?;

    threshold_key_gen_secure_isolated(
        clients,
        &preproc_id_1,
        &keygen_id_1,
        FheParameter::Test,
        None,
        None,
        None,
        None,
    )
    .await?;

    // Verify standard keygen completed on all parties
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id_1.into()))
            .await?;
        assert_eq!(result.into_inner().request_id, Some(keygen_id_1.into()));
    }

    // Step 2: Compressed keygen from existing secret shares (preprocessing + online)
    let preproc_id_2 = derive_request_id("compressed_existing_preproc_2")?;
    let keygen_id_2 = derive_request_id("compressed_existing_keygen_2")?;

    let (keyset_config, keyset_added_info) =
        compressed_from_existing_keygen_config(&keygen_id_1, &DEFAULT_EPOCH_ID);

    threshold_key_gen_secure_isolated(
        clients,
        &preproc_id_2,
        &keygen_id_2,
        FheParameter::Test,
        keyset_config,
        keyset_added_info,
        None,
        None,
    )
    .await?;

    // Verify compressed keygen completed on all parties
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let result = cur_client
            .get_key_gen_result(tonic::Request::new(keygen_id_2.into()))
            .await?;
        assert_eq!(result.into_inner().request_id, Some(keygen_id_2.into()));
    }

    // Do distributed decryption to verify the generated key is ok
    // TODO this could be refactored
    use crate::client::tests::threshold::public_decryption_tests::run_decryption_threshold;
    use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
    let material_dir = env.material_dir;
    let mut servers = env.servers;
    let mut clients = env.clients;

    let material_path = material_dir.path();
    let pub_storage_prefixes = &crate::consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..4];

    // Create internal client for decryption
    let mut pub_storage_map = std::collections::HashMap::new();
    for (i, prefix) in pub_storage_prefixes.iter().enumerate() {
        pub_storage_map.insert(
            (i + 1) as u32,
            FileStorage::new(Some(material_path), StorageType::PUB, prefix.as_deref())?,
        );
    }
    let client_storage = FileStorage::new(Some(material_path), StorageType::CLIENT, None)?;
    let mut internal_client = crate::client::client_wasm::Client::new_client(
        client_storage,
        pub_storage_map,
        &crate::consts::TEST_PARAM,
        None,
    )
    .await?;

    // Run ddec with the new keyset
    run_decryption_threshold(
        4,
        &mut servers,
        &mut clients,
        &mut internal_client,
        None,
        &keygen_id_2,
        None,
        vec![TestingPlaintext::U32(66)],
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        None,
        1,
        Some(material_path),
        true,
    )
    .await;

    // Run ddec by encrypting using the old public key but
    // still the new shares from the new keyset
    run_decryption_threshold(
        4,
        &mut servers,
        &mut clients,
        &mut internal_client,
        Some(&keygen_id_1),
        &keygen_id_2,
        None,
        vec![TestingPlaintext::U32(55)],
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        None,
        1,
        Some(material_path),
        false, // we do not used compressed_keys since that was the old public key
    )
    .await;

    for (_, server) in servers {
        server.assert_shutdown().await;
    }

    Ok(())
}

/// Test insecure threshold decompression key generation with decompression validation.
///
/// Generates two regular keysets using insecure mode, then generates a decompression key
/// between them using secure mode (required for decompression keys). Validates the keys
/// by running `run_decompression_test`, matching the work done by the non-isolated
/// `run_threshold_decompression_keygen`.
///
/// **Workflow:**
/// 1. Generate first keyset (insecure mode), reconstruct ClientKey + ServerKey via verify_keygen_responses
/// 2. Generate second keyset (insecure mode), reconstruct ClientKey via verify_keygen_responses
/// 3. Generate decompression key from keyset 1 to keyset 2 (secure mode with preprocessing)
/// 4. Retrieve decompression key from public storage
/// 5. Run run_decompression_test to validate key compatibility (mirrors non-isolated verification)
#[tokio::test]
#[cfg(feature = "slow_tests")]
async fn test_insecure_threshold_decompression_keygen_isolated() -> Result<()> {
    use crate::consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL;
    use crate::vault::storage::StorageType;
    use kms_grpc::kms::v1::{KeySetAddedInfo, KeySetConfig, KeySetType};
    use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;

    let env = ThresholdTestEnv::builder()
        .with_test_name("decompression_keygen")
        .with_party_count(4)
        .with_threshold(1)
        .with_prss()
        .force_isolated() // Prevent writing PRSS/keygen data to shared test-material source
        .build()
        .await?;

    let material_path = env.material_dir.path().to_path_buf();
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await?;

    // Step 1: Generate first keyset (insecure mode), reconstruct ClientKey + ServerKey
    let key_id_1 = derive_request_id("decom_dkg_key_1")?;
    let responses_1 =
        threshold_insecure_key_gen_isolated(&env.clients, &key_id_1, FheParameter::Test).await?;
    let (keys_1, _) = verify_keygen_responses(
        responses_1,
        Some(&material_path),
        &internal_client,
        &crate::engine::base::INSECURE_PREPROCESSING_ID,
        &key_id_1,
        &dummy_domain(),
        env.clients.len(),
        None,
        false,
    )
    .await
    .expect("keygen 1 verification failed");
    let (client_key_1, _, server_key_1) = keys_1.get_standard();

    // Step 2: Generate second keyset (insecure mode), reconstruct ClientKey
    let key_id_2 = derive_request_id("decom_dkg_key_2")?;
    let responses_2 =
        threshold_insecure_key_gen_isolated(&env.clients, &key_id_2, FheParameter::Test).await?;
    let (keys_2, _) = verify_keygen_responses(
        responses_2,
        Some(&material_path),
        &internal_client,
        &crate::engine::base::INSECURE_PREPROCESSING_ID,
        &key_id_2,
        &dummy_domain(),
        env.clients.len(),
        None,
        false,
    )
    .await
    .expect("keygen 2 verification failed");
    let (client_key_2, _, _) = keys_2.get_standard();

    // Step 3: Generate decompression key (secure mode - required for decompression)
    let preproc_id_3 = derive_request_id("decom_dkg_preproc_3")?;
    let key_id_3 = derive_request_id("decom_dkg_key_3")?;

    // Run preprocessing for decompression key generation
    let mut preproc_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let preproc_req = kms_grpc::kms::v1::KeyGenPreprocRequest {
            request_id: Some(preproc_id_3.into()),
            params: FheParameter::Test as i32,
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly.into(),
                standard_keyset_config: None,
            }),
            context_id: None,
            epoch_id: None,
        };
        preproc_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(preproc_req))
                .await
        });
    }

    while let Some(res) = preproc_tasks.join_next().await {
        res??;
    }

    // Wait for preprocessing to complete
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_preproc_result(tonic::Request::new(preproc_id_3.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_preproc_result(tonic::Request::new(preproc_id_3.into()))
                .await;
        }
        result?;
    }

    // Generate decompression key with proper configuration
    let mut keygen_tasks = tokio::task::JoinSet::new();
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let keygen_req = kms_grpc::kms::v1::KeyGenRequest {
            request_id: Some(key_id_3.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(preproc_id_3.into()),
            domain: Some(domain_to_msg(&dummy_domain())),
            keyset_config: Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly.into(),
                standard_keyset_config: None,
            }),
            keyset_added_info: Some(KeySetAddedInfo {
                existing_compression_keyset_id: None,
                compression_epoch_id: None,
                from_keyset_id_decompression_only: Some(key_id_1.into()),
                to_keyset_id_decompression_only: Some(key_id_2.into()),
                existing_keyset_id: None,
                existing_epoch_id: None,
            }),
            context_id: None,
            epoch_id: None,
        };
        keygen_tasks
            .spawn(async move { cur_client.key_gen(tonic::Request::new(keygen_req)).await });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Wait for decompression key generation to complete and collect the result
    let mut keygen_result_3 = None;
    for client in env.all_clients() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_key_gen_result(tonic::Request::new(key_id_3.into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_key_gen_result(tonic::Request::new(key_id_3.into()))
                .await;
        }
        // Only need one result to retrieve the decompression key from pub storage
        if keygen_result_3.is_none() {
            keygen_result_3 = Some(result?.into_inner());
        }
    }

    // Step 4: Retrieve the decompression key from public storage (party 1's storage)
    let pub_prefix = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0];
    let pub_storage = crate::vault::storage::file::FileStorage::new(
        Some(&material_path),
        StorageType::PUB,
        pub_prefix.as_deref(),
    )?;
    let decompression_key = internal_client
        .retrieve_decompression_key(&keygen_result_3.unwrap(), &pub_storage)
        .await?
        .expect("decompression key not found in storage");

    for (_, server) in env.servers {
        server.assert_shutdown().await;
    }

    // Step 5: Validate key compatibility — mirrors run_decompression_test in the non-isolated version
    run_decompression_test(
        &client_key_1,
        &client_key_2,
        Some(&server_key_1),
        decompression_key.into_raw_parts(),
    );

    Ok(())
}
