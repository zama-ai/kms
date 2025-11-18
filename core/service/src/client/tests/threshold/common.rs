use crate::client::client_wasm::Client;
use crate::client::test_tools::ServerHandle;
use crate::conf::{Keychain, SecretSharingKeychain};
use crate::consts::{
    BACKUP_STORAGE_PREFIX_THRESHOLD_ALL, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
    PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, SIGNING_KEY_ID,
};
use crate::util::key_setup::test_tools::file_backup_vault;
#[cfg(feature = "slow_tests")]
use crate::util::key_setup::test_tools::setup::ensure_default_material_exists;
use crate::util::key_setup::test_tools::setup::{ensure_dir_exist, ensure_testing_material_exists};
use crate::util::key_setup::{
    ensure_client_keys_exist, ensure_threshold_server_signing_keys_exist, max_threshold,
    ThresholdSigningKeyConfig,
};
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::{file::FileStorage, StorageType};
use crate::vault::Vault;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use std::path::Path;
use tfhe::core_crypto::commons::utils::ZipChecked;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tonic::transport::Channel;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Create storage configuration from optional path
fn storage_config_from_path(path: Option<&Path>) -> Option<conf::Storage> {
    path.map(|p| {
        conf::Storage::File(conf::FileStorage {
            path: p.to_path_buf(),
        })
    })
}

/// Create storage proxy for given type and role
fn create_storage_proxy(
    path: Option<&Path>,
    storage_type: StorageType,
    role: Option<Role>,
) -> crate::vault::storage::StorageProxy {
    make_storage(
        storage_config_from_path(path),
        storage_type,
        role,
        None,
        None,
    )
    .unwrap()
}

// ============================================================================
// TEST SETUP FUNCTIONS
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn threshold_handles_w_vaults(
    params: DKGParams,
    amount_parties: usize,
    run_prss: bool,
    generate_test_material: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    decryption_mode: Option<DecryptionMode>,
    vaults: Vec<Option<Vault>>,
    test_data_path: Option<&Path>,
) -> (
    HashMap<u32, ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
    Client,
) {
    // Compute threshold < amount_parties/3
    let threshold = max_threshold(amount_parties);
    let mut pub_storage = Vec::new();
    let mut priv_storage = Vec::new();
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    for (pub_prefix, priv_prefix) in pub_storage_prefixes
        .iter()
        .zip(priv_storage_prefixes.iter())
    {
        pub_storage.push(
            FileStorage::new(test_data_path, StorageType::PUB, pub_prefix.as_deref()).unwrap(),
        );
        priv_storage.push(
            FileStorage::new(test_data_path, StorageType::PRIV, priv_prefix.as_deref()).unwrap(),
        );
    }
    if generate_test_material {
        ensure_testing_material_exists(test_data_path).await;
        #[cfg(feature = "slow_tests")]
        ensure_default_material_exists().await;
    } else {
        // Only ensure that the signing key is there s.t. the KMS can start
        // TODO(#2491) this will be handled better when we add contexts s.t. we have different signing keys
        ensure_dir_exist(test_data_path).await;
        ensure_client_keys_exist(test_data_path, &SIGNING_KEY_ID, true).await;
        let _ = ensure_threshold_server_signing_keys_exist(
            &mut pub_storage,
            &mut priv_storage,
            &SIGNING_KEY_ID,
            true,
            ThresholdSigningKeyConfig::AllParties(
                (1..=amount_parties).map(|i| format!("party-{i}")).collect(),
            ),
            true,
        )
        .await
        .unwrap();
    }

    let (kms_servers, kms_clients) = crate::client::test_tools::setup_threshold(
        threshold as u8,
        pub_storage,
        priv_storage,
        vaults,
        run_prss,
        rate_limiter_conf,
        decryption_mode,
    )
    .await;
    let mut pub_storage = HashMap::with_capacity(amount_parties);
    for (i, prefix) in pub_storage_prefixes.iter().enumerate() {
        pub_storage.insert(
            (i + 1) as u32,
            FileStorage::new(test_data_path, StorageType::PUB, prefix.as_deref()).unwrap(),
        );
    }
    let client_storage = FileStorage::new(test_data_path, StorageType::CLIENT, None).unwrap();
    let internal_client = Client::new_client(client_storage, pub_storage, &params, decryption_mode)
        .await
        .unwrap();
    (kms_servers, kms_clients, internal_client)
}

/// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
/// of the servers, based on their ID, which starts from 1. A similar map is also returned
/// is the client endpoints needed to talk with each of the servers, finally the internal
/// client is returned (which is responsible for constructing requests and validating
/// responses).
/// This provides a setup _without_ custodian backup. Instead the backup vaults are just realized using
/// an uncrypted file storage.
pub(crate) async fn threshold_handles(
    params: DKGParams,
    amount_parties: usize,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    decryption_mode: Option<DecryptionMode>,
) -> (
    HashMap<u32, ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
    Client,
) {
    let mut vaults = Vec::new();
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let backup_storage_prefixes = &BACKUP_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    for (pub_prefix, backup_prefix) in pub_storage_prefixes
        .iter()
        .zip(backup_storage_prefixes.iter())
    {
        let cur_vault = file_backup_vault(
            None,
            None,
            None,
            pub_prefix.as_deref(),
            backup_prefix.as_deref(),
        )
        .await;
        vaults.push(Some(cur_vault));
    }
    threshold_handles_w_vaults(
        params,
        amount_parties,
        run_prss,
        true,
        rate_limiter_conf,
        decryption_mode,
        vaults,
        None, // Default test path
    )
    .await
}

/// Setup servers for backup tests
/// This means that secret sharing based custodian backup gets setup
/// with testing material _optionally_ being generated
pub(crate) async fn threshold_handles_custodian_backup(
    params: DKGParams,
    amount_parties: usize,
    run_prss: bool,
    generate_test_material: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    decryption_mode: Option<DecryptionMode>,
    test_data_path: Option<&Path>,
) -> (
    HashMap<u32, ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
    Client,
) {
    let mut vaults = Vec::new();
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let backup_storage_prefixes = &BACKUP_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    for (pub_prefix, backup_prefix) in pub_storage_prefixes
        .iter()
        .zip_checked(backup_storage_prefixes.iter())
    {
        let cur_vault = file_backup_vault(
            Some(&Keychain::SecretSharing(SecretSharingKeychain {})),
            test_data_path,
            test_data_path,
            pub_prefix.as_deref(),
            backup_prefix.as_deref(),
        )
        .await;
        vaults.push(Some(cur_vault));
    }
    threshold_handles_w_vaults(
        params,
        amount_parties,
        run_prss,
        generate_test_material,
        rate_limiter_conf,
        decryption_mode,
        vaults,
        test_data_path,
    )
    .await
}

pub(crate) async fn custodian_backup_vault(role: Role, test_data_path: Option<&Path>) -> Vault {
    let pub_proxy = create_storage_proxy(test_data_path, StorageType::PUB, Some(role));
    let backup_proxy = create_storage_proxy(test_data_path, StorageType::BACKUP, Some(role));
    let keychain = Some(
        make_keychain_proxy(
            &Keychain::SecretSharing(SecretSharingKeychain {}),
            None,
            None,
            Some(&pub_proxy),
        )
        .await
        .unwrap(),
    );
    Vault {
        storage: backup_proxy,
        keychain,
    }
}

pub(crate) async fn file_system_vault(role: Role, test_data_path: Option<&Path>) -> Vault {
    let backup_proxy = create_storage_proxy(test_data_path, StorageType::BACKUP, Some(role));
    Vault {
        storage: backup_proxy,
        keychain: None,
    }
}

// ============================================================================
// ISOLATED TEST HELPERS
// ============================================================================

/// Helper to generate threshold key using insecure mode (for isolated tests)
#[cfg(feature = "insecure")]
pub async fn threshold_key_gen_isolated(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    request_id: &kms_grpc::RequestId,
    params: kms_grpc::kms::v1::FheParameter,
) -> anyhow::Result<()> {
    use crate::client::test_tools::domain_to_msg;
    use crate::dummy_domain;
    use kms_grpc::kms::v1::KeyGenRequest;
    use tokio::task::JoinSet;

    let domain_msg = domain_to_msg(&dummy_domain());

    // Use insecure_key_gen endpoint which bypasses preprocessing validation
    let mut keygen_tasks = JoinSet::new();
    for client in clients.values() {
        let mut cur_client = client.clone();
        let keygen_req = KeyGenRequest {
            request_id: Some((*request_id).into()),
            params: Some(params as i32),
            preproc_id: None,
            domain: Some(domain_msg.clone()),
            keyset_config: None,
            keyset_added_info: None,
            context_id: None,
            epoch_id: None,
        };
        keygen_tasks.spawn(async move {
            cur_client
                .insecure_key_gen(tonic::Request::new(keygen_req))
                .await
        });
    }

    while let Some(res) = keygen_tasks.join_next().await {
        res??;
    }

    // Wait for key generation to complete on all parties
    for client in clients.values() {
        let mut cur_client = client.clone();
        let mut result = cur_client
            .get_insecure_key_gen_result(tonic::Request::new((*request_id).into()))
            .await;
        while result.is_err() && result.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            result = cur_client
                .get_insecure_key_gen_result(tonic::Request::new((*request_id).into()))
                .await;
        }
        result?;
    }

    Ok(())
}
