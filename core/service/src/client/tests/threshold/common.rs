use crate::client::client_wasm::Client;
use crate::client::test_tools::ServerHandle;
use crate::conf::{self, Keychain, SecretSharingKeychain};
use crate::consts::SIGNING_KEY_ID;
#[cfg(feature = "slow_tests")]
use crate::util::key_setup::test_tools::setup::ensure_default_material_exists;
use crate::util::key_setup::test_tools::setup::{ensure_dir_exist, ensure_testing_material_exists};
use crate::util::key_setup::{
    ensure_client_keys_exist, ensure_threshold_server_signing_keys_exist, max_threshold,
    ThresholdSigningKeyConfig,
};
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::keychain::make_keychain_proxy;
use crate::vault::storage::make_storage;
use crate::vault::storage::{file::FileStorage, StorageType};
use crate::vault::Vault;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use std::path::Path;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tonic::transport::Channel;

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
    for i in 1..=amount_parties {
        let cur_role = Role::indexed_from_one(i);
        priv_storage
            .push(FileStorage::new(test_data_path, StorageType::PRIV, Some(cur_role)).unwrap());
        pub_storage
            .push(FileStorage::new(test_data_path, StorageType::PUB, Some(cur_role)).unwrap());
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
        )
        .await;
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
    for i in 1..=amount_parties {
        pub_storage.insert(
            i as u32,
            FileStorage::new(None, StorageType::PUB, Some(Role::indexed_from_one(i))).unwrap(),
        );
    }
    let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
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
    for i in 1..=amount_parties {
        let cur_role = Role::indexed_from_one(i);
        let cur_vault = file_system_vault(cur_role, None).await;
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
    for i in 1..=amount_parties {
        let cur_role = Role::indexed_from_one(i);
        let cur_vault = custodian_backup_vault(cur_role, test_data_path).await;
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
    let store_path = test_data_path.map(|p| {
        conf::Storage::File(conf::FileStorage {
            path: p.to_path_buf(),
        })
    });
    let pub_proxy_storage =
        make_storage(store_path.clone(), StorageType::PUB, Some(role), None, None).unwrap();
    let backup_proxy_storage =
        make_storage(store_path, StorageType::BACKUP, Some(role), None, None).unwrap();
    let keychain = Some(
        make_keychain_proxy(
            &Keychain::SecretSharing(SecretSharingKeychain {}),
            None,
            None,
            Some(&pub_proxy_storage),
        )
        .await
        .unwrap(),
    );
    Vault {
        storage: backup_proxy_storage,
        keychain,
    }
}

pub(crate) async fn file_system_vault(role: Role, test_data_path: Option<&Path>) -> Vault {
    let store_path = test_data_path.map(|p| {
        conf::Storage::File(conf::FileStorage {
            path: p.to_path_buf(),
        })
    });
    let backup_proxy_storage =
        make_storage(store_path, StorageType::BACKUP, Some(role), None, None).unwrap();
    Vault {
        storage: backup_proxy_storage,
        keychain: None,
    }
}
