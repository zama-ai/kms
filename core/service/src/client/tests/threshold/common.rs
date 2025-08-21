use crate::client::client_wasm::Client;
use crate::client::test_tools::ServerHandle;
use crate::util::key_setup::max_threshold;
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::make_storage;
use crate::vault::storage::{file::FileStorage, StorageType};
use crate::vault::Vault;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;

use tonic::transport::Channel;

/// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
/// of the servers, based on their ID, which starts from 1. A similar map is also returned
/// is the client endpoints needed to talk with each of the servers, finally the internal
/// client is returned (which is responsible for constructing requests and validating
/// responses).
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
    // Compute threshold < amount_parties/3
    let threshold = max_threshold(amount_parties);
    let mut pub_storage = Vec::new();
    let mut priv_storage = Vec::new();
    let mut vaults = Vec::new();
    for i in 1..=amount_parties {
        priv_storage.push(
            FileStorage::new(None, StorageType::PRIV, Some(Role::indexed_from_one(i))).unwrap(),
        );
        pub_storage.push(
            FileStorage::new(None, StorageType::PUB, Some(Role::indexed_from_one(i))).unwrap(),
        );
        let public_storage = make_storage(
            None,
            StorageType::BACKUP,
            Some(Role::indexed_from_one(i)),
            None,
            None,
        )
        .unwrap();
        vaults.push(Some(Vault {
            storage: public_storage,
            keychain: None,
        }));
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
