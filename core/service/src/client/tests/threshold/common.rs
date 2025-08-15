use crate::client::test_tools::check_port_is_closed;
use crate::client::test_tools::ServerHandle;
use crate::client::Client;
#[cfg(feature = "wasm_tests")]
use crate::client::TestingUserDecryptionTranscript;
use crate::client::{await_server_ready, get_health_client, get_status};
use crate::client::{ParsedUserDecryptionRequest, ServerIdentities};
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::consts::DEFAULT_PARAM;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::consts::MAX_TRIES;
use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
use crate::consts::{DEFAULT_AMOUNT_PARTIES, TEST_CENTRAL_KEY_ID};
#[cfg(feature = "slow_tests")]
use crate::consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_KEY_ID_4P};
use crate::consts::{DEFAULT_THRESHOLD, TEST_THRESHOLD_KEY_ID_10P};
use crate::consts::{PRSS_INIT_REQ_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID};
use crate::cryptography::internal_crypto_types::{PrivateSigKey, Signature};
use crate::cryptography::internal_crypto_types::{
    UnifiedPrivateEncKey, UnifiedPublicEncKey, WrappedDKGParams,
};
use crate::dummy_domain;
use crate::engine::base::{compute_handle, derive_request_id, BaseKmsStruct, DSEP_PUBDATA_CRS};
#[cfg(feature = "slow_tests")]
use crate::engine::centralized::central_kms::tests::get_default_keys;
use crate::engine::centralized::central_kms::RealCentralizedKms;
use crate::engine::threshold::service::RealThresholdKms;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::engine::traits::BaseKms;
use crate::engine::validation::DSEP_USER_DECRYPTION;
#[cfg(feature = "wasm_tests")]
use crate::util::file_handling::write_element;
use crate::util::key_setup::max_threshold;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, purge, EncryptionConfig, TestingPlaintext,
};
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::crypto_material::get_core_signing_key;
#[cfg(feature = "insecure")]
use crate::vault::storage::delete_all_at_request_id;
use crate::vault::storage::{file::FileStorage, StorageType};
use crate::vault::storage::{make_storage, StorageReader};
use crate::vault::Vault;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use kms_grpc::kms::v1::CrsGenRequest;
use kms_grpc::kms::v1::{
    Empty, FheParameter, InitRequest, KeySetAddedInfo, KeySetConfig, KeySetType, TypedCiphertext,
    TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::{fhe_types_to_num_blocks, PrivDataType};
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType};
use kms_grpc::RequestId;
use serial_test::serial;
use std::collections::{hash_map::Entry, HashMap};
use std::str::FromStr;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use std::sync::Arc;
use tfhe::core_crypto::prelude::{
    decrypt_lwe_ciphertext, divide_round, ContiguousEntityContainer, LweCiphertextOwned,
};
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::prelude::ParameterSetConformant;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
use tfhe::shortint::server_key::ModulusSwitchConfiguration;
use tfhe::zk::CompactPkeCrs;
use tfhe::Tag;
use tfhe::{FheTypes, ProvenCompactCiphertextList};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "wasm_tests")]
use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;
use threshold_fhe::networking::grpc::GrpcServer;
use tokio::task::JoinSet;
use tonic::server::NamedService;
use tonic::transport::Channel;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::HealthCheckRequest;

// Time to sleep to ensure that previous servers and tests have shut down properly.
const TIME_TO_SLEEP_MS: u64 = 500;

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
