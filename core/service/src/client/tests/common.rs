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

pub(crate) async fn send_dec_reqs(
    amount_cts: usize,
    key_id: &RequestId,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &mut Client,
) -> (
    JoinSet<Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status>>,
    RequestId,
) {
    let mut cts = Vec::new();
    for i in 0..amount_cts {
        let msg = TestingPlaintext::U32(i as u32);
        let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
            None,
            msg,
            key_id,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
        )
        .await;
        let ctt = TypedCiphertext {
            ciphertext: ct,
            fhe_type: fhe_type as i32,
            ciphertext_format: ct_format.into(),
            external_handle: i.to_be_bytes().to_vec(),
        };
        cts.push(ctt);
    }

    // make parallel requests by calling [public_decrypt] in a thread
    let request_id = derive_request_id("TEST_DEC_ID").unwrap();
    let req = internal_client
        .public_decryption_request(cts.clone(), &dummy_domain(), &request_id, key_id)
        .unwrap();
    let mut join_set = JoinSet::new();
    for i in 1..=kms_clients.len() as u32 {
        let req_clone = req.clone();
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        join_set.spawn(async move {
            cur_client
                .public_decrypt(tonic::Request::new(req_clone))
                .await
        });
    }
    (join_set, request_id)
}

pub(crate) async fn get_pub_dec_resp(
    request_id: &RequestId,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> JoinSet<Result<tonic::Response<kms_grpc::kms::v1::PublicDecryptionResponse>, tonic::Status>> {
    // make parallel requests by calling [get_public_decryption_result] in a thread
    let mut join_set = JoinSet::new();
    for i in 1..=kms_clients.len() as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        let req_id_clone = *request_id;
        join_set.spawn(async move {
            cur_client
                .get_public_decryption_result(tonic::Request::new(req_id_clone.into()))
                .await
        });
    }
    join_set
}

pub(crate) fn assert_plaintext(expected: &TestingPlaintext, plaintext: &TypedPlaintext) {
    assert_eq!(expected.fhe_type(), plaintext.fhe_type().unwrap());
    match expected {
        TestingPlaintext::Bool(x) => assert_eq!(*x, plaintext.as_bool()),
        TestingPlaintext::U4(x) => assert_eq!(*x, plaintext.as_u4()),
        TestingPlaintext::U8(x) => assert_eq!(*x, plaintext.as_u8()),
        TestingPlaintext::U16(x) => assert_eq!(*x, plaintext.as_u16()),
        TestingPlaintext::U32(x) => assert_eq!(*x, plaintext.as_u32()),
        TestingPlaintext::U64(x) => assert_eq!(*x, plaintext.as_u64()),
        TestingPlaintext::U80(x) => assert_eq!(*x, plaintext.as_u80()),
        TestingPlaintext::U128(x) => assert_eq!(*x, plaintext.as_u128()),
        TestingPlaintext::U160(x) => assert_eq!(*x, plaintext.as_u160()),
        TestingPlaintext::U256(x) => assert_eq!(*x, plaintext.as_u256()),
        TestingPlaintext::U512(x) => assert_eq!(*x, plaintext.as_u512()),
        TestingPlaintext::U1024(x) => assert_eq!(*x, plaintext.as_u1024()),
        TestingPlaintext::U2048(x) => assert_eq!(*x, plaintext.as_u2048()),
    }
}

#[test]
fn num_blocks_sunshine() {
    let params: DKGParams = TEST_PARAM;
    let params = &params
        .get_params_basics_handle()
        .to_classic_pbs_parameters();
    // 2 bits per block, using Ebool as internal representation
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Bool, params, 1).unwrap(),
        1
    );
    // 2 bits per block, using Euint4 as internal representation
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint4, params, 1).unwrap(),
        2
    );
    // 2 bits per block
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint8, params, 1).unwrap(),
        4
    );
    // 2 bits per block
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint16, params, 1).unwrap(),
        8
    );
    // 2 bits per block
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint32, params, 1).unwrap(),
        16
    );
    // 2 bits per block
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint64, params, 1).unwrap(),
        32
    );
    // 2 bits per block
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint128, params, 1).unwrap(),
        64
    );
    // 2 bits per block
    assert_eq!(
        fhe_types_to_num_blocks(FheTypes::Uint160, params, 1).unwrap(),
        80
    );
}
