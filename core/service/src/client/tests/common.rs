use crate::client::client_wasm::Client;
use crate::consts::TEST_PARAM;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext,
};
use kms_grpc::identifiers::ContextId;
use kms_grpc::kms::v1::{TypedCiphertext, TypedPlaintext};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::fhe_types_to_num_blocks;
use kms_grpc::RequestId;
use std::collections::HashMap;
use tfhe::FheTypes;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::task::JoinSet;
use tonic::transport::Channel;

// Time to sleep to ensure that previous servers and tests have shut down properly.
pub(crate) const TIME_TO_SLEEP_MS: u64 = 500;

pub(crate) async fn send_dec_reqs(
    amount_cts: usize,
    key_id: &RequestId,
    context_id: Option<&ContextId>,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &mut Client,
    storage_prefixes: &[Option<String>],
) -> (
    JoinSet<Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status>>,
    RequestId,
) {
    let mut cts = Vec::new();
    let storage_prefix = storage_prefixes[0].as_deref(); // just need one storage prefix to compute cts
    for i in 0..amount_cts {
        let msg = TestingPlaintext::U32(i as u32);
        let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
            None,
            msg,
            key_id,
            storage_prefix,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            false, // compressed_keys
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
        .public_decryption_request(
            cts.clone(),
            &dummy_domain(),
            &request_id,
            context_id,
            key_id,
        )
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
        TestingPlaintext::U8(x) => assert_eq!(*x, plaintext.as_u8()),
        TestingPlaintext::U16(x) => assert_eq!(*x, plaintext.as_u16()),
        TestingPlaintext::U32(x) => assert_eq!(*x, plaintext.as_u32()),
        TestingPlaintext::U64(x) => assert_eq!(*x, plaintext.as_u64()),
        TestingPlaintext::U128(x) => assert_eq!(*x, plaintext.as_u128()),
        TestingPlaintext::U160(x) => assert_eq!(*x, plaintext.as_u160()),
        TestingPlaintext::U256(x) => assert_eq!(*x, plaintext.as_u256()),
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
