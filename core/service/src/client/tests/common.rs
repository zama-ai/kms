use crate::client::client_wasm::Client;
use crate::consts::TEST_PARAM;
use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::engine::utils::make_extra_data;
use crate::util::key_setup::test_tools::{
    EncryptionConfig, TestingPlaintext, compute_cipher_from_stored_key,
};
use crate::vault::storage::StorageReaderExt;
use kms_grpc::RequestId;
use kms_grpc::identifiers::{ContextId, EpochId};
use kms_grpc::kms::v1::{
    CompressedKeyConfig, KeySetAddedInfo, KeySetConfig, KeySetType, TypedCiphertext, TypedPlaintext,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::fhe_types_to_num_blocks;
use std::collections::HashMap;
use std::path::Path;
use tfhe::FheTypes;
use threshold_execution::tfhe_internals::parameters::DKGParams;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, sleep};
use tonic::transport::Channel;

// Time to sleep to ensure that previous servers and tests have shut down properly.
pub(crate) const TIME_TO_SLEEP_MS: u64 = 500;

/// Poll storage until it contains the given (`request_id`, `epoch_id`, `data_type`) tuple. Give up after 30s.
// TODO(dp): Not the most elegant solution; what's a better way? Came about because tests like e.g. `test_insecure_threshold_crs_backup`
// would try to inspect state before backup actually had time to happen.
pub(crate) async fn wait_for_storage<S>(
    storage: &S,
    request_id: &RequestId,
    epoch_id: &EpochId,
    data_type: &str,
) -> anyhow::Result<()>
where
    S: StorageReaderExt + Sync,
{
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if storage
            .data_exists_at_epoch(request_id, epoch_id, data_type)
            .await
            .unwrap_or(false)
        {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("timeout waiting for backup of {request_id}/{data_type}")
}

/// Constructs the extra data field based on the default context and epoch IDs.
pub(crate) fn default_isolated_extra_data() -> Vec<u8> {
    make_extra_data(2, Some(&DEFAULT_MPC_CONTEXT), Some(&DEFAULT_EPOCH_ID))
        .expect("make_extra_data with defaults cannot fail")
}

/// Returns the default keygen config.
///
/// The default is compressed public key material.
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) fn keygen_config() -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (
        Some(KeySetConfig {
            keyset_type: KeySetType::Standard.into(),
            standard_keyset_config: Some(kms_grpc::kms::v1::StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: 0,
                compressed_key_config: CompressedKeyConfig::CompressedAll.into(),
            }),
        }),
        None,
    )
}

/// Returns a keygen config explicitly requesting uncompressed keys.
///
/// Use this when a test specifically needs uncompressed keys.
#[cfg(any(feature = "slow_tests", feature = "insecure"))]
pub(crate) fn uncompressed_keygen_config() -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (
        Some(KeySetConfig {
            keyset_type: KeySetType::Standard.into(),
            standard_keyset_config: Some(kms_grpc::kms::v1::StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: 0,
                compressed_key_config: CompressedKeyConfig::CompressedNone.into(),
            }),
        }),
        None,
    )
}

/// Returns compressed keygen config that reuses existing secret key shares
#[cfg(feature = "slow_tests")]
pub(crate) fn keygen_config_from_existing(
    existing_keyset_id: &RequestId,
    use_existing_key_tag: bool,
) -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (
        Some(KeySetConfig {
            keyset_type: KeySetType::Standard.into(),
            standard_keyset_config: Some(kms_grpc::kms::v1::StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: kms_grpc::kms::v1::KeyGenSecretKeyConfig::UseExisting.into(),
                compressed_key_config: CompressedKeyConfig::CompressedAll.into(),
            }),
        }),
        Some(KeySetAddedInfo {
            existing_keyset_id: Some((*existing_keyset_id).into()),
            use_existing_key_tag,
            ..KeySetAddedInfo::default()
        }),
    )
}

/// Returns decompression-only keygen config
#[cfg(feature = "slow_tests")]
pub(crate) fn decompression_keygen_config(
    from_keyset_id: &RequestId,
    to_keyset_id: &RequestId,
) -> (Option<KeySetConfig>, Option<KeySetAddedInfo>) {
    (
        Some(KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        }),
        Some(KeySetAddedInfo {
            from_keyset_id_decompression_only: Some((*from_keyset_id).into()),
            to_keyset_id_decompression_only: Some((*to_keyset_id).into()),
            ..KeySetAddedInfo::default()
        }),
    )
}

/// Trait for accessing keyset config properties on `Option<KeySetConfig>`
pub(crate) trait OptKeySetConfigAccessor {
    fn is_compressed(&self) -> bool;
    fn is_decompression_only(&self) -> bool;
}

impl OptKeySetConfigAccessor for Option<KeySetConfig> {
    fn is_compressed(&self) -> bool {
        match self.as_ref() {
            // No config provided: server defaults to compressed
            None => true,
            Some(c) => match c.standard_keyset_config.as_ref() {
                // Standard type with no inner config: server defaults to compressed
                None => true,
                Some(sc) => sc.compressed_key_config == CompressedKeyConfig::CompressedAll as i32,
            },
        }
    }

    fn is_decompression_only(&self) -> bool {
        self.as_ref()
            .is_some_and(|c| c.keyset_type == KeySetType::DecompressionOnly as i32)
    }
}

/// Send decryption requests to KMS clients
///
/// # Arguments
/// * `pub_path` - Optional path to isolated test material directory
pub(crate) async fn send_dec_reqs(
    amount_cts: usize,
    key_id: &RequestId,
    context_id: Option<&ContextId>,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &mut Client,
    storage_prefixes: &[Option<String>],
    pub_path: Option<&Path>,
) -> (
    JoinSet<Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status>>,
    RequestId,
) {
    let mut cts = Vec::new();
    let storage_prefix = storage_prefixes[0].as_deref(); // just need one storage prefix to compute cts
    for i in 0..amount_cts {
        let msg = TestingPlaintext::U32(i as u32);
        let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
            pub_path,
            msg,
            key_id,
            storage_prefix,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            false, // use the default compressed keyset
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
            None,
            &[],
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
