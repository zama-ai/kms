use crate::client::tests::threshold::crs_gen_tests::crs_gen;
use crate::client::tests::threshold::key_gen_tests::{
    preproc_and_keygen, run_threshold_decompression_keygen,
};
use crate::client::tests::threshold::public_decryption_tests::decryption_threshold;
use crate::client::tests::threshold::user_decryption_tests::user_decryption_threshold;
use crate::consts::DEFAULT_THRESHOLD_KEY_ID;
use crate::consts::{DEFAULT_AMOUNT_PARTIES, DEFAULT_PARAM};
use crate::util::key_setup::test_tools::EncryptionConfig;
use crate::util::key_setup::test_tools::TestingPlaintext;
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;
use threshold_fhe::execution::runtime::party::Role;

#[rstest::rstest]
#[case(vec![TestingPlaintext::Bool(true)], 2, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U16(u16::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U64(u64::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[tracing_test::traced_test]
async fn default_decryption_threshold_with_sns_preprocessing(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true, false)] compression: bool,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        parallelism,
        amount_parties,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, DEFAULT_AMOUNT_PARTIES, Some(vec![7,4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::Bool(true)], 4, DEFAULT_AMOUNT_PARTIES, Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, DEFAULT_AMOUNT_PARTIES,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1, DEFAULT_AMOUNT_PARTIES, Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1, DEFAULT_AMOUNT_PARTIES, Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
// Note: the following takes approx. 138 secs locally. Disabled since we only support up to 256 bits for now starting with v0.12.0
// #[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, DEFAULT_AMOUNT_PARTIES,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_decryption_threshold_with_crash(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] party_ids_to_crash: Option<Vec<usize>>,
    #[case] key_id: &RequestId,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        amount_parties,
        party_ids_to_crash,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::Bool(true), 2, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U16(u16::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U32(u32::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U64(u64::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U128(u128::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[serial]
#[tracing_test::traced_test]
async fn default_user_decryption_threshold(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true)] secure: bool,
) {
    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::Bool(true), 2, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U16(u16::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U32(u32::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U64(u64::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U128(u128::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[serial]
#[tracing_test::traced_test]
async fn default_user_decryption_threshold_sns_precompute(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true, false)] compression: bool,
) {
    let secure = true;
    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        false,
        false,
        msg,
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        parallelism,
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![2,6,7]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::Bool(true), 4, DEFAULT_AMOUNT_PARTIES, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U16(u16::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U32(u32::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U64(u64::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U128(u128::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, DEFAULT_AMOUNT_PARTIES ,Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_user_decryption_threshold_with_crash(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] party_ids_to_crash: Option<Vec<usize>>,
    #[case] key_id: &RequestId,
    #[values(true, false)] secure: bool,
) {
    use crate::consts::DEFAULT_PARAM;

    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
        amount_parties,
        party_ids_to_crash.map(|party_ids| {
            party_ids
                .iter()
                .map(|id| Role::indexed_from_zero(*id))
                .collect()
        }),
        None,
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[tracing_test::traced_test]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_sequential_crs_test(#[case] amount_parties: usize) {
    // NOTE: When using tests parameters for CRS gen the maximum amount of bits supported is 512

    crs_gen(
        amount_parties,
        FheParameter::Test,
        Some(512),
        false,
        2,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_concurrent_crs_test(#[case] amount_parties: usize) {
    // NOTE: When using tests parameters for CRS gen the maximum amount of bits supported is 512
    crs_gen(
        amount_parties,
        FheParameter::Test,
        Some(512),
        false,
        2,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_sequential_crs_default(#[case] amount_parties: usize) {
    crs_gen(
        amount_parties,
        FheParameter::Default,
        Some(512),
        false,
        2,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_concurrent_crs_default(#[case] amount_parties: usize) {
    crs_gen(
        amount_parties,
        FheParameter::Default,
        Some(2048),
        false,
        2,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_sequential_keygen_test(#[case] amount_parties: usize) {
    preproc_and_keygen(
        amount_parties,
        FheParameter::Test,
        false,
        2,
        false,
        None,
        None,
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(4)]
#[serial]
async fn secure_threshold_keygen_with_partial_preproc(#[case] amount_parties: usize) {
    preproc_and_keygen(
        amount_parties,
        FheParameter::Test,
        false,
        1,
        false,
        None,
        None,
        Some(kms_grpc::kms::v1::PartialKeyGenPreprocParams {
            percentage_offline: 10,
            store_dummy_preprocessing: true,
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_concurrent_keygen_test(#[case] amount_parties: usize) {
    preproc_and_keygen(
        amount_parties,
        FheParameter::Test,
        false,
        2,
        true,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_decompression_keygen(#[case] amount_parties: usize) {
    run_threshold_decompression_keygen(amount_parties, FheParameter::Test, false).await;
}
