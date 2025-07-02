use super::{
    decryption_centralized, decryption_threshold, user_decryption_centralized,
    user_decryption_threshold,
};
use crate::client::tests::crs_gen;
use crate::client::tests::{
    crs_gen_centralized, preproc_and_keygen, run_threshold_decompression_keygen,
};
use crate::consts::{DEFAULT_AMOUNT_PARTIES, DEFAULT_PARAM};
use crate::consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_KEY_ID};
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_tools::EncryptionConfig;
use crate::util::key_setup::test_tools::{purge, TestingPlaintext};
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;

#[rstest::rstest]
#[case(vec![TestingPlaintext::Bool(true)], 2, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U16(u16::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U64(u64::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U80((1u128 << 80) - 1)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[tracing_test::traced_test]
async fn default_decryption_threshold_with_sns_preprocessing(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression: false, // in the future we will have precompute_sns with compression
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
#[case(vec![TestingPlaintext::Bool(true)], 5)]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 4)]
#[case(vec![TestingPlaintext::U8(0)], 4)]
#[case(vec![TestingPlaintext::U16(u16::MAX)], 2)]
#[case(vec![TestingPlaintext::U16(0)], 1)]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1)]
#[case(vec![TestingPlaintext::U32(1234567)], 1)]
#[case(vec![TestingPlaintext::U64(u64::MAX)], 1)]
#[case(vec![TestingPlaintext::U80((1u128 << 80) - 1)], 1)]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1)]
#[case(vec![TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1)]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1)]
#[case(vec![TestingPlaintext::U512(tfhe::integer::bigint::U512::from([512_u64; 8]))], 1)]
#[case(vec![TestingPlaintext::U1024(tfhe::integer::bigint::U1024::from([1024_u64; 16]))], 1)]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1)]
#[case(vec![TestingPlaintext::U8(0), TestingPlaintext::U64(999), TestingPlaintext::U32(32),TestingPlaintext::U128(99887766)], 1)] // test mixed types in batch
#[case(vec![TestingPlaintext::U8(0), TestingPlaintext::U64(999), TestingPlaintext::U32(32)], 3)] // test mixed types in batch and in parallel
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_decryption_centralized(
    #[case] msgs: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
) {
    decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        msgs,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::Bool(true)], 5)]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 4)]
#[case(vec![TestingPlaintext::U8(0)], 4)]
#[case(vec![TestingPlaintext::U16(u16::MAX)], 2)]
#[case(vec![TestingPlaintext::U16(0)], 1)]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1)]
#[case(vec![TestingPlaintext::U32(1234567)], 1)]
#[case(vec![TestingPlaintext::U64(u64::MAX)], 1)]
#[case(vec![TestingPlaintext::U80((1u128 << 80) - 1)], 1)]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1)]
#[case(vec![TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1)]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1)]
#[case(vec![TestingPlaintext::U512(tfhe::integer::bigint::U512::from([512_u64; 8]))], 1)]
#[case(vec![TestingPlaintext::U1024(tfhe::integer::bigint::U1024::from([1024_u64; 16]))], 1)]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1)]
#[case(vec![TestingPlaintext::U8(0), TestingPlaintext::U64(999), TestingPlaintext::U32(32),TestingPlaintext::U128(99887766)], 1)] // test mixed types in batch
#[case(vec![TestingPlaintext::U8(0), TestingPlaintext::U64(999), TestingPlaintext::U32(32)], 3)] // test mixed types in batch and in parallel
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_decryption_centralized_precompute_sns(
    #[case] msgs: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
) {
    decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        msgs,
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        parallelism,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::Bool(true), 2)]
#[case(TestingPlaintext::U8(u8::MAX), 1)]
#[case(TestingPlaintext::U8(0), 1)]
#[case(TestingPlaintext::U16(u16::MAX), 1)]
#[case(TestingPlaintext::U16(0), 1)]
#[case(TestingPlaintext::U32(u32::MAX), 1)]
#[case(TestingPlaintext::U32(1234567), 1)]
#[case(TestingPlaintext::U64(u64::MAX), 1)]
#[case(TestingPlaintext::U80((1u128 << 80) - 1), 1)]
#[case(TestingPlaintext::U128(u128::MAX), 1)]
#[case(TestingPlaintext::U128(0), 1)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_centralized(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[values(true, false)] secure: bool,
) {
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::Bool(true), 2)]
#[case(TestingPlaintext::U8(u8::MAX), 1)]
#[case(TestingPlaintext::U8(0), 1)]
#[case(TestingPlaintext::U16(u16::MAX), 1)]
#[case(TestingPlaintext::U16(0), 1)]
#[case(TestingPlaintext::U32(u32::MAX), 1)]
#[case(TestingPlaintext::U32(1234567), 1)]
#[case(TestingPlaintext::U64(u64::MAX), 1)]
#[case(TestingPlaintext::U80((1u128 << 80) - 1), 1)]
#[case(TestingPlaintext::U128(u128::MAX), 1)]
#[case(TestingPlaintext::U128(0), 1)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_centralized_precompute_sns(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[values(true, false)] secure: bool,
) {
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        false,
        msg,
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        parallelism,
        secure,
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
// Note: this takes approx. 138 secs locally.
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, DEFAULT_AMOUNT_PARTIES,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
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
#[case(TestingPlaintext::U80((1u128 << 80) - 1), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U128(u128::MAX), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
// Note: this takes approx. 300 secs locally.
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1, DEFAULT_AMOUNT_PARTIES, &DEFAULT_THRESHOLD_KEY_ID)]
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
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![2,6,7]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::Bool(true), 4, DEFAULT_AMOUNT_PARTIES, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U8(u8::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U16(u16::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U32(u32::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U64(u64::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U80((1u128 << 80) - 1), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U128(u128::MAX), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, DEFAULT_AMOUNT_PARTIES ,Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID)]
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1, DEFAULT_AMOUNT_PARTIES, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID)]
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
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
        amount_parties,
        party_ids_to_crash,
        None,
        None,
    )
    .await;
}

// We test for both insecure and secure since these are distinct endpoints, although inner computation is the same
#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_crs_gen_centralized() {
    let crs_req_id = derive_request_id("default_insecure_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, &crs_req_id, 1).await;

    crs_gen_centralized(&crs_req_id, FheParameter::Default, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_crs_gen_centralized() {
    let crs_req_id = derive_request_id("default_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, &crs_req_id, 1).await;
    // We test for both insecure and secure since these are distinct endpoints, although inner computation is the same
    crs_gen_centralized(&crs_req_id, FheParameter::Default, false).await;
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
    preproc_and_keygen(amount_parties, FheParameter::Test, false, 2, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(DEFAULT_AMOUNT_PARTIES)]
#[serial]
async fn secure_threshold_concurrent_keygen_test(#[case] amount_parties: usize) {
    preproc_and_keygen(amount_parties, FheParameter::Test, false, 2, true).await;
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
