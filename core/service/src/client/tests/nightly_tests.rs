use super::{
    decryption_centralized, decryption_threshold, reencryption_centralized, reencryption_threshold,
    verify_proven_ct_centralized, verify_proven_ct_threshold,
};
use crate::client::tests::crs_gen;
use crate::client::tests::{
    crs_gen_centralized, preproc_and_keygen, run_threshold_decompression_keygen,
};
use crate::consts::DEFAULT_PARAM;
use crate::consts::{
    DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_CRS_ID_10P, DEFAULT_THRESHOLD_KEY_ID_10P,
    DEFAULT_THRESHOLD_KEY_ID_4P,
};
use crate::util::key_setup::test_tools::EncryptionConfig;
use crate::util::key_setup::test_tools::{purge, TestingPlaintext};
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::kms::v1::RequestId;
use serial_test::serial;

#[rstest::rstest]
#[case(vec![TestingPlaintext::Bool(true)])]
#[case(vec![TestingPlaintext::U4(12)])]
#[case(vec![TestingPlaintext::U8(u8::MAX)])]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))])]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_verify_proven_ct_centralized(#[case] msgs: Vec<TestingPlaintext>) {
    let proven_ct_id = RequestId::derive("default_verify_proven_ct_centralized").unwrap();
    verify_proven_ct_centralized(
        msgs,
        &crate::consts::DEFAULT_PARAM,
        &proven_ct_id,
        &crate::consts::DEFAULT_CENTRAL_CRS_ID,
        &DEFAULT_CENTRAL_KEY_ID.to_string(),
    )
    .await;
}

#[rstest::rstest]
#[case(vec![TestingPlaintext::Bool(true)], 2, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 10, true, &DEFAULT_THRESHOLD_KEY_ID_10P.to_string())]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U16(u16::MAX)], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U64(u64::MAX)], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, 4, true, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[tracing_test::traced_test]
async fn default_decryption_threshold(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] compression: bool,
    #[case] key_id: &str,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression,
            precompute_sns: false,
        },
        parallelism,
        amount_parties,
        None,
        None,
    )
    .await;
}

#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 10, &DEFAULT_THRESHOLD_KEY_ID_10P.to_string())]
#[case(vec![TestingPlaintext::Bool(true)], 2, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U16(u16::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U64(u64::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[tracing_test::traced_test]
async fn default_decryption_threshold_with_sns_preprocessing(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &str,
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

#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 10, &DEFAULT_THRESHOLD_KEY_ID_10P, &DEFAULT_THRESHOLD_CRS_ID_10P)]
#[case(vec![TestingPlaintext::U128(u128::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_10P)]
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_10P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[tracing_test::traced_test]
async fn default_verify_proven_ct_threshold(
    #[case] msgs: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] crs_id: &RequestId,
) {
    verify_proven_ct_threshold(
        msgs,
        parallelism,
        crs_id,
        key_id,
        DEFAULT_PARAM,
        amount_parties,
        None,
    )
    .await
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
        &DEFAULT_CENTRAL_KEY_ID.to_string(),
        msgs,
        parallelism,
        false,
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
#[case(TestingPlaintext::U128(u128::MAX), 1)]
#[case(TestingPlaintext::U128(0), 1)]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_reencryption_centralized(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[values(true, false)] secure: bool,
) {
    reencryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID.to_string(),
        false,
        msg,
        parallelism,
        secure,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 10, Some(vec![7,4]), &DEFAULT_THRESHOLD_KEY_ID_10P.to_string())]
#[case(vec![TestingPlaintext::Bool(true)], 4, 4, Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U32(u32::MAX)], 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(vec![TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
// Note: this takes approx. 138 secs locally.
#[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_decryption_threshold_with_crash(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] party_ids_to_crash: Option<Vec<usize>>,
    #[case] key_id: &str,
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
#[case(TestingPlaintext::U8(u8::MAX), 1, 10, &DEFAULT_THRESHOLD_KEY_ID_10P.to_string())]
#[case(TestingPlaintext::Bool(true), 2, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U16(u16::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U32(u32::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U64(u64::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U128(u128::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
// Note: this takes approx. 300 secs locally.
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[serial]
#[tracing_test::traced_test]
async fn default_reencryption_threshold(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &str,
    #[values(true)] secure: bool,
) {
    reencryption_threshold(
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
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, 10, Some(vec![2,6,7]), &DEFAULT_THRESHOLD_KEY_ID_10P.to_string())]
#[case(TestingPlaintext::Bool(true), 4, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U16(u16::MAX), 1, 4,Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U32(u32::MAX), 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U64(u64::MAX), 1, 4,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U128(u128::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, 4,Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_reencryption_threshold_with_crash(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] party_ids_to_crash: Option<Vec<usize>>,
    #[case] key_id: &str,
    #[values(true, false)] secure: bool,
) {
    use crate::consts::DEFAULT_PARAM;

    reencryption_threshold(
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
    )
    .await;
}

// We test for both insecure and secure since these are distinct endpoints, although inner computation is the same
#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(4)]
#[case(10)]
#[serial]
async fn default_insecure_crs_gen_centralized(#[case] amount_parties: usize) {
    let crs_req_id = RequestId::derive(&format!(
        "default_insecure_crs_gen_centralized_{amount_parties}"
    ))
    .unwrap();
    // Delete potentially old data
    purge(None, None, &crs_req_id.to_string(), 1).await;

    crs_gen_centralized(&crs_req_id, FheParameter::Default, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(4)]
#[case(10)]
#[serial]
async fn default_crs_gen_centralized(#[case] amount_parties: usize) {
    let crs_req_id =
        RequestId::derive(&format!("default_crs_gen_centralized_{amount_parties}")).unwrap();
    // Delete potentially old data
    purge(None, None, &crs_req_id.to_string(), 1).await;
    // We test for both insecure and secure since these are distinct endpoints, although inner computation is the same
    crs_gen_centralized(&crs_req_id, FheParameter::Default, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[tracing_test::traced_test]
#[case(4)]
#[case(10)]
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
#[case(7)]
#[case(10)]
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
#[case(10)]
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
#[case(10)]
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
#[case(10)]
#[serial]
async fn secure_threshold_sequential_keygen_test(#[case] amount_parties: usize) {
    preproc_and_keygen(amount_parties, FheParameter::Test, false, 2, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(10)]
#[serial]
async fn secure_threshold_concurrent_keygen_test(#[case] amount_parties: usize) {
    preproc_and_keygen(amount_parties, FheParameter::Test, false, 2, true).await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[tracing_test::traced_test]
#[rstest::rstest]
#[case(4)]
#[case(10)]
#[serial]
async fn secure_threshold_decompression_keygen(#[case] amount_parties: usize) {
    run_threshold_decompression_keygen(amount_parties, FheParameter::Test, false).await;
}
