use crate::client::tests::centralized::crs_gen_tests::crs_gen_centralized;
use crate::client::tests::centralized::public_decryption_tests::decryption_centralized;
use crate::client::tests::centralized::user_decryption_tests::user_decryption_centralized;
use crate::consts::DEFAULT_CENTRAL_KEY_ID;
use crate::consts::DEFAULT_PARAM;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_tools::EncryptionConfig;
use crate::util::key_setup::test_tools::{purge, TestingPlaintext};
use kms_grpc::kms::v1::FheParameter;
use serial_test::serial;

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
    #[values(true, false)] compression: bool,
) {
    decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        msgs,
        EncryptionConfig {
            compression,
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
    #[values(true, false)] compression: bool,
) {
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        false,
        false,
        msg,
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        parallelism,
        secure,
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
    purge(None, None, None, &crs_req_id, 1).await;

    crs_gen_centralized(&crs_req_id, FheParameter::Default, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_crs_gen_centralized() {
    let crs_req_id = derive_request_id("default_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // We test for both insecure and secure since these are distinct endpoints, although inner computation is the same
    crs_gen_centralized(&crs_req_id, FheParameter::Default, false).await;
}
