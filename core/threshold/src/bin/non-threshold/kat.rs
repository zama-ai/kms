use tfhe::Tag;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{FftAlgo, Method, Plan, setup_custom_fft_plan};
use tfhe::core_crypto::prelude::NormalizedHammingWeightBound;
use tfhe::xof_key_set::CompressedXofKeySet;
use tfhe::{
    ClientKey, FheUint64, Seed,
    core_crypto::commons::generators::DeterministicSeeder,
    prelude::{FheDecrypt, FheEncrypt},
    set_server_key,
    shortint::engine::ShortintEngine,
};
use tfhe_csprng::generators::SoftwareRandomGenerator;
use threshold_execution::tfhe_internals::parameters::{DKGParams, NIST_PARAMS_P32_SNS_FGLWE};
use threshold_fhe::utils::check_hash;

const CLIENT_KEY_PATH: &str = "client_key.bin";
const SERVER_KEY_PATH: &str = "server_key.bin";
const EXPECTED_HASH_CLIENT_KEY: &str =
    "e632247063e3712eb6de0244fdf08bede700dc7052d018fbc9420e60cfceb36b";
const EXPECTED_HASH_SERVER_KEY: &str =
    "9580a04fc3277c52842ea23b52a45a1ae787d27533f57f4aba8812c64dbdb531";

const CIPHERTEXT43_PATH: &str = "ciphertext_43.bin";
const CIPHERTEXT4445_PATH: &str = "ciphertext_4445.bin";
const CIPHERTEXT_ADD_PATH: &str = "ciphertext_add.bin";
const CIPHERTEXT_MULT_PATH: &str = "ciphertext_mult.bin";
const EXPECTED_HASH_CTXT_43: &str =
    "55d217ab5f970299619a3a08c7388eb74887c0f7830aa0b60d5ee50a467b4498";
const EXPECTED_HASH_CTXT_4445: &str =
    "85fb15a41a29abea8e732afd43c640b21b7009f96e0c11460c83e07e302b2c8f";
const EXPECTED_HASH_CTXT_ADD: &str =
    "b586addc5282f8455aa7a02cc715889df881b97f5d3d4c78e13f80c53d95f7d5";
const EXPECTED_HASH_CTXT_MUL: &str =
    "53d133225f103fd45419b90ee92678aceec2d931033b6d8203e8080b13d25b02";

fn generate_keys(params: DKGParams) -> (ClientKey, CompressedXofKeySet) {
    let config = params.to_tfhe_config();
    let max_norm_hwt = params
        .get_params_basics_handle()
        .get_sk_deviations()
        .expect("Expect to have pmax params")
        .pmax;
    let (client_key, compressed_server_key) = CompressedXofKeySet::generate(
        config,
        vec![42, 43, 44, 45],
        128,
        NormalizedHammingWeightBound::new(max_norm_hwt).expect("Invalid hwt bound for KAT"),
        Tag::from("KAT"),
    )
    .expect("XofKeySet generation for KAT failed");

    let serialized_ck = bc2wrap::serialize(&(params, &client_key)).unwrap();
    let serialized_sk = bc2wrap::serialize(&(params, &compressed_server_key)).unwrap();

    check_hash(
        CLIENT_KEY_PATH,
        &serialized_ck,
        EXPECTED_HASH_CLIENT_KEY,
        false,
    );
    check_hash(
        SERVER_KEY_PATH,
        &serialized_sk,
        EXPECTED_HASH_SERVER_KEY,
        false,
    );

    (client_key, compressed_server_key)
}

fn generate_ciphertexts(client_key: &ClientKey) -> (FheUint64, FheUint64, FheUint64, FheUint64) {
    let ciphertext_43 = FheUint64::encrypt(43u32, client_key);
    let ciphertext_4445 = FheUint64::encrypt(4445u32, client_key);

    let ciphertext_add = &ciphertext_43 + &ciphertext_4445;
    let ciphertext_mult = &ciphertext_43 * &ciphertext_4445;

    let serialized_ct_43 = bc2wrap::serialize(&ciphertext_43).unwrap();
    let serialized_ct_4445 = bc2wrap::serialize(&ciphertext_4445).unwrap();
    let serialized_ct_add = bc2wrap::serialize(&ciphertext_add).unwrap();
    let serialized_ct_mult = bc2wrap::serialize(&ciphertext_mult).unwrap();

    check_hash(
        CIPHERTEXT43_PATH,
        &serialized_ct_43,
        EXPECTED_HASH_CTXT_43,
        false,
    );
    check_hash(
        CIPHERTEXT4445_PATH,
        &serialized_ct_4445,
        EXPECTED_HASH_CTXT_4445,
        false,
    );

    println!(
        "NOTE: Hashes for addition and multiplication ciphertexts are CPU dependent due to FFT and may vary across machines"
    );
    check_hash(
        CIPHERTEXT_ADD_PATH,
        &serialized_ct_add,
        EXPECTED_HASH_CTXT_ADD,
        true,
    );
    check_hash(
        CIPHERTEXT_MULT_PATH,
        &serialized_ct_mult,
        EXPECTED_HASH_CTXT_MUL,
        true,
    );

    (
        ciphertext_43,
        ciphertext_4445,
        ciphertext_add,
        ciphertext_mult,
    )
}

pub fn set_plan() {
    for n in [512, 1024, 2048] {
        let my_plan = Plan::new(
            // n / 2 is due to how TFHE-rs handles ffts
            n / 2,
            Method::UserProvided {
                // User responsibility to choose an algorithm compatible with their n
                // Both for the algorithm and the base_n
                base_algo: FftAlgo::Dif4,
                base_n: n / 2,
            },
        );
        setup_custom_fft_plan(my_plan);
    }
}

fn main() {
    println!("STARTING TFHE KAT");

    set_plan();

    // Run KATs with NIST_PARAMS_P32_SNS_FGLWE
    let params = NIST_PARAMS_P32_SNS_FGLWE;

    // Small hack to set the randomness in the ShortintEngine to be deterministic
    let mut seeder = DeterministicSeeder::<SoftwareRandomGenerator>::new(Seed(1995));
    let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
    ShortintEngine::with_thread_local_mut(|engine| std::mem::replace(engine, shortint_engine));

    let (client_key, compressed_server_key) = generate_keys(params);

    set_server_key(
        compressed_server_key
            .decompress()
            .expect("Decompression failed")
            .into_raw_parts()
            .1,
    );

    let (ciphertext_43, ciphertext_4445, ciphertext_add, ciphertext_mult) =
        generate_ciphertexts(&client_key);

    println!("Decrypting ciphertexts and verifying results...");
    let decrypted_43: u64 = FheUint64::decrypt(&ciphertext_43, &client_key);
    let decrypted_4445: u64 = FheUint64::decrypt(&ciphertext_4445, &client_key);
    let decrypted_add: u64 = FheUint64::decrypt(&ciphertext_add, &client_key);
    let decrypted_mult: u64 = FheUint64::decrypt(&ciphertext_mult, &client_key);

    assert_eq!(
        decrypted_43, 43u64,
        "❌ Decryption of 43 ciphertext did not yield expected result"
    );
    assert_eq!(
        decrypted_4445, 4445u64,
        "❌ Decryption of 4445 ciphertext did not yield expected result"
    );
    assert_eq!(
        decrypted_add,
        43u64 + 4445u64,
        "❌ Decryption of addition ciphertext did not yield expected result"
    );
    assert_eq!(
        decrypted_mult,
        43u64 * 4445u64,
        "❌ Decryption of multiplication ciphertext did not yield expected result"
    );
    println!("✅ All decrypted results are correct !");
}
