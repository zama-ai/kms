use clap::Parser;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::{
    core_crypto::commons::generators::DeterministicSeeder,
    prelude::{FheDecrypt, FheEncrypt},
    set_server_key,
    shortint::engine::ShortintEngine,
    ClientKey, CompressedServerKey, FheUint64, Seed,
};
use tfhe_csprng::generators::SoftwareRandomGenerator;
use threshold_fhe::execution::tfhe_internals::parameters::{DKGParams, NIST_PARAMS_P32_SNS_FGLWE};

#[derive(Parser, Debug)]
#[clap(name = "tfhe-kat")]
#[clap(about = "Known Answer Tests for TFHE")]
struct KatCli {
    /// Whether to generate the KAT files (instead of reading and verifying them)
    #[clap(short, long, default_value_t = false)]
    generate_kat: bool,

    /// Path to the folder where to read/write the KAT files
    #[clap(short, long, default_value = "./tfhe_kat")]
    path_to_kat_folder: String,
}

fn generate_and_save_keys(
    params: DKGParams,
    storage_path: &str,
    save: bool,
) -> (ClientKey, CompressedServerKey) {
    let config = params.to_tfhe_config();
    //NOTE: REAL KAT SHOULD USE XOFKEYSET BUT WE CAN NOT GENERATE THOSE YET
    let client_key = ClientKey::generate_with_seed(config, Seed(42));
    let compressed_server_key = client_key.generate_compressed_server_key();

    if save {
        // Save keys to files
        let path_to_client_key = format!("{}/client_key.bin", storage_path);
        let path_to_server_key = format!("{}/server_key.bin", storage_path);

        let serialized_ck = bc2wrap::serialize(&(params, &client_key)).unwrap();
        let serialized_sk = bc2wrap::serialize(&(params, &compressed_server_key)).unwrap();

        std::fs::write(path_to_client_key, serialized_ck).unwrap();
        std::fs::write(path_to_server_key, serialized_sk).unwrap();

        println!(
            "KAT files for the keys generated and saved to {}",
            storage_path
        );
    }

    (client_key, compressed_server_key)
}

fn read_keys(expected_params: DKGParams, storage_path: &str) -> (ClientKey, CompressedServerKey) {
    println!("Reading KAT files of the keys from {}", storage_path);

    let path_to_client_key = format!("{}/client_key.bin", storage_path);
    let path_to_server_key = format!("{}/server_key.bin", storage_path);

    let (params, client_key): (DKGParams, ClientKey) =
        bc2wrap::deserialize_unsafe(&std::fs::read(path_to_client_key).unwrap()).unwrap();
    let (params_sk, compressed_server_key): (DKGParams, CompressedServerKey) =
        bc2wrap::deserialize_unsafe(&std::fs::read(path_to_server_key).unwrap()).unwrap();

    assert_eq!(
        expected_params, params,
        "Parameters read from client key KAT do not match expected parameters"
    );

    assert_eq!(
        params, params_sk,
        "Mismatched parameters between client and server keys"
    );
    (client_key, compressed_server_key)
}

fn generate_and_save_ciphertexts(
    client_key: &ClientKey,
    storage_path: &str,
    save: bool,
) -> (FheUint64, FheUint64, FheUint64, FheUint64) {
    let ciphertext_43 = FheUint64::encrypt(43u32, client_key);
    let ciphertext_4445 = FheUint64::encrypt(4445u32, client_key);

    let ciphertext_add = &ciphertext_43 + &ciphertext_4445;
    let ciphertext_mult = &ciphertext_43 * &ciphertext_4445;

    if save {
        let path_to_ciphertext_43 = format!("{}/ciphertext_43.bin", storage_path);
        let path_to_ciphertext_4445 = format!("{}/ciphertext_4445.bin", storage_path);
        let path_to_ciphertext_add = format!("{}/ciphertext_add.bin", storage_path);
        let path_to_ciphertext_mult = format!("{}/ciphertext_mult.bin", storage_path);

        let serialized_ct_43 = bc2wrap::serialize(&ciphertext_43).unwrap();
        let serialized_ct_4445 = bc2wrap::serialize(&ciphertext_4445).unwrap();
        let serialized_ct_add = bc2wrap::serialize(&ciphertext_add).unwrap();
        let serialized_ct_mult = bc2wrap::serialize(&ciphertext_mult).unwrap();

        std::fs::write(path_to_ciphertext_43, serialized_ct_43).unwrap();
        std::fs::write(path_to_ciphertext_4445, serialized_ct_4445).unwrap();
        std::fs::write(path_to_ciphertext_add, serialized_ct_add).unwrap();
        std::fs::write(path_to_ciphertext_mult, serialized_ct_mult).unwrap();

        println!(
            "KAT files for the ciphertexts generated and saved to {}",
            storage_path
        );
    }

    (
        ciphertext_43,
        ciphertext_4445,
        ciphertext_add,
        ciphertext_mult,
    )
}

fn read_ciphertexts(storage_path: &str) -> (FheUint64, FheUint64, FheUint64, FheUint64) {
    println!("Reading KAT files of the ciphertexts from {}", storage_path);

    let path_to_ciphertext_43 = format!("{}/ciphertext_43.bin", storage_path);
    let path_to_ciphertext_4445 = format!("{}/ciphertext_4445.bin", storage_path);
    let path_to_ciphertext_add = format!("{}/ciphertext_add.bin", storage_path);
    let path_to_ciphertext_mult = format!("{}/ciphertext_mult.bin", storage_path);

    let ciphertext_43: FheUint64 =
        bc2wrap::deserialize_unsafe(&std::fs::read(path_to_ciphertext_43).unwrap()).unwrap();
    let ciphertext_4445: FheUint64 =
        bc2wrap::deserialize_unsafe(&std::fs::read(path_to_ciphertext_4445).unwrap()).unwrap();
    let ciphertext_add: FheUint64 =
        bc2wrap::deserialize_unsafe(&std::fs::read(path_to_ciphertext_add).unwrap()).unwrap();
    let ciphertext_mult: FheUint64 =
        bc2wrap::deserialize_unsafe(&std::fs::read(path_to_ciphertext_mult).unwrap()).unwrap();

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
    let args = KatCli::parse();

    set_plan();

    // Run KATs with NIST_PARAMS_P32_SNS_FGLWE
    let params = NIST_PARAMS_P32_SNS_FGLWE;

    // Small hack to set the randomness in the ShortintEngine to be deterministic
    let mut seeder = DeterministicSeeder::<SoftwareRandomGenerator>::new(Seed(1995));
    let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
    ShortintEngine::with_thread_local_mut(|engine| std::mem::replace(engine, shortint_engine));

    let (client_key, compressed_server_key) =
        generate_and_save_keys(params, &args.path_to_kat_folder, args.generate_kat);

    if !args.generate_kat {
        println!("Verifying generated keys against KAT files...");
        let (expected_client_key, expected_compressed_server_key) =
            read_keys(params, &args.path_to_kat_folder);

        // Check there serialization, cause the struct don't derive eq
        assert_eq!(
            bc2wrap::serialize(&expected_client_key).unwrap(),
            bc2wrap::serialize(&client_key).unwrap(),
            "Client key read from KAT does not match generated client key"
        );

        assert_eq!(
            bc2wrap::serialize(&expected_compressed_server_key).unwrap(),
            bc2wrap::serialize(&compressed_server_key).unwrap(),
            "Compressed server key read from KAT does not match generated compressed server key"
        );

        println!("Keys are identical !");
    }

    set_server_key(compressed_server_key.decompress());

    let (ciphertext_43, ciphertext_4445, ciphertext_add, ciphertext_mult) =
        generate_and_save_ciphertexts(&client_key, &args.path_to_kat_folder, args.generate_kat);

    if !args.generate_kat {
        println!("Verifying generated ciphertexts against KAT files...");
        let (
            expected_ciphertext_43,
            expected_ciphertext_4445,
            expected_ciphertext_add,
            expected_ciphertext_mult,
        ) = read_ciphertexts(&args.path_to_kat_folder);

        assert_eq!(
            bc2wrap::serialize(&expected_ciphertext_43).unwrap(),
            bc2wrap::serialize(&ciphertext_43).unwrap(),
            "Ciphertext of 43 read from KAT does not match generated ciphertext"
        );

        assert_eq!(
            bc2wrap::serialize(&expected_ciphertext_4445).unwrap(),
            bc2wrap::serialize(&ciphertext_4445).unwrap(),
            "Ciphertext of 4445 read from KAT does not match generated ciphertext"
        );

        assert_eq!(
            bc2wrap::serialize(&expected_ciphertext_add).unwrap(),
            bc2wrap::serialize(&ciphertext_add).unwrap(),
            "Ciphertext of addition read from KAT does not match generated ciphertext"
        );

        assert_eq!(
            bc2wrap::serialize(&expected_ciphertext_mult).unwrap(),
            bc2wrap::serialize(&ciphertext_mult).unwrap(),
            "Ciphertext of multiplication read from KAT does not match generated ciphertext"
        );
        println!("All ciphertexts are identical !");
    }

    println!("Decrypting ciphertexts and verifying results...");
    let decrypted_43: u64 = FheUint64::decrypt(&ciphertext_43, &client_key);
    let decrypted_4445: u64 = FheUint64::decrypt(&ciphertext_4445, &client_key);
    let decrypted_add: u64 = FheUint64::decrypt(&ciphertext_add, &client_key);
    let decrypted_mult: u64 = FheUint64::decrypt(&ciphertext_mult, &client_key);

    assert_eq!(
        decrypted_43, 43u64,
        "Decryption of 43 ciphertext did not yield expected result"
    );
    assert_eq!(
        decrypted_4445, 4445u64,
        "Decryption of 4445 ciphertext did not yield expected result"
    );
    assert_eq!(
        decrypted_add,
        43u64 + 4445u64,
        "Decryption of addition ciphertext did not yield expected result"
    );
    assert_eq!(
        decrypted_mult,
        43u64 * 4445u64,
        "Decryption of multiplication ciphertext did not yield expected result"
    );
    println!("All decrypted results are correct !");
}
