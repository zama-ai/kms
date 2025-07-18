use aes_prng::AesRng;
use clap::Parser;
use kms_grpc::rpc_types::PubDataType;
use kms_lib::{
    backup::{
        custodian::Custodian,
        operator::OperatorBackupOutput,
        seed_phrase::{generate_keys_from_rng, generate_keys_from_seed_phrase},
    },
    consts::RND_SIZE,
    cryptography::{
        backup_pke::{self, BackupPublicKey},
        internal_crypto_types::PublicSigKey,
    },
    engine::base::derive_request_id,
    util::file_handling::{safe_read_element_versioned, safe_write_element_versioned},
    vault::storage::{
        file::FileStorage, store_text_at_request_id, Storage, StorageReader, StorageType,
    },
};
use rand::{RngCore, SeedableRng};
use std::{env, path::PathBuf};
use threshold_fhe::{
    execution::runtime::party::Role,
    hashing::{hash_element, DomainSep},
};

const DSEP_ENTROPY: DomainSep = *b"ENTROPY_";
const CUSTODIAN_ENC_KEY: &str = "CUSTODIAN_ENC_KEY";
const CUSTODIAN_VERF_KEY: &str = "CUSTODIAN_ENC_KEY";

const SEED_PHRASE_DESC: &str = "The SECRET seed phrase for the custodian keys is: ";

#[derive(Debug, Parser, Clone)]
pub struct GenerateParams {
    #[clap(long, short = 'r', default_value = None)]
    pub randomness: Option<String>,
    #[clap(long, short = 'p', default_value = None)]
    pub path: Option<PathBuf>,
}
#[derive(Debug, Parser, Clone)]
pub struct VerifyParams {
    #[clap(long, short = 's')]
    pub seed_phrase: String,
    #[clap(long, short = 'p', default_value = None)]
    pub path: Option<PathBuf>,
}
#[derive(Debug, Parser, Clone)]
pub struct CoreDecParams {
    #[clap(long, short = 'c', required = true)]
    pub ct_path: PathBuf,
    #[clap(long, short = 'e', required = true)]
    pub enc_key_path: PathBuf,
    #[clap(long, short = 'v', required = true)]
    pub verf_key_path: PathBuf, // TODO should be optional once we move to encrypt-then-sign
}
#[derive(Debug, Parser, Clone)]
pub struct DecryptParams {
    #[clap(long, short = 's')]
    pub seed_phrase: String,
    #[clap(long, short = 'r', default_value = None)]
    pub randomness: Option<String>,
    #[clap(long, short = 'c', required = true)]
    pub ct_path: PathBuf,
    #[clap(long, short = 'e', required = true)]
    // This and the key below could be combined into a single struct as they come from the new operator
    pub enc_key_path: PathBuf,
    #[clap(long, short = 'v', required = true)]
    pub verf_key_path: PathBuf, // TODO should be optional once we move to encrypt-then-sign
    #[clap(long, short = 'o', required = true)]
    pub output_path: PathBuf,
    // #[clap(long, short = 'c', required = true)]
    // #[arg(num_args(1..))]
    // pub payloads: Vec<CoreDecParams>,
}
#[derive(Debug, Parser, Clone)]
pub struct NoParameters {}

#[derive(Debug, Clone, Parser)]
pub enum CustodianCommand {
    Generate(GenerateParams),
    Verify(VerifyParams),
    Decrypt(DecryptParams),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = CustodianCommand::parse();
    match args {
        CustodianCommand::Generate(params) => {
            // Logic for generating keys and setup
            let mut rng = get_rng(params.randomness.as_ref());
            println!("Generating custodian keys...");
            let (custodian_keys, mnemonic) =
                generate_keys_from_rng(&mut rng).expect("Failed to generate keys");
            let path = params.path.as_deref();
            let mut storage = FileStorage::new(path, StorageType::PRIV, None)?;
            storage
                .store_data(
                    &custodian_keys.nested_enc_key,
                    &derive_request_id(CUSTODIAN_ENC_KEY)?,
                    &PubDataType::PublicEncKey.to_string(),
                )
                .await?;
            storage
                .store_data(
                    &custodian_keys.verf_key,
                    &derive_request_id(CUSTODIAN_VERF_KEY)?,
                    &PubDataType::VerfKey.to_string(),
                )
                .await?;
            let ethereum_address =
                alloy_signer::utils::public_key_to_address(custodian_keys.verf_key.pk());
            store_text_at_request_id(
                &mut storage,
                &derive_request_id(CUSTODIAN_VERF_KEY)?,
                &ethereum_address.to_string(),
                &PubDataType::VerfAddress.to_string(),
            )
            .await?;
            println!("{SEED_PHRASE_DESC}{mnemonic}",);
        }
        CustodianCommand::Verify(params) => {
            // Logic for recovering keys
            println!("Validating custodian keys");
            let custodian_keys = generate_keys_from_seed_phrase(&params.seed_phrase)
                .expect("Failed to recover keys");
            let path = params.path.as_deref();
            let storage = FileStorage::new(path, StorageType::PRIV, None)?;
            let pub_verf_key: PublicSigKey = storage
                .read_data(
                    &derive_request_id(CUSTODIAN_VERF_KEY)?,
                    &PubDataType::VerfKey.to_string(),
                )
                .await?;
            if pub_verf_key != custodian_keys.verf_key {
                println!("Verification failed: Public verification key does not match the generated key!");
            }
            let pub_enc_key: backup_pke::BackupPublicKey = storage
                .read_data(
                    &derive_request_id(CUSTODIAN_ENC_KEY)?,
                    &PubDataType::PublicEncKey.to_string(),
                )
                .await?;
            if pub_enc_key != custodian_keys.nested_enc_key {
                println!(
                    "Verification failed: Public encryption key does not match the generated key!"
                );
            }
        }
        CustodianCommand::Decrypt(params) => {
            // Logic for decrypting payloads
            let custodian_keys = generate_keys_from_seed_phrase(&params.seed_phrase)
                .expect("Failed to recover keys");
            let custodian = Custodian::new(
                Role::indexed_from_one(1),
                custodian_keys.sig_key,
                custodian_keys.verf_key,
                custodian_keys.nested_dec_key,
                custodian_keys.nested_enc_key,
            )?;
            let mut rng = get_rng(params.randomness.as_ref());
            // for payload in params.payloads {
            let ct: OperatorBackupOutput = safe_read_element_versioned(&params.ct_path).await?;
            let core_enc_key: BackupPublicKey =
                safe_read_element_versioned(&params.enc_key_path).await?;
            let core_verf_key: PublicSigKey =
                safe_read_element_versioned(&params.verf_key_path).await?;
            let res = custodian.verify_reencrypt(
                &mut rng,
                &ct,
                &core_verf_key,
                &core_enc_key,
                derive_request_id("TODO")?,
                Role::indexed_from_one(1),
            )?;
            safe_write_element_versioned(&params.output_path, &res).await?;
            println!(
                "Reencryption successful! Output written to {}",
                params.output_path.display()
            );
            // let mut handles = Vec::new();
            // let mut error: Option<anyhow::Error> = None;
            // handles.push(tokio::spawn(async move {
            //     let res: OperatorBackupOutput =
            //         match safe_read_element_versioned(&params.ct_path).await {
            //             Ok(res) => res,
            //             Err(e) => {
            //                 error = Some(e);
            //                 return;
            //             }
            //         };
            //     // todo
            // }));

            // for handle in handles {
            //     handle.await?;
            // }
        }
    }

    println!(
        "Starting KMS Custodian Client v{}",
        env!("CARGO_PKG_VERSION")
    );

    Ok(())
}

fn get_rng(randomness: Option<&String>) -> AesRng {
    match randomness {
        Some(user_seed) => {
            let mut base_rng = AesRng::from_entropy();
            // If randomness is provided then use this along with system randomness
            let mut base_rng_bytes = [0u8; RND_SIZE];
            base_rng.fill_bytes(&mut base_rng_bytes);
            let mut user_seed_bytes = hash_element(&DSEP_ENTROPY, user_seed);
            user_seed_bytes.truncate(RND_SIZE);
            let mut rng_bytes = [0u8; RND_SIZE];
            for i in 0..RND_SIZE {
                rng_bytes[i] = user_seed_bytes[i] ^ base_rng_bytes[i];
            }
            AesRng::from_seed(rng_bytes)
        }
        None => AesRng::from_entropy(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{get_rng, SEED_PHRASE_DESC};
    use aes_prng::AesRng;
    use assert_cmd::Command;
    use kms_lib::{
        backup::{
            custodian::{Custodian, CustodianSetupMessage},
            operator::Operator,
        },
        cryptography::{
            backup_pke::{self, BackupPrivateKey},
            internal_crypto_types::{gen_sig_keys, PrivateSigKey},
        },
        engine::base::derive_request_id,
        util::file_handling::safe_write_element_versioned,
    };
    use std::{fs, path::Path, thread};
    use threshold_fhe::execution::runtime::party::Role;

    const TEST_DIR: &str = "./temp/custodian-test";

    fn run_commands(commands: Vec<String>) -> String {
        let h = thread::spawn(|| {
            let mut cmd = Command::cargo_bin("kms-custodian").unwrap();
            for arg in commands {
                cmd.arg(arg);
            }
            let out = cmd.output();
            assert!(out.is_ok(), "Command failed to execute");
            out
        });

        let out = h.join().unwrap().unwrap();
        let output_string = String::from_utf8_lossy(&out.stdout);
        let errors = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "Command did not execute successfully: {} : {}",
            out.status,
            errors
        );
        assert!(errors.is_empty());
        output_string.trim().to_owned()
    }

    fn extract_seed_phrase(output: &str) -> &str {
        let seed_phrase_line = output.lines().find(|line| line.contains(SEED_PHRASE_DESC));
        seed_phrase_line
            .unwrap()
            .split_at(SEED_PHRASE_DESC.len())
            .1
            .trim()
    }

    #[test]
    #[serial_test::serial]
    fn sunshine_generate() {
        purge();
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--path".to_string(),
            "./temp/custodian-test-keys".to_string(),
        ];

        let output = run_commands(gen_command.clone());
        let seed_phrase = extract_seed_phrase(output.as_ref());

        // Ensure that randomness is always sampled on top of given randomness
        let output2 = run_commands(gen_command);
        let seed_phrase2 = extract_seed_phrase(output2.as_ref());
        assert_ne!(seed_phrase, seed_phrase2);
    }

    #[test]
    #[serial_test::serial]
    fn sunshine_verify() {
        purge();
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--path".to_string(),
            TEST_DIR.to_string(),
        ];

        let gen_out = run_commands(gen_command.clone());
        let seed_phrase = extract_seed_phrase(gen_out.as_ref());

        let verf_command = vec![
            "verify".to_string(),
            "--seed-phrase".to_string(),
            seed_phrase.to_string(),
            "--path".to_string(),
            TEST_DIR.to_string(),
        ];

        let verf_out = run_commands(verf_command);
        println!("Verification output: {verf_out}");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sunshine_decrypt() {
        purge();
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--path".to_string(),
            TEST_DIR.to_string(),
        ];

        let gen_out = run_commands(gen_command.clone());
        let seed_phrase = extract_seed_phrase(gen_out.as_ref());

        // Generate backup
        let role = Role::indexed_from_one(1);
        let custodian: Custodian<PrivateSigKey, BackupPrivateKey> =
            Custodian::from_seed_phrase(role, seed_phrase).unwrap();
        let mut rng = get_rng(Some(&"secret".to_string()));
        let setup_msg = custodian.generate_setup_message(&mut rng).unwrap();
        let operator = operator_key_gen(&mut rng, &setup_msg, role).await.unwrap();
        let ct_map = operator
            .secret_share_and_encrypt(
                &mut rng,
                "super secret data".as_bytes(),
                derive_request_id("TODO").unwrap(),
            )
            .unwrap();
        let ct_path = format!("{TEST_DIR}/backups/ct.bin");
        let ct = ct_map.get(&role).unwrap();
        // TODO CONITNUE HERE still does not work.
        safe_write_element_versioned(&Path::new(&ct_path), ct)
            .await
            .unwrap();

        // Decrypt
        let decrypt_command = vec![
            "decrypt".to_string(),
            "--seed-phrase".to_string(),
            seed_phrase.to_string(),
            "-c".to_string(),
            ct_path,
            "-e".to_string(),
            format!("{TEST_DIR}/operator-enc-key.bin"),
            "-v".to_string(),
            format!("{TEST_DIR}/operator-verf-key.bin"),
            "-o".to_string(),
            format!("{TEST_DIR}/recovered_keys"),
        ];

        let verf_out = run_commands(decrypt_command);
        println!("Verification output: {verf_out}");
    }

    async fn operator_key_gen(
        rng: &mut AesRng,
        setup_msg: &CustodianSetupMessage,
        role: Role,
    ) -> anyhow::Result<Operator<PrivateSigKey, BackupPrivateKey>> {
        let (verification_key, signing_key) = gen_sig_keys(rng);
        let (private_key, public_key) = backup_pke::keygen(rng).unwrap();
        safe_write_element_versioned(Path::new("./temp/custodian-enc-key.bin"), &public_key)
            .await?;
        safe_write_element_versioned(
            Path::new("./temp/custodian-verf-key.bin"),
            &verification_key,
        )
        .await?;

        Ok(Operator::new(
            role,
            vec![setup_msg.clone()],
            signing_key,
            verification_key,
            private_key,
            public_key,
            0,
        )?)

        // let mut storage = FileStorage::new(
        //     Some(Path::new("./temp/custodian-test-keys")),
        //     StorageType::PRIV,
        //     None,
        // )
        // .unwrap();
        // storage
        //     .store_data(
        //         &public_key,
        //         &derive_request_id(CUSTODIAN_ENC_KEY).unwrap(),
        //         &PubDataType::PublicEncKey.to_string(),
        //     )
        //     .await
        //     .unwrap();
        // Ok(())
    }

    // fn purge_all() {
    //     let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    //     let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    //     purge_file_storage(&priv_storage);
    //     purge_file_storage(&pub_storage);

    //     let role = Some(Role::indexed_from_one(1));
    //     let priv_storage = FileStorage::new(None, StorageType::PRIV, role).unwrap();
    //     let pub_storage = FileStorage::new(None, StorageType::PUB, role).unwrap();
    //     purge_file_storage(&priv_storage);
    //     purge_file_storage(&pub_storage);

    //     let key_dir = PathBuf::from_str(KEY_PATH_PREFIX).unwrap();
    //     if key_dir.exists() {
    //         fs::remove_dir_all(key_dir).unwrap();
    //     }
    // }

    fn purge() {
        let dir = Path::new(TEST_DIR);
        if dir.exists() {
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
