use aes_prng::AesRng;
use clap::Parser;
use kms_grpc::{rpc_types::PubDataType, RequestId};
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
use observability::{conf::TelemetryConfig, telemetry::init_tracing};
use rand::{RngCore, SeedableRng};
use std::{env, path::PathBuf, str::FromStr};
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
    #[clap(long, short = 'i', required = true)]
    pub backup_id: String,
    #[clap(long, required = true)]
    pub custodian_role: usize,
    #[clap(long, required = true)]
    pub operator_role: usize,
    #[clap(long, short = 'c', required = true)]
    pub ct_path: PathBuf,
    #[clap(long, short = 'e', required = true)]
    // This and the key below could be combined into a single struct as they come from the new operator
    pub enc_key_path: PathBuf,
    #[clap(long, short = 'v', required = true)]
    pub verf_key_path: PathBuf, // TODO should be optional once we move to encrypt-then-sign
    #[clap(long, short = 'o', required = true)]
    pub output_path: PathBuf,
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
    let telemetry = TelemetryConfig::builder()
        .tracing_service_name("kms_core".to_string())
        .build();
    init_tracing(&telemetry).await?;

    tracing::info!(
        "Welcome to the KMS Custodian Client v{}",
        env!("CARGO_PKG_VERSION")
    );
    let args = CustodianCommand::parse();
    match args {
        CustodianCommand::Generate(params) => {
            // Logic for generating keys and setup
            let mut rng = get_rng(params.randomness.as_ref());
            tracing::info!("Generating custodian keys...");
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
            tracing::info!("Custodian keys generated successfully! Mnemonic will now be printed:");
            println!("{SEED_PHRASE_DESC}{mnemonic}",);
        }
        CustodianCommand::Verify(params) => {
            // Logic for recovering keys
            tracing::info!("Validating custodian keys. Any validation errors will be printed below as warnings.");
            let custodian_keys = generate_keys_from_seed_phrase(&params.seed_phrase)
                .expect("Failed to recover keys");
            let mut validation_ok = true;
            let path = params.path.as_deref();
            let storage = FileStorage::new(path, StorageType::PRIV, None)?;
            let pub_verf_key: PublicSigKey = storage
                .read_data(
                    &derive_request_id(CUSTODIAN_VERF_KEY)?,
                    &PubDataType::VerfKey.to_string(),
                )
                .await?;
            if pub_verf_key != custodian_keys.verf_key {
                tracing::warn!("Verification failed: Public verification key does not match the generated key!");
                validation_ok = false;
            }
            let pub_enc_key: backup_pke::BackupPublicKey = storage
                .read_data(
                    &derive_request_id(CUSTODIAN_ENC_KEY)?,
                    &PubDataType::PublicEncKey.to_string(),
                )
                .await?;
            if pub_enc_key != custodian_keys.nested_enc_key {
                tracing::warn!(
                    "Verification failed: Public encryption key does not match the generated key!"
                );
                validation_ok = false;
            }
            if validation_ok {
                tracing::info!("Custodian keys verified successfully!");
            } else {
                tracing::warn!(
                    "Custodian keys verification failed. Please check the logs for details."
                );
            }
        }
        CustodianCommand::Decrypt(params) => {
            tracing::info!(
                "Decrypting ciphertexts for custodian role: {}",
                params.custodian_role
            );
            let backup_id =
                RequestId::from_str(&params.backup_id).expect("Invalid backup ID format");
            // Logic for decrypting payloads
            let custodian_keys = generate_keys_from_seed_phrase(&params.seed_phrase)
                .expect("Failed to recover keys");
            let custodian = Custodian::new(
                Role::indexed_from_one(params.custodian_role),
                custodian_keys.sig_key,
                custodian_keys.verf_key,
                custodian_keys.nested_dec_key,
                custodian_keys.nested_enc_key,
            )?;
            tracing::info!("Custodian initialized successfully");
            let mut rng = get_rng(params.randomness.as_ref());
            let ct: OperatorBackupOutput = safe_read_element_versioned(&params.ct_path).await?;
            tracing::info!("Read ciphertext from {}", params.ct_path.display());
            let core_enc_key: BackupPublicKey =
                safe_read_element_versioned(&params.enc_key_path).await?;
            tracing::info!(
                "Read operator's encryption key from {}",
                params.enc_key_path.display()
            );
            let core_verf_key: PublicSigKey =
                safe_read_element_versioned(&params.verf_key_path).await?;
            tracing::info!(
                "Read operator's verification key from {}",
                params.verf_key_path.display()
            );

            let res = custodian.verify_reencrypt(
                &mut rng,
                &ct,
                &core_verf_key,
                &core_enc_key,
                backup_id,
                Role::indexed_from_one(params.operator_role),
            )?;
            tracing::info!("Verified reencryption successfully");
            safe_write_element_versioned(&params.output_path, &res).await?;
            tracing::info!(
                "Reencryption successful! Output written to {}",
                params.output_path.display()
            );
        }
    }
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
    use kms_grpc::RequestId;
    use kms_lib::{
        backup::{
            custodian::{Custodian, CustodianRecoveryOutput, CustodianSetupMessage},
            operator::Operator,
        },
        cryptography::{
            backup_pke::{self, BackupPrivateKey},
            internal_crypto_types::{gen_sig_keys, PrivateSigKey},
        },
        engine::base::derive_request_id,
        util::file_handling::{safe_read_element_versioned, safe_write_element_versioned},
    };
    use std::{collections::BTreeMap, fs, path::Path, thread};
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
        tracing::info!("Command output: {}", output_string);
        tracing::error!("Command errors: {}", errors);
        assert!(
            out.status.success(),
            "Command did not execute successfully: {} : {}",
            out.status,
            errors
        );
        assert!(errors.is_empty());
        output_string.trim().to_owned()
    }

    #[test]
    #[serial_test::serial]
    fn sunshine_generate() {
        purge();
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(1);
        let (seed_phrase2, _setup_msgs) = generate_custodian_keys_to_file(1);

        // Ensure that randomness is always sampled on top of given randomness
        assert_ne!(seed_phrase, seed_phrase2);
    }

    #[test]
    #[serial_test::serial]
    fn sunshine_verify() {
        purge();
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(1);
        let verf_command = vec![
            "verify".to_string(),
            "--seed-phrase".to_string(),
            seed_phrase.to_string(),
            "--path".to_string(),
            TEST_DIR.to_string(),
        ];
        // Note that `run_commands` validate that the command executed successfully
        let _verf_out = run_commands(verf_command);
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    #[serial_test::serial]
    async fn sunshine_decrypt() {
        purge();
        let threshold = 1;
        let amount_custodians = 2 * threshold + 1; // Minimum amount of custodians is 2 * threshold + 1
        let amount_operators = 4;
        let backup_id = derive_request_id("backuptest").unwrap();

        // Generate custodian keys
        let (seed_phrase, setup_msgs) = generate_custodian_keys_to_file(amount_custodians);

        // Generate operator keys along with the message to be backed up
        let mut commitments = Vec::new();
        let mut operators = Vec::new();
        for operator_index in 1..=amount_operators {
            let (cur_commitments, operator) = make_backup(
                threshold,
                Role::indexed_from_one(operator_index),
                setup_msgs.clone(),
                backup_id,
                format!("super secret data{operator_index}").as_bytes(),
            )
            .await;
            commitments.push(cur_commitments);
            operators.push(operator);
        }

        // Decrypt
        for custodian_index in 1..=amount_custodians {
            for operator_index in 1..=amount_operators {
                let ct_path = format!(
                    "{TEST_DIR}/backups/ct-{operator_index}-to-{custodian_index}.bin", // todo should use delimiter in case of windows
                );
                let decrypt_command = vec![
                    "decrypt".to_string(),
                    "--seed-phrase".to_string(),
                    seed_phrase.to_string(),
                    "--backup-id".to_string(),
                    backup_id.to_string(),
                    "--custodian-role".to_string(),
                    custodian_index.to_string(),
                    "--operator-role".to_string(),
                    operator_index.to_string(),
                    "-c".to_string(),
                    ct_path,
                    "-e".to_string(),
                    format!("{TEST_DIR}/operator-enc-key-{}.bin", operator_index),
                    "-v".to_string(),
                    format!("{TEST_DIR}/operator-verf-key-{}.bin", operator_index),
                    "-o".to_string(),
                    format!(
                        "{TEST_DIR}/recovered_keys-{}-{}.bin",
                        operator_index, custodian_index
                    ),
                ];
                let _verf_out = run_commands(decrypt_command);
            }
        }

        // Validate the decryption
        for (operator, commitment) in operators.iter().zip(commitments) {
            let cur_res =
                decrypt_recovery(amount_custodians, operator, commitment, backup_id).await;
            let expected_res = format!("super secret data{}", operator.role().one_based());
            assert_eq!(
                cur_res,
                expected_res.as_bytes(),
                "Decryption did not match expected data for operator {}",
                operator.role().one_based()
            );
        }
    }

    fn generate_custodian_keys_to_file(amount: usize) -> (String, Vec<CustodianSetupMessage>) {
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--path".to_string(),
            TEST_DIR.to_string(),
        ];
        let gen_out = run_commands(gen_command.clone());
        let seed_phrase = extract_seed_phrase(gen_out.as_ref());
        let mut setup_msgs = Vec::new();
        for custodian_index in 1..=amount {
            let role = Role::indexed_from_one(custodian_index);
            let custodian: Custodian<PrivateSigKey, BackupPrivateKey> =
                Custodian::from_seed_phrase(role, seed_phrase).unwrap();
            let mut rng = get_rng(Some(&format!("custodian{custodian_index}").to_string()));
            let setup_msg = custodian.generate_setup_message(&mut rng).unwrap();
            setup_msgs.push(setup_msg);
        }
        (seed_phrase.to_string(), setup_msgs)
    }

    fn extract_seed_phrase(output: &str) -> &str {
        let seed_phrase_line = output.lines().find(|line| line.contains(SEED_PHRASE_DESC));
        seed_phrase_line
            .unwrap()
            .split_at(SEED_PHRASE_DESC.len())
            .1
            .trim()
    }

    async fn make_backup(
        threshold: usize,
        operator_role: Role,
        setup_msgs: Vec<CustodianSetupMessage>,
        backup_id: RequestId,
        msg: &[u8],
    ) -> (
        BTreeMap<Role, Vec<u8>>,
        Operator<PrivateSigKey, BackupPrivateKey>,
    ) {
        let amount_custodians = setup_msgs.len();
        let mut rng = get_rng(Some(&format!("operator{operator_role}").to_string()));
        let operator = operator_key_gen(&mut rng, setup_msgs.clone(), operator_role, threshold)
            .await
            .unwrap();
        let ct_map = operator
            .secret_share_and_encrypt(&mut rng, msg, backup_id)
            .unwrap();
        let mut commitments = BTreeMap::new();
        for custodian_index in 1..=amount_custodians {
            let custodian_role = Role::indexed_from_one(custodian_index);
            let ct_path = format!("{TEST_DIR}/backups/ct-{operator_role}-to-{custodian_role}.bin");
            let ct = ct_map.get(&custodian_role).unwrap();
            commitments.insert(custodian_role, ct.commitment.clone());
            safe_write_element_versioned(&Path::new(&ct_path), ct)
                .await
                .unwrap();
        }
        (commitments, operator)
    }

    async fn decrypt_recovery(
        amount_custodians: usize,
        operator: &Operator<PrivateSigKey, BackupPrivateKey>,
        commitment: BTreeMap<Role, Vec<u8>>,
        backup_id: RequestId,
    ) -> Vec<u8> {
        let mut outputs = BTreeMap::new();
        for custodian_index in 1..=amount_custodians {
            let payload_path = format!(
                "{TEST_DIR}/recovered_keys-{}-{}.bin",
                operator.role().one_based(),
                custodian_index
            );
            let payload: CustodianRecoveryOutput =
                safe_read_element_versioned(&Path::new(&payload_path))
                    .await
                    .unwrap();
            outputs.insert(Role::indexed_from_one(custodian_index), payload);
        }
        operator
            .verify_and_recover(&outputs, &commitment, backup_id)
            .unwrap()
    }

    async fn operator_key_gen(
        rng: &mut AesRng,
        setup_msgs: Vec<CustodianSetupMessage>,
        role: Role,
        threshold: usize,
    ) -> anyhow::Result<Operator<PrivateSigKey, BackupPrivateKey>> {
        let (verification_key, signing_key) = gen_sig_keys(rng);
        let (private_key, public_key) = backup_pke::keygen(rng).unwrap();
        safe_write_element_versioned(
            Path::new(&format!(
                "{TEST_DIR}/operator-enc-key-{}.bin",
                role.one_based()
            )),
            &public_key,
        )
        .await?;
        safe_write_element_versioned(
            Path::new(&format!(
                "{TEST_DIR}/operator-verf-key-{}.bin",
                role.one_based(),
            )),
            &verification_key,
        )
        .await?;

        Ok(Operator::new(
            role,
            setup_msgs,
            signing_key,
            verification_key,
            private_key,
            public_key,
            threshold,
        )?)
    }

    fn purge() {
        let dir = Path::new(TEST_DIR);
        if dir.exists() {
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
