use aes_prng::AesRng;
use clap::Parser;
use kms_lib::{
    backup::{
        custodian::{Custodian, CustodianSetupMessage},
        operator::{OperatorBackupOutput, RecoveryRequest},
        seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
    },
    consts::RND_SIZE,
    cryptography::{backup_pke::BackupPrivateKey, internal_crypto_types::PrivateSigKey},
    util::file_handling::{safe_read_element_versioned, safe_write_element_versioned},
};
use observability::{conf::TelemetryConfig, telemetry::init_tracing};
use rand::{RngCore, SeedableRng};
use std::{env, path::PathBuf};
use threshold_fhe::{
    execution::runtime::party::Role,
    hashing::{hash_element, DomainSep},
};

const DSEP_ENTROPY: DomainSep = *b"ENTROPY_";
const SEED_PHRASE_DESC: &str = "The SECRET seed phrase for the custodian keys is: ";

/// The parameters needed to generate custodian keys and setup
#[derive(Debug, Parser, Clone)]
pub struct GenerateParams {
    /// Optional randomness to be used, along with the system entropy, to generate the keys
    #[clap(long, short = 'r', default_value = None)]
    pub randomness: Option<String>,
    /// The custodian role (1-based index) who is generating the keys.
    #[clap(long, short = 'c', required = true)]
    pub custodian_role: usize,
    /// The relative path for storing the generated *public* keys.
    #[clap(long, short = 'p', required = true)]
    pub path: PathBuf,
}

/// The parameters needed to verify existing custodian keys against the stored public keys.
#[derive(Debug, Parser, Clone)]
pub struct VerifyParams {
    /// The BIP39 seed phrase needed to recover the custodian keys
    #[clap(long, short = 's')]
    pub seed_phrase: String,
    /// The relative path for reading the previously generated *public* keys.
    #[clap(long, short = 'p', required = true)]
    pub path: PathBuf,
}

/// The parameters needed for a custodian to decrypt a backup for a given operator.
#[derive(Debug, Parser, Clone)]
pub struct DecryptParams {
    /// The BIP39 seed phrase needed to recover the custodian keys
    #[clap(long, short = 's')]
    pub seed_phrase: String,
    /// Optional randomness to be used, along with the system entropy, to generate the keys
    #[clap(long, short = 'r', default_value = None)]
    pub randomness: Option<String>,
    /// The custodian role (1-based index) who is doing the decryption.
    #[clap(long, short = 'c', required = true)]
    pub custodian_role: usize,
    /// The relative path to the [`RecoveryRequest`] file containing the request of an operator for recovery
    #[clap(long, short = 'b', required = true)]
    pub recovery_request_path: String,
    /// The relative path for the reencrypted backup which will be given to the operator.
    #[clap(long, short = 'o', required = true)]
    pub output_path: PathBuf,
}

#[derive(Debug, Clone, Parser)]
pub enum CustodianCommand {
    Generate(GenerateParams),
    Verify(VerifyParams),
    Decrypt(DecryptParams),
}
/// KMS Backup CLI Tool
///
/// This CLI tool allows to make custodian keys using a BIP39 seed phrase and help operators
/// in recovery of backups (through reencryption) by using a seed pharase.
///
/// # Commands
///
/// - `generate`: Generate new custodian keys and store their public parts.
/// - `verify`: Verify that a seed phrase matches the stored public keys.
/// - `decrypt`: Decrypt a backup for an operator using the custodian's keys.
///
/// Use `--help` with any command for more details.
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
            let role = Role::indexed_from_one(params.custodian_role);
            let mnemonic = seed_phrase_from_rng(&mut rng).expect("Failed to generate seed phrase");
            let custodian: Custodian<PrivateSigKey, BackupPrivateKey> =
                custodian_from_seed_phrase(&mnemonic, role).unwrap();
            let setup_msg = custodian.generate_setup_message(&mut rng).unwrap();
            safe_write_element_versioned(&params.path, &setup_msg).await?;
            tracing::info!("Custodian keys generated successfully! Mnemonic will now be printed:");
            println!("{SEED_PHRASE_DESC}{mnemonic}",);
        }
        CustodianCommand::Verify(params) => {
            // Logic for recovering keys
            tracing::info!("Validating custodian keys. Any validation errors will be printed below as warnings.");
            let mut validation_ok = true;
            let setup_msg: CustodianSetupMessage =
                safe_read_element_versioned(&params.path).await?;
            let recovered_keys =
                custodian_from_seed_phrase(&params.seed_phrase, setup_msg.msg.custodian_role)
                    .expect("Failed to recover keys");
            if &setup_msg.verification_key != recovered_keys.verification_key() {
                tracing::warn!("Verification failed: Public verification key does not match the generated key!");
                validation_ok = false;
            }
            if &setup_msg.msg.public_key != recovered_keys.public_key() {
                tracing::warn!(
                    "Verification failed: Public encryption key does not match the generated key!"
                );
                validation_ok = false;
            }
            if validation_ok {
                tracing::info!(
                    "Custodian keys verified successfully for custodian {}!",
                    setup_msg.msg.custodian_role
                );
            } else {
                tracing::warn!(
                    "Custodian keys verification failed for custodian {}. Please check the logs for details.",
                    setup_msg.msg.custodian_role
                );
            }
        }
        CustodianCommand::Decrypt(params) => {
            tracing::info!(
                "Decrypting ciphertexts for custodian role: {}",
                params.custodian_role
            );
            let recovery_request: RecoveryRequest =
                safe_read_element_versioned(&params.recovery_request_path).await?;
            if !recovery_request.is_valid() {
                return Err(anyhow::anyhow!("Invalid RecoveryRequest data"));
            }
            // Logic for decrypting payloads
            let custodian = custodian_from_seed_phrase(
                &params.seed_phrase,
                Role::indexed_from_one(params.custodian_role),
            )
            .expect("Failed to reconstruct custodians");
            tracing::info!("Custodian initialized successfully");
            let mut rng = get_rng(params.randomness.as_ref());
            let custodian_backup: &OperatorBackupOutput = recovery_request
                .ciphertexts()
                .get(&Role::indexed_from_one(params.custodian_role))
                .unwrap_or_else(|| {
                    panic!(
                        "No ciphertext found for custodian role: {}",
                        custodian.role()
                    )
                });
            let res = custodian.verify_reencrypt(
                &mut rng,
                custodian_backup,
                recovery_request.verification_key(),
                recovery_request.encryption_key(),
                recovery_request.backup_id(),
                recovery_request.operator_role(),
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
            custodian::{CustodianRecoveryOutput, CustodianSetupMessage},
            operator::{Operator, RecoveryRequest},
            seed_phrase::custodian_from_seed_phrase,
        },
        cryptography::{
            backup_pke::{self, BackupPrivateKey},
            internal_crypto_types::{gen_sig_keys, PrivateSigKey},
        },
        engine::base::derive_request_id,
        util::file_handling::{safe_read_element_versioned, safe_write_element_versioned},
    };
    use std::path::MAIN_SEPARATOR;
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
            format!("{TEST_DIR}{MAIN_SEPARATOR}custodian-1{MAIN_SEPARATOR}setup_msg.bin",),
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
        let mut setup_msgs = Vec::new();
        let mut seed_phrases: Vec<_> = Vec::new();
        for custodian_index in 1..=amount_custodians {
            let (seed_phrase, setup_msg) = generate_custodian_keys_to_file(custodian_index);
            setup_msgs.push(setup_msg);
            seed_phrases.push(seed_phrase);
        }

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
                let decrypt_command = vec![
                    "decrypt".to_string(),
                    "--seed-phrase".to_string(),
                    seed_phrases[custodian_index - 1].to_string(),
                    "--custodian-role".to_string(),
                    custodian_index.to_string(),
                    "-b".to_string(),
                    format!("{TEST_DIR}{MAIN_SEPARATOR}operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-request.bin"),
                    "-o".to_string(),
                    format!(
                        "{TEST_DIR}{MAIN_SEPARATOR}operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-recovered-keys-from-{custodian_index}.bin",
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

    fn generate_custodian_keys_to_file(custodian_index: usize) -> (String, CustodianSetupMessage) {
        let gen_command = vec![
                "generate".to_string(),
                "--randomness".to_string(),
                "123456".to_string(),
                "--custodian-role".to_string(),
                custodian_index.to_string(),
                "--path".to_string(),
                format!(
                    "{TEST_DIR}{MAIN_SEPARATOR}custodian-{custodian_index}{MAIN_SEPARATOR}setup_msg.bin",
                ),
            ];
        let gen_out = run_commands(gen_command.clone());
        let seed_phrase = extract_seed_phrase(gen_out.as_ref());
        let role = Role::indexed_from_one(custodian_index);
        let custodian = custodian_from_seed_phrase(seed_phrase, role).unwrap();
        let mut rng = get_rng(Some(&format!("custodian{custodian_index}").to_string()));
        let setup_msg = custodian.generate_setup_message(&mut rng).unwrap();
        (seed_phrase.to_string(), setup_msg)
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
        let mut ciphertexts = BTreeMap::new();
        for custodian_index in 1..=amount_custodians {
            let custodian_role = Role::indexed_from_one(custodian_index);
            let ct = ct_map.get(&custodian_role).unwrap();
            commitments.insert(custodian_role, ct.commitment.clone());
            ciphertexts.insert(custodian_role, ct.to_owned());
        }
        let recovery_request = RecoveryRequest::new(
            operator.public_key().to_owned(),
            operator.verification_key().to_owned(),
            ciphertexts,
            backup_id,
            operator_role,
        )
        .unwrap();
        let request_path = format!(
            "{TEST_DIR}{MAIN_SEPARATOR}operator-{}{MAIN_SEPARATOR}{backup_id}-request.bin",
            operator_role.one_based()
        );
        safe_write_element_versioned(&Path::new(&request_path), &recovery_request)
            .await
            .unwrap();
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
            let recovered_backup_path = format!("{TEST_DIR}{MAIN_SEPARATOR}operator-{}{MAIN_SEPARATOR}{backup_id}-recovered-keys-from-{custodian_index}.bin", operator.role());
            let payload: CustodianRecoveryOutput =
                safe_read_element_versioned(&Path::new(&recovered_backup_path))
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
        // Note that in the actual deployment, the operator keys are generated before the encryption keys
        let (verification_key, signing_key) = gen_sig_keys(rng);
        let (private_key, public_key) = backup_pke::keygen(rng).unwrap();
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
