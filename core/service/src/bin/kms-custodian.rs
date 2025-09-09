use aes_prng::AesRng;
use clap::Parser;
use kms_lib::{
    backup::{
        custodian::{Custodian, InternalCustodianSetupMessage},
        operator::{InnerOperatorBackupOutput, InternalRecoveryRequest},
        seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
    },
    consts::RND_SIZE,
    cryptography::{
        backup_pke::BackupPrivateKey,
        internal_crypto_types::{PrivateSigKey, PublicSigKey},
    },
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
    /// The human readable name of the custodian.
    #[clap(long, short = 'n', required = true)]
    pub custodian_name: String,
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
    /// Public verification key of the operator who requested the recovery
    #[clap(long, short = 'v', required = true)]
    pub operator_verf_key: PathBuf,
    /// The relative path to the [`RecoveryRequest`] file containing the request of an operator for recovery
    #[clap(long, short = 'b', required = true)]
    pub recovery_request_path: PathBuf,
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
/// in recovery of backups (through reencryption) by using a seed phrase.
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
        .tracing_service_name("kms_custodian".to_string())
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
            let setup_msg = custodian
                .generate_setup_message(&mut rng, params.custodian_name)
                .unwrap();
            safe_write_element_versioned(&params.path, &setup_msg).await?;
            tracing::info!("Custodian keys generated successfully! Mnemonic will now be printed:");
            println!("{SEED_PHRASE_DESC}{mnemonic}",);
        }
        CustodianCommand::Verify(params) => {
            // Logic for recovering keys
            tracing::info!("Validating custodian keys. Any validation errors will be printed below as warnings.");
            let mut validation_ok = true;
            let setup_msg: InternalCustodianSetupMessage =
                safe_read_element_versioned(&params.path).await?;
            let recovered_keys =
                custodian_from_seed_phrase(&params.seed_phrase, setup_msg.custodian_role)
                    .expect("Failed to recover keys");
            if &setup_msg.public_verf_key != recovered_keys.verification_key() {
                tracing::warn!("Verification failed: Public verification key does not match the generated key!");
                validation_ok = false;
            }
            if &setup_msg.public_enc_key != recovered_keys.public_key() {
                tracing::warn!(
                    "Verification failed: Public encryption key does not match the generated key!"
                );
                validation_ok = false;
            }
            if validation_ok {
                tracing::info!(
                    "Custodian keys verified successfully for custodian {}!",
                    setup_msg.custodian_role
                );
            } else {
                tracing::warn!(
                    "Custodian keys verification failed for custodian {}. Please check the logs for details.",
                    setup_msg.custodian_role
                );
            }
        }
        CustodianCommand::Decrypt(params) => {
            tracing::info!(
                "Decrypting ciphertexts for custodian role: {}",
                params.custodian_role
            );
            let verf_key: PublicSigKey =
                safe_read_element_versioned(&params.operator_verf_key).await?;
            let recovery_request: InternalRecoveryRequest =
                safe_read_element_versioned(&params.recovery_request_path).await?;
            if !recovery_request
                .is_valid(&verf_key)
                .expect("Failed to validate recovery request")
            {
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
            let custodian_backup: &InnerOperatorBackupOutput = recovery_request
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
                &verf_key,
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
    use assert_cmd::Command;
    use kms_grpc::{
        kms::v1::CustodianContext, rpc_types::InternalCustodianRecoveryOutput, RequestId,
    };
    use kms_lib::{
        backup::{
            custodian::{InternalCustodianContext, InternalCustodianSetupMessage},
            operator::{BackupCommitments, InternalRecoveryRequest, Operator},
            seed_phrase::custodian_from_seed_phrase,
        },
        cryptography::{
            backup_pke::{self, BackupPrivateKey},
            internal_crypto_types::gen_sig_keys,
        },
        engine::base::derive_request_id,
        util::file_handling::{safe_read_element_versioned, safe_write_element_versioned},
    };
    use std::path::MAIN_SEPARATOR;
    use std::{collections::BTreeMap, path::Path, thread};
    use threshold_fhe::execution::runtime::party::Role;

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
        println!("Command output: {output_string}");
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
        let temp_dir = tempfile::tempdir().unwrap();
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);
        let (seed_phrase2, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);

        // Ensure that randomness is always sampled on top of given randomness
        assert_ne!(seed_phrase, seed_phrase2);
    }

    #[test]
    #[serial_test::serial]
    fn sunshine_verify() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir
            .path()
            .join(format!("custodian-1{MAIN_SEPARATOR}setup_msg.bin"));
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);
        let verf_command = vec![
            "verify".to_string(),
            "--seed-phrase".to_string(),
            seed_phrase.to_string(),
            "--path".to_string(),
            path.to_str().unwrap().to_string(),
        ];
        // Note that `run_commands` validate that the command executed successfully
        let _verf_out = run_commands(verf_command);
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    #[serial_test::serial]
    async fn sunshine_decrypt_custodian() {
        let threshold = 1;
        let amount_custodians = 2 * threshold + 1; // Minimum amount of custodians is 2 * threshold + 1
        let amount_operators = 4;
        let backup_id = derive_request_id("backuptest").unwrap();

        let temp_dir = tempfile::tempdir().unwrap();

        // Generate custodian keys
        let mut setup_msgs = Vec::new();
        let mut seed_phrases: Vec<_> = Vec::new();
        for custodian_index in 1..=amount_custodians {
            let (seed_phrase, setup_msg) =
                generate_custodian_keys_to_file(temp_dir.path(), custodian_index);
            setup_msgs.push(setup_msg);
            seed_phrases.push(seed_phrase);
        }

        // Generate operator keys along with the message to be backed up
        let mut commitments = Vec::new();
        let mut operators = Vec::new();
        let mut ephemeral_dec_keys = Vec::new();
        let mut backup_dec_keys = Vec::new();
        for operator_index in 1..=amount_operators {
            let (cur_commitments, operator, ephemeral_dec, backup_dec) = make_backup(
                temp_dir.path(),
                threshold,
                Role::indexed_from_one(operator_index),
                setup_msgs.clone(),
                backup_id,
            )
            .await;
            commitments.push(cur_commitments);
            operators.push(operator);
            ephemeral_dec_keys.push(ephemeral_dec);
            backup_dec_keys.push(backup_dec);
        }

        // Decrypt
        for custodian_index in 1..=amount_custodians {
            for operator_index in 1..=amount_operators {
                let request_path = temp_dir.path().join(format!(
                    "operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-request.bin"
                ));
                let recovery_path = temp_dir.path().join(format!(
                    "operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-recovered-keys-from-{custodian_index}.bin"
                ));
                let operator_verf_path = temp_dir.path().join(format!(
                    "operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-verf_key.bin"
                ));
                let decrypt_command = vec![
                    "decrypt".to_string(),
                    "--seed-phrase".to_string(),
                    seed_phrases[custodian_index - 1].to_string(),
                    "--custodian-role".to_string(),
                    custodian_index.to_string(),
                    "--operator-verf-key".to_string(),
                    operator_verf_path.to_str().unwrap().to_string(),
                    "-b".to_string(),
                    request_path.to_str().unwrap().to_string(),
                    "-o".to_string(),
                    recovery_path.to_str().unwrap().to_string(),
                ];
                let _verf_out = run_commands(decrypt_command);
            }
        }

        // Validate the decryption
        for ((operator, commitment), dec_key) in
            operators.iter().zip(&commitments).zip(&ephemeral_dec_keys)
        {
            let cur_res = decrypt_recovery(
                temp_dir.path(),
                amount_custodians,
                operator,
                commitment,
                backup_id,
                dec_key,
            )
            .await;
            assert_eq!(
                cur_res,
                bc2wrap::serialize(&backup_dec_keys[&operator.role()]).unwrap(),
                "Decryption did not match expected data for operator {}",
                operator.role().one_based()
            );
        }
    }

    fn generate_custodian_keys_to_file(
        root_path: &Path,
        custodian_index: usize,
    ) -> (String, InternalCustodianSetupMessage) {
        let final_dir = root_path.join(format!(
            "custodian-{custodian_index}{MAIN_SEPARATOR}setup_msg.bin"
        ));
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--custodian-role".to_string(),
            custodian_index.to_string(),
            "--custodian-name".to_string(),
            format!("skynet-{custodian_index}"),
            "--path".to_string(),
            final_dir.to_str().unwrap().to_string(),
        ];
        let gen_out = run_commands(gen_command.clone());
        let seed_phrase = extract_seed_phrase(gen_out.as_ref());
        let role = Role::indexed_from_one(custodian_index);
        let custodian = custodian_from_seed_phrase(seed_phrase, role).unwrap();
        let mut rng = get_rng(Some(&format!("custodian{custodian_index}").to_string()));
        let setup_msg = custodian
            .generate_setup_message(&mut rng, "Homer Simpson".to_string())
            .unwrap();
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
        root_path: &Path,
        threshold: usize,
        operator_role: Role,
        setup_msgs: Vec<InternalCustodianSetupMessage>,
        backup_id: RequestId,
    ) -> (
        BackupCommitments,
        Operator,
        BackupPrivateKey,
        BackupPrivateKey,
    ) {
        let request_path = root_path.join(format!(
            "operator-{operator_role}{MAIN_SEPARATOR}{backup_id}-request.bin"
        ));
        let operator_verf_path = root_path.join(format!(
            "operator-{operator_role}{MAIN_SEPARATOR}{backup_id}-verf_key.bin"
        ));
        let amount_custodians = setup_msgs.len();
        let mut rng = get_rng(Some(&format!("operator{operator_role}").to_string()));
        // Note that in the actual deployment, the operator keys are generated before the encryption keys
        let (verification_key, signing_key) = gen_sig_keys(&mut rng);
        let (ephemeral_pub_key, ephemeral_priv_key) = backup_pke::keygen(&mut rng).unwrap();
        let operator: Operator = Operator::new(
            operator_role,
            setup_msgs.clone(),
            signing_key.clone(),
            threshold,
        )
        .unwrap();
        let (backup_pke, backup_ske) = backup_pke::keygen(&mut rng).unwrap();
        let (ct_map, commitments) = operator
            .secret_share_and_encrypt(
                &mut rng,
                &bc2wrap::serialize(&backup_ske).unwrap(),
                backup_id,
            )
            .unwrap();
        let custodian_context = InternalCustodianContext::new(
            CustodianContext {
                custodian_nodes: setup_msgs
                    .iter()
                    .map(|cur| cur.to_owned().try_into().unwrap())
                    .collect(),
                context_id: Some(backup_id.into()),
                previous_context_id: None,
                threshold: threshold as u32,
            },
            backup_pke,
        )
        .unwrap();
        let backup_com =
            BackupCommitments::new(commitments.clone(), custodian_context, &signing_key).unwrap();
        let mut ciphertexts = BTreeMap::new();
        for custodian_index in 1..=amount_custodians {
            let custodian_role = Role::indexed_from_one(custodian_index);
            let ct = ct_map.get(&custodian_role).unwrap();
            ciphertexts.insert(custodian_role, ct.to_owned());
        }
        let recovery_request = InternalRecoveryRequest::new(
            ephemeral_pub_key,
            ciphertexts,
            backup_id,
            operator_role,
            Some(&verification_key),
        )
        .unwrap();
        safe_write_element_versioned(&Path::new(&operator_verf_path), &verification_key)
            .await
            .unwrap();
        safe_write_element_versioned(&Path::new(&request_path), &recovery_request)
            .await
            .unwrap();
        (backup_com, operator, ephemeral_priv_key, backup_ske)
    }

    async fn decrypt_recovery(
        root_path: &Path,
        amount_custodians: usize,
        operator: &Operator,
        commitment: &BackupCommitments,
        backup_id: RequestId,
        dec_key: &BackupPrivateKey,
    ) -> Vec<u8> {
        let mut outputs = Vec::new();
        for custodian_index in 1..=amount_custodians {
            let recovery_path = root_path.join(format!(
                "operator-{}{MAIN_SEPARATOR}{backup_id}-recovered-keys-from-{custodian_index}.bin",
                operator.role()
            ));
            let payload: InternalCustodianRecoveryOutput =
                safe_read_element_versioned(&Path::new(&recovery_path))
                    .await
                    .unwrap();
            outputs.push(payload);
        }
        operator
            .verify_and_recover(&outputs, commitment, backup_id, dec_key)
            .unwrap()
    }
}
