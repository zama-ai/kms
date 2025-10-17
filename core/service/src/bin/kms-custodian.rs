use aes_prng::AesRng;
use clap::Parser;
use kms_lib::backup::SEED_PHRASE_DESC;
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
            println!("{SEED_PHRASE_DESC}{mnemonic}");
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
