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
    util::file_handling::safe_read_element_versioned,
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
    pub enc_key_path: PathBuf,
    #[clap(long, short = 'v', required = true)]
    pub verf_key_path: PathBuf, // TODO should be optional once we move to encrypt-then-sign
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
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
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
            println!("The SECRET seed phrase for the custodian keys is: {mnemonic}",);
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
            // Logic for decrypti]ng payloads
            // let mut handles = Vec::new();
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
            let _res = custodian.verify_reencrypt(
                &mut rng,
                &ct,
                &core_verf_key,
                &core_enc_key,
                derive_request_id("TODO")?,
                Role::indexed_from_one(1),
            )?;
            // TODO continue here
            // handles.push(tokio::spawn(async move {
            //     let res: OperatorBackupOutput =
            //         safe_read_element_versioned(&payload_path).await?;
            //     // todo
            // }));
            // }

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
