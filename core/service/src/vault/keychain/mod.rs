use crate::{
    anyhow_error_and_log,
    backup::{
        custodian::{CustodianRecoveryOutput, InternalCustodianContext},
        operator::BackupCommitments,
    },
    conf::{AwsKmsKeySpec, AwsKmsKeychain, Keychain as KeychainConf, SecretSharingKeychain},
    cryptography::{attestation::SecurityModuleProxy, backup_pke::BackupCiphertext},
    vault::{
        storage::{read_versioned_at_request_id, StorageReader},
        Vault,
    },
};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use aes_prng::AesRng;
use aws_sdk_kms::Client as AWSKMSClient;
use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use kms_grpc::{rpc_types::PrivDataType, RequestId};
use rand::SeedableRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, convert::Into};
use strum_macros::EnumTryAs;
use tfhe::{named::Named, Unversionize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_fhe::execution::runtime::party::Role;

pub mod awskms;
pub mod secretsharing;

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum AppKeyBlobVersioned {
    V0(AppKeyBlob),
}

/// Container type for encrypted application keys (such as FHE private keys)
#[derive(Serialize, Deserialize, Versionize, PartialEq, Debug, Clone)]
#[versionize(AppKeyBlobVersioned)]
pub struct AppKeyBlob {
    pub root_key_id: String,
    pub data_key_blob: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

impl Named for AppKeyBlob {
    const NAME: &'static str = "AppKeyBlob";
}

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait Keychain {
    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        payload_id: &RequestId,
        payload: &T,
    ) -> anyhow::Result<EnvelopeStore>;

    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        payload_id: &RequestId,
        envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T>;
}

#[allow(clippy::large_enum_variant)]
#[enum_dispatch(Keychain)]
#[derive(Clone)]
pub enum KeychainProxy {
    AwsKmsSymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Symm, AesRng>),
    AwsKmsAsymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Asymm, AesRng>),
    SecretSharing(secretsharing::SecretShareKeychain<AesRng>),
}

#[derive(EnumTryAs, Clone)]
pub enum EnvelopeLoad {
    AppKeyBlob(AppKeyBlob),
    OperatorRecoveryInput(BTreeMap<Role, CustodianRecoveryOutput>, BackupCommitments),
}

#[derive(EnumTryAs)]
pub enum EnvelopeStore {
    AppKeyBlob(AppKeyBlob),
    OperatorBackupOutput(BackupCiphertext),
}

pub async fn make_keychain(
    keychain_conf: &KeychainConf,
    awskms_client: Option<AWSKMSClient>,
    security_module: Option<SecurityModuleProxy>,
    private_storage: Option<&Vault>,
) -> anyhow::Result<KeychainProxy> {
    let rng = AesRng::from_entropy();
    let keychain = match keychain_conf {
        KeychainConf::AwsKms(AwsKmsKeychain {
            root_key_id,
            root_key_spec,
        }) => {
            let awskms_client = awskms_client.expect("AWS KMS client must be configured");
            let security_module = security_module.expect("Security module must be present");
            match root_key_spec {
                AwsKmsKeySpec::Symm => KeychainProxy::from(awskms::AWSKMSKeychain::new(
                    rng,
                    awskms_client,
                    security_module,
                    awskms::Symm::new(root_key_id.clone()),
                )?),
                AwsKmsKeySpec::Asymm => KeychainProxy::from(awskms::AWSKMSKeychain::new(
                    rng,
                    awskms_client.clone(),
                    security_module,
                    awskms::Asymm::new(awskms_client, root_key_id.clone()).await?,
                )?),
            }
        }
        // Note that it is only possible to use the secret share keychain if there is already a context present.
        // This presents a bootstrapping issue hence the system needs to initially NOT use the secret share keychain but once a custodian context is set up,
        // it can switch to it by changing the configuration file and rebooting.
        KeychainConf::SecretSharing(SecretSharingKeychain {}) => {
            // If secret share backup is used with the centralized KMS, assume);
            let private_vault = private_storage
                .expect("Public vault must be provided to load custodian setup messages");
            let all_custodian_ids = private_vault
                .all_data_ids(&PrivDataType::CustodianInfo.to_string())
                .await?;
            // Get the latest context ID which should be the most recent one
            let latest_context_id = match all_custodian_ids.iter().sorted().last() {
                Some(latest_context_id) => latest_context_id,
                None => {
                    return Err(anyhow_error_and_log(
                        "No custodian setup available in the vault",
                    ))
                }
            };
            let custodian_context: InternalCustodianContext = read_versioned_at_request_id(
                private_vault,
                latest_context_id,
                &PrivDataType::CustodianInfo.to_string(),
            )
            .await?;
            KeychainProxy::from(secretsharing::SecretShareKeychain::new(
                rng,
                custodian_context.backup_enc_key.clone(),
            ))
        }
    };
    Ok(keychain)
}

/// Given a symmetric key and an initialization vector, encrypt some bytes in place and return the AES-GCM authentication tag.
pub fn encrypt_under_data_key(
    plaintext: &mut [u8],
    key: &[u8],
    iv: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow_error_and_log("Invalid data key length: must be 256 bits"))?;
    let nonce = Nonce::from_slice(iv);
    let auth_tag = cipher
        .encrypt_in_place_detached(nonce, b"", plaintext)
        .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt application key: {e}")))?;
    Ok(auth_tag.to_vec())
}

/// Given a symmetric key, an initialization vector and an AES-GCM authentication tag, decrypt some bytes in place.
pub fn decrypt_under_data_key(
    ciphertext: &mut [u8],
    key: &[u8],
    iv: &[u8],
    auth_tag: &Vec<u8>,
) -> anyhow::Result<()> {
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow_error_and_log("Invalid data key length: must be 256 bits"))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt_in_place_detached(nonce, b"", ciphertext, auth_tag.as_slice().into())
        .map_err(|e| anyhow_error_and_log(format!("{e}")))?;
    Ok(())
}
