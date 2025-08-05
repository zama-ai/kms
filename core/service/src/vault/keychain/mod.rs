use crate::{
    anyhow_error_and_log,
    backup::{
        custodian::{CustodianRecoveryOutput, InternalCustodianContext},
        operator::BackupCommitments,
    },
    conf::{AwsKmsKeySpec, AwsKmsKeychain, Keychain as KeychainConf, SecretSharingKeychain},
    cryptography::{
        attestation::SecurityModuleProxy,
        backup_pke::{BackupCiphertext, BackupPublicKey},
        internal_crypto_types::PrivateSigKey,
    },
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
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Into,
};
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
    // todo scan be removed and since we can get the same by cehcking. SecretSharing or AwsKMSSymm AWSKMSAssymm
    fn envelope_share_ids(&self) -> Option<BTreeSet<Role>>;

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
    my_role: Option<Role>,
    signer: Option<PrivateSigKey>,
) -> anyhow::Result<KeychainProxy> {
    let rng = AesRng::from_entropy(); // todo parameterize
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
        // TODO obsolete since we use a KEM to backup things, ie backup vault will either be awskms secured (in case of export) or public (ie no keychain) in case of secretsharing custodian based backup
        KeychainConf::SecretSharing(SecretSharingKeychain {
            custodian_keys, //todo remove
            threshold,
        }) => {
            // If secret share backup is used with the centralized KMS, assume
            // that my_id is 0
            let my_role = my_role.unwrap_or(Role::indexed_from_zero(0));
            let signer = signer.expect("Signing key must be loaded");
            let private_vault = private_storage
                .expect("Public vault must be provided to load custodian setup messages");
            // let ck_type = PrivDataType::CustodianSetupMessage.to_string();
            // let custodian_key_hashes = custodian_keys
            //     .iter()
            //     .map(|ck| ck.into_request_id())
            //     .collect::<anyhow::Result<Vec<_>>>()?;
            // let custodian_messages: Vec<InternalCustodianSetupMessage> = try_join_all(
            //     custodian_key_hashes
            //         .iter()
            //         .map(|ck_hash| read_versioned_at_request_id(private_vault, ck_hash, &ck_type)),
            // )
            // .await?;
            let all_custodian_ids = private_vault
                .all_data_ids(&PrivDataType::CustodianInfo.to_string())
                .await?;
            // Get the latest context ID which should be the most recent one
            let latest_context_id = match all_custodian_ids.iter().sorted().last() {
                Some(latest_context_id) => latest_context_id,
                None => {
                    return Err(anyhow_error_and_log(format!(
                        "No custodian setup available in the vault for role {my_role:?}",
                    )))
                }
            };
            let custodian_context: InternalCustodianContext = read_versioned_at_request_id(
                private_vault,
                latest_context_id,
                &PrivDataType::CustodianInfo.to_string(),
            )
            .await?;
            let backup_enc_key: BackupPublicKey = read_versioned_at_request_id(
                private_vault,
                latest_context_id,
                &PrivDataType::PubBackupKey.to_string(),
            )
            .await?;
            // for (ck, cm) in custodian_keys.iter().zip(custodian_messages.iter()) {
            //     let cm_key_der = cm.public_verf_key.pk().to_public_key_der()?;
            //     if cm_key_der.as_bytes() != ck.into_pem()?.contents {
            //         return Err(anyhow_error_and_log(format!(
            //             "Verification key in the setup message does not match the trusted key for custodian {}",
            //             cm.custodian_role,
            //         )));
            //     }
            // }
            KeychainProxy::from(secretsharing::SecretShareKeychain::new(
                rng,
                backup_enc_key,
                custodian_context.custodian_nodes.len(),
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
