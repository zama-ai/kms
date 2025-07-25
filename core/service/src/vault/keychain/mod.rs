use crate::{
    anyhow_error_and_log,
    backup::{
        custodian::{CustodianRecoveryOutput, InternalCustodianSetupMessage},
        operator::OperatorBackupOutput,
    },
    conf::{AwsKmsKeySpec, AwsKmsKeychain, Keychain as KeychainConf, SecretSharingKeychain},
    cryptography::{attestation::SecurityModuleProxy, internal_crypto_types::PrivateSigKey},
    vault::{storage::read_versioned_at_request_id, Vault},
};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use aws_sdk_kms::Client as AWSKMSClient;
use enum_dispatch::enum_dispatch;
use futures_util::future::try_join_all;
use k256::pkcs8::EncodePublicKey;
use kms_grpc::{rpc_types::PubDataType, RequestId};
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
pub enum KeychainProxy {
    AwsKmsSymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Symm>),
    AwsKmsAsymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Asymm>),
    SecretSharing(secretsharing::SecretShareKeychain),
}

#[derive(EnumTryAs, Clone)]
pub enum EnvelopeLoad {
    AppKeyBlob(AppKeyBlob),
    OperatorRecoveryInput(
        BTreeMap<Role, CustodianRecoveryOutput>,
        BTreeMap<Role, Vec<u8>>,
    ),
}

#[derive(EnumTryAs)]
pub enum EnvelopeStore {
    AppKeyBlob(AppKeyBlob),
    OperatorBackupOutput(BTreeMap<Role, OperatorBackupOutput>),
}

pub async fn make_keychain(
    keychain_conf: &KeychainConf,
    awskms_client: Option<AWSKMSClient>,
    security_module: Option<SecurityModuleProxy>,
    public_vault: Option<&Vault>,
    my_role: Option<Role>,
    signer: Option<PrivateSigKey>,
) -> anyhow::Result<KeychainProxy> {
    let keychain = match keychain_conf {
        KeychainConf::AwsKms(AwsKmsKeychain {
            root_key_id,
            root_key_spec,
        }) => {
            let awskms_client = awskms_client.expect("AWS KMS client must be configured");
            let security_module = security_module.expect("Security module must be present");
            match root_key_spec {
                AwsKmsKeySpec::Symm => KeychainProxy::from(awskms::AWSKMSKeychain::new(
                    awskms_client,
                    security_module,
                    awskms::Symm::new(root_key_id.clone()),
                )?),
                AwsKmsKeySpec::Asymm => KeychainProxy::from(awskms::AWSKMSKeychain::new(
                    awskms_client.clone(),
                    security_module,
                    awskms::Asymm::new(awskms_client, root_key_id.clone()).await?,
                )?),
            }
        }
        KeychainConf::SecretSharing(SecretSharingKeychain {
            custodian_keys,
            threshold,
        }) => {
            // If secret share backup is used with the centralized KMS, assume
            // that my_id is 0
            let my_role = my_role.unwrap_or(Role::indexed_from_zero(0));
            let signer = signer.expect("Signing key must be loaded");
            let public_vault = public_vault
                .expect("Public vault must be provided to load custodian setup messages");
            let ck_type = PubDataType::CustodianSetupMessage.to_string();
            let custodian_key_hashes = custodian_keys
                .iter()
                .map(|ck| ck.into_request_id())
                .collect::<anyhow::Result<Vec<_>>>()?;
            let custodian_messages: Vec<InternalCustodianSetupMessage> = try_join_all(
                custodian_key_hashes
                    .iter()
                    .map(|ck_hash| read_versioned_at_request_id(public_vault, ck_hash, &ck_type)),
            )
            .await?;
            for (ck, cm) in custodian_keys.iter().zip(custodian_messages.iter()) {
                let cm_key_der = cm.public_verf_key.pk().to_public_key_der()?;
                if cm_key_der.as_bytes() != ck.into_pem()?.contents {
                    return Err(anyhow_error_and_log(format!(
                        "Verification key in the setup message does not match the trusted key for custodian {}",
                        cm.custodian_role,
                    )));
                }
            }
            KeychainProxy::from(secretsharing::SecretShareKeychain::new(
                custodian_messages,
                my_role,
                signer,
                *threshold,
            )?)
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
