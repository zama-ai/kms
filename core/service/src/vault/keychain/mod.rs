use crate::{
    anyhow_error_and_log,
    backup::BackupCiphertext,
    conf::{AwsKmsKeySpec, AwsKmsKeychain, Keychain as KeychainConf, SecretSharingKeychain},
    cryptography::attestation::SecurityModuleProxy,
    vault::storage::StorageReader,
};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use aes_prng::AesRng;
use aws_sdk_kms::Client as AWSKMSClient;
use enum_dispatch::enum_dispatch;
use iam_rs::IAMPolicy;
use rand::SeedableRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{convert::Into, sync::Arc};
use strum_macros::EnumTryAs;
use tfhe::{named::Named, Unversionize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_fhe::networking::tls::ReleasePCRValues;

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
    /// Encrypt some data. The `data_type` is used to identify the type of data being encrypted must be of the `PrivDataType` type.
    /// I.e. _Not_ the full `BackupDataType`.
    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_type: &str,
    ) -> anyhow::Result<EnvelopeStore>;

    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T>;

    fn root_key_measurements(&self) -> Arc<RootKeyMeasurements>;
}

#[allow(clippy::large_enum_variant)]
#[enum_dispatch(Keychain)]
pub enum KeychainProxy {
    AwsKmsSymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Symm, AesRng>),
    AwsKmsAsymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Asymm, AesRng>),
    SecretSharing(secretsharing::SecretShareKeychain<AesRng>),
}

#[derive(EnumTryAs, Clone)]
pub enum EnvelopeLoad {
    AppKeyBlob(AppKeyBlob),
    OperatorRecoveryInput(BackupCiphertext),
}

#[derive(EnumTryAs)]
pub enum EnvelopeStore {
    AppKeyBlob(AppKeyBlob),
    OperatorBackupOutput(BackupCiphertext),
}

/// Parties can optionally attest to the key policies they use for private vault
/// root keys. The key policy attestation outcome is recorded in this data
/// structure and included in the attestation document as user data.
#[derive(EnumTryAs, Serialize, Deserialize, Debug)]
pub enum RootKeyMeasurements {
    AwsKms {
        // AWS KMS keys might be fully managed by AWS KMS, by an external key
        // store, or be imported. We only want root keys fully managed by AWS
        // KMS, otherwise an attacker could possess a root key copy that he can
        // use without passing AWS Nitro attestation.
        key_origin: String,
        // We expect the parties to use key policies that restrict the use of
        // root keys to enclaves that can attest to expected PCR values.
        key_policy: IAMPolicy,
    },
    // Currently, we don't have any machine-verifiable key policies for the
    // custodian secret sharing backup scheme.
    SecretSharing {},
}

/// When private vault root key policy attestation is enabled, this function is
/// supplied to the `AttestedVerifier` as a `user_data_verifier`. It constructs
/// a canonical policy by substituting the provided PCR values into the policy
/// template and compares it against the one supplied in the user data section
/// of the attestation document. If the two match, we assume that the remote
/// party is using the expected root key policy.
pub fn verify_root_key_measurements(
    pcr_values: ReleasePCRValues,
    user_data: Vec<u8>,
) -> anyhow::Result<bool> {
    let measurements: RootKeyMeasurements = ciborium::from_reader(user_data.as_slice())?;
    match measurements {
        RootKeyMeasurements::AwsKms {
            key_origin,
            key_policy,
        } => Ok(key_origin == "AWS_KMS" && key_policy == awskms::make_root_key_policy(pcr_values)),
        RootKeyMeasurements::SecretSharing {} => Ok(true),
    }
}

pub async fn make_keychain_proxy(
    keychain_conf: &KeychainConf,
    awskms_client: Option<AWSKMSClient>,
    security_module: Option<Arc<SecurityModuleProxy>>,
    pub_storage: Option<&impl StorageReader>,
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
                    awskms_client.clone(),
                    security_module,
                    awskms::Symm::new(awskms_client, root_key_id.clone()).await?,
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
        // it can switch to it by rebooting.
        KeychainConf::SecretSharing(SecretSharingKeychain {}) => {
            let ssk = secretsharing::SecretShareKeychain::new(rng, pub_storage).await?;
            KeychainProxy::from(ssk)
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow_error_and_log("Invalid data key length: must be 256 bits"))?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt_in_place_detached(nonce, b"", ciphertext, auth_tag.as_slice().into())
        .map_err(|e| anyhow_error_and_log(format!("{e}")))?;
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::{
        awskms::{canonicalize_iam_policy, make_root_key_policy},
        verify_root_key_measurements, RootKeyMeasurements,
    };
    use iam_rs::{IAMPolicy, IAMVersion};
    use threshold_fhe::networking::tls::ReleasePCRValues;

    #[test]
    fn test_verify_root_key_measurements() {
        let good_pcr_values = ReleasePCRValues {
            pcr0: hex::decode("abcdef01").unwrap(),
            pcr1: hex::decode("abcdef02").unwrap(),
            pcr2: hex::decode("abcdef03").unwrap(),
        };
        let good_key_policy = make_root_key_policy(good_pcr_values.clone());
        let good_key_measurements = RootKeyMeasurements::AwsKms {
            key_origin: "AWS_KMS".to_string(),
            key_policy: good_key_policy,
        };
        let mut good_key_measurements_bytes = Vec::with_capacity(1024);
        ciborium::into_writer(&good_key_measurements, &mut good_key_measurements_bytes).unwrap();
        assert!(
            good_key_measurements_bytes.len() <= 1024,
            "Attested root key policy should not be longer than 1024 bytes"
        );
        assert!(
            verify_root_key_measurements(good_pcr_values.clone(), good_key_measurements_bytes)
                .unwrap(),
            "Attested good root key policy should match the known policy template"
        );

        let mut empty_key_policy = IAMPolicy::with_version(IAMVersion::V20121017);
        canonicalize_iam_policy(&mut empty_key_policy);
        let careless_key_measurements = RootKeyMeasurements::AwsKms {
            key_origin: "AWS_KMS".to_string(),
            key_policy: empty_key_policy,
        };
        let mut careless_key_measurements_bytes = Vec::with_capacity(1024);
        ciborium::into_writer(
            &careless_key_measurements,
            &mut careless_key_measurements_bytes,
        )
        .unwrap();
        assert!(
            !verify_root_key_measurements(good_pcr_values.clone(), careless_key_measurements_bytes)
                .unwrap(),
            "Empty root key policy should not match the known policy template"
        );

        let bad_pcr_values = ReleasePCRValues {
            pcr0: hex::decode("05060708").unwrap(),
            pcr1: hex::decode("05060708").unwrap(),
            pcr2: hex::decode("05060708").unwrap(),
        };
        let bad_key_policy = make_root_key_policy(bad_pcr_values.clone());
        let bad_key_measurements = RootKeyMeasurements::AwsKms {
            key_origin: "AWS_KMS".to_string(),
            key_policy: bad_key_policy,
        };
        let mut bad_key_measurements_bytes = Vec::with_capacity(1024);
        ciborium::into_writer(&bad_key_measurements, &mut bad_key_measurements_bytes).unwrap();
        assert!(
            !verify_root_key_measurements(good_pcr_values, bad_key_measurements_bytes).unwrap(),
            "Attested bad root key policy should not match the known policy template"
        );
    }
}
