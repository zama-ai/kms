use crate::{anyhow_error_and_log, cryptography::attestation::SecurityModuleProxy, some_or_err};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use aws_sdk_kms::Client as AWSKMSClient;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tfhe::{named::Named, Unversionize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use url::Url;

pub mod awskms;

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum AppKeyBlobVersioned {
    V0(AppKeyBlob),
}

/// Container type for encrypted application keys (such as FHE private keys)
#[derive(Serialize, Deserialize, Versionize, PartialEq, Debug)]
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

#[tonic::async_trait]
pub trait Keychain {
    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &self,
        payload: &T,
    ) -> anyhow::Result<AppKeyBlob>;
    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        envelope: &mut AppKeyBlob,
    ) -> anyhow::Result<T>;
}

pub enum KeychainProxy {
    AwsKmsSymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Symm>),
    AwsKmsAsymm(awskms::AWSKMSKeychain<SecurityModuleProxy, awskms::Asymm>),
}

#[tonic::async_trait]
impl Keychain for KeychainProxy {
    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &self,
        payload: &T,
    ) -> anyhow::Result<AppKeyBlob> {
        match &self {
            KeychainProxy::AwsKmsSymm(k) => k.encrypt(payload).await,
            KeychainProxy::AwsKmsAsymm(k) => k.encrypt(payload).await,
        }
    }
    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        envelope: &mut AppKeyBlob,
    ) -> anyhow::Result<T> {
        match &self {
            KeychainProxy::AwsKmsSymm(k) => k.decrypt(envelope).await,
            KeychainProxy::AwsKmsAsymm(k) => k.decrypt(envelope).await,
        }
    }
}

pub async fn make_keychain(
    keychain_url: Url,
    awskms_client: Option<AWSKMSClient>,
    security_module: Option<SecurityModuleProxy>,
) -> anyhow::Result<KeychainProxy> {
    let keychain = match keychain_url.scheme() {
        "awskms" => {
            let awskms_client = awskms_client.expect("AWS KMS client must be configured");
	    let security_module = security_module.expect("Security module must be present");
            let root_key_spec = some_or_err(
                keychain_url.host_str(),
                "Root key spec (symm/asymm) must be provided".to_string(),
            )?;
	    let root_key_id = some_or_err(
		keychain_url.path_segments().and_then(|mut p| p.next()),
		"Root key ID must be provided".to_string(),
	    )?.to_string();
	    match root_key_spec {
		"symm" => KeychainProxy::AwsKmsSymm(awskms::AWSKMSKeychain::new(
                    awskms_client,
                    security_module,
                    awskms::Symm::new(root_key_id),
		)?),
		"asymm" => KeychainProxy::AwsKmsAsymm(awskms::AWSKMSKeychain::new(
		    awskms_client.clone(),
		    security_module,
		    awskms::Asymm::new(awskms_client, root_key_id).await?,
		)?),
		other => anyhow::bail!("Root key spec must be one of symm/asymm, but {} was specified in keychain {}", other, keychain_url)
	    }
        }
        _ => anyhow::bail!("Only AWS KMS is currently supported, make sure to specify a keychain URL in the format awskms://root_key_spec/root_key_id"),
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
        .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt application key: {}", e)))?;
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
        .map_err(|e| anyhow_error_and_log(format!("{}", e)))?;
    Ok(())
}
