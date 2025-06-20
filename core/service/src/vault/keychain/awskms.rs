use super::{
    decrypt_under_data_key, encrypt_under_data_key, AppKeyBlob, EnvelopeLoad, EnvelopeStore,
    Keychain,
};
use crate::{
    anyhow_error_and_log, consts::SAFE_SER_SIZE_LIMIT, cryptography::attestation::SecurityModule,
    some_or_err,
};
use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, IvSizeUser, KeyIvInit, KeySizeUser},
    Aes256,
};
use anyhow::{bail, ensure};
use aws_config::SdkConfig;
use aws_sdk_kms::{
    primitives::Blob,
    types::{
        DataKeySpec::Aes256 as Aes256Type, KeyEncryptionMechanism, KeySpec::Rsa4096 as Rsa4096Type,
        KeyUsageType::EncryptDecrypt, RecipientInfo as KMSRecipientInfo,
    },
    Client as AWSKMSClient,
};
use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
use hyper_rustls::HttpsConnectorBuilder;
use kms_grpc::RequestId;
#[cfg(feature = "non-wasm")]
use rand::rngs::OsRng;
use rasn::{
    ber::de::{Decoder, DecoderOptions},
    de::Decode,
    types::{Integer, OctetString, Oid},
};
use rasn_cms::{
    algorithms::AES256_CBC, ContentInfo, EnvelopedData, RecipientInfo, CONTENT_DATA,
    CONTENT_ENVELOPED_DATA,
};
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    sha2::Sha256,
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeSet;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{named::Named, Unversionize, Versionize};
use threshold_fhe::execution::runtime::party::Role;
use url::Url;

// recipient enclave RSA keypair size
pub const RECIPIENT_KEYPAIR_SIZE: usize = 2048;
// AES256-GCM-SIV uses 96 bit nonces
pub const APP_BLOB_NONCE_SIZE: usize = 12;
// AWS KMS is expected to produce this version of the CMS structure
const AWS_KMS_ENVELOPED_DATA_VERSION: isize = 2;
// AWS KMS is expected to produce this version of the recipient substructure
const AWS_KMS_ENVELOPED_DATA_RECIPIENT_VERSION: isize = 2;

pub trait RootKey {}

pub struct Symm {
    pub key_id: String,
}

impl Symm {
    pub fn new(key_id: String) -> Self {
        Self { key_id }
    }
}

impl RootKey for Symm {}

pub struct Asymm {
    pub key_id: String,
    pub pk: RsaPublicKey,
}

impl Asymm {
    pub async fn new(awskms_client: AWSKMSClient, root_key_id: String) -> anyhow::Result<Self> {
        let get_public_key_response = awskms_client
            .get_public_key()
            .key_id(root_key_id.clone())
            .send()
            .await?;

        let pk_spec = some_or_err(
            get_public_key_response.key_spec,
            "No key spec returned for the root public key by AWS KMS".to_string(),
        )?;
        ensure!(
            pk_spec == Rsa4096Type,
            "Root public key must be RSA4096: check AWS KMS deployment"
        );

        let pk_usage = some_or_err(
            get_public_key_response.key_usage,
            "No key usage returned for the root public key by AWS KMS".to_string(),
        )?;
        ensure!(pk_usage == EncryptDecrypt, "Root public key is not allowed to be used for encryption/decryption: check AWS KMS key policy");

        let pk_bytes = some_or_err(
            get_public_key_response.public_key,
            "No public key blob returned by AWS KMS".to_string(),
        )?;

        let pk = RsaPublicKey::from_public_key_der(pk_bytes.as_ref())?;

        Ok(Self {
            key_id: root_key_id,
            pk,
        })
    }
}

impl RootKey for Asymm {}

/// Keeps together everything needed for running a chain of trust for working
/// with application secret keys (such as FHE private keys). The root key
/// encrypt data keys which encrypt application keys. The root key is stored in
/// AWS KMS and never leaves it. Encrypted application keys (together with the
/// corresponding data keys) are stored on S3. The enclave keypair permits
/// secure decryption of data keys by AWS KMS.
pub struct AWSKMSKeychain<S: SecurityModule, K: RootKey> {
    awskms_client: AWSKMSClient,
    security_module: S,
    recipient_sk: RsaPrivateKey,
    recipient_pk: RsaPublicKey,
    root_key: K,
}

impl<S: SecurityModule, K: RootKey> AWSKMSKeychain<S, K> {
    pub fn new(
        awskms_client: AWSKMSClient,
        security_module: S,
        root_key: K,
    ) -> anyhow::Result<Self> {
        let recipient_sk = RsaPrivateKey::new(&mut OsRng, RECIPIENT_KEYPAIR_SIZE)?;
        let recipient_pk = RsaPublicKey::from(&recipient_sk);
        Ok(AWSKMSKeychain {
            awskms_client,
            security_module,
            recipient_sk,
            recipient_pk,
            root_key,
        })
    }

    /// Requests the AWS KMS to decrypt a data key using a root key (managed by AWS KMS) and uses that
    /// data key to decrypt an application key (such as an FHE private key).
    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        envelope: &mut AppKeyBlob,
    ) -> anyhow::Result<T> {
        // request enclave attestation before making an AWS KMS request, so the
        // attestation is fresh and not older than 5 minutes
        let attestation = self
            .security_module
            .attest_pk_bytes(self.recipient_pk.to_public_key_der()?.to_vec())
            .await?;

        // decrypt the data key under which the app key was encrypted
        let decrypt_data_key_response = self
            .awskms_client
            .decrypt()
            .key_id(&envelope.root_key_id)
            .ciphertext_blob(Blob::new(envelope.data_key_blob.clone()))
            .recipient(
                KMSRecipientInfo::builder()
                    .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                    .attestation_document(Blob::new(attestation))
                    .build(),
            )
            .send()
            .await?;
        let decrypt_data_key_response_ciphertext_bytes = some_or_err(
            decrypt_data_key_response.ciphertext_for_recipient,
            "No blob returned in decryption response from AWS".to_string(),
        )?;
        let data_key = decrypt_ciphertext_for_recipient(
            decrypt_data_key_response_ciphertext_bytes.into_inner(),
            &self.recipient_sk,
        )?;

        // decrypt the app key
        decrypt_under_data_key(
            &mut envelope.ciphertext,
            &data_key,
            &envelope.iv,
            &envelope.auth_tag,
        )?;
        let mut buf = std::io::Cursor::new(&envelope.ciphertext);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
    }
}

//#[tonic::async_trait]
impl<S: SecurityModule + Sync + Send> Keychain for AWSKMSKeychain<S, Symm> {
    fn envelope_share_ids(&self) -> Option<BTreeSet<Role>> {
        None::<BTreeSet<Role>>
    }

    /// Request a data key from AWS KMS and encrypt an application key (such as the FHE private key) on
    /// it. Stores a copy of the data key encrypted on the root key (stored in AWS KMS) together with
    /// the encrypted application key.
    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        _payload_id: &RequestId,
        payload: &T,
    ) -> anyhow::Result<EnvelopeStore> {
        // request enclave attestation before making an AWS KMS request, so the
        // attestation is fresh and not older than 5 minutes
        let attestation = self
            .security_module
            .attest_pk_bytes(self.recipient_pk.to_public_key_der()?.to_vec())
            .await?;

        // request the data key from AWS KMS to encrypt the app key
        let gen_data_key_response = self
            .awskms_client
            .generate_data_key()
            .key_id(&self.root_key.key_id)
            .key_spec(Aes256Type)
            .recipient(
                KMSRecipientInfo::builder()
                    .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                    .attestation_document(Blob::new(attestation))
                    .build(),
            )
            .send()
            .await?;

        // decrypt the data key with the Nitro enclave private key
        let gen_data_key_response_ciphertext_blob = some_or_err(
            gen_data_key_response.ciphertext_for_recipient,
            "No ciphertext for recipient returned in data key generation response from AWS KMS"
                .to_string(),
        )?;
        let data_key = decrypt_ciphertext_for_recipient(
            gen_data_key_response_ciphertext_blob.into_inner(),
            &self.recipient_sk,
        )?;

        // encrypt the app key under the data key
        let mut blob_bytes = Vec::new();
        safe_serialize(payload, &mut blob_bytes, SAFE_SER_SIZE_LIMIT)?;
        let iv = self.security_module.get_random(APP_BLOB_NONCE_SIZE).await?;
        let auth_tag = encrypt_under_data_key(&mut blob_bytes, &data_key, &iv)?;
        Ok(EnvelopeStore::AppKeyBlob(AppKeyBlob {
            root_key_id: self.root_key.key_id.to_string(),
            data_key_blob: some_or_err(
                gen_data_key_response.ciphertext_blob,
                "No ciphertext blob returned in data key generation response from AWS KMS"
                    .to_string(),
            )?
            .into_inner(),
            ciphertext: blob_bytes,
            iv,
            auth_tag,
        }))
    }

    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        _payload_id: &RequestId,
        envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T> {
        AWSKMSKeychain::<S, Symm>::decrypt(
            self,
            &mut envelope
                .clone()
                .try_as_app_key_blob()
                .ok_or(anyhow_error_and_log("Expected single share encrypted data"))?,
        )
        .await
    }
}

//#[tonic::async_trait]
impl<S: SecurityModule + Sync + Send> Keychain for AWSKMSKeychain<S, Asymm> {
    fn envelope_share_ids(&self) -> Option<BTreeSet<Role>> {
        None::<BTreeSet<Role>>
    }

    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        _payload_id: &RequestId,
        payload: &T,
    ) -> anyhow::Result<EnvelopeStore> {
        // generate a fresh data key
        let data_key = self.security_module.get_random(Aes256::key_size()).await?;
        let enc_data_key = self
            .root_key
            .pk
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), data_key.as_ref())
            .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt data key: {}", e)))?;

        // encrypt the app key under the data key
        let mut blob_bytes = Vec::new();
        safe_serialize(payload, &mut blob_bytes, SAFE_SER_SIZE_LIMIT)?;
        let iv = self.security_module.get_random(APP_BLOB_NONCE_SIZE).await?;
        let auth_tag = encrypt_under_data_key(&mut blob_bytes, &data_key, &iv)?;
        Ok(EnvelopeStore::AppKeyBlob(AppKeyBlob {
            root_key_id: self.root_key.key_id.clone(),
            data_key_blob: enc_data_key,
            ciphertext: blob_bytes,
            iv,
            auth_tag,
        }))
    }

    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        _payload_id: &RequestId,
        envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T> {
        AWSKMSKeychain::<S, Asymm>::decrypt(
            self,
            &mut envelope
                .clone()
                .try_as_app_key_blob()
                .ok_or(anyhow_error_and_log(
                    "Expected single share encrypted value",
                ))?,
        )
        .await
    }
}

/// Given the address of a vsock-to-TCP proxy, constructs an AWS KMS client for use inside of a
/// Nitro enclave.
pub async fn build_aws_kms_client(
    aws_sdk_config: &SdkConfig,
    aws_kms_endpoint: Option<Url>,
) -> AWSKMSClient {
    let region = aws_sdk_config.region().expect("AWS region must be set");
    let awskms_config = match aws_kms_endpoint {
        Some(p) => {
            let https_connector = HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_only()
                // Overrides the hostname checked during the TLS handshake
                .with_server_name(format!("kms.{}.amazonaws.com", region))
                .enable_http1()
                .build();
            let http_client = HyperClientBuilder::new().build(https_connector);
            aws_sdk_kms::config::Builder::from(aws_sdk_config)
                // Overrides the hostname used for the TCP connection
                .endpoint_url(p)
                .http_client(http_client)
                .build()
        }
        None => aws_sdk_kms::config::Builder::from(aws_sdk_config).build(),
    };
    AWSKMSClient::from_conf(awskms_config)
}

/// If a Nitro enclave attestation document is attached to a AWS KMS request,
/// the response will contain all plaintext values encrypted on the enclave
/// public key. This function allows for their decryption using the enclave
/// private key. In a better world, there would be a Nitro Enclave SDK for Rust
/// that implements this function. Alas, only the C SDK currently exists.
pub fn decrypt_ciphertext_for_recipient(
    ciphertext: Vec<u8>,
    recipient_sk: &RsaPrivateKey,
) -> anyhow::Result<Vec<u8>> {
    // peek inside of the top-level message and check that it contains PKCS7
    // Enveloped Data
    let mut cms_decoder = Decoder::new(ciphertext.as_slice(), DecoderOptions::ber());
    let cms = ContentInfo::decode(&mut cms_decoder)?;
    ensure!(
        cms.content_type == CONTENT_ENVELOPED_DATA,
        "User decrypted ciphertext content must be PKCS#7 Enveloped Data, actual content type: {}",
        cms.content_type
    );
    let mut envelope_decoder = Decoder::new(cms.content.as_ref(), DecoderOptions::ber());
    let envelope = EnvelopedData::decode(&mut envelope_decoder)?;

    // validate the PKCS7 envelope
    ensure!(
        envelope.version == Integer::Primitive(AWS_KMS_ENVELOPED_DATA_VERSION),
        "User decrypted ciphertext envelope must have version {}, actual version: {}",
        AWS_KMS_ENVELOPED_DATA_VERSION,
        envelope.version
    );
    ensure!(
        envelope.recipient_infos.len() == 1,
        "User decrypted ciphertext envelope must have exactly one recipient"
    );
    let RecipientInfo::KeyTransRecipientInfo(ktri) =
        envelope.recipient_infos.to_vec().pop().unwrap()
    else {
        bail!("User decrypted ciphertext envelope does not contain a recipient");
    };
    ensure!(
        ktri.version == Integer::Primitive(AWS_KMS_ENVELOPED_DATA_RECIPIENT_VERSION),
        "User decrypted ciphertext envelope recipient info must have version {}, actual version: {}",
        AWS_KMS_ENVELOPED_DATA_RECIPIENT_VERSION,
        ktri.version
    );
    ensure!(ktri.key_encryption_algorithm.algorithm == Oid:: ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSAES_OAEP,
	    "User decrypted ciphertext envelope must use RSA-OAEP for envelope encryption, actual algorithm: {}",
	    ktri.key_encryption_algorithm.algorithm
    );
    ensure!(
        envelope.encrypted_content_info.content_type == CONTENT_DATA,
        "User decrypted ciphertext envelope content must be PKCS#7 Data, actual content type: {}",
        envelope.encrypted_content_info.content_type
    );
    ensure!(
	envelope.encrypted_content_info.content_encryption_algorithm.algorithm == AES256_CBC,
	"User decrypted ciphertext envelope must use AES-256-CBC for content encryption, actual algorithm: {}",
	envelope.encrypted_content_info.content_encryption_algorithm.algorithm
    );
    let enc_session_key = ktri.encrypted_key.as_ref();
    let Some(iv_string) = envelope
        .encrypted_content_info
        .content_encryption_algorithm
        .parameters
    else {
        bail!("User decrypted ciphertext envelope does not contain an AES-256-CBC initialization vector")
    };
    let Some(enc_payload) = envelope.encrypted_content_info.encrypted_content else {
        bail!("User decrypted ciphertext envelope does not contain a payload")
    };

    // decrypt the PKCS7 envelope session key
    // RSA-OAEP-SHA256 is the only choice supported by AWS KMS
    let session_key = recipient_sk
        .decrypt(Oaep::new::<Sha256>(), enc_session_key)
        .map_err(|e| {
            anyhow_error_and_log(format!("Cannot decrypt PKCS7 envelope session key: {}", e))
        })?;
    ensure!(
        session_key.len() == Aes256::key_size(),
        "User decrypted ciphertext envelope session key is not {} bits long, actual length: {} bits",
        Aes256::key_size() * 8,
        session_key.len() * 8
    );

    // decode the initialization vector from ASN.1
    let mut iv_decoder = Decoder::new(iv_string.as_ref(), DecoderOptions::ber());
    let iv = OctetString::decode(&mut iv_decoder)?;
    ensure!(iv.len() == cbc::Decryptor::<Aes256>::iv_size(),
	    "User decrypted ciphertext envelope initialization vector is not {} bits long, actual length: {} bits",
	    cbc::Decryptor::<Aes256>::iv_size() * 8,
	    iv.len() * 8
    );

    // decrypt the ciphertext for recipient enclave
    // AES256-CBC is the only choice supported by AWS KMS
    let plaintext = cbc::Decryptor::<Aes256>::new_from_slices(session_key.as_slice(), iv.as_ref())?
        .decrypt_padded_vec_mut::<Pkcs7>(enc_payload.as_ref())
        .map_err(|e| {
            anyhow_error_and_log(format!("Cannot decrypt ciphertext for recipient: {}", e))
        })?;
    Ok(plaintext)
}
