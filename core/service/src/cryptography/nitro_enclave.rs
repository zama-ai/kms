use crate::anyhow_error_and_log;
use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, IvSizeUser, KeyIvInit, KeySizeUser},
    Aes256,
};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use anyhow::{bail, ensure};
#[cfg(feature = "non-wasm")]
use aws_nitro_enclaves_nsm_api::api::{Request as NSMRequest, Response as NSMResponse};
#[cfg(feature = "non-wasm")]
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use rasn::{
    ber::de::{Decoder, DecoderOptions},
    de::Decode,
    types::{Integer, OctetString, Oid},
};
use rasn_cms::{
    algorithms::AES256_CBC, ContentInfo, EnvelopedData, RecipientInfo, CONTENT_DATA,
    CONTENT_ENVELOPED_DATA,
};
use rsa::sha2::Sha256;
#[cfg(feature = "non-wasm")]
use rsa::{pkcs8::EncodePublicKey, RsaPublicKey};
use rsa::{Oaep, RsaPrivateKey};

#[cfg(feature = "non-wasm")]
pub const ENCLAVE_SK_SIZE: usize = 2048;
#[cfg(feature = "non-wasm")]
const ATTESTATION_NONCE_SIZE: usize = 8;
// AES256-GCM-SIV uses 96 bit nonces
pub const APP_BLOB_NONCE_SIZE: usize = 12;
// AWS KMS is expected to produce this version of the CMS structure
const AWS_KMS_ENVELOPED_DATA_VERSION: isize = 2;
// AWS KMS is expected to produce this version of the recipient substructure
const AWS_KMS_ENVELOPED_DATA_RECIPIENT_VERSION: isize = 2;

/// Request the attestation document from the Nitro security module. Attestation
/// documents are used in AWS KMS requests to receive responses where the
/// sensitive data that can only be shared with enclaves running an approved
/// software version is encrypted under the attested enclave public key.
#[cfg(feature = "non-wasm")]
pub fn request_nitro_enclave_attestation(enclave_pk: &RsaPublicKey) -> anyhow::Result<Vec<u8>> {
    // generate a nonce to include into the attestation document
    let attestation_nonce = nitro_enclave_get_random(ATTESTATION_NONCE_SIZE)?;

    // request Nitro enclave attestation
    let nsm_fd = nsm_driver::nsm_init();
    let nsm_request = NSMRequest::Attestation {
        public_key: Some(enclave_pk.to_public_key_der()?.to_vec().into()),
        user_data: None,
        // The nonce can potentially be used in protocols that do not allow using the same
        // attestation twice. The AWS KMS API allows reusing attestations (in fact, there
        // does not seem to be a way to forbid it).
        nonce: Some(attestation_nonce.into()),
    };
    let NSMResponse::Attestation { document } =
        nsm_driver::nsm_process_request(nsm_fd, nsm_request)
    else {
        nsm_driver::nsm_exit(nsm_fd);
        bail!("Nitro enclave attestation request failed");
    };
    nsm_driver::nsm_exit(nsm_fd);

    Ok(document)
}

/// Request random bytes from the Nitro security module. Only used for generating initialization
/// vectors in symmetric encryption and attestation document nonces at the moment.
#[cfg(feature = "non-wasm")]
pub fn nitro_enclave_get_random(i: usize) -> anyhow::Result<Vec<u8>> {
    let nsm_fd = nsm_driver::nsm_init();
    let nsm_request = NSMRequest::GetRandom;
    let NSMResponse::GetRandom { random } = nsm_driver::nsm_process_request(nsm_fd, nsm_request)
    else {
        nsm_driver::nsm_exit(nsm_fd);
        bail!("Nitro enclave entropy generation request failed");
    };
    nsm_driver::nsm_exit(nsm_fd);
    ensure!(
        random.len() >= 256,
        "NSM returned less than 256 bytes of entropy"
    );
    ensure!(
        i <= random.len(),
        "More bytes of entropy requested than generated"
    );
    Ok(random[0..i].to_vec())
}

/// If a Nitro enclave attestation document is attached to a AWS KMS request,
/// the response will contain all plaintext values encrypted on the enclave
/// public key. This function allows for their decryption using the enclave
/// private key. In a better world, there would be a Nitro Enclave SDK for Rust
/// that implements this function. Alas, only the C SDK currently exists.
pub fn decrypt_ciphertext_for_recipient(
    ciphertext: Vec<u8>,
    enclave_sk: &RsaPrivateKey,
) -> anyhow::Result<Vec<u8>> {
    // peek inside of the top-level message and check that it contains PKCS7
    // Enveloped Data
    let mut cms_decoder = Decoder::new(ciphertext.as_slice(), DecoderOptions::ber());
    let cms = ContentInfo::decode(&mut cms_decoder)?;
    ensure!(
        cms.content_type == CONTENT_ENVELOPED_DATA,
        "Re-encrypted ciphertext content must be PKCS#7 Enveloped Data, actual content type: {}",
        cms.content_type
    );
    let mut envelope_decoder = Decoder::new(cms.content.as_ref(), DecoderOptions::ber());
    let envelope = EnvelopedData::decode(&mut envelope_decoder)?;

    // validate the PKCS7 envelope
    ensure!(
        envelope.version == Integer::Primitive(AWS_KMS_ENVELOPED_DATA_VERSION),
        "Re-encrypted ciphertext envelope must have version {}, actual version: {}",
        AWS_KMS_ENVELOPED_DATA_VERSION,
        envelope.version
    );
    ensure!(
        envelope.recipient_infos.len() == 1,
        "Re-encrypted ciphertext envelope must have exactly one recipient"
    );
    let RecipientInfo::KeyTransRecipientInfo(ktri) =
        envelope.recipient_infos.to_vec().pop().unwrap()
    else {
        bail!("Re-encrypted ciphertext envelope does not contain a recipient");
    };
    ensure!(
        ktri.version == Integer::Primitive(AWS_KMS_ENVELOPED_DATA_RECIPIENT_VERSION),
        "Re-encrypted ciphertext envelope recipient info must have version {}, actual version: {}",
        AWS_KMS_ENVELOPED_DATA_RECIPIENT_VERSION,
        ktri.version
    );
    ensure!(ktri.key_encryption_algorithm.algorithm == Oid:: ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSAES_OAEP,
	    "Re-encrypted ciphertext envelope must use RSA-OAEP for envelope encryption, actual algorithm: {}",
	    ktri.key_encryption_algorithm.algorithm
    );
    ensure!(
        envelope.encrypted_content_info.content_type == CONTENT_DATA,
        "Re-encrypted ciphertext envelope content must be PKCS#7 Data, actual content type: {}",
        envelope.encrypted_content_info.content_type
    );
    ensure!(
	envelope.encrypted_content_info.content_encryption_algorithm.algorithm == AES256_CBC,
	"Re-encrypted ciphertext envelope must use AES-256-CBC for content encryption, actual algorithm: {}",
	envelope.encrypted_content_info.content_encryption_algorithm.algorithm
    );
    let enc_session_key = ktri.encrypted_key.as_ref();
    let Some(iv_string) = envelope
        .encrypted_content_info
        .content_encryption_algorithm
        .parameters
    else {
        bail!("Re-encrypted ciphertext envelope does not contain an AES-256-CBC initialization vector")
    };
    let Some(enc_payload) = envelope.encrypted_content_info.encrypted_content else {
        bail!("Re-encrypted ciphertext envelope does not contain a payload")
    };

    // decrypt the PKCS7 envelope session key
    // RSA-OAEP-SHA256 is the only choice supported by AWS KMS
    let session_key = enclave_sk
        .decrypt(Oaep::new::<Sha256>(), enc_session_key)
        .map_err(|e| {
            anyhow_error_and_log(format!("Cannot decrypt PKCS7 envelope session key: {}", e))
        })?;
    ensure!(
        session_key.len() == Aes256::key_size(),
        "Reencrypted ciphertext envelope session key is not {} bits long, actual length: {} bits",
        Aes256::key_size() * 8,
        session_key.len() * 8
    );

    // decode the initialization vector from ASN.1
    let mut iv_decoder = Decoder::new(iv_string.as_ref(), DecoderOptions::ber());
    let iv = OctetString::decode(&mut iv_decoder)?;
    ensure!(iv.len() == cbc::Decryptor::<Aes256>::iv_size(),
	    "Reencrypted ciphertext envelope initialization vector is not {} bits long, actual length: {} bits",
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

/// Given a symmetric key and an initialization vector, encrypt some bytes in place and return the AES-GCM authentication tag.
pub fn encrypt_on_data_key(plaintext: &mut [u8], key: &[u8], iv: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow_error_and_log("Invalid data key length: must be 256 bits"))?;
    let nonce = Nonce::from_slice(iv);
    let auth_tag = cipher
        .encrypt_in_place_detached(nonce, b"", plaintext)
        .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt application key: {}", e)))?;
    Ok(auth_tag.to_vec())
}

/// Given a symmetric key, an initialization vector and an AES-GCM authentication tag, decrypt some bytes in place.
pub fn decrypt_on_data_key(
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
