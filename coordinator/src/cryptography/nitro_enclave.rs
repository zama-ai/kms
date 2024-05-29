use crate::anyhow_error_and_log;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit, Nonce};
use anyhow::{bail, ensure};
#[cfg(feature = "non-wasm")]
use aws_nitro_enclaves_nsm_api::api::{Request as NSMRequest, Response as NSMResponse};
#[cfg(feature = "non-wasm")]
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use cms::enveloped_data::{EnvelopedData, RecipientInfo as PKCS7RecipientInfo};
use der::{Decode, DecodeValue, Header, SliceReader};
#[cfg(feature = "non-wasm")]
use rand::rngs::OsRng;
#[cfg(feature = "non-wasm")]
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
#[cfg(feature = "non-wasm")]
use serde_bytes::ByteBuf;

/// A keypair that the Nitro enclave uses to communicate securely with AWS KMS. This keypair is
/// signed by the Nitro security module, and the signature is included in the attestation
/// document. This way AWS KMS can establish its authenticity and only respond to requests from
/// authorized enclave instances.
#[derive(Clone)]
pub struct NitroEnclaveKeys {
    pub enclave_sk: RsaPrivateKey,
    pub enclave_pk: RsaPublicKey,
    pub attestation_document: Vec<u8>,
}

#[cfg(feature = "non-wasm")]
const ENCLAVE_SK_SIZE: usize = 2048;
#[cfg(feature = "non-wasm")]
const ATTESTATION_NONCE_SIZE: usize = 8;
// AES256-GCM-SIV uses 96 bit nonces
pub const APP_BLOB_NONCE_SIZE: usize = 12;

#[cfg(feature = "non-wasm")]
pub fn gen_nitro_enclave_keys() -> anyhow::Result<NitroEnclaveKeys> {
    // generate a Nitro enclave keypair
    let enclave_sk = RsaPrivateKey::new(&mut OsRng, ENCLAVE_SK_SIZE)?;
    let enclave_pk = RsaPublicKey::from(&enclave_sk);
    let enclave_pk_der = enclave_pk.to_pkcs1_der()?;
    let enclave_pk_der_bytes = enclave_pk_der.as_ref().to_vec();

    // generate a nonce to include into the attestation document
    let attestation_nonce = nitro_enclave_get_random(ATTESTATION_NONCE_SIZE)?;

    // request Nitro enclave attestation
    let nsm_fd = nsm_driver::nsm_init();
    let nsm_request = NSMRequest::Attestation {
        public_key: Some(ByteBuf::from(enclave_pk_der_bytes)),
        user_data: None,
        // The nonce can potentially be used in protocols that do not allow using the same
        // attestation twice. The AWS KMS API allows reusing attestations (in fact, there
        // does not seem to be a way to forbid it).
        nonce: Some(ByteBuf::from(attestation_nonce)),
    };
    let NSMResponse::Attestation { document } =
        nsm_driver::nsm_process_request(nsm_fd, nsm_request)
    else {
        nsm_driver::nsm_exit(nsm_fd);
        bail!("Nitro enclave attestation request failed");
    };
    nsm_driver::nsm_exit(nsm_fd);

    Ok(NitroEnclaveKeys {
        enclave_sk,
        enclave_pk,
        attestation_document: document,
    })
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

/// If a Nitro enclave attestation document is attached to a AWS KMS request, the response will
/// contain all plaintext values encrypted on the enclave public key. This function allows for their
/// decryption using the enclave private key. In a better world, it would be implemented by the
/// Nitro enclave SDK but, alas, it is currently not.
pub fn decrypt_ciphertext_for_recipient(
    ciphertext: Vec<u8>,
    enclave_sk: &RsaPrivateKey,
) -> anyhow::Result<Vec<u8>> {
    // peek inside the re-encrypted key PKCS7 envelope
    let envelope_header = Header::from_der(ciphertext.as_slice())?;
    let mut envelope_reader = SliceReader::new(ciphertext.as_slice())?;
    let envelope: EnvelopedData =
        EnvelopedData::decode_value(&mut envelope_reader, envelope_header)?;
    ensure!(
        envelope.recip_infos.0.len() == 1,
        "Re-encrypted ciphertext envelope must have exactly one recipient"
    );
    let PKCS7RecipientInfo::Ktri(ktri) = envelope.recip_infos.0.get(0).unwrap() else {
        bail!("Re-encrypted ciphertext envelope does not contain a session key");
    };
    ensure!(
        ktri.version == envelope.version,
        "Re-encrypted ciphertext envelope malformed"
    );
    let enc_session_key = ktri.enc_key.as_bytes();
    // NOTE: `cms` doesn't parse OIDs yet but it would be good to validate that
    // encrypted_content.content_type == pkcs7_data and that
    // encrypted_content.content_enc_alg.oid == aes_256_cbc
    ensure!(
        envelope
            .encrypted_content
            .content_enc_alg
            .parameters
            .is_some(),
        "Re-encrypted ciphertext envelope does not contain an initialization vector"
    );
    let iv = envelope
        .encrypted_content
        .content_enc_alg
        .parameters
        .unwrap();
    ensure!(
        envelope.encrypted_content.encrypted_content.is_some(),
        "Re-encrypted ciphertext envelope does not contain a payload"
    );
    let envelope_payload = envelope.encrypted_content.encrypted_content.unwrap();

    // decrypt the PKCS7 envelope session key
    let session_key = enclave_sk.decrypt(Oaep::new::<Sha256>(), enc_session_key)?;

    // decrypt the ciphertext for recipient enclave
    let plaintext =
        cbc::Decryptor::<aes::Aes256>::new(session_key.as_slice().into(), iv.value().into())
            .decrypt_padded_vec_mut::<Pkcs7>(envelope_payload.as_bytes())
            .map_err(|e| anyhow_error_and_log(format!("{}", e)))?;
    Ok(plaintext)
}

/// Given a symmetric key and an initialization vector, encrypt some bytes in place and return the AES-GCM authentication tag.
pub fn encrypt_on_data_key(plaintext: &mut [u8], key: &[u8], iv: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| anyhow_error_and_log("Invalid data key length: must be 256 bits"))?;
    let nonce = Nonce::from_slice(iv);
    let auth_tag = cipher
        .encrypt_in_place_detached(nonce, b"", plaintext)
        .map_err(|e| anyhow_error_and_log(format!("{}", e)))?;
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
