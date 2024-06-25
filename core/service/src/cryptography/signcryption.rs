//! Necessary methods for secure client communication in relation to decryption requests.
//!
//! Client requests to the server should be validated against the client's ECDSA secp256k1 key.
//! Based on the request the server does sign-then-encrypt to securely encrypt a payload for the
//! client. Signing for the server is also carried out using ECDSA with secp256k1 and the client
//! can validate this against the server's public key.
//!
//! For encryption a hybrid encryption is used based on ECIES using Libsodium. More specifically
//! using ECDH with curve 25519 and Salsa. NOTE This may change in the future to be more compatible
//! with NIST standardized schemes.

use super::der_types::{
    Cipher, PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, Signature, SigncryptionPair,
    SigncryptionPubKey,
};
use crate::rpc::rpc_types::{Plaintext, SigncryptionPayload};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log};
use ::signature::{Signer, Verifier};
#[cfg(feature = "non-wasm")]
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{Nonce, SalsaBox, SecretKey};
use k256::ecdsa::SigningKey;
use nom::AsBytes;
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use serde_asn1_der::{from_bytes, to_vec};
use sha3::{Digest, Sha3_256};

const DIGEST_BYTES: usize = 256 / 8; // SHA3-256 digest
pub(crate) const SIG_SIZE: usize = 64; // a 32 byte r value and a 32 byte s value
pub const RND_SIZE: usize = 128 / 8; // the amount of bytes used for sampling random values to stop brute-forcing or statistical attacks

/// Generate ephemeral keys used for encryption.
///
/// Concretely it involves generating ECDH keys for curve 25519 to be used in ECIES for hybrid
/// encryption using Salsa.
pub fn encryption_key_generation(
    rng: &mut (impl CryptoRng + RngCore),
) -> (PublicEncKey, PrivateEncKey) {
    let sk = SecretKey::generate(rng);
    (PublicEncKey(sk.public_key()), PrivateEncKey(sk))
}

/// Computing the signature on message based on the server's signing key.
///
/// Returns the signed message as a vector of bytes. Concretely r || s.
pub fn sign<T>(msg: &T, server_sig_key: &PrivateSigKey) -> anyhow::Result<Signature>
where
    T: Serialize + AsRef<[u8]>,
{
    let sig: k256::ecdsa::Signature = server_sig_key.sk.try_sign(msg.as_ref())?;
    // Normalize s value to ensure a consistant signature and protect against malleability
    sig.normalize_s();
    Ok(Signature { sig })
}

alloy_sol_types::sol! {
    struct ReencryptSol {
        uint8[] pub_enc_key;
    }
}

pub fn sign_eip712<T: SolStruct>(
    msg: &T,
    domain: &alloy_sol_types::Eip712Domain,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Signature> {
    let signing_hash = msg.eip712_signing_hash(domain);
    let sig: k256::ecdsa::Signature = server_sig_key.sk.try_sign(&signing_hash[..])?;
    // Normalize s value to ensure a consistant signature and protect against malleability
    sig.normalize_s();
    Ok(Signature { sig })
}

/// Verify a plain signature.
///
/// Returns true if the signature is ok and false otherwise.
#[cfg(feature = "non-wasm")]
pub(crate) fn internal_verify_sig<T>(
    payload: &T,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
) -> bool
where
    T: Serialize + AsRef<[u8]>,
{
    // Check that the signature is normalized
    if !check_normalized(sig) {
        return false;
    }

    // Verify signature
    if server_verf_key
        .pk
        .verify(payload.as_ref(), &sig.sig)
        .is_err()
    {
        tracing::warn!("Signature {:X?} is not valid", sig.sig);
        return false;
    }

    true
}

#[cfg(feature = "non-wasm")]
pub(crate) fn internal_verify_sig_eip712<T: SolStruct>(
    msg: &T,
    domain: &Eip712Domain,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
) -> bool {
    // Check that the signature is normalized
    if !check_normalized(sig) {
        return false;
    }
    let signing_hash = msg.eip712_signing_hash(domain);
    if server_verf_key
        .pk
        .verify(&signing_hash[..], &sig.sig)
        .is_err()
    {
        tracing::warn!("Signature {:X?} is not valid", sig.sig);
        return false;
    }

    true
}

/// Compute the signcryption of a message based on the public keys received from a client and the
/// server's signing key.
///
/// Returns the signcrypted message.
///
/// WARNING: It is assumed that the client's public key HAS been validated to come from a valid
/// `ClientRequest` and validated to be consistent with the blockchain identity of the client BEFORE
/// calling this method. IF THIS HAS NOT BEEN DONE THEN ANYONE CAN IMPERSONATE ANY CLIENT!!!
pub fn signcrypt<T>(
    rng: &mut (impl CryptoRng + RngCore),
    msg: &T,
    client_pk: &PublicEncKey,
    client_verf_key: &PublicSigKey,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Cipher>
where
    T: Serialize + AsRef<[u8]>,
{
    // Adds the hash digest of the receivers public encryption key to the message to sign
    // Sign msg || H(client_verf_key) || H(client_enc_key)
    let to_sign = [
        msg.as_ref(),
        &hash_element(&to_vec(client_verf_key)?),
        &hash_element(&to_vec(client_pk)?),
    ]
    .concat();
    let sig: k256::ecdsa::Signature = server_sig_key.sk.sign(to_sign.as_ref());
    // Normalize s value to ensure a consistant signature and protect against malleability
    sig.normalize_s();

    // Generate the server part of the key agreement
    // Oberve that we don't need to keep the secret key as we don't need the client to send the
    // server messages
    let (server_enc_pk, server_enc_sk) = encryption_key_generation(rng);
    // Encrypt msg || sig || H(server_verification_key) || H(server_enc_key)
    // OBSERVE: serialization is simply r concatenated with s. That is, NOT an Ethereum compatible
    // signature since we preclude the v value The verification key is serialized based on the
    // SEC1 standard
    let to_encrypt = [
        msg.as_ref(),
        &sig.to_bytes(),
        &hash_element(&to_vec(&PublicSigKey {
            pk: SigningKey::verifying_key(&server_sig_key.sk).to_owned(),
        })?),
        &hash_element(&to_vec(&server_enc_pk)?),
    ]
    .concat();

    let enc_box = SalsaBox::new(&client_pk.0, &server_enc_sk.0);
    let nonce = SalsaBox::generate_nonce(rng);
    let ciphertext = match enc_box.encrypt(&nonce, &to_encrypt[..]) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            return Err(anyhow_error_and_log("Could not encrypt message"));
        }
    };

    Ok(Cipher {
        bytes: ciphertext,
        nonce: nonce.to_vec(),
        server_enc_key: server_enc_pk,
    })
}

/// Validate a signcryption and decrypt the payload if everything validates correctly.
///
/// Returns None if validation fails.
pub fn validate_and_decrypt(
    cipher: &Cipher,
    client_keys: &SigncryptionPair,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    let nonce = Nonce::from_slice(cipher.nonce.as_bytes());
    let dec_box = SalsaBox::new(&cipher.server_enc_key.0, &client_keys.sk.decryption_key.0);
    let decrypted_plaintext = match dec_box.decrypt(nonce, cipher.bytes.as_ref()) {
        Ok(decrypted_plaintext) => decrypted_plaintext,
        Err(e) => {
            return Err(anyhow_error_and_warn_log(format!(
                "Could not decrypt message. Failed with error: {:?}",
                e
            )));
        }
    };
    let (msg, sig) = match parse_msg(decrypted_plaintext, &cipher.server_enc_key, server_verf_key) {
        Ok((msg, sig)) => (msg, sig),
        Err(_) => return Ok(None),
    };

    if !check_signature(msg.clone(), &sig, server_verf_key, &client_keys.pk) {
        tracing::warn!("The signature did not validate");
        return Ok(None);
    }
    Ok(Some(msg))
}

/// Helper method for parsing a signcrypted message consisting of the _true_ msg || sig ||
/// H(server_verification_key) || H(server_enc_key)
fn parse_msg(
    decrypted_plaintext: Vec<u8>,
    server_enc_key: &PublicEncKey,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<(Vec<u8>, Signature)> {
    // The plaintext contains msg || sig || H(server_verification_key) || H(server_enc_key)
    let msg_len = decrypted_plaintext.len() - 2 * DIGEST_BYTES - SIG_SIZE;
    let msg = &decrypted_plaintext[..msg_len];
    let sig_bytes = &decrypted_plaintext[msg_len..(msg_len + SIG_SIZE)];
    let server_ver_key_digest =
        &decrypted_plaintext[(msg_len + SIG_SIZE)..(msg_len + SIG_SIZE + DIGEST_BYTES)];
    let server_enc_key_digest = &decrypted_plaintext
        [(msg_len + SIG_SIZE + DIGEST_BYTES)..(msg_len + 2 * DIGEST_BYTES + SIG_SIZE)];
    // Verify verification key digest
    if hash_element(&to_vec(server_verf_key)?) != server_ver_key_digest {
        return Err(anyhow_error_and_warn_log(format!(
            "Unexpected verification key digest {:X?} was part of the decryption",
            server_ver_key_digest
        )));
    }
    // Verify encryption key digest
    if hash_element(&to_vec(server_enc_key)?) != server_enc_key_digest {
        return Err(anyhow_error_and_warn_log(format!(
            "Unexpected encryption key digest {:X?} was part of the decryption",
            server_enc_key
        )));
    }
    let sig = k256::ecdsa::Signature::from_slice(sig_bytes)?;
    Ok((msg.to_vec(), Signature { sig }))
}

/// Helper method for performing the necesary checks on a signcryption signature.
/// Returns true if the signature is ok and false otherwise
fn check_signature(
    msg: Vec<u8>,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
    client_pk: &SigncryptionPubKey,
) -> bool {
    let verf_key_digest = match to_vec(&client_pk.verification_key) {
        Ok(verf_key_digest) => verf_key_digest,
        Err(_) => {
            tracing::warn!(
                "Could not serialize verification key {:?}",
                client_pk.verification_key
            );
            return false;
        }
    };
    let enc_key_digest = match to_vec(&client_pk.enc_key) {
        Ok(enc_key_digest) => enc_key_digest,
        Err(_) => {
            tracing::warn!("Could not serialize encryption key {:?}", client_pk.enc_key);
            return false;
        }
    };
    // What should be signed is msg || H(client_verification_key) || H(client_enc_key)
    let msg_signed = [
        msg,
        hash_element(&verf_key_digest),
        hash_element(&enc_key_digest),
    ]
    .concat();

    // Check that the signature is normalized
    if !check_normalized(sig) {
        return false;
    }

    // Verify signature
    if server_verf_key
        .pk
        .verify(&msg_signed[..], &sig.sig)
        .is_err()
    {
        tracing::warn!("Signature {:X?} is not valid", sig.sig);
        return false;
    }

    true
}

pub(crate) fn check_normalized(sig: &Signature) -> bool {
    if sig.sig.normalize_s().is_some() {
        tracing::warn!(
            "Received signature {:X?} was not normalized as expected",
            sig.sig
        );
        return false;
    };
    true
}

pub(crate) fn hash_element<T>(element: &T) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    // Use of SHA3 to stay as much as possible with current NIST standards
    let mut hasher = Sha3_256::new();
    hasher.update(element.as_ref());
    let digest = hasher.finalize();
    digest.to_vec()
}

/// Serialize an element and hash it using a cryptographic hash function.
#[cfg(any(feature = "testing", feature = "non-wasm"))]
pub(crate) fn serialize_hash_element<T>(msg: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize,
{
    let to_hash = match to_vec(msg) {
        Ok(to_hash) => to_hash,
        Err(e) => {
            return Err(anyhow_error_and_warn_log(format!(
                "Could not encode message due to error: {:?}",
                e
            )));
        }
    };
    Ok(hash_element(&to_hash))
}

/// decrypt a signcrypted message and verify the signature
///
/// this fn also checks that the provided link parameter corresponds to the link in the signcryption payload
pub(crate) fn decrypt_signcryption(
    cipher: &[u8],
    link: &[u8],
    client_keys: &SigncryptionPair,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<Option<Plaintext>> {
    let cipher: Cipher = from_bytes(cipher)?;
    let decrypted_signcryption = match validate_and_decrypt(&cipher, client_keys, server_verf_key)?
    {
        Some(decrypted_signcryption) => decrypted_signcryption,
        None => {
            tracing::warn!("Signcryption validation failed");
            return Ok(None);
        }
    };
    let signcrypted_msg: SigncryptionPayload = serde_asn1_der::from_bytes(&decrypted_signcryption)?;
    if link != signcrypted_msg.link {
        tracing::warn!("Link validation for signcryption failed");
        return Ok(None);
    }
    Ok(Some(signcrypted_msg.plaintext))
}

/// Decrypt a signcrypted message and ignore the signature
/// This function does *not* do any verification and is thus insecure and should be used only for testing.
/// TODO hide behind flag for insecure function?
pub(crate) fn insecure_decrypt_ignoring_signature(
    cipher: &[u8],
    client_keys: &SigncryptionPair,
) -> anyhow::Result<Option<Plaintext>> {
    let cipher: Cipher = from_bytes(cipher)?;

    let nonce = Nonce::from_slice(cipher.nonce.as_bytes());
    let dec_box = SalsaBox::new(&cipher.server_enc_key.0, &client_keys.sk.decryption_key.0);
    let decrypted_plaintext = match dec_box.decrypt(nonce, cipher.bytes.as_ref()) {
        Ok(decrypted_plaintext) => decrypted_plaintext,
        Err(e) => {
            return Err(anyhow_error_and_warn_log(format!(
                "Could not decrypt message. Failed with error: {:?}",
                e
            )));
        }
    };

    // strip off the signature bytes
    let msg_len = decrypted_plaintext.len() - 2 * DIGEST_BYTES - SIG_SIZE;
    let msg = &decrypted_plaintext[..msg_len];
    let signcrypted_msg: SigncryptionPayload = serde_asn1_der::from_bytes(msg)?;

    Ok(Some(signcrypted_msg.plaintext))
}

#[cfg(test)]
mod tests {
    use super::{PrivateSigKey, PublicSigKey, SigncryptionPair};
    use crate::cryptography::der_types::Signature;
    use crate::cryptography::request::{ephemeral_key_generation, ClientRequest};
    use crate::cryptography::signcryption::{
        check_signature, encryption_key_generation, hash_element, internal_verify_sig, parse_msg,
        sign, signcrypt, validate_and_decrypt, DIGEST_BYTES, RND_SIZE, SIG_SIZE,
    };
    use aes_prng::AesRng;
    use k256::ecdsa::SigningKey;
    use rand::{CryptoRng, RngCore, SeedableRng};
    use serde_asn1_der::{from_bytes, to_vec};
    use signature::Signer;
    use tracing_test::traced_test;

    /// Helper method for generating keys for digital signatures
    fn signing_key_generation(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (PublicSigKey, PrivateSigKey) {
        let sk = SigningKey::random(rng);
        let pk = SigningKey::verifying_key(&sk);
        (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
    }

    /// Helper method that creates an rng, a valid client request (on a dummy fhe cipher) and client
    /// singcryption keys SigncryptionPair Returns the rng, client request, client signcryption
    /// keys and the dummy fhe cipher the request is made for.
    fn test_setup() -> (AesRng, ClientRequest, SigncryptionPair, Vec<u8>) {
        let cipher = [42_u8; 1];
        let mut rng = AesRng::seed_from_u64(1);
        let client_sig_key = PrivateSigKey {
            sk: SigningKey::random(&mut rng),
        };
        let (request, keys) = ClientRequest::new(&cipher, &client_sig_key, &mut rng).unwrap();
        (rng, request, keys, cipher.to_vec())
    }

    #[test]
    fn sunshine() {
        let (mut rng, request, client_signcryption_keys, fhe_cipher) = test_setup();
        assert!(request.verify(&fhe_cipher).unwrap());
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.verification_key,
            &server_sig_key,
        )
        .unwrap();
        let decrypted_msg =
            validate_and_decrypt(&cipher, &client_signcryption_keys, &server_verf_key)
                .unwrap()
                .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn sunshine_encoding_decoding() {
        let (mut rng, request, client_signcryption_keys, _fhe_cipher) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A message".as_bytes();
        let cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.verification_key,
            &server_sig_key,
        )
        .unwrap();
        // Observe that the methods from serde_asn1_der is used to make an en-decoding in DER ASN1
        let enc_req = to_vec(&request).unwrap();
        let dec_req = from_bytes(&enc_req).unwrap();
        assert_eq!(request, dec_req);
        let enc_pk = to_vec(&client_signcryption_keys.pk).unwrap();
        let dec_pk = from_bytes(&enc_pk).unwrap();
        assert_eq!(client_signcryption_keys.pk, dec_pk);
        let enc_cipher = to_vec(&cipher).unwrap();
        let dec_cipher = from_bytes(&enc_cipher).unwrap();
        assert_eq!(cipher, dec_cipher);
        let enc_sig_key = to_vec(&server_sig_key).unwrap();
        let dec_sig_key: PrivateSigKey = from_bytes(&enc_sig_key).unwrap();
        assert_eq!(server_sig_key, dec_sig_key);
        let enc_verf_key = to_vec(&server_verf_key).unwrap();
        let dec_verf_key: PublicSigKey = from_bytes(&enc_verf_key).unwrap();
        assert_eq!(server_verf_key, dec_verf_key);
    }

    #[test]
    fn plain_signing() {
        let mut rng = AesRng::seed_from_u64(1);
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let sig = sign(&msg, &server_sig_key).unwrap();
        assert!(internal_verify_sig(&msg.to_vec(), &sig, &server_verf_key));
    }

    #[test]
    fn bad_request_sig() {
        let (_rng, mut request, client_signcryption_keys, fhe_cipher) = test_setup();
        let wrong_sig = Signature {
            sig: client_signcryption_keys
                .sk
                .signing_key
                .unwrap()
                .sk
                .sign("not a key".as_ref()),
        };
        request.signature = wrong_sig;
        assert!(!request.verify(&fhe_cipher).unwrap())
    }

    #[test]
    fn bad_request_digest() {
        let (_rng, mut request, _client_signcryption_keys, fhe_cipher) = test_setup();
        request.payload.digest = Vec::from([0_u8; DIGEST_BYTES]);
        assert!(!request.verify(&fhe_cipher).unwrap())
    }

    #[test]
    fn bad_request_randomness() {
        let (_rng, mut request, _client_signcryption_keys, fhe_cipher) = test_setup();
        request.payload.sig_randomization = Vec::from([0_u8; RND_SIZE]);
        assert!(!request.verify(&fhe_cipher).unwrap())
    }

    #[traced_test]
    #[test]
    fn wrong_decryption_nonce() {
        let (mut rng, _request, client_signcryption_keys, _fhe_cipher) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A message".as_bytes();
        let mut cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.verification_key,
            &server_sig_key,
        )
        .unwrap();
        // Flip a bit in the nonce
        cipher.nonce[0] ^= 1;
        let decrypted_msg =
            validate_and_decrypt(&cipher, &client_signcryption_keys, &server_verf_key);
        assert!(logs_contain("Could not decrypt message."));
        // unwrapping fails
        assert!(decrypted_msg.is_err());
    }

    #[traced_test]
    #[test]
    fn incorrect_server_verf_key() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = signing_key_generation(&mut rng);
        let (sever_enc_key, _server_dec_key) = encryption_key_generation(&mut rng);
        let to_encrypt = [0_u8; 1 + 2 * DIGEST_BYTES + SIG_SIZE];
        let res = parse_msg(to_encrypt.to_vec(), &sever_enc_key, &server_verf_key);
        assert!(logs_contain("Unexpected verification key digest"));
        // unwrapping fails
        assert!(res.is_err());
    }

    #[traced_test]
    #[test]
    fn incorrect_server_enc_key() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = signing_key_generation(&mut rng);
        let (server_enc_key, _server_dec_key) = encryption_key_generation(&mut rng);
        let mut to_encrypt = [0_u8; 1 + 2 * DIGEST_BYTES + SIG_SIZE].to_vec();
        let key_digest = hash_element(&to_vec(&server_verf_key).unwrap());
        // Set the correct verification key so that part of `parse_msg` won't fail
        to_encrypt.splice(
            1 + SIG_SIZE..1 + SIG_SIZE + DIGEST_BYTES,
            key_digest.iter().cloned(),
        );
        let res = parse_msg(to_encrypt.to_vec(), &server_enc_key, &server_verf_key);
        assert!(logs_contain("Unexpected encryption key digest"));
        // unwrapping fails
        assert!(res.is_err());
    }

    #[traced_test]
    #[test]
    fn bad_signature() {
        let (mut rng, _request, client_signcryption_keys, _fhe_cipher) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "Some message".as_bytes();
        let sig = Signature {
            sig: server_sig_key.sk.sign(msg),
            // pk: client_signcryption_keys.pk.clone().verification_key,
        };
        // Fails as the correct key digets are not included in the message whose signature gets
        // checked
        let res = check_signature(
            msg.to_vec(),
            &sig,
            &server_verf_key,
            &client_signcryption_keys.pk,
        );
        assert!(logs_contain("is not valid"));
        // unwrapping fails
        assert!(!res);
    }

    #[traced_test]
    #[test]
    fn unnormalized_signature() {
        let mut rng = AesRng::seed_from_u64(1);
        let msg = "some message".as_bytes();
        let client_sig_key = PrivateSigKey {
            sk: SigningKey::random(&mut rng),
        };
        let client_signcryption_keys = ephemeral_key_generation(&mut rng, &client_sig_key);
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let to_sign = [
            msg,
            &hash_element(&to_vec(&client_signcryption_keys.pk.verification_key).unwrap()),
            &hash_element(&to_vec(&client_signcryption_keys.pk.enc_key).unwrap()),
        ]
        .concat();
        let sig = Signature {
            sig: server_sig_key.sk.sign(to_sign.as_ref()),
        };
        // Ensure the signature is normalized
        let internal_sig = sig.sig.normalize_s().unwrap_or(sig.sig);
        // Ensure the signature is ok
        assert!(check_signature(
            msg.to_vec(),
            &Signature { sig: internal_sig },
            &server_verf_key,
            &client_signcryption_keys.pk,
        ));
        // Undo normalization
        let bad_sig =
            k256::ecdsa::Signature::from_scalars(internal_sig.r(), internal_sig.s().negate())
                .unwrap();
        let res = check_signature(
            msg.to_vec(),
            &Signature { sig: bad_sig },
            &server_verf_key,
            &client_signcryption_keys.pk,
        );
        assert!(logs_contain("was not normalized as expected"));
        // unwrapping fails
        assert!(!res);
    }
}
