//! Necessary methods for secure client communication in relation to decryption requests.
//!
//! Client requests to the server should be validated against the client's ECDSA secp256k1 key.
//! Based on the request the server does sign-then-encrypt to securely encrypt a payload for the
//! client. Signing for the server is also carried out using ECDSA with secp256k1 and the client
//! can validate this against the server's public key.
//!
//! For encryption a hybrid encryption is used based on ECIES using Libsodium. More specifically
//! using ECDH with curve 25519 and Salsa.
//! NOTE: This may change in the future to be more compatible with NIST standardized schemes.

use super::internal_crypto_types::{
    Cipher, PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, Signature, SigncryptionPair,
    SigncryptionPubKey,
};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log};
use crate::{
    consts::SIG_SIZE,
    rpc::rpc_types::{Plaintext, SigncryptionPayload},
};
use ::signature::{Signer, Verifier};
use bincode::{deserialize, serialize};
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{Nonce, SalsaBox, SecretKey};
use k256::ecdsa::SigningKey;
use nom::AsBytes;
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use sha3::{Digest, Sha3_256};

const DIGEST_BYTES: usize = 256 / 8; // SHA3-256 digest

/// Generate ephemeral keys used for encryption.
///
/// Concretely it involves generating ECDH keys for curve 25519 to be used in ECIES for hybrid
/// encryption using Salsa.
pub fn ephemeral_encryption_key_generation(
    rng: &mut (impl CryptoRng + RngCore),
) -> (PublicEncKey, PrivateEncKey) {
    let sk = SecretKey::generate(rng);
    (PublicEncKey(sk.public_key()), PrivateEncKey(sk))
}

/// Compute the signature on message based on the server's signing key.
///
/// Returns the [Signature]. Concretely r || s.
pub fn sign<T>(msg: &T, server_sig_key: &PrivateSigKey) -> anyhow::Result<Signature>
where
    T: Serialize + AsRef<[u8]>,
{
    let sig: k256::ecdsa::Signature = server_sig_key.sk().try_sign(msg.as_ref())?;
    // Normalize s value to ensure a consistent signature and protect against malleability
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(Signature { sig })
}

// This type (and its fields) should not be renamed
// since it needs to match what is in fhevmjs!
alloy_sol_types::sol! {
    struct Reencrypt {
        bytes publicKey;
    }
}

// Solidity struct for decryption result signature
alloy_sol_types::sol! {
    struct DecryptionResult {
        address aclAddress;
        uint256[] handlesList;
        bytes decryptedResult;
    }
}

/// Compute the signature on message based on the server's signing key for a given EIP712 domain.
///
/// Returns the [Signature]. Concretely r || s.
pub fn sign_eip712<T: alloy_sol_types::SolStruct>(
    msg: &T,
    domain: &alloy_sol_types::Eip712Domain,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Signature> {
    let signing_hash = msg.eip712_signing_hash(domain);
    let sig: k256::ecdsa::Signature = server_sig_key.sk().try_sign(&signing_hash[..])?;
    // Normalize s value to ensure a consistent signature and protect against malleability
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(Signature { sig })
}

/// Verify a plain signature.
///
/// Returns Ok if the signature is ok.
pub(crate) fn internal_verify_sig<T>(
    payload: &T,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<()>
where
    T: Serialize + AsRef<[u8]>,
{
    // Check that the signature is normalized
    check_normalized(sig)?;

    // Verify signature
    server_verf_key
        .pk()
        .verify(payload.as_ref(), &sig.sig)
        .map_err(anyhow::Error::new)
}

/// Compute the signcryption of a message encrypted under the public keys received from a client and
/// signed by the server's signing key.
///
/// Returns the signcrypted message.
///
/// WARNING: It is assumed that the client's public key HAS been validated to come from a valid
/// `ClientRequest` and validated to be consistent with the blockchain identity of the client BEFORE
/// calling this method. IF THIS HAS NOT BEEN DONE THEN ANYONE CAN IMPERSONATE ANY CLIENT!!!
pub fn signcrypt<T>(
    rng: &mut (impl CryptoRng + RngCore),
    msg: &T,
    client_pub_key: &PublicEncKey,
    client_address: &alloy_primitives::Address,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Cipher>
where
    T: Serialize + AsRef<[u8]>,
{
    // Adds the hash digest of the receivers public encryption key to the message to sign
    // Sign msg || H(client_verf_key) || H(client_enc_key)
    let to_sign = [
        msg.as_ref(),
        client_address.as_bytes(),
        &serialize_hash_element(client_pub_key)?,
    ]
    .concat();
    let sig: k256::ecdsa::Signature = server_sig_key.sk().sign(to_sign.as_ref());
    // Normalize s value to ensure a consistent signature and protect against malleability
    let sig = sig.normalize_s().unwrap_or(sig);

    // Generate the server part of the key agreement
    // Observe that we don't need to keep the secret key as we don't need the client to send the
    // server messages
    let (server_enc_pub_key, server_enc_sk) = ephemeral_encryption_key_generation(rng);
    // Encrypt msg || sig || H(server_verification_key) || H(server_enc_pub_key)
    // OBSERVE: serialization is simply r concatenated with s. That is NOT an Ethereum compatible
    // signature since we preclude the v value.
    // The verification key is serialized based on the SEC1 standard.
    let to_encrypt = [
        msg.as_ref(),
        &sig.to_bytes(),
        &serialize_hash_element(&PublicSigKey::new(
            SigningKey::verifying_key(server_sig_key.sk()).to_owned(),
        ))?,
        &serialize_hash_element(&server_enc_pub_key)?,
    ]
    .concat();

    let enc_box = SalsaBox::new(&client_pub_key.0, &server_enc_sk.0);
    let nonce = SalsaBox::generate_nonce(rng);
    let ciphertext = match enc_box.encrypt(&nonce, &to_encrypt[..]) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            return Err(anyhow_error_and_log(
                "Could not encrypt message using SalsaBox.",
            ));
        }
    };

    Ok(Cipher {
        bytes: ciphertext,
        nonce: nonce.to_vec(),
        server_enc_key: server_enc_pub_key,
    })
}

/// Validate a signcryption and decrypt the payload if everything validates correctly.
///
/// Returns Err if validation fails and Ok(message) if validation succeeds.
pub fn validate_and_decrypt(
    cipher: &Cipher,
    client_keys: &SigncryptionPair,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<Vec<u8>> {
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
    let (msg, sig) = parse_msg(decrypted_plaintext, &cipher.server_enc_key, server_verf_key)?;

    check_signature_and_log(msg.clone(), &sig, server_verf_key, &client_keys.pk)?;
    Ok(msg)
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
    if serialize_hash_element(server_verf_key)? != server_ver_key_digest {
        return Err(anyhow_error_and_warn_log(format!(
            "Unexpected verification key digest {:X?} was part of the decryption",
            server_ver_key_digest
        )));
    }
    // Verify encryption key digest
    if serialize_hash_element(server_enc_key)? != server_enc_key_digest {
        return Err(anyhow_error_and_warn_log(format!(
            "Unexpected encryption key digest {:X?} was part of the decryption",
            server_enc_key
        )));
    }
    let sig = k256::ecdsa::Signature::from_slice(sig_bytes)?;
    Ok((msg.to_vec(), Signature { sig }))
}

/// Helper method for performing the necessary checks on a signcryption signature.
/// Returns true if the signature is ok and false otherwise
fn check_signature_and_log(
    msg: Vec<u8>,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
    client_pk: &SigncryptionPubKey,
) -> anyhow::Result<()> {
    let enc_key_digest = match serialize(&client_pk.enc_key) {
        Ok(enc_key_digest) => enc_key_digest,
        Err(e) => {
            return Err(anyhow_error_and_log(format!(
                "Could not serialize encryption key {:?} with error {}",
                client_pk.enc_key, e
            )));
        }
    };
    // What should be signed is msg || H(client_verification_key) || H(client_enc_key)
    let msg_signed = [
        msg,
        client_pk.client_address.to_vec(),
        hash_element(&enc_key_digest),
    ]
    .concat();

    // Check that the signature is normalized
    check_normalized(sig)?;

    // Verify signature
    server_verf_key
        .pk()
        .verify(&msg_signed[..], &sig.sig)
        .map_err(|e| {
            tracing::error!("signature verification failed with error {e}");
            anyhow::Error::new(e)
        })
}

/// Check if a signature is normalized in "low S" form as described in
/// [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub(crate) fn check_normalized(sig: &Signature) -> anyhow::Result<()> {
    if sig.sig.normalize_s().is_some() {
        tracing::warn!(
            "Received signature {:X?} was not normalized as expected",
            sig.sig
        );
        return Err(anyhow::anyhow!(
            "Signature {:X?} is not normalized",
            sig.sig
        ));
    };
    Ok(())
}

/// Compute the SHA3-256 has of an element. Returns the hash as a vector of bytes.
pub fn hash_element<T>(element: &T) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    // Use of SHA3 to stay as much as possible with current NIST standards
    let mut hasher = Sha3_256::new();
    hasher.update(element.as_ref());
    let digest = hasher.finalize();
    digest.to_vec()
}

/// Serialize an element and hash it using SHA3-256. Returns the hash as a vector of bytes.
pub(crate) fn serialize_hash_element<T>(msg: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize,
{
    let to_hash = match serialize(msg) {
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

/// Decrypt a signcrypted message and verify the signature.
///
/// This fn also checks that the provided link parameter corresponds to the link in the signcryption
/// payload.
pub(crate) fn decrypt_signcryption(
    cipher: &[u8],
    link: &[u8],
    client_keys: &SigncryptionPair,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<Plaintext> {
    let cipher: Cipher = deserialize(cipher)?;
    let decrypted_signcryption = validate_and_decrypt(&cipher, client_keys, server_verf_key)?;

    let signcrypted_msg: SigncryptionPayload = bincode::deserialize(&decrypted_signcryption)?;
    if link != signcrypted_msg.link {
        return Err(anyhow_error_and_warn_log(
            "Signcryption link does not match!",
        ));
    }
    Ok(signcrypted_msg.plaintext)
}

/// Decrypt a signcrypted message and ignore the signature
///
/// This function does *not* do any verification and is thus insecure and should be used only for
/// testing.
/// TODO hide behind flag for insecure function?
pub(crate) fn insecure_decrypt_ignoring_signature(
    cipher: &[u8],
    client_keys: &SigncryptionPair,
) -> anyhow::Result<Plaintext> {
    let cipher: Cipher = deserialize(cipher)?;

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

    // strip off the signature bytes (these are ignored here)
    let msg_len = decrypted_plaintext.len() - 2 * DIGEST_BYTES - SIG_SIZE;
    let msg = &decrypted_plaintext[..msg_len];

    let signcrypted_msg: SigncryptionPayload = deserialize(msg)?;

    Ok(signcrypted_msg.plaintext)
}

/// Helper method for what the client is supposed to do when generating ephemeral keys linked to the
/// client's blockchain signing key
#[cfg(test)]
pub(crate) fn ephemeral_signcryption_key_generation(
    rng: &mut (impl CryptoRng + RngCore),
    sig_key: &PrivateSigKey,
) -> SigncryptionPair {
    let verification_key = PublicSigKey::new(*SigningKey::verifying_key(sig_key.sk()));
    let (enc_pk, enc_sk) = ephemeral_encryption_key_generation(rng);
    SigncryptionPair {
        sk: crate::cryptography::internal_crypto_types::SigncryptionPrivKey {
            signing_key: Some(sig_key.clone()),
            decryption_key: enc_sk,
        },
        pk: crate::cryptography::internal_crypto_types::SigncryptionPubKey {
            client_address: alloy_primitives::Address::from_public_key(verification_key.pk()),
            enc_key: enc_pk,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ephemeral_signcryption_key_generation, PrivateSigKey, PublicSigKey, SigncryptionPair,
    };
    use crate::cryptography::internal_crypto_types::Signature;
    use crate::cryptography::signcryption::{
        check_signature_and_log, ephemeral_encryption_key_generation, internal_verify_sig,
        parse_msg, serialize_hash_element, sign, signcrypt, validate_and_decrypt, DIGEST_BYTES,
        SIG_SIZE,
    };
    use aes_prng::AesRng;
    use k256::ecdsa::SigningKey;
    use rand::{CryptoRng, RngCore, SeedableRng};
    use signature::Signer;
    use tracing_test::traced_test;

    /// Helper method for generating keys for digital signatures
    fn signing_key_generation(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (PublicSigKey, PrivateSigKey) {
        let sk = SigningKey::random(rng);
        let pk = SigningKey::verifying_key(&sk);
        (PublicSigKey::new(*pk), PrivateSigKey::new(sk))
    }

    /// Helper method that creates an rng, a valid client request (on a dummy fhe cipher) and client
    /// signcryption keys SigncryptionPair Returns the rng, client request, client signcryption
    /// keys and the dummy fhe cipher the request is made for.
    fn test_setup() -> (AesRng, SigncryptionPair) {
        let mut rng = AesRng::seed_from_u64(1);
        let client_sig_key = PrivateSigKey::new(SigningKey::random(&mut rng));
        let keys = ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);
        (rng, keys)
    }

    #[test]
    fn sunshine() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.client_address,
            &server_sig_key,
        )
        .unwrap();
        let decrypted_msg =
            validate_and_decrypt(&cipher, &client_signcryption_keys, &server_verf_key).unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn sunshine_encoding_decoding() {
        // test the bincode serialization because that is what we use for all of kms
        let (mut rng, client_signcryption_keys) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.client_address,
            &server_sig_key,
        )
        .unwrap();

        let serialized_cipher = bincode::serialize(&cipher).unwrap();
        let deserialized_cipher: crate::cryptography::internal_crypto_types::Cipher =
            bincode::deserialize(&serialized_cipher).unwrap();

        let serialized_server_verf_key = bincode::serialize(&server_verf_key).unwrap();
        let deserialized_server_verf_key: PublicSigKey =
            bincode::deserialize(&serialized_server_verf_key).unwrap();

        let decrypted_msg = validate_and_decrypt(
            &deserialized_cipher,
            &client_signcryption_keys,
            &deserialized_server_verf_key,
        )
        .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn plain_signing() {
        let mut rng = AesRng::seed_from_u64(1);
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let sig = sign(&msg, &server_sig_key).unwrap();
        assert!(internal_verify_sig(&msg.to_vec(), &sig, &server_verf_key).is_ok());
    }

    #[test]
    fn bad_signcryption() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let correct_cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.client_address,
            &server_sig_key,
        )
        .unwrap();

        // flip a bit in the payload
        {
            let mut cipher = correct_cipher.clone();
            cipher.bytes[0] ^= 1;

            assert!(
                validate_and_decrypt(&cipher, &client_signcryption_keys, &server_verf_key,)
                    .is_err()
            );
        }

        // flip a bit in the nonce
        {
            let mut cipher = correct_cipher.clone();
            cipher.nonce[0] ^= 1;

            assert!(
                validate_and_decrypt(&cipher, &client_signcryption_keys, &server_verf_key,)
                    .is_err()
            );
        }

        // use the wrong client signcryption key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let client_sig_key = PrivateSigKey::new(SigningKey::random(&mut rng));
            let client_signcryption_keys =
                ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);

            assert!(validate_and_decrypt(
                &correct_cipher,
                &client_signcryption_keys,
                &server_verf_key,
            )
            .is_err());
        }

        // use the wrong server key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let (server_verf_key, _server_sig_key) = signing_key_generation(&mut rng);

            assert!(validate_and_decrypt(
                &correct_cipher,
                &client_signcryption_keys,
                &server_verf_key,
            )
            .is_err());
        }

        // happy path should still work at the end
        let decrypted_msg =
            validate_and_decrypt(&correct_cipher, &client_signcryption_keys, &server_verf_key)
                .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[traced_test]
    #[test]
    fn wrong_decryption_nonce() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A message".as_bytes();
        let mut cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk.enc_key,
            &client_signcryption_keys.pk.client_address,
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
        let (sever_enc_key, _server_dec_key) = ephemeral_encryption_key_generation(&mut rng);
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
        let (server_enc_key, _server_dec_key) = ephemeral_encryption_key_generation(&mut rng);
        let mut to_encrypt = [0_u8; 1 + 2 * DIGEST_BYTES + SIG_SIZE].to_vec();
        let key_digest = serialize_hash_element(&server_verf_key).unwrap();
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
        let (mut rng, client_signcryption_keys) = test_setup();
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "Some message".as_bytes();
        let sig = Signature {
            sig: server_sig_key.sk().sign(msg),
            // pk: client_signcryption_keys.pk.clone().verification_key,
        };
        // Fails as the correct key digests are not included in the message whose signature gets
        // checked
        let res = check_signature_and_log(
            msg.to_vec(),
            &sig,
            &server_verf_key,
            &client_signcryption_keys.pk,
        );
        assert!(logs_contain("signature error"));
        // unwrapping fails
        assert!(res.is_err());
    }

    #[traced_test]
    #[test]
    fn unnormalized_signature() {
        let mut rng = AesRng::seed_from_u64(1);
        let msg = "some message".as_bytes();
        let client_sig_key = PrivateSigKey::new(SigningKey::random(&mut rng));
        let client_signcryption_keys =
            ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let to_sign = [
            msg,
            client_signcryption_keys.pk.client_address.as_slice(),
            &serialize_hash_element(&client_signcryption_keys.pk.enc_key).unwrap(),
        ]
        .concat();
        let sig = Signature {
            sig: server_sig_key.sk().sign(to_sign.as_ref()),
        };
        // Ensure the signature is normalized
        let internal_sig = sig.sig.normalize_s().unwrap_or(sig.sig);
        // Ensure the signature is ok
        assert!(check_signature_and_log(
            msg.to_vec(),
            &Signature { sig: internal_sig },
            &server_verf_key,
            &client_signcryption_keys.pk,
        )
        .is_ok());
        // Undo normalization
        let bad_sig =
            k256::ecdsa::Signature::from_scalars(internal_sig.r(), internal_sig.s().negate())
                .unwrap();
        let res = check_signature_and_log(
            msg.to_vec(),
            &Signature { sig: bad_sig },
            &server_verf_key,
            &client_signcryption_keys.pk,
        );
        assert!(logs_contain("was not normalized as expected"));
        // unwrapping fails
        assert!(res.is_err());
    }
}
