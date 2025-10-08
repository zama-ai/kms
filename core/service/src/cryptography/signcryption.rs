//! Necessary methods for secure client communication in relation to user decryption requests.
//!
//! Client requests to the server should be validated against the client's wallet address,
//! which is derived from a ECDSA secp256k1 key.
//! Based on the request the server does sign-then-encrypt to securely encrypt a payload for the
//! client. Signing for the server is also carried out using ECDSA with secp256k1 and the client
//! can validate this against the server's public key.
//! Unfortunately we cannot use PQ signatures such as ML-DSA because the server identities
//! must be compatible with EVM on-chain verification.
//!
//! For encryption a hybrid encryption scheme is used based on ML-KEM and AES GCM.

use super::internal_crypto_types::{Cipher, PrivateSigKey, PublicSigKey, Signature};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem;
#[cfg(test)]
use crate::cryptography::internal_crypto_types::{CryptoRand, UnifiedSigncryptionKeyPairOwned};
use crate::cryptography::internal_crypto_types::{
    Designcrypt, DesigncryptFHEPlaintext, Signcrypt, SigncryptFHEPlaintext,
    UnifiedDesigncryptionKey, UnifiedPrivateDecKey, UnifiedPublicEncKey, UnifiedSigncryption,
    UnifiedSigncryptionKey, UnifiedSigncryptionKeyPair,
};
use crate::{anyhow_tracked, consts::SIG_SIZE};
use ::signature::{Signer, Verifier};
use kms_grpc::kms::v1::TypedPlaintext;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tfhe::FheTypes;
use threshold_fhe::hashing::{serialize_hash_element, DomainSep, DIGEST_BYTES};

const DSEP_SIGNCRYPTION: DomainSep = *b"SIGNCRYP";

/// Representation of the data stored in a signcryption,
/// needed to facilitate FHE decryption and request linking.
/// The result is linked to some byte array.
/// LEGACY CODE! Do not use in new code!
/// TODO should be versioned while supporting this old legacy format see issue XXX
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub struct SigncryptionPayload {
    pub plaintext: TypedPlaintext,
    pub link: Vec<u8>,
}

/// Compute the signature on message based on the server's signing key.
///
/// Returns the [Signature]. Concretely r || s.
pub(crate) fn internal_sign<T>(
    dsep: &DomainSep,
    msg: &T,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Signature>
where
    T: AsRef<[u8]> + ?Sized,
{
    let sig: k256::ecdsa::Signature = server_sig_key
        .sk()
        .try_sign(&[dsep, msg.as_ref()].concat())?;
    // Normalize s value to ensure a consistent signature and protect against malleability
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(Signature { sig })
}

/// Compute the signature on message based on the server's signing key for a given EIP712 domain.
///
/// Returns the [Signature]. Concretely r || s.
/// TODO method is dead code
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
    dsep: &DomainSep,
    payload: &T,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<()>
where
    T: AsRef<[u8]> + ?Sized,
{
    // Check that the signature is normalized
    check_normalized(sig)?;

    // Verify signature
    server_verf_key
        .pk()
        .verify(&[dsep, payload.as_ref()].concat(), &sig.sig)
        .map_err(|e| anyhow_tracked(e.to_string()))
}

/// Compute the signcryption of a message encrypted under the public keys received from a client and
/// signed by the server's signing key.
///
/// Returns the signcrypted message.
///
/// WARNING: It is assumed that the client's public key HAS been validated to come from a valid
/// `ClientRequest` and validated to be consistent with the blockchain identity of the client BEFORE
/// calling this method. IF THIS HAS NOT BEEN DONE THEN ANYONE CAN IMPERSONATE ANY CLIENT!!!
impl Signcrypt for UnifiedSigncryptionKey {
    #[allow(unknown_lints)]
    // We allow modifying the rng before return
    #[allow(non_local_effect_before_error_return)]
    fn signcrypt<T>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>
    where
        T: Serialize + AsRef<[u8]>,
    {
        // Adds the hash digest of the receivers public encryption key to the message to sign
        // Sign msg || H(client_verf_key) || H(client_pub_key)
        // Note that H(client_verf_key) = client_address
        // Only serialize the inner structure to ensure backwards compatibility!!!
        let serialized_enc_key = match &self.receiver_enc_key {
            UnifiedPublicEncKey::MlKem512(public_enc_key) => {
                serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                    .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
            }
            UnifiedPublicEncKey::MlKem1024(public_enc_key) => {
                serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                    .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
            }
        };
        let to_sign = [msg.as_ref(), &self.receiver_id, &serialized_enc_key].concat();
        let sig = internal_sign(dsep, &to_sign, &self.signing_key)
            .map_err(|e| CryptographyError::SigningError(e.to_string()))?
            .sig;

        // Encrypt msg || sig || H(server_verification_key) || H(server_enc_pub_key)
        // OBSERVE: serialization is simply r concatenated with s. That is NOT an Ethereum compatible
        // signature since we preclude the v value.
        // The verification key is serialized based on the SEC1 standard.
        let verf_key_hash = &serialize_hash_element(
            &DSEP_SIGNCRYPTION,
            // TODO this is horrible! We are using address above be here we use digest! This should be changed to use  &self.signing_key.verf_key().verf_key_id(),
            // Idem below
            &PublicSigKey::from_sk(&self.signing_key),
        )
        .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?;
        let to_encrypt = [msg.as_ref(), &sig.to_bytes(), verf_key_hash].concat();

        let ciphertext = match &self.receiver_enc_key {
            UnifiedPublicEncKey::MlKem512(public_enc_key) => {
                hybrid_ml_kem::enc::<ml_kem::MlKem512, _>(rng, &to_encrypt, &public_enc_key.0)
            }
            UnifiedPublicEncKey::MlKem1024(public_enc_key) => {
                hybrid_ml_kem::enc::<ml_kem::MlKem1024, _>(rng, &to_encrypt, &public_enc_key.0)
            }
        }?;
        let res = UnifiedSigncryption {
            payload: bc2wrap::serialize(&Cipher(ciphertext))
                .map_err(|e| CryptographyError::BincodeError(e.to_string()))?, // TODO legacy, should be updated
            encryption_type: (&self.receiver_enc_key).into(),
            signing_type: (&self.signing_key).into(),
        };
        Ok(res)
    }
}

impl SigncryptFHEPlaintext for UnifiedSigncryptionKey {
    fn signcrypt_plaintext(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        plaintext: Vec<u8>,
        fhe_type: FheTypes,
        link: Vec<u8>,
    ) -> Result<UnifiedSigncryption, CryptographyError> {
        let signcryption_msg = SigncryptionPayload {
            plaintext: TypedPlaintext::from_bytes(plaintext, fhe_type),
            link: link.clone(),
        };
        self.signcrypt(rng, dsep, &bc2wrap::serialize(&signcryption_msg)?)
    }
}

impl Designcrypt for UnifiedDesigncryptionKey {
    /// Validate a signcryption and decrypt the payload if everything validates correctly.
    ///
    /// Returns Err if validation fails and Ok(message) if validation succeeds.
    fn designcrypt(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<Vec<u8>, CryptographyError> {
        // TODO this should be versioned. Current way is only to handle legacy approach
        let cipher: Cipher = bc2wrap::deserialize(&cipher.payload)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        let decrypted_plaintext = match &self.decryption_key {
            UnifiedPrivateDecKey::MlKem512(dec_key) => {
                hybrid_ml_kem::dec::<ml_kem::MlKem512>(cipher.0, &dec_key.0)
            }
            UnifiedPrivateDecKey::MlKem1024(dec_key) => {
                hybrid_ml_kem::dec::<ml_kem::MlKem1024>(cipher.0, &dec_key.0)
            }
        }?;
        let (msg, sig) = parse_msg(decrypted_plaintext, &self.sender_verf_key)?;
        check_format_and_signature(dsep, msg.clone(), &sig, self)?;
        Ok(msg)
    }
}

impl DesigncryptFHEPlaintext for UnifiedDesigncryptionKey {
    fn designcrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
        link: Vec<u8>,
    ) -> Result<Vec<u8>, CryptographyError> {
        let decrypted_signcryption = self.designcrypt(dsep, signcryption)?;

        let signcrypted_msg: SigncryptionPayload = bc2wrap::deserialize(&decrypted_signcryption)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        if link != signcrypted_msg.link {
            return Err(CryptographyError::VerificationError(
                "signcryption link does not match!".to_string(),
            ));
        }
        Ok(signcrypted_msg.plaintext.bytes) // TODO continue
    }
}

/// Helper method for parsing a signcrypted message consisting of the _true_ msg || sig ||
/// H(server_verification_key)
fn parse_msg(
    decrypted_plaintext: Vec<u8>,
    server_verf_key: &PublicSigKey,
) -> Result<(Vec<u8>, Signature), CryptographyError> {
    // The plaintext contains msg || sig || H(server_verification_key)
    let msg_len = decrypted_plaintext
        .len()
        .checked_sub(DIGEST_BYTES)
        .and_then(|len| len.checked_sub(SIG_SIZE))
        .ok_or_else(||
            CryptographyError::LengthError(
                format!("Message is too short ({} bytes) to contain sig || H(server_verification_key) ({} bytes) ",
                decrypted_plaintext.len(),
                DIGEST_BYTES + SIG_SIZE)
            )
        )?;
    let msg = &decrypted_plaintext[..msg_len];
    let sig_bytes = &decrypted_plaintext[msg_len..(msg_len + SIG_SIZE)];
    let server_ver_key_digest =
        &decrypted_plaintext[(msg_len + SIG_SIZE)..(msg_len + SIG_SIZE + DIGEST_BYTES)];
    // TODO this should just be based on key id. Again legacy code that could be done more proper by using the notion of an id!
    // Verify verification key digest
    if serialize_hash_element(&DSEP_SIGNCRYPTION, server_verf_key)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?
        != server_ver_key_digest
    {
        return Err(CryptographyError::VerificationError(format!(
            "unexpected verification key digest {server_ver_key_digest:X?} was part of the decryption",
        )));
    }
    let sig = k256::ecdsa::Signature::from_slice(sig_bytes)
        .map_err(|e| CryptographyError::SerializationError(e.to_string()))?;
    Ok((msg.to_vec(), Signature { sig }))
}

/// Helper method for performing the necessary checks on a signcryption signature.
/// Returns true if the signature is ok and false otherwise
fn check_format_and_signature(
    dsep: &DomainSep,
    msg: Vec<u8>,
    sig: &Signature,
    designcryption_key: &UnifiedDesigncryptionKey,
) -> Result<(), CryptographyError> {
    // What should be signed is dsep || msg || H(client_verification_key) || H(client_enc_key)
    let serialized_enc_key = match &designcryption_key.encryption_key {
        UnifiedPublicEncKey::MlKem512(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
        }
        UnifiedPublicEncKey::MlKem1024(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
        }
    };
    let msg_signed = [
        dsep.to_vec(),
        msg,
        designcryption_key.receiver_id.clone(),
        serialized_enc_key,
    ]
    .concat();
    // Check that the signature is normalized
    check_normalized(sig)?;
    // Verify signature
    designcryption_key
        .sender_verf_key
        .pk()
        .verify(&msg_signed[..], &sig.sig)
        .map_err(|e| CryptographyError::VerificationError(e.to_string()))
}

/// Check if a signature is normalized in "low S" form as described in
/// [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub(crate) fn check_normalized(sig: &Signature) -> Result<(), CryptographyError> {
    if sig.sig.normalize_s().is_some() {
        return Err(CryptographyError::VerificationError(format!(
            "Signature {:X?} is not normalized",
            sig.sig
        )));
    };
    Ok(())
}
/// Decrypt a signcrypted message and verify the signature.
///
/// This fn also checks that the provided link parameter corresponds to the link in the signcryption
/// payload.
pub fn decrypt_signcryption_with_link(
    dsep: &DomainSep,
    cipher: &[u8],
    link: &[u8],
    design_key: &UnifiedDesigncryptionKey,
) -> anyhow::Result<TypedPlaintext> {
    // TODO this method
    let signcryption_cipher = UnifiedSigncryption::new(
        cipher.to_vec(),
        (&design_key.decryption_key).into(),
        (&design_key.sender_verf_key).into(),
    );
    let decrypted_signcryption = design_key.designcrypt(dsep, &signcryption_cipher)?;

    let signcrypted_msg: SigncryptionPayload = bc2wrap::deserialize(&decrypted_signcryption)?;
    if link != signcrypted_msg.link {
        return Err(anyhow_tracked(
            "signcryption link does not match!".to_string(),
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
    client_keys: &UnifiedSigncryptionKeyPair,
) -> Result<TypedPlaintext, CryptographyError> {
    let cipher: Cipher =
        bc2wrap::deserialize(cipher).map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let decrypted_plaintext = match &client_keys.designcryption_key.decryption_key {
        UnifiedPrivateDecKey::MlKem512(client_keys) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem512>(cipher.0.clone(), &client_keys.0)?
        }
        UnifiedPrivateDecKey::MlKem1024(client_keys) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem1024>(cipher.0.clone(), &client_keys.0)?
        }
    };

    // strip off the signature bytes (these are ignored here)
    let msg_len = decrypted_plaintext.len() - DIGEST_BYTES - SIG_SIZE;
    let msg = &decrypted_plaintext[..msg_len];

    let signcrypted_msg: SigncryptionPayload =
        bc2wrap::deserialize(msg).map_err(|e| CryptographyError::BincodeError(e.to_string()))?;

    Ok(signcrypted_msg.plaintext)
}

/// Helper method for what the client is supposed to do when generating ephemeral keys linked to the
/// client's blockchain signing key
#[cfg(test)]
pub(crate) fn ephemeral_signcryption_key_generation(
    rng: &mut impl CryptoRand,
    server_verf_key: &PublicSigKey,
) -> UnifiedSigncryptionKeyPairOwned {
    use crate::cryptography::internal_crypto_types::{
        gen_sig_keys, Encryption, EncryptionScheme, EncryptionSchemeType,
    };
    let (client_verf_key, client_sig_key) = gen_sig_keys(rng);
    let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, rng);
    let (dec_key, enc_key) = encryption.keygen().unwrap();
    UnifiedSigncryptionKeyPairOwned {
        signcrypt_key: UnifiedSigncryptionKey::new(
            client_sig_key.clone(),
            enc_key.clone(),
            client_verf_key.verf_key_id(),
        ),
        designcrypt_key: UnifiedDesigncryptionKey::new(
            dec_key,
            enc_key,
            server_verf_key.clone(),
            client_verf_key.verf_key_id(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt_signcryption_with_link, ephemeral_signcryption_key_generation, PublicSigKey,
        SigncryptionPayload,
    };
    use crate::cryptography::internal_crypto_types::{
        gen_sig_keys, Designcrypt, EncryptionSchemeType, Signature, Signcrypt,
        UnifiedDesigncryptionKey, UnifiedSigncryption, UnifiedSigncryptionKeyPairOwned,
    };
    use crate::cryptography::signcryption::{
        check_format_and_signature, internal_sign, internal_verify_sig, parse_msg, DIGEST_BYTES,
        DSEP_SIGNCRYPTION, SIG_SIZE,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::TypedPlaintext;
    use rand::SeedableRng;
    use threshold_fhe::hashing::serialize_hash_element;

    /// Helper method that creates an rng, a valid client request (on a dummy fhe cipher) and client
    /// signcryption keys SigncryptionPair Returns the rng, client request, client signcryption
    /// keys and the dummy fhe cipher the request is made for.
    fn test_setup() -> (AesRng, UnifiedSigncryptionKeyPairOwned) {
        let mut rng = AesRng::seed_from_u64(1);
        let (server_verf_key, _) = gen_sig_keys(&mut rng);
        let keys = ephemeral_signcryption_key_generation(&mut rng, &server_verf_key);
        (rng, keys)
    }

    #[test]
    fn sunshine() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();
        let decrypted_msg = client_signcryption_keys
            .designcrypt_key
            .designcrypt(b"TESTTEST", &cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn sunshine_encoding_decoding() {
        // test the bincode serialization because that is what we use for all of kms
        let (mut rng, client_signcryption_keys) = test_setup();
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();
        let serialized_cipher = bc2wrap::serialize(&cipher).unwrap();
        let deserialized_cipher: UnifiedSigncryption =
            bc2wrap::deserialize(&serialized_cipher).unwrap();

        let serialized_server_verf_key =
            bc2wrap::serialize(&client_signcryption_keys.designcrypt_key.sender_verf_key).unwrap();
        let deserialized_server_verf_key: PublicSigKey =
            bc2wrap::deserialize(&serialized_server_verf_key).unwrap();

        let new_keys = UnifiedDesigncryptionKey::new(
            client_signcryption_keys
                .designcrypt_key
                .decryption_key
                .clone(),
            client_signcryption_keys
                .designcrypt_key
                .encryption_key
                .clone(),
            deserialized_server_verf_key.clone(),
            client_signcryption_keys.designcrypt_key.receiver_id.clone(),
        );
        let decrypted_msg = new_keys
            .designcrypt(b"TESTTEST", &deserialized_cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn plain_signing() {
        let mut rng = AesRng::seed_from_u64(1);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        assert!(internal_verify_sig(b"TESTTEST", &msg.to_vec(), &sig, &server_verf_key).is_ok());
    }

    #[test]
    fn bad_signcryption() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let correct_cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();

        // flip a bit in the payload
        {
            let mut cipher = correct_cipher.clone();
            cipher.payload[0] ^= 1;

            assert!(client_signcryption_keys
                .designcrypt_key
                .designcrypt(b"TESTTEST", &cipher)
                .is_err());
        }

        // wrong scheme
        {
            let mut cipher = correct_cipher.clone();
            cipher.encryption_type = EncryptionSchemeType::MlKem1024;
            assert!(client_signcryption_keys
                .designcrypt_key
                .designcrypt(b"TESTTEST", &cipher)
                .is_err());
        }

        // use the wrong client signcryption key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let wrong_keys = ephemeral_signcryption_key_generation(
                &mut rng,
                &client_signcryption_keys.designcrypt_key.sender_verf_key,
            );
            assert!(wrong_keys
                .designcrypt_key
                .designcrypt(b"TESTTEST", &correct_cipher)
                .is_err());
        }

        // use the wrong server key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let (wrong_verf_key, _) = gen_sig_keys(&mut rng);
            let wrong_keys = UnifiedDesigncryptionKey::new(
                client_signcryption_keys
                    .designcrypt_key
                    .decryption_key
                    .clone(),
                client_signcryption_keys
                    .designcrypt_key
                    .encryption_key
                    .clone(),
                wrong_verf_key,
                client_signcryption_keys.designcrypt_key.receiver_id.clone(),
            );
            assert!(wrong_keys
                .designcrypt(b"TESTTEST", &correct_cipher)
                .is_err());
        }

        // use bad domain separator
        {
            assert!(client_signcryption_keys
                .designcrypt_key
                .designcrypt(b"blahblah", &correct_cipher)
                .is_err());
        }

        // happy path should still work at the end
        let decrypted_msg = client_signcryption_keys
            .designcrypt_key
            .designcrypt(b"TESTTEST", &correct_cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn incorrect_server_verf_key() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);
        let to_encrypt = [0_u8; 1 + DIGEST_BYTES + SIG_SIZE];
        let res = parse_msg(to_encrypt.to_vec(), &server_verf_key);
        // unwrapping fails
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("unexpected verification key digest"));
    }

    #[test]
    fn bad_signature() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        let wrong_msg = "Some message...longer".as_bytes();
        let res = internal_verify_sig(b"TESTTEST", &wrong_msg, &sig, &server_verf_key);
        // unwrapping fails
        assert!(res.is_err());
    }

    #[test]
    fn bad_dsep() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        let res = internal_verify_sig(
            b"TESTTES_", // wrong domain separator
            &msg,
            &sig,
            &server_verf_key,
        );
        // unwrapping fails
        assert!(res.is_err());
    }

    #[test]
    fn unnormalized_signature() {
        let (_rng, client_signcryption_keys) = test_setup();
        let msg = "Some message".as_bytes();

        let to_sign = [
            msg,
            &client_signcryption_keys
                .designcrypt_key
                .sender_verf_key
                .verf_key_id(),
            &serialize_hash_element(
                &DSEP_SIGNCRYPTION,
                &client_signcryption_keys.signcrypt_key.receiver_enc_key,
            )
            .unwrap(),
        ]
        .concat();
        let sig = internal_sign(
            b"TESTTEST",
            &to_sign,
            &client_signcryption_keys.signcrypt_key.signing_key,
        )
        .unwrap();
        // Ensure the signature is normalized
        let internal_sig = sig.sig.normalize_s().unwrap_or(sig.sig);
        // Ensure the signature is ok
        assert!(check_format_and_signature(
            b"TESTTEST",
            msg.to_vec(),
            &Signature { sig: internal_sig },
            &client_signcryption_keys.designcrypt_key,
        )
        .is_ok());
        // Undo normalization
        let bad_sig =
            k256::ecdsa::Signature::from_scalars(internal_sig.r(), internal_sig.s().negate())
                .unwrap();
        let res = check_format_and_signature(
            b"TESTTEST",
            msg.to_vec(),
            &Signature { sig: bad_sig },
            &client_signcryption_keys.designcrypt_key,
        );
        // unwrapping fails
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("is not normalized"));
    }

    #[test]
    fn signcryption_with_bad_link() {
        let (_rng, client_signcryption_keys) = test_setup();
        let link = [0, 1, 2, 3u8];
        let msg = TypedPlaintext {
            bytes: b"A relatively long message that we wish to be able to later validate".to_vec(),
            fhe_type: 1,
        };
        let payload = bc2wrap::serialize(&SigncryptionPayload {
            plaintext: msg.clone(),
            link: link.into(),
        })
        .unwrap();
        let bad_link = [1, 2, 3, 4u8];
        let _ = decrypt_signcryption_with_link(
            b"TESTTEST",
            &payload,
            &bad_link,
            &client_signcryption_keys.designcrypt_key,
        )
        .unwrap_err();
    }
}
