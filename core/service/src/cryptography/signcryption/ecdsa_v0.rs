//! The original, ECDSA-only signcryption envelope. **FROZEN.**
//!
//! Every user-decryption ciphertext produced since 0.11 uses this layout and the
//! deployed browser-side verifier parses it, so its bytes cannot change. See the
//! module documentation of [`super`] for the full list of what pins them.
//!
//! Only the layout lives here. The receiver binding and the KEM/DEM plumbing are
//! shared with every other format and live in [`super::common`].

use super::common::{DSEP_SIGNCRYPTION, hybrid_decrypt, hybrid_encrypt, receiver_binding};
use super::{
    SigncryptionPayload, UnifiedSigncryption, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey,
};
use crate::cryptography::encryption::{HasPkeScheme, UnifiedPrivateEncKey};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::HybridKemCt;
use crate::cryptography::signatures::{
    PublicSigKey, SIG_SIZE, Signature, check_normalized, internal_sign,
};
use ::signature::Verifier;
use hashing::{DIGEST_BYTES, DomainSep, serialize_hash_element};
use kms_grpc::kms::v1::TypedPlaintext;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// The digest of the sender's verification key, as it appears in the encrypted
/// plaintext's tail.
///
/// LEGACY: this is horrible! The receiver is bound into the signed preimage by
/// its *address*, but the sender is bound here by a digest of its serialized
/// key. This should be changed to use the notion of a key id.
fn sender_verf_key_digest(verf_key: &PublicSigKey) -> Result<Vec<u8>, CryptographyError> {
    serialize_hash_element(&DSEP_SIGNCRYPTION, verf_key)
        .map_err(|e| CryptographyError::DeserializationError(e.to_string()))
}

// Implements the actual signcryption but without serialization
//
// This is the FROZEN layout; see the module
// documentation for what depends on its bytes and on its RNG usage.
pub(super) fn inner_signcryption(
    signcrypt_key: &UnifiedSigncryptionKey,
    rng: &mut (impl CryptoRng + RngCore),
    dsep: &DomainSep,
    msg: &[u8],
) -> Result<UnifiedSigncryption, CryptographyError> {
    // Adds the hash digest of the receivers public encryption key to the message to sign
    // Sign msg || H(client_verf_key) || H(client_pub_key)
    // Note that H(client_verf_key) = client_address
    // Only serialize the inner structure to ensure backwards compatibility!!!
    let binding = receiver_binding(signcrypt_key.receiver_id, signcrypt_key.receiver_enc_key)?;
    // Wipe the temporary signed message after signing.
    let to_sign = Zeroizing::new([msg, binding.as_slice()].concat());
    let sig = internal_sign(dsep, &to_sign, signcrypt_key.signing_key)
        .map_err(|e| CryptographyError::SigningError(e.to_string()))?;

    // Encrypt msg || sig || H(server_verification_key) || H(server_enc_pub_key)
    // OBSERVE: serialization is simply r concatenated with s. That is NOT an Ethereum compatible
    // signature since we preclude the v value.
    // The verification key is serialized based on the SEC1 standard.
    let verf_key_hash = sender_verf_key_digest(&PublicSigKey::from_sk(signcrypt_key.signing_key))?;
    // Wipe the temporary encrypted message after encryption.
    let to_encrypt =
        Zeroizing::new([msg, sig.to_bytes().as_ref(), verf_key_hash.as_ref()].concat());

    let ciphertext = hybrid_encrypt(rng, &to_encrypt, signcrypt_key.receiver_enc_key)?;
    // LEGACY: approach to serialization
    Ok(UnifiedSigncryption::new(
        bc2wrap::serialize(&ciphertext)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?,
        signcrypt_key.encryption_scheme_type(),
    ))
}

/// Implements the actual unsigncryption process, but without any deserialization
///
/// This is the FROZEN layout; see the module
/// documentation.
pub(super) fn inner_unsigncrypt(
    unsign_key: &UnifiedUnsigncryptionKey,
    sender_verf_key: &PublicSigKey,
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    if cipher.pke_type != unsign_key.encryption_key.encryption_scheme_type() {
        return Err(CryptographyError::VerificationError(
            "encryption type of cipher does not match the decryption key type".to_string(),
        ));
    }
    // LEGACY Code: should be using safe_deserialization from tfhe-rs
    let deserialized_payload: HybridKemCt = bc2wrap::deserialize_slice(&cipher.payload)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let decrypted_plaintext = hybrid_decrypt(deserialized_payload, unsign_key.decryption_key)?;
    let (msg, sig) = parse_msg(decrypted_plaintext, sender_verf_key)?;
    check_format_and_signature(dsep, &msg, &sig, unsign_key, sender_verf_key)?;
    Ok(msg)
}

/// Helper method for parsing a signcrypted message consisting of the _true_ msg || sig ||
/// H(server_verification_key)
fn parse_msg(
    decrypted_plaintext: Zeroizing<Vec<u8>>,
    server_verf_key: &PublicSigKey,
) -> Result<(Zeroizing<Vec<u8>>, Signature), CryptographyError> {
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
    // LEGACY: this should just be based on key id. Again legacy code that could be done more proper by using the notion of an id!
    // Verify verification key digest
    if sender_verf_key_digest(server_verf_key)? != server_ver_key_digest {
        return Err(CryptographyError::VerificationError(format!(
            "unexpected verification key digest {server_ver_key_digest:X?} was part of the decryption",
        )));
    }
    let sig = k256::ecdsa::Signature::from_slice(sig_bytes)
        .map_err(|e| CryptographyError::SerializationError(e.to_string()))?;
    // Wipe the extracted message on drop.
    Ok((Zeroizing::new(msg.to_vec()), Signature::from_ecdsa(sig)))
}

/// Helper method for performing the necessary checks on a signcryption signature.
/// Returns true if the signature is ok and false otherwise
fn check_format_and_signature(
    dsep: &DomainSep,
    msg: &[u8],
    sig: &Signature,
    unsigncryption_key: &UnifiedUnsigncryptionKey,
    sender_verf_key: &PublicSigKey,
) -> Result<(), CryptographyError> {
    // What should be signed is dsep || msg || H(client_verification_key) || H(client_enc_key)
    let binding = receiver_binding(
        unsigncryption_key.receiver_id,
        unsigncryption_key.encryption_key,
    )?;

    let msg_signed = Zeroizing::new([&dsep[..], msg, binding.as_slice()].concat());

    check_normalized(sig)?;

    sender_verf_key
        .raw_verifying_key()
        .verify(
            &msg_signed,
            &sig.ecdsa_sig()
                .map_err(|e| CryptographyError::VerificationError(e.to_string()))?,
        )
        .map_err(|e| CryptographyError::VerificationError(e.to_string()))
}

/// Decrypt a signcrypted message and ignore the signature
///
/// This function does *not* do any verification and is thus insecure and should be used only for
/// testing.
/// TODO hide behind flag for insecure function?
pub(crate) fn insecure_decrypt_ignoring_signature(
    cipher: &[u8],
    dec_key: &UnifiedPrivateEncKey,
) -> Result<TypedPlaintext, CryptographyError> {
    // LEGACY should be using safe_deserialization from tfhe-rs
    let cipher: HybridKemCt = bc2wrap::deserialize_slice(cipher)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let decrypted_plaintext = hybrid_decrypt(cipher, dec_key)?;

    // strip off the signature bytes (these are ignored here)
    let msg_len = decrypted_plaintext.len() - DIGEST_BYTES - SIG_SIZE;
    let msg = &decrypted_plaintext[..msg_len];
    // LEGACY should be using safe_deserialization from tfhe-rs
    let signcrypted_msg: SigncryptionPayload = bc2wrap::deserialize_slice(msg)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;

    Ok(signcrypted_msg.plaintext)
}

#[cfg(test)]
mod tests {
    use super::super::common::{expected_enc_key_digest, lock_fixture};
    use super::super::{Signcrypt, Unsigncrypt};
    use super::*;
    use crate::consts::SAFE_SER_SIZE_LIMIT;
    use crate::cryptography::encryption::PkeSchemeType;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tfhe::safe_serialization::safe_serialize;

    #[test]
    fn incorrect_server_verf_key() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);
        let to_encrypt = [0_u8; 1 + DIGEST_BYTES + SIG_SIZE];
        // Keep test input under the zeroizing ownership contract.
        let res = parse_msg(Zeroizing::new(to_encrypt.to_vec()), &server_verf_key);
        // unwrapping fails
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("unexpected verification key digest")
        );
    }

    /// The signed preimage is exactly `dsep ‖ msg ‖ receiver_id ‖ H(enc key)`.
    ///
    /// Rebuilt here from the hashing primitive rather than from
    /// [`receiver_binding`], so that a reordering of the concatenation is caught
    /// at the preimage level instead of only by a whole-artifact comparison.
    #[test]
    fn ecdsa_v0_signed_preimage_is_locked() {
        const DSEP: &DomainSep = b"ECDSAV0T";
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let f = lock_fixture(scheme, 100);
            let msg = b"the message a signcryption signs over";

            let expected = [
                &DSEP[..],
                msg.as_slice(),
                f.receiver_id.as_slice(),
                expected_enc_key_digest(&f.enc_key).as_slice(),
            ]
            .concat();

            // What `inner_signcryption` signs: `dsep` (prepended by
            // `internal_sign`) followed by the message and the receiver binding.
            let binding = receiver_binding(&f.receiver_id, &f.enc_key).unwrap();
            let signed = [&DSEP[..], msg.as_slice(), binding.as_slice()].concat();
            assert_eq!(signed, expected, "{scheme}: signed preimage changed");

            // ...and the verifier rebuilds exactly those bytes.
            let sig = internal_sign(
                DSEP,
                &[msg.as_slice(), binding.as_slice()].concat(),
                &f.signing_key,
            )
            .unwrap();
            let unsign_key = UnifiedUnsigncryptionKey::new(
                &f.dec_key,
                &f.enc_key,
                &f.sender_verf_key,
                &f.receiver_id,
            );
            check_format_and_signature(DSEP, msg, &sig, &unsign_key, &f.sender_verf_key).unwrap();
        }
    }

    /// The encrypted plaintext is exactly `msg ‖ sig(64) ‖ H(sender key)(32)`,
    /// with the two tail fields fixed-size and in that order.
    ///
    /// This is the contract [`parse_msg`] relies on when it recovers `msg_len`
    /// by subtracting from the end. Before this test, the layout was implied by
    /// that arithmetic alone.
    #[test]
    fn ecdsa_v0_envelope_layout_is_locked() {
        const DSEP: &DomainSep = b"ECDSAV0T";
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let mut f = lock_fixture(scheme, 200);
            let payload = TestType { i: 4711 };
            let signcrypt_key =
                UnifiedSigncryptionKey::new(&f.signing_key, &f.enc_key, &f.receiver_id);

            let mut expected_msg = Vec::new();
            safe_serialize(&payload, &mut expected_msg, SAFE_SER_SIZE_LIMIT).unwrap();

            let cipher = signcrypt_key.signcrypt(&mut f.rng, DSEP, &payload).unwrap();
            assert_eq!(cipher.pke_type, scheme);

            let kem_ct: HybridKemCt = bc2wrap::deserialize_slice(&cipher.payload).unwrap();
            let plaintext = hybrid_decrypt(kem_ct, &f.dec_key).unwrap();

            // Exactly three fields, the last two of fixed size.
            assert_eq!(
                plaintext.len(),
                expected_msg.len() + SIG_SIZE + DIGEST_BYTES,
                "{scheme}: plaintext is not msg ‖ sig ‖ digest"
            );
            let msg_len = expected_msg.len();
            assert_eq!(&plaintext[..msg_len], expected_msg.as_slice());

            // The middle field is the ECDSA signature over the locked preimage.
            let binding = receiver_binding(&f.receiver_id, &f.enc_key).unwrap();
            let signed = [expected_msg.as_slice(), binding.as_slice()].concat();
            let sig = Signature::from_ecdsa(
                k256::ecdsa::Signature::from_slice(&plaintext[msg_len..msg_len + SIG_SIZE])
                    .unwrap(),
            );
            check_normalized(&sig).expect("the signature must be low-s normalized");
            f.sender_verf_key
                .raw_verifying_key()
                .verify(
                    &[&DSEP[..], signed.as_slice()].concat(),
                    &sig.ecdsa_sig().unwrap(),
                )
                .expect("the middle field must sign the locked preimage");

            // The tail field is the digest of the sender's verification key.
            assert_eq!(
                &plaintext[msg_len + SIG_SIZE..],
                sender_verf_key_digest(&f.sender_verf_key)
                    .unwrap()
                    .as_slice(),
                "{scheme}: tail is not H(sender verification key)"
            );
        }
    }

    /// Truncating the plaintext below the two fixed tail fields is a length
    /// error, not a panic. The arithmetic in [`parse_msg`] is the only thing
    /// standing between a short plaintext and an out-of-bounds slice.
    #[test]
    fn a_short_plaintext_is_a_length_error() {
        let f = lock_fixture(PkeSchemeType::MlKem512, 400);
        for len in 0..(SIG_SIZE + DIGEST_BYTES) {
            let short = Zeroizing::new(vec![0u8; len]);
            assert!(
                matches!(
                    parse_msg(short, &f.sender_verf_key),
                    Err(CryptographyError::LengthError(_))
                ),
                "a {len}-byte plaintext must be rejected as too short"
            );
        }
    }

    /// Captures the frozen byte vectors the layout is locked against.
    ///
    /// Ignored by default because the constants below still have to be filled in
    /// once, by hand: they are the output of the very code under test, so they
    /// cannot be written before it has run. Run
    ///
    /// ```text
    /// cargo test -p kms --lib \
    ///   cryptography::signcryption::tests::ecdsa_v0_frozen_byte_vectors \
    ///   -- --ignored --nocapture
    /// ```
    ///
    /// paste the printed literals into the constants, and delete the
    /// `#[ignore]`. From then on this is the strongest guard here: it pins a
    /// real ciphertext together with the key that opens it, so it proves current
    /// code still *opens* material produced earlier. Every other test
    /// establishes that only transitively, by regenerating and comparing.
    #[test]
    #[ignore = "golden vectors must be captured once; see the doc comment"]
    fn ecdsa_v0_frozen_byte_vectors() {
        const DSEP: &DomainSep = b"ECDSAV0T";
        // Hex of a `UnifiedSigncryption.payload` for ML-KEM-512, seed 200.
        const FROZEN_MLKEM512: &str = "";
        // Hex of a `UnifiedSigncryption.payload` for MLKEM1024-P384, seed 200.
        const FROZEN_MLKEM1024P384: &str = "";

        for (scheme, frozen) in [
            (PkeSchemeType::MlKem512, FROZEN_MLKEM512),
            (PkeSchemeType::MlKem1024P384, FROZEN_MLKEM1024P384),
        ] {
            let mut f = lock_fixture(scheme, 200);
            let payload = TestType { i: 4711 };
            let signcrypt_key =
                UnifiedSigncryptionKey::new(&f.signing_key, &f.enc_key, &f.receiver_id);
            let cipher = signcrypt_key.signcrypt(&mut f.rng, DSEP, &payload).unwrap();

            assert!(
                !frozen.is_empty(),
                "{scheme}: paste this into the constant, then drop #[ignore]:\n{}",
                hex::encode(&cipher.payload)
            );

            // The frozen ciphertext must still open under the same key...
            let frozen_payload = hex::decode(frozen).expect("the constant must be valid hex");
            let unsign_key = UnifiedUnsigncryptionKey::new(
                &f.dec_key,
                &f.enc_key,
                &f.sender_verf_key,
                &f.receiver_id,
            );
            let frozen_cipher = UnifiedSigncryption::new(frozen_payload.clone(), scheme);
            let opened: TestType = unsign_key
                .unsigncrypt(DSEP, &frozen_cipher)
                .expect("current code must still open the frozen ciphertext");
            assert_eq!(opened, payload, "{scheme}");

            // ...and today's code must still produce it bit for bit.
            assert_eq!(
                cipher.payload, frozen_payload,
                "{scheme}: the produced envelope no longer matches the frozen vector"
            );
        }
    }
}
