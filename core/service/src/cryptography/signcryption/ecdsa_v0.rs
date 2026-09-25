//! The original, ECDSA-only signcryption envelope. **FROZEN.**
//!
//! Every user-decryption ciphertext produced since 0.11 uses this layout and the
//! deployed browser-side verifier parses it, so its bytes cannot change. See the
//! module documentation of [`super`] for the full list of what pins them.

use super::common::DSEP_SIGNCRYPTION;
use super::{
    SigncryptionPayload, UnifiedSigncryption, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey,
};
use crate::cryptography::encryption::{HasPkeScheme, UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::HybridKemCt;
use crate::cryptography::signatures::{
    PublicSigKey, SIG_SIZE, Signature, check_normalized, internal_sign,
};
use crate::cryptography::signcryption::common::receiver_enc_key_digest;
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
// This is the FROZEN layout.
pub(super) fn seal(
    signcrypt_key: &UnifiedSigncryptionKey,
    rng: &mut (impl CryptoRng + RngCore),
    dsep: &DomainSep,
    msg: &[u8],
) -> Result<UnifiedSigncryption, CryptographyError> {
    // Adds the hash digest of the receivers public encryption key to the message to sign
    // Sign msg || H(client_verf_key) || H(client_pub_key)
    // Note that H(client_verf_key) = client_address
    // Only serialize the inner structure to ensure backwards compatibility!!!
    let binding = receiver_binding(&signcrypt_key.receiver_id, &signcrypt_key.receiver_enc_key)?;
    let signing_key = signcrypt_key.signing_key();
    // Wipe the temporary signed message after signing.
    let to_sign = Zeroizing::new([msg, binding.as_slice()].concat());
    let sig = internal_sign(dsep, &to_sign, signing_key)
        .map_err(|e| CryptographyError::SigningError(e.to_string()))?;

    // Encrypt msg || sig || H(server_verification_key)
    // OBSERVE: serialization is simply r concatenated with s. That is NOT an Ethereum compatible
    // signature since we preclude the v value.
    // The verification key is serialized based on the SEC1 standard.
    let verf_key_hash = sender_verf_key_digest(&PublicSigKey::from_sk(signing_key))?;
    // Wipe the temporary encrypted message after encryption.
    let to_encrypt =
        Zeroizing::new([msg, sig.to_bytes().as_ref(), verf_key_hash.as_ref()].concat());

    let ciphertext = signcrypt_key
        .receiver_enc_key
        .hybrid_encrypt(rng, &to_encrypt)?;
    // LEGACY: approach to serialization
    Ok(UnifiedSigncryption::new(
        bc2wrap::serialize(&ciphertext)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?,
        signcrypt_key.encryption_scheme_type(),
    ))
}

/// Implements the actual unsigncryption process, but without any deserialization
///
/// This is the FROZEN layout.
pub(super) fn open(
    unsign_key: &UnifiedUnsigncryptionKey,
    sender_verf_key: &PublicSigKey,
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    // LEGACY Code: should be using safe_deserialization from tfhe-rs
    let deserialized_payload: HybridKemCt = bc2wrap::deserialize_slice(&cipher.payload)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let decrypted_plaintext = unsign_key
        .decryption_key
        .hybrid_decrypt(deserialized_payload)?;
    let (msg, sig) = parse_msg(decrypted_plaintext, sender_verf_key)?;
    check_format_and_signature(dsep, &msg, &sig, unsign_key, sender_verf_key)?;
    Ok(msg)
}

/// Split a decrypted frozen-layout plaintext into `msg`, `sig` and
/// `H(sender verification key)`.
fn split_frozen_plaintext(plaintext: &[u8]) -> Result<(&[u8], &[u8], &[u8]), CryptographyError> {
    // The plaintext contains msg || sig || H(server_verification_key)
    let msg_len = plaintext
        .len()
        .checked_sub(DIGEST_BYTES)
        .and_then(|len| len.checked_sub(SIG_SIZE))
        .ok_or_else(|| {
            CryptographyError::LengthError(format!(
                "Message is too short ({} bytes) to contain sig || H(server_verification_key) ({} bytes) ",
                plaintext.len(),
                DIGEST_BYTES + SIG_SIZE
            ))
        })?;
    Ok((
        &plaintext[..msg_len],
        &plaintext[msg_len..msg_len + SIG_SIZE],
        &plaintext[msg_len + SIG_SIZE..],
    ))
}

/// Helper method for parsing a signcrypted message consisting of the _true_ msg || sig ||
/// H(server_verification_key)
fn parse_msg(
    decrypted_plaintext: Zeroizing<Vec<u8>>,
    server_verf_key: &PublicSigKey,
) -> Result<(Zeroizing<Vec<u8>>, Signature), CryptographyError> {
    let (msg, sig_bytes, server_ver_key_digest) = split_frozen_plaintext(&decrypted_plaintext)?;
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
        &unsigncryption_key.receiver_id,
        &unsigncryption_key.encryption_key,
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

/// `receiver_id ‖ H(receiver public encryption key)`: the suffix that binds a
/// signcryption to who it was made for.
fn receiver_binding(
    receiver_id: &[u8],
    enc_key: &UnifiedPublicEncKey,
) -> Result<Vec<u8>, CryptographyError> {
    Ok([receiver_id, receiver_enc_key_digest(enc_key)?.as_slice()].concat())
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
    let decrypted_plaintext = dec_key.hybrid_decrypt(cipher)?;

    // Strip off the signature and the sender key digest; this path checks neither.
    let (msg, _sig, _sender_digest) = split_frozen_plaintext(&decrypted_plaintext)?;
    // LEGACY should be using safe_deserialization from tfhe-rs
    let signcrypted_msg: SigncryptionPayload = bc2wrap::deserialize_slice(msg)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;

    Ok(signcrypted_msg.plaintext)
}

#[cfg(test)]
mod tests {
    use super::super::Signcrypt;
    use super::super::common::test_support::signcryption_fixture;
    use super::*;
    use crate::consts::SAFE_SER_SIZE_LIMIT;
    use crate::cryptography::encryption::PkeSchemeType;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tfhe::safe_serialization::safe_serialize;

    /// `parse_msg` rejects a plaintext that is not `msg ‖ sig ‖ H(sender key)`, on
    /// both of the things it can check: the length, and the key the tail names.
    #[test]
    fn parse_msg_rejects_a_malformed_plaintext() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);

        // Too short to hold the two fixed tail fields: a length error, not a panic.
        for len in 0..(SIG_SIZE + DIGEST_BYTES) {
            // Keep test input under the zeroizing ownership contract.
            let short = Zeroizing::new(vec![0u8; len]);
            assert!(
                matches!(
                    parse_msg(short, &server_verf_key),
                    Err(CryptographyError::LengthError(_))
                ),
                "a {len}-byte plaintext must be rejected as too short"
            );
        }

        // Long enough, but the tail names some other sender.
        let attributed_elsewhere = Zeroizing::new(vec![0u8; 1 + DIGEST_BYTES + SIG_SIZE]);
        let err = parse_msg(attributed_elsewhere, &server_verf_key).unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected verification key digest"),
            "{err}"
        );
    }

    /// The encrypted plaintext is exactly `msg ‖ sig(64) ‖ H(sender key)(32)`,
    /// with the two tail fields fixed-size and in that order.
    ///
    /// This is the contract [`split_frozen_plaintext`] relies on when it recovers
    /// `msg_len` by subtracting from the end.
    #[test]
    fn ecdsa_v0_envelope_layout_is_locked() {
        const DSEP: &DomainSep = b"ECDSAV0T";
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let mut f = signcryption_fixture(scheme, 200);
            let payload = TestType { i: 4711 };
            let sender_verf_key = f.sender_verf_key();

            let mut expected_msg = Vec::new();
            safe_serialize(&payload, &mut expected_msg, SAFE_SER_SIZE_LIMIT).unwrap();

            let cipher = f
                .signcryption_key
                .signcrypt(&mut f.rng, DSEP, &payload)
                .unwrap();
            assert_eq!(cipher.pke_type, scheme);

            let kem_ct: HybridKemCt = bc2wrap::deserialize_slice(&cipher.payload).unwrap();
            let plaintext = f
                .unsigncryption_key
                .decryption_key
                .hybrid_decrypt(kem_ct)
                .unwrap();

            // Exactly three fields, the last two of fixed size.
            assert_eq!(
                plaintext.len(),
                expected_msg.len() + SIG_SIZE + DIGEST_BYTES,
                "{scheme}: plaintext is not msg ‖ sig ‖ digest"
            );
            let msg_len = expected_msg.len();
            assert_eq!(&plaintext[..msg_len], expected_msg.as_slice());

            // The middle field is the ECDSA signature over the locked preimage.
            let binding = receiver_binding(
                &f.signcryption_key.receiver_id,
                &f.signcryption_key.receiver_enc_key,
            )
            .unwrap();
            let signed = [expected_msg.as_slice(), binding.as_slice()].concat();
            let sig = Signature::from_ecdsa(
                k256::ecdsa::Signature::from_slice(&plaintext[msg_len..msg_len + SIG_SIZE])
                    .unwrap(),
            );
            check_normalized(&sig).expect("the signature must be low-s normalized");
            sender_verf_key
                .raw_verifying_key()
                .verify(
                    &[&DSEP[..], signed.as_slice()].concat(),
                    &sig.ecdsa_sig().unwrap(),
                )
                .expect("the middle field must sign the locked preimage");

            // The tail field is the digest of the sender's verification key.
            assert_eq!(
                &plaintext[msg_len + SIG_SIZE..],
                sender_verf_key_digest(&sender_verf_key).unwrap().as_slice(),
                "{scheme}: tail is not H(sender verification key)"
            );
        }
    }

    /// The binding must separate recipients on *both* of its inputs, since it is
    /// the only thing tying a signature to who may open it.
    #[test]
    fn receiver_binding_separates_recipients() {
        let f = signcryption_fixture(PkeSchemeType::MlKem512, 500);
        let other = signcryption_fixture(PkeSchemeType::MlKem512, 501);

        let id = &f.signcryption_key.receiver_id;
        let enc = &f.signcryption_key.receiver_enc_key;
        let other_id = &other.signcryption_key.receiver_id;
        let other_enc = &other.signcryption_key.receiver_enc_key;

        let base = receiver_binding(id, enc).unwrap();
        assert_eq!(base, receiver_binding(id, enc).unwrap());
        assert_ne!(base, receiver_binding(other_id, enc).unwrap());
        assert_ne!(base, receiver_binding(id, other_enc).unwrap());
    }
}
