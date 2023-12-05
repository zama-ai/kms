use super::der_types::{
    Cipher, PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, Signature, SigncryptionPair,
    SigncryptionPubKey,
};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log};
use ::signature::{Signer, Verifier};
use crypto_box::{
    aead::{Aead, AeadCore},
    Nonce, SalsaBox, SecretKey,
};
use k256::ecdsa::SigningKey;
use nom::AsBytes;
use rand_chacha::rand_core::CryptoRngCore;
use serde::Serialize;
use sha3::{Digest, Sha3_256};

///
/// This file is supposed to implemente the necesary methods required for secure client communication in relation to decryption requests.
/// This means that the client sends a request to the server which it validates against the client's ECDSA secp256k1 key.
/// Based on the request the server does sign-then-encrypt to securely encrypt a payload for the client.
/// Signing for the server is also carried out using ECDSA with secp256k1 and the client can validate this against the server's public key
///  assoicated with its blockchain address.
///
/// For encryption a hybrid encryption is used based on ECIES using Libsodium. More specifically using ECDH with curve 25519 and Salsa.
/// NOTE This may change in the future to be more compatible with NIST standardized schemes.
///
const DIGEST_BYTES: usize = 256 / 8; // SHA3-256 digest
const SIG_SIZE: usize = 64; // a 32 byte r value and a 32 byte s value
pub(crate) const RND_SIZE: usize = 256 / 8; // the amount of bytes used for sampling random values to stop brute-forcing or statistical attacks

/// Generate ephemeral keys used for encryption
/// Concretely it involves generating ECDH keys for curve 25519 to be used in ECIES for hybrid encryption using Salsa
pub fn encryption_key_generation(rng: &mut impl CryptoRngCore) -> (PublicEncKey, PrivateEncKey) {
    let sk = SecretKey::generate(rng);
    (PublicEncKey(sk.public_key()), sk)
}

/// Method for computing the signature on a payload, `msg`, based on the server's signing key `server_sig_key`.
/// Returns the signed message as a vector of bytes/
/// Concretely r || s
pub fn sign<T>(msg: &T, server_sig_key: &PrivateSigKey) -> anyhow::Result<Signature>
where
    T: Serialize + AsRef<[u8]>,
{
    let sig: k256::ecdsa::Signature = server_sig_key.sk.sign(msg.as_ref());
    // Normalize s value to ensure a consistant signature and protect against malleability
    sig.normalize_s();
    Ok(Signature { sig })
}

/// Method method for performing the necesary checks on a plain signature.
/// Returns true if the signature is ok and false otherwise
pub fn verify_sig(msg: Vec<u8>, sig: &Signature, server_verf_key: &PublicSigKey) -> bool {
    // Check that the signature is normalized
    if !check_normalized(sig) {
        return false;
    }

    // Verify signature
    if server_verf_key.pk.verify(&msg[..], &sig.sig).is_err() {
        tracing::warn!("Signature {:X?} is not valid", sig.sig);
        return false;
    }

    true
}

/// Method for computing the signcryption of a payload, `msg`, based on the necessary public keys `client_pk`
/// received from a client, and the server's signing key `server_sig_key`.
/// Returns the signcrypted message.
///
/// WARNING: It is assumed that the client's public key HAS been validated to come from a valid [ClientRequest] and
/// validated to be consistent with the blockchain identity of the client BEFORE calling this method.
/// IF THIS HAS NOT BEEN DONE THEN ANYONE CAN IMPERSONATE ANY CLIENT!!!
pub fn signcrypt<T>(
    rng: &mut impl CryptoRngCore,
    msg: &T,
    client_pk: &SigncryptionPubKey,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Cipher>
where
    T: Serialize + AsRef<[u8]>,
{
    // Adds the hash digest of the receivers public encryption key to the message to sign
    // Sign msg || H(client_verification_key) || H(client_enc_key)
    let to_sign = [
        msg.as_ref(),
        &hash_element(&client_pk.verification_key.pk.to_sec1_bytes())[..],
        &hash_element(&client_pk.enc_key)[..],
    ]
    .concat();
    let sig: k256::ecdsa::Signature = server_sig_key.sk.sign(to_sign.as_ref());
    // Normalize s value to ensure a consistant signature and protect against malleability
    sig.normalize_s();

    // Generate the server part of the key agreement
    // Oberve that we don't need to keep the secret key as we don't need the client to send the server messages
    let (server_enc_pk, server_enc_sk) = encryption_key_generation(rng);
    // Encrypt msg || sig || H(server_verification_key) || H(server_enc_key)
    // OBSERVE: serialization is simply r concatenated with s. That is, NOT an Ethereum compatible signature since we preclude the v value
    // The verification key is serialized based on the SEC1 standard
    let server_verification_key =
        &SigningKey::verifying_key(&server_sig_key.sk).to_sec1_bytes()[..];
    let to_encrypt = [
        msg.as_ref(),
        &sig.to_bytes(),
        &hash_element(server_verification_key),
        &hash_element(server_enc_pk.as_ref()),
    ]
    .concat();

    let enc_box = SalsaBox::new(&client_pk.enc_key.0, &server_enc_sk);
    let nonce = SalsaBox::generate_nonce(rng);
    let ciphertext = match enc_box.encrypt(&nonce, &to_encrypt[..]) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            return Err(anyhow_error_and_log(
                "Could not encrypt message".to_string(),
            ));
        }
    };

    Ok(Cipher {
        bytes: ciphertext,
        nonce: nonce.to_vec(),
        server_enc_key: server_enc_pk,
    })
}

/// Validates a signcryption and decrypts the payload if everything validates correctly.
/// Returns None if validation fails.
pub fn validate_and_decrypt(
    cipher: &Cipher,
    client_keys: &SigncryptionPair,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    let nonce = Nonce::from_slice(cipher.nonce.as_bytes());
    let dec_box = SalsaBox::new(&cipher.server_enc_key.0, &client_keys.sk.decryption_key);
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
        return Ok(None);
    }
    Ok(Some(msg))
}

/// Helper method for parsing a signcrypted message consisting of the _true_ msg || sig || H(server_verification_key) || H(server_enc_key)
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
    if hash_element(&server_verf_key.pk.to_sec1_bytes()) != server_ver_key_digest {
        return Err(anyhow_error_and_warn_log(format!(
            "Unexpected verification key digest {:X?} was part of the decryption",
            server_ver_key_digest
        )));
    }
    // Verify encryption key digest
    if hash_element(server_enc_key.as_ref()) != server_enc_key_digest {
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
    // What should be signed is msg || H(client_verification_key) || H(client_enc_key)
    let msg_signed = [
        msg,
        hash_element(&client_pk.verification_key.pk.to_sec1_bytes()[..]),
        hash_element(client_pk.enc_key.as_ref()),
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

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand::SeedableRng;
    use rand_chacha::{rand_core::CryptoRngCore, ChaCha20Rng};
    use serde_asn1_der::{from_bytes, to_vec};
    use signature::Signer;
    use tracing_test::traced_test;

    use crate::core::{
        der_types::Signature,
        request::ClientRequest,
        signcryption::{
            check_signature, encryption_key_generation, hash_element, parse_msg, sign, signcrypt,
            validate_and_decrypt, verify_sig, DIGEST_BYTES, RND_SIZE, SIG_SIZE,
        },
    };

    use super::{PrivateSigKey, PublicSigKey, SigncryptionPair};

    /// Helper method for generating keys for digital signatures
    pub fn signing_key_generation(rng: &mut impl CryptoRngCore) -> (PublicSigKey, PrivateSigKey) {
        let sk = SigningKey::random(rng);
        let pk = SigningKey::verifying_key(&sk);
        (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
    }

    /// Helper method that creates an rng, a valid client request (on a dummy fhe cipher) and client singcryption keys SigncryptionPair
    /// Returns the rng, client request, client signcryption keys and the dummy fhe cipher the request is made for.
    fn test_setup() -> (ChaCha20Rng, ClientRequest, SigncryptionPair, Vec<u8>) {
        let cipher = [42_u8; 1];
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let client_sig_key = PrivateSigKey {
            sk: SigningKey::random(&mut rng),
        };
        let (request, keys) = ClientRequest::new(&cipher, &client_sig_key, &mut rng).unwrap();
        (rng, request, keys, cipher.to_vec())
    }

    #[cfg(test)]
    #[ctor::ctor]
    fn setup_data_for_integration() {
        use crate::file_handling::write_element;

        let (mut rng, request, client_signcryption_keys, _fhe_cipher) = test_setup();
        let (_server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A message".as_bytes();
        let cipher = signcrypt(
            &mut rng,
            &msg,
            &client_signcryption_keys.pk,
            &server_sig_key,
        )
        .unwrap();
        // Dump encodings for use in client implementation validation
        let enc_req = to_vec(&request).unwrap();
        write_element("temp/client_req.der".to_string(), &enc_req).unwrap();
        let enc_pk = to_vec(&client_signcryption_keys.pk).unwrap();
        write_element("temp/client_signcryption_pk.der".to_string(), &enc_pk).unwrap();
        let enc_cipher = to_vec(&cipher).unwrap();
        write_element("temp/signcryption.der".to_string(), &enc_cipher).unwrap();
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
            &client_signcryption_keys.pk,
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
            &client_signcryption_keys.pk,
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
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let sig = sign(&msg, &server_sig_key).unwrap();
        assert!(verify_sig(msg.to_vec(), &sig, &server_verf_key));
    }

    #[test]
    fn bad_request_sig() {
        let (_rng, mut request, client_signcryption_keys, fhe_cipher) = test_setup();
        let wrong_sig = Signature {
            sig: client_signcryption_keys
                .sk
                .signing_key
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
            &client_signcryption_keys.pk,
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
        let mut rng = ChaCha20Rng::seed_from_u64(42);
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
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = signing_key_generation(&mut rng);
        let (server_enc_key, _server_dec_key) = encryption_key_generation(&mut rng);
        let mut to_encrypt = [0_u8; 1 + 2 * DIGEST_BYTES + SIG_SIZE].to_vec();
        let key_digest = hash_element(&server_verf_key.pk.to_sec1_bytes()[..]);
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
        };
        // Fails as the correct key digets are not included in the message whose signature gets checked
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
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let msg = "some message".as_bytes();
        let client_sig_key = PrivateSigKey {
            sk: SigningKey::random(&mut rng),
        };
        let client_signcryption_keys =
            ClientRequest::ephemeral_key_generation(&mut rng, &client_sig_key);
        let (server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
        let to_sign = [
            msg,
            &hash_element(
                &client_signcryption_keys
                    .pk
                    .verification_key
                    .pk
                    .to_sec1_bytes(),
            )[..],
            &hash_element(&client_signcryption_keys.pk.enc_key)[..],
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
