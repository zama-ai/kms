use ::signature::{Signer, Verifier};
use crypto_box::{
    aead::{Aead, AeadCore},
    Nonce, SalsaBox, SecretKey,
};
use k256::ecdsa::{SigningKey, VerifyingKey};
use nom::AsBytes;
use rand_chacha::rand_core::CryptoRngCore;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use sha3::{Digest, Sha3_256};

use crate::error::error_handler::{anyhow_error_and_log, anyhow_error_and_warn_log};

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
const RND_SIZE: usize = 256 / 8; // the amount of bytes used for sampling random values to stop brute-forcing or statistical attacks

// Type used for the signcrypted payload returned by a server
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub struct Cipher {
    bytes: Vec<u8>,
    nonce: Vec<u8>,
    server_enc_key: PublicEncKey,
}

// Alias wrapping the ephemeral public encryption key the client constructs and the server uses to encrypt its payload
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct PublicEncKey(pub crypto_box::PublicKey);

impl AsRef<[u8]> for PublicEncKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl Serialize for PublicEncKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes()[..])
    }
}
impl<'de> Deserialize<'de> for PublicEncKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicEncKeyVisitor)
    }
}

struct PublicEncKeyVisitor;
/// Serialize a point encryption key for libsodium's ECIES. Concretely as a Montgomery point
impl<'de> Visitor<'de> for PublicEncKeyVisitor {
    type Value = PublicEncKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public key for libsodium crypto box using salsa and curve 25519")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let array = match v.try_into() {
            Ok(array) => array,
            Err(_) => {
                let msg = "Byte array of incorrect length";
                tracing::error!(msg);
                return Err(serde::de::Error::custom(msg));
            }
        };
        Ok(PublicEncKey(crypto_box::PublicKey::from_bytes(array)))
    }
}

// Alias wrapping the ephemeral private decryption key the client constructs to receive the server's encrypted payload
pub type PrivateEncKey = crypto_box::SecretKey;
// Struct wrapping signature verification key used by both the client and server
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicSigKey {
    pk: k256::ecdsa::VerifyingKey,
}
/// Serialize the public key using SEC1
impl Serialize for PublicSigKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.pk.to_sec1_bytes().as_bytes())
    }
}
impl<'de> Deserialize<'de> for PublicSigKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicSigKeyVisitor)
    }
}
struct PublicSigKeyVisitor;
impl<'de> Visitor<'de> for PublicSigKeyVisitor {
    type Value = PublicSigKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public verification key for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match VerifyingKey::from_sec1_bytes(v) {
            Ok(pk) => Ok(PublicSigKey { pk }),
            Err(e) => Err(E::custom(format!(
                "Could not decode verification key: {:?}",
                e
            ))),
        }
    }
}

// Strcut wrapping signature signing key used by both the client and server to authenticate their messages to one another
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateSigKey {
    sk: k256::ecdsa::SigningKey,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigncryptionPrivKey {
    signing_key: PrivateSigKey,
    decryption_key: PrivateEncKey,
}

/// Structure for public keys for signcryption that can get DER encoded as follows:
///     verification_key, (SEC1 as an OCTET STRING)
///     enc_key, (Montgomery point following libsodium serialization as OCTET STRING)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SigncryptionPubKey {
    verification_key: PublicSigKey,
    enc_key: PublicEncKey,
}

/// Structure for private keys for signcryption
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigncryptionPair {
    sk: SigncryptionPrivKey,
    pk: SigncryptionPubKey,
}

/// Wrapper struct for a digital signature
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    sig: k256::ecdsa::Signature,
}
/// Serialize a signature as a 64 bytes sequence of big endian bytes, consisting of r followed by s
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.sig.to_vec()[..])
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SignatureVisitor)
    }
}
struct SignatureVisitor;
impl<'de> Visitor<'de> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A signature for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match k256::ecdsa::Signature::from_slice(v) {
            Ok(sig) => Ok(Signature { sig }),
            Err(e) => Err(E::custom(format!("Could not decode signature: {:?}", e))),
        }
    }
}

/// Struct reflecting the client's decryption request of FHE ciphertext.
/// Concretely containing the client's public keys and a signature on the ephemeral encryption key (in reality a cryptobox
/// from libsodium for ECIES based on ECDH with curve 25519 and using Salsa for hybrid encryptoin).
/// DER encoding of the request as a SEQUENCE of ClientPayload and signature ( r||s in big endian encoded using OCTET STRINGS)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ClientRequest {
    payload: ClientPayload,
    signature: Signature,
}
/// Structure for DER encoding as a SEQUENCE of client_signcryption_key and digest (as OCTET STRING)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ClientPayload {
    client_signcryption_key: SigncryptionPubKey, // The client's public keys needed for signcryption
    digest: Vec<u8>, // Digest of the fhe_cipher the client wish to have decrypted
    sig_randomization: Vec<u8>, // Randomness to concatenate to the encrypted message to ensure EU-CMA security, see https://link.springer.com/content/pdf/10.1007/3-540-36492-7_1.pdf
}
impl ClientRequest {
    /// Constructs a new signcryption request for a message `msg` by sampling necesary ephemeral keys and returning the aggegrated signcryption keys
    pub fn new<T: Serialize + AsRef<[u8]>>(
        fhe_cipher: &T,
        client_sig_sk: &PrivateSigKey,
        rng: &mut impl CryptoRngCore,
    ) -> anyhow::Result<(Self, SigncryptionPair)> {
        let keys = ClientRequest::ephemeral_key_generation(rng, client_sig_sk);
        let digest = hash_element(fhe_cipher);
        let mut r = [0_u8; RND_SIZE];
        rng.fill_bytes(r.as_mut());
        let payload = ClientPayload {
            client_signcryption_key: keys.pk.clone(),
            digest,
            sig_randomization: r.to_vec(),
        };
        // DER encode the payload
        let to_sign = serde_asn1_der::to_vec(&payload)?;
        // Sign the public key and digest of the message
        let signature: Signature = Signature {
            sig: keys.sk.signing_key.sk.sign(&to_sign[..]),
        };
        Ok((ClientRequest { payload, signature }, keys))
    }

    /// Verify the request.
    /// This involves validating the signature on the client's request based on the client's verification key
    /// and that the message requested to be decrypted is as expected.
    ///
    /// Returns true if everything is ok and false otherwise.
    ///
    /// WARNING: IT IS ASSUMED THAT THE CLIENT'S PUBLIC VERIFICATION KEY HAS BEEN CROSS-CHECKED TO BELONG TO A CLIENT
    /// THAT IS ALLOWED TO DECRYPT `fhe_cipher`
    pub fn verify<T: Serialize + AsRef<[u8]>>(&self, fhe_cipher: &T) -> anyhow::Result<bool> {
        let digest = hash_element(fhe_cipher);
        if digest != self.payload.digest {
            return Ok(false);
        };
        // DER encode the payload
        let signed = serde_asn1_der::to_vec(&self.payload)?;
        // Verify the signature
        if self
            .payload
            .client_signcryption_key
            .verification_key
            .pk
            .verify(&signed[..], &self.signature.sig)
            .is_err()
        {
            return Ok(false);
        }
        // Check that the signature is normalized
        Ok(check_normalized(&self.signature))
    }

    /// Helper method for what the client is supposed to do when generating ephemeral keys linked to the client's blockchain signing key
    fn ephemeral_key_generation(
        rng: &mut impl CryptoRngCore,
        sig_key: &PrivateSigKey,
    ) -> SigncryptionPair {
        let verification_key = PublicSigKey {
            pk: *SigningKey::verifying_key(&sig_key.sk),
        };
        let (enc_pk, enc_sk) = encryption_key_generation(rng);
        SigncryptionPair {
            sk: SigncryptionPrivKey {
                signing_key: sig_key.clone(),
                decryption_key: enc_sk,
            },
            pk: SigncryptionPubKey {
                verification_key,
                enc_key: enc_pk,
            },
        }
    }
}

/// Generate ephemeral keys used for encryption
/// Concretely it involves generating ECDH keys for curve 25519 to be used in ECIES for hybrid encryption using Salsa
pub fn encryption_key_generation(rng: &mut impl CryptoRngCore) -> (PublicEncKey, PrivateEncKey) {
    let sk = SecretKey::generate(rng);
    (PublicEncKey(sk.public_key()), sk)
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

fn check_normalized(sig: &Signature) -> bool {
    if sig.sig.normalize_s().is_some() {
        tracing::warn!(
            "Received signature {:X?} was not normalized as expected",
            sig.sig
        );
        return false;
    };
    true
}
fn hash_element<T>(element: &T) -> Vec<u8>
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

    use crate::{
        execution::endpoints::reencryption::{
            check_signature, encryption_key_generation, hash_element, parse_msg, signcrypt,
            validate_and_decrypt, ClientRequest, Signature, DIGEST_BYTES, RND_SIZE, SIG_SIZE,
        },
        file_handling::write_element,
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
        let (_server_verf_key, server_sig_key) = signing_key_generation(&mut rng);
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
