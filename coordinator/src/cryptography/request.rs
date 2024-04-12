use super::der_types::{
    PrivateSigKey, PublicSigKey, Signature, SigncryptionPair, SigncryptionPrivKey,
    SigncryptionPubKey,
};
use super::signcryption::{check_normalized, encryption_key_generation, hash_element, RND_SIZE};
use crate::anyhow_error_and_log;
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

/// Struct reflecting the client's decryption request of FHE ciphertext.
/// Concretely containing the client's public keys and a signature on the ephemeral encryption key
/// (in reality a cryptobox from libsodium for ECIES based on ECDH with curve 25519 and using Salsa
/// for hybrid encryptoin). DER encoding of the request as a SEQUENCE of ClientPayload and signature
/// ( r||s in big endian encoded using OCTET STRINGS)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub(crate) struct ClientRequest {
    pub(crate) payload: ClientPayload,
    pub(crate) signature: Signature,
}

/// Structure for DER encoding as a SEQUENCE of client_signcryption_key and digest (as OCTET STRING)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub(crate) struct ClientPayload {
    pub(crate) client_signcryption_key: SigncryptionPubKey, /* The client's public keys needed for
                                                             * signcryption */
    pub(crate) digest: Vec<u8>, // Digest of the fhe_cipher the client wish to have decrypted
    pub(crate) sig_randomization: Vec<u8>, /* Randomness to concatenate to the encrypted message to ensure EU-CMA security, see https://link.springer.com/content/pdf/10.1007/3-540-36492-7_1.pdf */
}

#[allow(dead_code)]
impl ClientRequest {
    /// Constructs a new signcryption request for a message `msg` by sampling necesary ephemeral
    /// keys and returning the aggegrated signcryption keys
    pub(crate) fn new<T: Serialize + AsRef<[u8]>>(
        fhe_cipher: &T,
        client_sig_sk: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> anyhow::Result<(Self, SigncryptionPair)> {
        let keys = ephemeral_key_generation(rng, client_sig_sk);
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
        let signature: k256::ecdsa::Signature = match &keys.sk.signing_key {
            Some(sk) => sk.sk.sign(&to_sign[..]),
            None => return Err(anyhow_error_and_log("signing key is None".to_string())),
        };
        Ok((
            ClientRequest {
                payload,
                signature: Signature { sig: signature },
            },
            keys,
        ))
    }

    /// Verify the request.
    /// This involves validating the signature on the client's request based on the client's
    /// verification key and that the message requested to be decrypted is as expected.
    ///
    /// Returns true if everything is ok and false otherwise.
    ///
    /// WARNING: IT IS ASSUMED THAT THE CLIENT'S PUBLIC VERIFICATION KEY HAS BEEN CROSS-CHECKED TO
    /// BELONG TO A CLIENT THAT IS ALLOWED TO DECRYPT `fhe_cipher`
    pub(crate) fn verify<T: Serialize + AsRef<[u8]>>(
        &self,
        fhe_cipher: &T,
    ) -> anyhow::Result<bool> {
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
}

/// Helper method for what the client is supposed to do when generating ephemeral keys linked to the
/// client's blockchain signing key
pub(crate) fn ephemeral_key_generation(
    rng: &mut (impl CryptoRng + RngCore),
    sig_key: &PrivateSigKey,
) -> SigncryptionPair {
    let verification_key = PublicSigKey {
        pk: *SigningKey::verifying_key(&sig_key.sk),
    };
    let (enc_pk, enc_sk) = encryption_key_generation(rng);
    SigncryptionPair {
        sk: SigncryptionPrivKey {
            signing_key: Some(sig_key.clone()),
            decryption_key: enc_sk,
        },
        pk: SigncryptionPubKey {
            verification_key,
            enc_key: enc_pk,
        },
    }
}
