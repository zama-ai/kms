use k256::ecdsa::VerifyingKey;
use nom::AsBytes;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

// Alias wrapping the ephemeral public encryption key the client constructs and the server uses to encrypt its payload
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct PublicEncKey(pub(crate) crypto_box::PublicKey);
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
    pub(crate) pk: k256::ecdsa::VerifyingKey,
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
// Struct wrapping signature signing key used by both the client and server to authenticate their messages to one another
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateSigKey {
    pub(crate) sk: k256::ecdsa::SigningKey,
}
impl Serialize for PrivateSigKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.sk.to_bytes().as_bytes())
    }
}
impl<'de> Deserialize<'de> for PrivateSigKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrivateSigKeyVisitor)
    }
}
struct PrivateSigKeyVisitor;
impl<'de> Visitor<'de> for PrivateSigKeyVisitor {
    type Value = PrivateSigKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public verification key for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match k256::ecdsa::SigningKey::from_bytes(v.into()) {
            Ok(sk) => Ok(PrivateSigKey { sk }),
            Err(e) => Err(E::custom(format!("Could not decode signing key: {:?}", e))),
        }
    }
}

// Type used for the signcrypted payload returned by a server
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub struct Cipher {
    pub(crate) bytes: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
    pub(crate) server_enc_key: PublicEncKey,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigncryptionPrivKey {
    pub(crate) signing_key: PrivateSigKey,
    pub(crate) decryption_key: PrivateEncKey,
}

/// Structure for public keys for signcryption that can get DER encoded as follows:
///     verification_key, (SEC1 as an OCTET STRING)
///     enc_key, (Montgomery point following libsodium serialization as OCTET STRING)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SigncryptionPubKey {
    pub(crate) verification_key: PublicSigKey,
    pub(crate) enc_key: PublicEncKey,
}

/// Structure for private keys for signcryption
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigncryptionPair {
    pub(crate) sk: SigncryptionPrivKey,
    pub(crate) pk: SigncryptionPubKey,
}

/// Wrapper struct for a digital signature
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    pub(crate) sig: k256::ecdsa::Signature,
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
    pub payload: ClientPayload,
    pub signature: Signature,
}

/// Structure for DER encoding as a SEQUENCE of client_signcryption_key and digest (as OCTET STRING)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ClientPayload {
    pub client_signcryption_key: SigncryptionPubKey, // The client's public keys needed for signcryption
    pub digest: Vec<u8>, // Digest of the fhe_cipher the client wish to have decrypted
    pub sig_randomization: Vec<u8>, // Randomness to concatenate to the encrypted message to ensure EU-CMA security, see https://link.springer.com/content/pdf/10.1007/3-540-36492-7_1.pdf
}
