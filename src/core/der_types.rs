use super::signcryption::SIG_SIZE;
use crypto_box::SecretKey;
use k256::ecdsa::VerifyingKey;
use nom::AsBytes;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

// Alias wrapping the ephemeral public encryption key the user's wallet constructs and the server uses to
// encrypt its payload
#[wasm_bindgen]
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct PublicEncKey(pub(crate) crypto_box::PublicKey);
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

// Alias wrapping the ephemeral private decryption key the user's wallet constructs to receive the server's
// encrypted payload
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateEncKey(pub(crate) crypto_box::SecretKey);

impl Serialize for PrivateEncKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> Deserialize<'de> for PrivateEncKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrivateEncKeyVisitor)
    }
}

struct PrivateEncKeyVisitor;
impl<'de> Visitor<'de> for PrivateEncKeyVisitor {
    type Value = PrivateEncKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("An ephemeral private decryption key")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match SecretKey::from_slice(v) {
            Ok(sk) => Ok(PrivateEncKey(sk)),
            Err(e) => Err(E::custom(format!(
                "Could not decode decryption key: {:?}",
                e
            ))),
        }
    }
}

// Struct wrapping signature verification key used by both the user's wallet and server
#[wasm_bindgen]
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
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicSigKeyVisitor)
    }
}
impl std::hash::Hash for PublicSigKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pk.to_sec1_bytes().hash(state);
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
// Struct wrapping signature signing key used by both the client and server to authenticate their
// messages to one another
#[wasm_bindgen]
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
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigncryptionPrivKey {
    pub signing_key: PrivateSigKey,
    pub decryption_key: PrivateEncKey,
}

/// Structure for public keys for signcryption that can get DER encoded as follows:
///     verification_key, (SEC1 as an OCTET STRING)
///     enc_key, (Montgomery point following libsodium serialization as OCTET STRING)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SigncryptionPubKey {
    pub verification_key: PublicSigKey,
    pub enc_key: PublicEncKey,
}

/// Structure for private keys for signcryption
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigncryptionPair {
    pub sk: SigncryptionPrivKey,
    pub pk: SigncryptionPubKey,
}

/// Wrapper struct for a digital signature
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    pub sig: k256::ecdsa::Signature,
}
/// Serialize a signature as a 64 bytes sequence of big endian bytes, consisting of r followed by s
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.sig.to_vec());
        // to_ser.append(&mut self.pk.pk.to_sec1_bytes().to_vec());
        serializer.serialize_bytes(&to_ser)
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
        let sig = match k256::ecdsa::Signature::from_slice(&v[0..SIG_SIZE]) {
            Ok(sig) => sig,
            Err(e) => Err(E::custom(format!("Could not decode signature: {:?}", e)))?,
        };
        Ok(Signature { sig })
    }
}
