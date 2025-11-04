use crate::{anyhow_tracked, cryptography::error::CryptographyError, impl_generic_versionize};
use ::signature::{Signer, Verifier};
use aes_prng::AesRng;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolStruct};
use k256::ecdsa::{SigningKey, VerifyingKey};
use nom::AsBytes;
use rand::SeedableRng;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use strum_macros::Display;
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::hashing::DomainSep;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroize;

pub const SIG_SIZE: usize = 64; // a 32 byte r value and a 32 byte s value

pub trait HasSigningScheme {
    fn signing_scheme_type(&self) -> SigningSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum SigningSchemeTypeVersioned {
    V0(SigningSchemeType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, Versionize)]
#[versionize(SigningSchemeTypeVersioned)]
pub enum SigningSchemeType {
    Ecdsa256k1,
    // Eventually we will support post quantum signatures as well
}

impl From<kms_grpc::kms::v1::SigningSchemeType> for SigningSchemeType {
    fn from(value: kms_grpc::kms::v1::SigningSchemeType) -> Self {
        // Map the gRPC enum to your local enum
        match value {
            kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 => SigningSchemeType::Ecdsa256k1,
        }
    }
}
impl TryFrom<i32> for SigningSchemeType {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SigningSchemeType::Ecdsa256k1),
            // Future signing schemes can be added here
            _ => Err(anyhow::anyhow!(
                "Unsupported SigningSchemeType: {:?}",
                value
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PublicSigKeyVersioned {
    V0(PublicSigKey),
}

// Struct wrapping signature verification key used by both the user's wallet and server
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize, Versionize)]
#[versionize(PublicSigKeyVersioned)]
pub struct PublicSigKey {
    pk: WrappedVerifyingKey,
}
impl Zeroize for PublicSigKey {
    fn zeroize(&mut self) {
        // Don't do anything, public key is not secret, but method is needed for types using both this and private keys
    }
}

impl Named for PublicSigKey {
    const NAME: &'static str = "PublicSigKey";
}

impl PublicSigKey {
    pub fn new(pk: k256::ecdsa::VerifyingKey) -> Self {
        Self {
            pk: WrappedVerifyingKey(pk),
        }
    }

    /// Return a concise identifier for this verification key. For ECDSA keys, this is the Ethereum address.
    pub fn verf_key_id(&self) -> Vec<u8> {
        // Let the ID of both a normal ecdsa256k1 key and an eip712 key be the Ethereum address
        self.address().to_vec()
    }

    /// DEPRECATED LEGACY code since this is not the right way to serialize as it is not versioned
    #[deprecated(
        note = "This is legacy code and should not be used for new development. Will be handled in #2781"
    )]
    pub fn get_serialized_verf_key(&self) -> anyhow::Result<Vec<u8>> {
        // TODO check if this is the same as hex::encode(pk.pk().to_encoded_point(false).to_bytes()) same with verf id
        let serialized_verf_key = bc2wrap::serialize(&PublicSigKey::new(self.pk.0.to_owned()))?;
        Ok(serialized_verf_key)
    }

    pub fn from_sk(sk: &PrivateSigKey) -> Self {
        let pk = SigningKey::verifying_key(&sk.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }

    pub fn address(&self) -> alloy_primitives::Address {
        alloy_primitives::Address::from_public_key(&self.pk.0)
    }

    #[deprecated(
        note = "This is legacy code and should not be used for new development. Will be handled in #2781"
    )]
    pub fn pk(&self) -> &k256::ecdsa::VerifyingKey {
        &self.pk.0
    }
}

impl HasSigningScheme for PublicSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        // Only one scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct WrappedVerifyingKey(k256::ecdsa::VerifyingKey);
impl_generic_versionize!(WrappedVerifyingKey);

/// Serialize the public key as a SEC1 point, which is what is used in Ethereum
impl Serialize for WrappedVerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.to_sec1_bytes().as_bytes())
    }
}

impl<'de> Deserialize<'de> for WrappedVerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicSigKeyVisitor)
    }
}
impl std::hash::Hash for WrappedVerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_sec1_bytes().hash(state);
    }
}

impl From<PrivateSigKey> for PublicSigKey {
    fn from(value: PrivateSigKey) -> Self {
        let pk = SigningKey::verifying_key(&value.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }
}
impl From<Arc<PrivateSigKey>> for PublicSigKey {
    fn from(value: Arc<PrivateSigKey>) -> Self {
        let pk = SigningKey::verifying_key(&value.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }
}

struct PublicSigKeyVisitor;
impl Visitor<'_> for PublicSigKeyVisitor {
    type Value = WrappedVerifyingKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public verification key for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match VerifyingKey::from_sec1_bytes(v) {
            Ok(pk) => Ok(WrappedVerifyingKey(pk)),
            Err(e) => Err(E::custom(format!(
                "Could not decode verification key: {e:?}"
            ))),
        }
    }
}
// Drop manually implemented due to conflict with Versionize macro
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum PrivateSigKeyVersioned {
    V0(PrivateSigKey),
}
// TODO(#2781) should eventually be replaced or consolidated with the UnifiedPrivateSigningKey
// Struct wrapping signature signing key used by both the client and server to authenticate their
// messages to one another
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(PrivateSigKeyVersioned)]
pub struct PrivateSigKey {
    sk: WrappedSigningKey,
}

impl Named for PrivateSigKey {
    const NAME: &'static str = "PrivateSigKey";
}

impl PrivateSigKey {
    pub fn new(sk: k256::ecdsa::SigningKey) -> Self {
        Self {
            sk: WrappedSigningKey(sk),
        }
    }

    /// TODO(#2781) DEPRECATED: code should be refactored to not use this outside on this class
    #[deprecated(
        note = "This is legacy code and should not be used for new development. Will be handled in #2781"
    )]
    pub fn sk(&self) -> &k256::ecdsa::SigningKey {
        &self.sk.0
    }

    pub fn verf_key(&self) -> PublicSigKey {
        PublicSigKey::from_sk(self)
    }

    /// Return a concise identifier for this signing key. For ECDSA keys, this is the Ethereum address.
    pub fn signing_key_id(&self) -> Vec<u8> {
        // Let the ID of both a normal ecdsa256k1 key and an eip712 key be the Ethereum address
        let addr = alloy_primitives::Address::from_private_key(&self.sk.0);
        addr.as_bytes().to_vec()
    }

    pub fn address(&self) -> alloy_primitives::Address {
        alloy_primitives::Address::from_private_key(&self.sk.0)
    }
}

impl HasSigningScheme for PrivateSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        // Only one scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct WrappedSigningKey(k256::ecdsa::SigningKey);
impl_generic_versionize!(WrappedSigningKey);

impl Zeroize for WrappedSigningKey {
    // We want to allow unused assignments here as we are intentionally overwriting the key material
    #[warn(unused_assignments)]
    fn zeroize(&mut self) {
        let mut rng = AesRng::seed_from_u64(0);
        // The simplest way is to overwrite the entire key with a random, static key, since we cannot directly zerorize the content of the key
        let (_pk, sk) = gen_sig_keys(&mut rng);
        // SAFETY: We're modifying a local copy of the key bytes, but this does not modify the actual key in memory.
        // To securely zeroize the key, use the Zeroize trait on the underlying scalar or key type if available.
        unsafe {
            std::ptr::write(self, sk.sk);
        }
    }
}

impl Drop for WrappedSigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Serialize for WrappedSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.to_bytes().as_bytes())
    }
}
impl<'de> Deserialize<'de> for WrappedSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrivateSigKeyVisitor)
    }
}

struct PrivateSigKeyVisitor;
impl Visitor<'_> for PrivateSigKeyVisitor {
    type Value = WrappedSigningKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public verification key for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match k256::ecdsa::SigningKey::from_bytes(v.into()) {
            Ok(sk) => Ok(WrappedSigningKey(sk)),
            Err(e) => Err(E::custom(format!("Could not decode signing key: {e:?}"))),
        }
    }
}

pub fn gen_sig_keys<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    use k256::ecdsa::SigningKey;

    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey::new(*pk), PrivateSigKey::new(sk))
}

//TODO(#2781) should also be versionized
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
impl Visitor<'_> for SignatureVisitor {
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
            Err(e) => Err(E::custom(format!("Could not decode signature: {e:?}")))?,
        };
        Ok(Signature { sig })
    }
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
        .sk
        .0
        .try_sign(&[dsep, msg.as_ref()].concat())?;
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
        .pk
        .0
        .verify(&[dsep, payload.as_ref()].concat(), &sig.sig)
        .map_err(|e| anyhow_tracked(e.to_string()))
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

pub fn hash_sol_struct<D: SolStruct>(
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    let message_hash = data.eip712_signing_hash(eip712_domain);
    tracing::info!("Public Data EIP-712 Message hash: {:?}", message_hash);
    Ok(message_hash)
}

/// take some public data (e.g. public key or CRS) and sign it using EIP-712 for external verification (e.g. in fhevm).
pub fn compute_eip712_signature<D: SolStruct>(
    sk: &PrivateSigKey,
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = hash_sol_struct(data, eip712_domain)?;
    compute_eip712_signature_from_msg_hash(sk, &message_hash)
}

pub fn compute_eip712_signature_from_msg_hash(
    sk: &PrivateSigKey,
    msg_hash: &B256,
) -> anyhow::Result<Vec<u8>> {
    let signer = PrivateKeySigner::from_signing_key(sk.sk.0.clone());
    let signer_address = signer.address();
    tracing::info!("Signer address: {:?}", signer_address);

    // Sign the hash synchronously with the wallet.
    let signature = signer.sign_hash_sync(&msg_hash)?.as_bytes().to_vec();

    tracing::info!(
        "Public Data EIP-712 Signature: {:?}",
        hex::encode(signature.clone())
    );

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn plain_signing() {
        let mut rng = AesRng::seed_from_u64(1);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        assert!(internal_verify_sig(b"TESTTEST", &msg.to_vec(), &sig, &server_verf_key).is_ok());
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
        let mut rng = AesRng::seed_from_u64(42);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();

        let sig = internal_sign(b"TESTTEST", &msg, &sig_key).unwrap();
        // Ensure the signature is normalized
        let internal_sig = sig.sig.normalize_s().unwrap_or(sig.sig);
        // Ensure the signature is ok
        assert!(internal_verify_sig(b"TESTTEST", &msg, &sig, &verf_key).is_ok());
        // Undo normalization
        let bad_sig = Signature {
            sig: k256::ecdsa::Signature::from_scalars(internal_sig.r(), internal_sig.s().negate())
                .unwrap(),
        };
        let res = internal_verify_sig(b"TESTTEST", &msg, &bad_sig, &verf_key);
        // unwrapping fails
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("is not normalized"));
    }

    #[test]
    fn validate_zeroize_signing_key() {
        let mut rng = AesRng::seed_from_u64(1);
        let (_pk, mut sk) = gen_sig_keys(&mut rng);
        let old_sk = sk.clone();
        sk.zeroize();
        // Validate a change happens from zeroize
        assert_ne!(sk, old_sk);
    }

    #[test]
    fn regression_consistent_enc() {
        let mut rng = AesRng::seed_from_u64(42);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let verf_id = verf_key.verf_key_id();
        let signing_id = sig_key.signing_key_id();
        assert!(verf_id == signing_id);
    }
}
