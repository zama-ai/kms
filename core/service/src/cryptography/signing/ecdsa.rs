//! ECDSA over secp256k1 signing backend.

use super::{HasSigningScheme, Signature, SigningError, SigningScheme, SigningSchemeType};
use crate::anyhow_tracked;
use crate::cryptography::error::CryptographyError;
use crate::cryptography::internal_crypto_types::LegacySerialization;
use crate::impl_generic_versionize;
use ::signature::{Signer, Verifier};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolStruct};
use hashing::DomainSep;
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::Visitor};
use std::sync::Arc;
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SIG_SIZE: usize = 64; // a 32 byte r value and a 32 byte s value

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PublicSigKeyVersions {
    V0(PublicSigKey),
}

// Struct wrapping signature verification key used by both the user's wallet and server
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize, Versionize)]
#[versionize(PublicSigKeyVersions)]
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

    pub fn from_sk(sk: &PrivateSigKey) -> Self {
        let pk = SigningKey::verifying_key(&sk.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }

    /// Return a concise identifier for this verification key. For ECDSA keys, this is the Ethereum address.
    pub fn verf_key_id(&self) -> Vec<u8> {
        // Let the ID of both a normal ecdsa256k1 key and an eip712 key be the Ethereum address
        self.address().to_vec()
    }

    pub fn address(&self) -> alloy_primitives::Address {
        alloy_primitives::Address::from_public_key(&self.pk.0)
    }

    /// The raw secp256k1 verifying key, for the crate-internal ECDSA backend.
    pub(crate) fn raw_verifying_key(&self) -> &k256::ecdsa::VerifyingKey {
        &self.pk.0
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
        SigningSchemeType::Ecdsa256k1
    }
}

impl LegacySerialization for PublicSigKey {
    fn to_legacy_bytes(&self) -> Result<Vec<u8>, CryptographyError> {
        bc2wrap::serialize(self).map_err(|e| {
            CryptographyError::SerializationError(format!("Could not serialize key {}", e))
        })
    }

    fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, CryptographyError>
    where
        Self: Sized,
    {
        bc2wrap::deserialize_slice(bytes).map_err(|e| {
            CryptographyError::DeserializationError(format!("Could not deserialize key {}", e))
        })
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
        serializer.serialize_bytes(&self.0.to_sec1_bytes())
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
pub enum PrivateSigKeyVersions {
    V0(PrivateSigKey),
}

// Struct wrapping signature signing key used by both the client and server to authenticate their
// messages to one another
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(PrivateSigKeyVersions)]
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
        addr.to_vec()
    }

    pub fn address(&self) -> alloy_primitives::Address {
        alloy_primitives::Address::from_private_key(&self.sk.0)
    }

    /// The raw secp256k1 signing key, for the crate-internal ECDSA backend.
    pub(crate) fn raw_signing_key(&self) -> &k256::ecdsa::SigningKey {
        &self.sk.0
    }
}

impl HasSigningScheme for PrivateSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        SigningSchemeType::Ecdsa256k1
    }
}

// Marker only: the `sk: WrappedSigningKey` field is `ZeroizeOnDrop`, so dropping
// a `PrivateSigKey` wipes its key material. Not derived because that would
// generate a `Drop` impl, which conflicts with the other macros on this type
// (this is why the zeroizing `Drop` lives on the `WrappedSigningKey` newtype).
impl ZeroizeOnDrop for PrivateSigKey {}

#[derive(Clone, PartialEq, Eq, Debug, ZeroizeOnDrop)]
struct WrappedSigningKey(k256::ecdsa::SigningKey);
impl_generic_versionize!(WrappedSigningKey);

impl Zeroize for WrappedSigningKey {
    fn zeroize(&mut self) {
        // Swap in a known-valid dummy and let the original drop —
        // `SigningKey<Secp256k1>: ZeroizeOnDrop` wipes its scalar.
        // `[1u8; 32]` is `0x0101…01` ≪ secp256k1 order `n`, so the
        // constructor is in practice infallible; `if let Ok` keeps the
        // Drop path panic-free at the type level — future edits to the
        // constant or to the underlying type can't introduce a panic
        // surface inside `Drop` (this method is called from the
        // `#[derive(ZeroizeOnDrop)]`-generated `Drop` impl).
        if let Ok(dummy) = SigningKey::from_slice(&[1u8; 32]) {
            let _wiped = std::mem::replace(&mut self.0, dummy);
        }
        // If construction ever failed (unreachable today), `self.0` would
        // be untouched here — and Rust's drop glue still wipes the
        // original via `SigningKey<Secp256k1>: ZeroizeOnDrop` when the
        // generated `Drop` returns. No security loss.
    }
}

impl Serialize for WrappedSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
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
        formatter.write_str("A private signing key for ECDSA signatures using secp256k1")
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

impl Signature {
    /// Build an `Ecdsa256k1`-tagged [`Signature`] from a k256 signature.
    ///
    /// The stored bytes are the 64-byte `r‖s` encoding.
    pub fn from_ecdsa(sig: k256::ecdsa::Signature) -> Self {
        Signature::new(SigningSchemeType::Ecdsa256k1, sig.to_vec())
    }

    /// Decode the k256 signature from an `Ecdsa256k1`-tagged [`Signature`].
    pub(crate) fn ecdsa_sig(&self) -> anyhow::Result<k256::ecdsa::Signature> {
        if self.scheme != SigningSchemeType::Ecdsa256k1 {
            anyhow::bail!("expected an ECDSA signature, got {:?}", self.scheme);
        }
        if self.sig.len() != SIG_SIZE {
            anyhow::bail!(
                "expected {SIG_SIZE}-byte ECDSA signature, got {}",
                self.sig.len()
            );
        }
        k256::ecdsa::Signature::from_slice(&self.sig)
            .map_err(|e| anyhow::anyhow!("could not decode ECDSA signature: {e}"))
    }
}

/// Compute the signature on message based on the server's signing key.
///
/// Returns an `Ecdsa256k1`-tagged [`Signature`]; concretely r || s.
pub(crate) fn internal_sign<T>(
    dsep: &DomainSep,
    msg: &T,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Signature>
where
    T: AsRef<[u8]> + ?Sized,
{
    let sig: k256::ecdsa::Signature = server_sig_key
        .raw_signing_key()
        .try_sign(&[dsep, msg.as_ref()].concat())?;
    // Normalize s value to ensure a consistent signature and protect against malleability
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(Signature::from_ecdsa(sig))
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

    let ecdsa_sig = sig.ecdsa_sig()?;
    // Verify signature
    server_verf_key
        .raw_verifying_key()
        .verify(&[dsep, payload.as_ref()].concat(), &ecdsa_sig)
        .map_err(|e| anyhow_tracked(e.to_string()))
}

/// Check if a signature is normalized in "low S" form as described in
/// [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub(crate) fn check_normalized(sig: &Signature) -> Result<(), CryptographyError> {
    let ecdsa_sig = sig
        .ecdsa_sig()
        .map_err(|e| CryptographyError::VerificationError(e.to_string()))?;
    if ecdsa_sig.normalize_s().is_some() {
        return Err(CryptographyError::VerificationError(format!(
            "Signature {:X?} is not normalized",
            ecdsa_sig
        )));
    };
    Ok(())
}

/// take some public data (e.g. public key or CRS) and sign it using EIP-712 for external verification (e.g. in fhevm).
pub fn compute_eip712_signature<D: SolStruct>(
    sk: &PrivateSigKey,
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = data.eip712_signing_hash(eip712_domain);
    let signer = PrivateKeySigner::from_signing_key(sk.raw_signing_key().clone());

    // Sign the hash synchronously with the wallet.
    let signature = signer.sign_hash_sync(&message_hash)?.as_bytes().to_vec();

    tracing::info!(
        "Public data EIP-712 hash {} with signature {} from signer {}",
        message_hash,
        hex::encode(signature.clone()),
        signer.address(),
    );

    Ok(signature)
}

pub const ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGTH: &str =
    "Expected external signature of length 65 Bytes";

pub fn recover_address_from_ext_signature<S: SolStruct>(
    data: &S,
    domain: &Eip712Domain,
    external_sig: &[u8],
) -> anyhow::Result<alloy_primitives::Address> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow::anyhow!(
            "{ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGTH}, but got {:?}",
            external_sig.len()
        ));
    }
    // Deserialize the Signature.
    let sig = alloy_primitives::Signature::from_bytes_and_parity(
        external_sig,
        external_sig[64] & 0x01 == 0,
    );

    tracing::debug!(
        "ext. signature bytes: {:x?}, ext. signature: {:?}, EIP-712 domain: {:?}",
        external_sig,
        sig,
        domain
    );

    let hash = data.eip712_signing_hash(domain);
    tracing::debug!("Public Data EIP-712 Message hash: {:?}", hash);

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::debug!("Reconstructed address: {}", addr);

    Ok(addr)
}

/// Marker type for the ECDSA/secp256k1 signature scheme.
pub struct Ecdsa256k1;

impl SigningScheme for Ecdsa256k1 {
    type SigningKey = PrivateSigKey;
    type VerificationKey = PublicSigKey;

    fn sign(dsep: &DomainSep, msg: &[u8], sk: &PrivateSigKey) -> Result<Vec<u8>, SigningError> {
        internal_sign(dsep, msg, sk)
            .map(|s| s.to_bytes())
            .map_err(|e| SigningError::Sign(e.to_string()))
    }

    fn verify(
        dsep: &DomainSep,
        msg: &[u8],
        sig: &[u8],
        vk: &PublicSigKey,
    ) -> Result<(), SigningError> {
        let signature = Signature::new(SigningSchemeType::Ecdsa256k1, sig.to_vec());
        internal_verify_sig(dsep, msg, &signature, vk)
            .map_err(|e| SigningError::Verify(e.to_string()))
    }

    fn verifying_key(sk: &PrivateSigKey) -> Result<PublicSigKey, SigningError> {
        Ok(sk.verf_key())
    }
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
        assert!(res.is_err());
    }

    #[test]
    fn unnormalized_signature() {
        let mut rng = AesRng::seed_from_u64(42);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();

        let sig = internal_sign(b"TESTTEST", &msg, &sig_key).unwrap();
        let ecdsa_sig = sig.ecdsa_sig().unwrap();
        // Ensure the signature is normalized
        let internal_sig = ecdsa_sig.normalize_s().unwrap_or(ecdsa_sig);
        // Ensure the signature is ok
        assert!(internal_verify_sig(b"TESTTEST", &msg, &sig, &verf_key).is_ok());
        // Undo normalization
        let bad_sig = Signature::from_ecdsa(
            k256::ecdsa::Signature::from_scalars(internal_sig.r(), internal_sig.s().negate())
                .unwrap(),
        );
        let res = internal_verify_sig(b"TESTTEST", &msg, &bad_sig, &verf_key);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("is not normalized"));
    }

    #[test]
    fn validate_zeroize_signing_key() {
        let mut rng = AesRng::seed_from_u64(1);
        let (_pk, mut sk) = gen_sig_keys(&mut rng);
        let old_sk = sk.clone();
        sk.zeroize();
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

    #[test]
    fn sunshine_verf_key_legacy_serialization() {
        let mut rng = AesRng::seed_from_u64(42);
        let (verf_key, _sig_key) = gen_sig_keys(&mut rng);
        let serialized_key = verf_key.to_legacy_bytes().unwrap();
        let deserialized_key = PublicSigKey::from_legacy_bytes(&serialized_key).unwrap();
        assert_eq!(verf_key, deserialized_key);
    }
}
