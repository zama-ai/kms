//! Transaction signing key

use ecdsa::signature::{Keypair, Signer};
use k256::ecdsa::{Signature, VerifyingKey};

use super::bip::derive_key;
use super::pubkey::PublicKey;
use crate::errors::Error;

/// ECDSA/secp256k1 signing key (i.e. private key)
///
/// This is a wrapper type which supports any pluggable ECDSA/secp256k1 signer
/// implementation which impls the [`EcdsaSigner`] trait.
///
/// By default it uses [`k256::ecdsa::SigningKey`] as the signer implementation,
/// however it can be instantiated from any compatible signer (e.g. HSM, KMS,
/// etc) by using [`SigningKey::new`].
///
/// Supported alternative signer implementations:
/// - [`yubihsm::ecdsa::secp256k1::Signer`]: YubiHSM-backed ECDSA/secp256k1 signer
///
/// [`yubihsm::ecdsa::secp256k1::Signer`]: https://docs.rs/yubihsm/latest/yubihsm/ecdsa/secp256k1/type.Signer.html
pub struct SigningKey {
    inner: Box<dyn EcdsaSigner>,
}

impl SigningKey {
    /// Derives a signing key from a mnemonic using a specified key derivation path.
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic seed phrase.
    ///
    /// # Returns
    /// A `secp256k1::SigningKey` derived from the mnemonic.
    pub fn key_from_mnemonic(mnemonic: &str) -> Result<SigningKey, Error> {
        let pk = derive_key(mnemonic, "")?;
        SigningKey::from_slice(&pk)
    }

    /// Initialize from a provided signer object.
    ///
    /// Use [`SigningKey::from_slice`] to initialize from a raw private key.
    pub fn new(signer: Box<dyn EcdsaSigner>) -> Self {
        Self { inner: signer }
    }

    /// Initialize from a raw scalar value (big endian).
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(bytes)?;
        Ok(Self::new(Box::new(signing_key)))
    }

    /// Sign the given message, returning a signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let signature = self.inner.try_sign(msg)?;
        Ok(signature)
    }

    /// Get the [`PublicKey`] for this [`SigningKey`].
    pub fn public_key(&self) -> PublicKey {
        self.inner.verifying_key().into()
    }
}

impl From<Box<dyn EcdsaSigner>> for SigningKey {
    fn from(signer: Box<dyn EcdsaSigner>) -> Self {
        Self::new(signer)
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

/// ECDSA/secp256k1 signer trait.
///
/// This is a trait which enables plugging any backing signing implementation
/// which produces a compatible [`Signature`] and [`VerifyingKey`].
///
/// Note that this trait is bounded on [`ecdsa::signature::Signer`], which is
/// what is actually used to produce a signature for a given message.
pub trait EcdsaSigner:
    Signer<Signature> + Keypair<VerifyingKey = VerifyingKey> + Sync + Send
{
}

impl<T> EcdsaSigner for T where
    T: Signer<Signature> + Keypair<VerifyingKey = VerifyingKey> + Sync + Send
{
}
