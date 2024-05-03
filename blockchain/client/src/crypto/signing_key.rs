//! Transaction signing key

use std::str::FromStr;

use bip32::XPrv;
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

    /// Derives a signing key from a bip32 encoded string.
    ///
    /// # Arguments
    ///
    /// * `bip32_encoded` - The bip32 encoded string.
    ///
    /// # Returns
    ///
    /// A `secp256k1::SigningKey` derived from the bip32 encoded string.
    ///
    pub fn from_bip32(bip32_encoded: &str) -> Result<SigningKey, Error> {
        let pk = XPrv::from_str(bip32_encoded)?.to_bytes();
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

#[cfg(test)]
mod tests {
    use bip32::Prefix;
    use ecdsa::signature::rand_core::OsRng;

    use super::*;

    #[test]
    fn test_signing_key_from_mnemonic() {
        let mnemonic = "thing guitar always vacuum cabbage shove practice defense seminar pair ensure trim crew fade hawk rough flame cupboard illness decline gesture gentle denial giant";
        let signing_key = SigningKey::key_from_mnemonic(mnemonic);
        assert!(signing_key.is_ok());
    }

    #[test]
    fn test_signing_key_from_bip32() {
        let mnemonic_seed = bip32::Mnemonic::random(OsRng, Default::default());
        let seed = mnemonic_seed.to_seed("");
        let bip32 = bip32::XPrv::new(seed.as_bytes()).unwrap();

        let signing_key = SigningKey::from_bip32(bip32.to_string(Prefix::XPRV).as_str());
        assert!(signing_key.is_ok());
    }

    #[test]
    fn test_signing_key_from_bip32_manually_generated() {
        let key = SigningKey::from_bip32("xprv9s21ZrQH143K4JxNZRVvjEHhWWkjRMrtUvKVXa58yFkqxkywvuqFehnnfxMQFZPK25jz2X2PbmGXYr873VbVNsXrFCycje7R7DuFwprZxk2");
        assert!(key.is_ok());
    }
}
