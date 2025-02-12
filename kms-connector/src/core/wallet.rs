use alloy_primitives::{Address, ChainId, B256};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::{coins_bip39::English, MnemonicBuilder, PrivateKeySigner};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Signer error: {0}")]
    SignerError(#[from] alloy_signer::Error),
    #[error("Local signer error: {0}")]
    LocalSignerError(#[from] alloy_signer_local::LocalSignerError),
    #[error("Failed to load wallet: {0}")]
    LoadError(String),
}

pub type Result<T> = std::result::Result<T, WalletError>;

/// KMS wallet for signing decryption responses
#[derive(Clone)]
pub struct KmsWallet {
    pub signer: PrivateKeySigner,
}

impl KmsWallet {
    /// Create a new wallet from a mnemonic phrase
    pub fn from_mnemonic(phrase: &str, chain_id: Option<ChainId>) -> Result<Self> {
        let signer = MnemonicBuilder::<English>::default()
            .phrase(phrase)
            .build()?
            .with_chain_id(chain_id);

        Ok(Self { signer })
    }

    /// Create a new wallet from a mnemonic file
    pub fn from_mnemonic_file(path: PathBuf, chain_id: Option<ChainId>) -> Result<Self> {
        let phrase = std::fs::read_to_string(&path)
            .map_err(|e| WalletError::LoadError(format!("Failed to read mnemonic file: {}", e)))?;
        Self::from_mnemonic(phrase.trim(), chain_id)
    }

    /// Create a new random wallet
    pub fn random(chain_id: Option<ChainId>) -> Result<Self> {
        let signer = PrivateKeySigner::random().with_chain_id(chain_id);
        Ok(Self { signer })
    }

    /// Get the wallet's address
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a message
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signer.sign_message_sync(message)?.as_bytes().to_vec())
    }

    /// Sign a hash
    pub fn sign_hash(&self, hash: &B256) -> Result<Vec<u8>> {
        Ok(self.signer.sign_hash_sync(hash)?.as_bytes().to_vec())
    }

    /// Sign a decryption response
    pub fn sign_decryption_response(&self, id: &[u8], result: &[u8]) -> Result<Vec<u8>> {
        // Create message to sign: keccak256(abi.encodePacked(id, result))
        let mut message = Vec::with_capacity(id.len() + result.len());
        message.extend_from_slice(id);
        message.extend_from_slice(result);
        self.sign_message(&message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHAIN_ID: u64 = 1337;

    #[test]
    fn test_wallet_from_mnemonic() {
        let wallet = KmsWallet::random(Some(TEST_CHAIN_ID)).unwrap();
        assert!(wallet.address() != Address::ZERO);
    }

    #[test]
    fn test_sign_decryption_response() {
        let wallet = KmsWallet::random(Some(TEST_CHAIN_ID)).unwrap();

        let id = b"test_id";
        let result = b"test_result";
        let signature = wallet.sign_decryption_response(id, result).unwrap();

        assert!(!signature.is_empty());
    }
}
