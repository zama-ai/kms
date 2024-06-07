use crate::util::wallet::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use std::fs;
use std::path::Path;

pub struct WalletManager {
    pub wallet: Wallet<SigningKey>,
}

impl Default for WalletManager {
    fn default() -> Self {
        // Wallet directory and file path
        let wallet_dir = Path::new(".wallet");
        let wallet_path = wallet_dir.join("key");

        // Ensure wallet directory exists
        if !wallet_dir.exists() {
            fs::create_dir_all(wallet_dir).expect("Failed to create wallet directory");
        }
        // Load or generate private key
        let wallet = if wallet_path.exists() {
            let keyfile = fs::read_to_string(&wallet_path).expect("Invalid key");
            keyfile.parse::<LocalWallet>().expect("Invalid key")
        } else {
            let wallet = LocalWallet::new(&mut rand::thread_rng());
            let private_key = hex::encode(wallet.signer().to_bytes());
            // Save the private key to the wallet
            fs::write(&wallet_path, private_key.as_bytes()).expect("Failed to save key");
            println!("-- Generated new key --");
            println!("   To fund the wallet address, run the following command:");
            println!(
                "   docker exec -i zama-chain-fevm-full-node-1 faucet {}",
                hex::encode(wallet.address().as_bytes())
            );
            println!("-- End of key generation --");
            wallet
        };
        WalletManager { wallet }
    }
}
