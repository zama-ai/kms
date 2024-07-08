use crate::config::{init_conf_gateway, GatewayConfig};
use crate::util::wallet::k256::ecdsa::SigningKey;
use ethers::prelude::*;

pub struct WalletManager {
    pub wallet: Wallet<SigningKey>,
}

impl Default for WalletManager {
    fn default() -> Self {
        let config: GatewayConfig = init_conf_gateway("config/gateway").unwrap();

        let wallet = config
            .ethereum
            .relayer_key
            .parse::<LocalWallet>()
            .expect("Invalid key");
        WalletManager { wallet }
    }
}
