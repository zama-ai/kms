use crate::config::GatewayConfig;
use crate::config::Settings;
use crate::util::wallet::k256::ecdsa::SigningKey;
use ethers::prelude::*;

pub struct WalletManager {
    pub wallet: Wallet<SigningKey>,
}

impl Default for WalletManager {
    fn default() -> Self {
        let config: GatewayConfig = Settings::builder()
            .path(Some("config/gateway"))
            .build()
            .init_conf()
            .unwrap();

        let wallet = config
            .ethereum
            .relayer_key
            .parse::<LocalWallet>()
            .expect("Invalid key");
        WalletManager { wallet }
    }
}
