use crate::blockchain::blockchain_impl;
use crate::blockchain::ciphertext_provider::CiphertextProvider;
use crate::blockchain::handlers::k256::ecdsa::SigningKey;
use crate::common::provider::GatewayContract;
use crate::config::EthereumConfig;
use crate::config::GatewayConfig;
use crate::events::manager::ApiReencryptValues;
use crate::events::manager::DecryptionEvent;
use crate::util::wallet::WalletManager;
use anyhow::Context;
use ethers::abi::encode;
use ethers::abi::Token;
use ethers::middleware::gas_escalator::*;
use ethers::prelude::*;
use events::kms::ReencryptResponseValues;
use std::sync::Arc;

pub(crate) async fn handle_event_decryption(
    event: &Arc<DecryptionEvent>,
    config: &GatewayConfig,
) -> anyhow::Result<()> {
    tracing::debug!("🍻 handle_event_decryption enter");

    let client = Arc::new(http_provider(config).await?);
    let oracle_predeploy_address = config.ethereum.oracle_predeploy_address;
    let contract = GatewayContract::new(oracle_predeploy_address, client.clone());

    let start = std::time::Instant::now();
    let mut tokens: Vec<Token> = Vec::with_capacity(event.filter.cts.len());
    for ct_handle in event.filter.cts.iter() {
        let token = decrypt(
            &client,
            &config.clone(),
            event.filter.request_id,
            *ct_handle,
            event.block_number,
        )
        .await
        .unwrap();
        tokens.push(token);
    }

    let duration = start.elapsed();
    tracing::info!("⏱️ KMS Response Time elapsed: {:?}", duration);

    // Fake signatures for now
    let signatures = vec![Bytes::from(vec![0u8; 65])];
    tracing::info!("Fulfilling request: {:?}", event.filter.request_id);

    let encoded_bytes: Bytes = encode(&tokens).into();
    tracing::info!("Encoded bytes: {:?}", encoded_bytes);

    let encoded_packed_bytes: Bytes = abi::encode_packed(&tokens)?.into();
    tracing::info!("Encoded packed bytes: {:?}", encoded_packed_bytes);

    match contract
        .fulfill_request(event.filter.request_id, encoded_bytes, signatures)
        .gas_price(config.ethereum.gas_price)
        .send()
        .await
    {
        Ok(pending_tx) => match pending_tx.await {
            Ok(receipt) => {
                tracing::info!("Fulfilled request: {:?}", event.filter.request_id);
                tracing::trace!("Transaction receipt: {:?}", receipt);
            }
            Err(e) => {
                tracing::error!("Failed to await transaction receipt: {:?}", e);
            }
        },
        Err(e) => {
            tracing::error!("Failed to send fulfill_request transaction: {:?}", e);
        }
    }

    tracing::debug!("🍻 handle_event_decryption exit");
    Ok(())
}

async fn decrypt(
    client: &Arc<SignerMiddleware<GasEscalatorMiddleware<Provider<Http>>, Wallet<SigningKey>>>,
    config: &GatewayConfig,
    request_id: U256,
    ct_handle: U256,
    block_number: u64,
) -> Result<Token, Box<dyn std::error::Error>> {
    let mut ct_handle_bytes = [0u8; 32];
    ct_handle.to_big_endian(&mut ct_handle_bytes);
    let (ct_bytes, fhe_type) =
        <EthereumConfig as Into<Box<dyn CiphertextProvider>>>::into(config.clone().ethereum)
            .get_ciphertext(
                client,
                ct_handle_bytes.to_vec(),
                Some(BlockId::from(block_number)),
            )
            .await?;
    tracing::info!("🚀 request_id: {}, fhe_type: {}", request_id, fhe_type,);

    Ok(blockchain_impl(config)
        .await
        .decrypt(ct_bytes, fhe_type)
        .await?)
}

pub(crate) async fn handle_reencryption_event(
    event: &ApiReencryptValues,
    config: &GatewayConfig,
) -> anyhow::Result<Vec<ReencryptResponseValues>> {
    let client = Arc::new(http_provider(config).await?);
    let start = std::time::Instant::now();

    let chain_id = client.provider().get_chainid().await?;

    let ethereum_ct_handle = event.ciphertext_handle.0.clone();
    let (ciphertext, fhe_type) =
        <EthereumConfig as Into<Box<dyn CiphertextProvider>>>::into(config.clone().ethereum)
            .get_ciphertext(&client, ethereum_ct_handle.clone(), None)
            .await?;
    let response = blockchain_impl(config)
        .await
        .reencrypt(
            event.signature.0.clone(),
            event.user_address.0.clone(),
            event.enc_key.0.clone(),
            fhe_type,
            ciphertext,
            event.eip712_verifying_contract.clone(),
            chain_id,
        )
        .await;
    let duration = start.elapsed();
    tracing::info!("⏱️ KMS Response Time elapsed: {:?}", duration);
    response
}

async fn http_provider(
    config: &GatewayConfig,
) -> anyhow::Result<SignerMiddleware<GasEscalatorMiddleware<Provider<Http>>, Wallet<SigningKey>>> {
    let gas_escalator = gas_escalator(
        config.ethereum.gas_escalator_retry_interval,
        config.ethereum.gas_escalator_increase as f64,
    );
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Http>::connect(&config.ethereum.http_url).await;
    let provider = GasEscalatorMiddleware::new(provider, gas_escalator, Frequency::PerBlock);
    let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
    Ok(provider)
}

async fn _ws_provider(
    config: &GatewayConfig,
) -> anyhow::Result<SignerMiddleware<GasEscalatorMiddleware<Provider<Ws>>, Wallet<SigningKey>>> {
    let gas_escalator = gas_escalator(
        config.ethereum.gas_escalator_retry_interval,
        config.ethereum.gas_escalator_increase as f64,
    );
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Ws>::connect(&config.ethereum.wss_url)
        .await
        .context("Failed to connect to WSS")?;
    let provider = GasEscalatorMiddleware::new(provider, gas_escalator, Frequency::PerBlock);
    let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
    Ok(provider)
}

fn gas_escalator(every_secs: u64, percentage_increase: f64) -> GeometricGasPrice {
    let max_price: Option<i32> = None;
    let coefficient = 1.0 + (percentage_increase / 100.0);
    GeometricGasPrice::new(coefficient, every_secs, max_price)
}
