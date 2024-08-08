use crate::blockchain::blockchain_impl;
use crate::blockchain::ciphertext_provider::CiphertextProvider;
use crate::blockchain::handlers::k256::ecdsa::SigningKey;
use crate::common::provider::GatewayContract;
use crate::config::BaseGasPrice;
use crate::config::EthereumConfig;
use crate::config::GatewayConfig;
use crate::events::manager::ApiReencryptValues;
use crate::events::manager::DecryptionEvent;
use crate::util::wallet::WalletManager;
use anyhow::Context;
use ethers::abi::encode;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::ReencryptResponseValues;
use std::ops::Mul;
use std::sync::Arc;

pub(crate) async fn handle_event_decryption(
    event: &Arc<DecryptionEvent>,
    config: &GatewayConfig,
) -> anyhow::Result<()> {
    tracing::debug!("🍻 handle_event_decryption enter");
    let start = std::time::Instant::now();
    let block_number = event.block_number;
    let ciphertexts = event.filter.cts.clone();

    let client = Arc::new(http_provider(config).await.unwrap());

    let (tokens, sigs) = decrypt(&client, config, ciphertexts, block_number)
        .await
        .unwrap();

    tracing::info!("⏱️ KMS Response Time elapsed: {:?}", start.elapsed());

    // Signatures into Bytes type
    let signatures = sigs.iter().map(|s| Bytes::from(s.clone())).collect();
    tracing::info!("Fulfilling Ethereum request: {:?}", event.filter.request_id);

    // prepend a uint256 placeholder token to the tokens vec
    let mut tok = vec![Token::Uint(U256::from(42))];
    tok.extend(tokens.clone());

    let encoded_bytes: Bytes = encode(&tok).into();
    let encoded_bytes = encoded_bytes.as_ref()[32..].to_vec();
    tracing::debug!("Encoded bytes: {:?}", hex::encode(encoded_bytes.clone()));

    let client = Arc::new(http_provider(config).await.unwrap());
    let current_gas_price = client.provider().get_gas_price().await.unwrap();
    tracing::debug!("Current gas price: {:?}", current_gas_price);

    let (max_fee_per_gas, max_priority_fee_per_gas) =
        client.provider().estimate_eip1559_fees(None).await.unwrap();
    tracing::debug!("Max fee per gas: {:?}", max_fee_per_gas);
    tracing::debug!("Max priority fee per gas: {:?}", max_priority_fee_per_gas);

    let gas_price = match config.ethereum.gas_price {
        Some(gas_price) => {
            tracing::debug!("⛽ Using configured gas price: {:?}", gas_price);
            U256::from(gas_price)
        }
        None => match config.ethereum.base_gas {
            BaseGasPrice::CurrentGasPrice => {
                let gas_price = client.provider().get_gas_price().await?;
                let gas_price = gas_price.mul(1 + (config.ethereum.gas_escalator_increase / 100));

                tracing::debug!("⛽ Calculated CurrentGasPrice gas price: {:?}", gas_price);
                gas_price
            }
            BaseGasPrice::Eip1559MaxPriorityFeePerGas => {
                let (_, max_priority_fee_per_gas) =
                    client.provider().estimate_eip1559_fees(None).await?;
                let gas_price = max_priority_fee_per_gas
                    .mul(1 + (config.ethereum.gas_escalator_increase / 100));
                tracing::debug!(
                    "⛽ Calculated Eip1559MaxPriorityFeePerGas gas price: {:?}",
                    gas_price
                );
                gas_price
            }
        },
    };
    tracing::debug!("⛽ Using calculated gas price: {:?}", gas_price);

    let contract = GatewayContract::new(config.ethereum.oracle_predeploy_address, client);
    let fullfillment = contract
        .fulfill_request(event.filter.request_id, encoded_bytes.into(), signatures)
        .gas_price(gas_price)
        .gas(config.ethereum.gas_limit.unwrap_or(1_000_000));

    match fullfillment.send().await {
        Ok(pending_tx) => match pending_tx.await {
            Ok(receipt) => {
                tracing::info!(
                    "✅ Fulfilled Ethereum request: {:?}",
                    event.filter.request_id
                );
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
    client: &Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>,
    config: &GatewayConfig,
    ct_handles: Vec<U256>,
    block_number: u64,
) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
    let mut typed_cts = Vec::new();

    // get ct for every handle
    for ct_handle in ct_handles {
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
        typed_cts.push((ct_bytes, fhe_type));
    }

    blockchain_impl(config).await.decrypt(typed_cts).await
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

    // check the format EIP-55
    _ = alloy_primitives::Address::parse_checksummed(&event.client_address, None)?;
    _ = alloy_primitives::Address::parse_checksummed(&event.eip712_verifying_contract, None)?;

    let response = blockchain_impl(config)
        .await
        .reencrypt(
            event.signature.0.clone(),
            event.client_address.clone(),
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
) -> anyhow::Result<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>> {
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Http>::connect(&config.ethereum.http_url).await;
    let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
    Ok(provider)
}

async fn _ws_provider(
    config: &GatewayConfig,
) -> anyhow::Result<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>> {
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Ws>::connect(&config.ethereum.wss_url)
        .await
        .context("Failed to connect to WSS")?;
    let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
    Ok(provider)
}

#[cfg(test)]
mod tests {

    use ethers::abi::encode;
    use ethers::abi::Token;
    use ethers::prelude::*;

    // test encoding
    #[tokio::test]
    async fn test_handle_event_decryption() {
        let tok = vec![
            Token::Uint(U256::from(31)),
            Token::Address("76e1e8877b40973B9A269100F1C97Df9B78ac407".parse().unwrap()),
            Token::Bytes(hex::decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffff9c6").unwrap()),
            Token::Uint(U256::from(19)),
            Token::Bytes(hex::decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a").unwrap()),
        ];

        let encoded_bytes: Bytes = encode(&tok).into();
        let encoded_bytes = encoded_bytes.as_ref()[32..].to_vec();
        println!("Encoded bytes: {:?}", hex::encode(encoded_bytes.clone()));
    }
}
