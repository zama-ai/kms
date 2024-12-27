use super::ciphertext_provider::InternalMiddleware;
use super::Blockchain;
use crate::blockchain::ciphertext_provider::CiphertextProvider;
use crate::blockchain::handlers::k256::ecdsa::SigningKey;
use crate::common::provider::GatewayContract;
use crate::config::BaseGasPrice;
use crate::config::EthereumConfig;
use crate::config::GatewayConfig;
use crate::config::KeyUrlResponseValues;
use crate::config::VerifyProvenCtResponseToClient;
use crate::events::manager::ApiReencryptValues;
use crate::events::manager::ApiVerifyProvenCtValues;
use crate::events::manager::DecryptionEvent;
use crate::util::wallet::WalletManager;
use anyhow::Context;
use ethers::abi::encode;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::ReencryptResponseValues;
use kms_grpc::kms::Eip712DomainMsg;
use std::ops::Mul;
use std::sync::Arc;
use tracing::trace_span;

#[tracing::instrument(skip(config, blockchain, middleware))]
pub(crate) async fn handle_event_decryption(
    event: &Arc<DecryptionEvent>,
    config: &GatewayConfig,
    blockchain: Arc<dyn Blockchain>,
    middleware: Arc<Box<dyn InternalMiddleware>>,
) -> anyhow::Result<()> {
    tracing::debug!("🍻 handle_event_decryption enter");
    let start = tokio::time::Instant::now();
    let block_number = event.block_number;
    let ciphertexts = event.filter.cts.clone();

    let (tokens, sigs) = decrypt(middleware, config, ciphertexts, block_number, blockchain)
        .await
        .unwrap();

    tracing::info!(
        "⏱️ KMS Response Time elapsed for decryption: {:?}",
        start.elapsed()
    );

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

    let gas_price = match config.ethereum.gas_price {
        Some(gas_price) => {
            tracing::debug!("⛽ Using configured gas price: {:?}", gas_price);
            U256::from(gas_price)
        }
        // let max_priority_fee_per_gas = U256::from(3000000000u64);
        // let gas_price_factor = U256::from(20) + U256::from(100);
        // let calculated_gas_price =
        //     (max_priority_fee_per_gas.mul(gas_price_factor)).div_mod(U256::from(100));
        None => match config.ethereum.base_gas {
            BaseGasPrice::CurrentGasPrice => {
                let current_network_gas_price = client.provider().get_gas_price().await?;
                let gas_price_factor_percentage =
                    U256::from(config.ethereum.gas_escalator_increase) + U256::from(100);
                let (calculated_gas_price, _) = current_network_gas_price
                    .mul(gas_price_factor_percentage)
                    .div_mod(U256::from(100));
                tracing::debug!(
                        "⛽ Calculated gas price: {:?} (current network gas price: {:?}, factor : {:?}%)",
                        calculated_gas_price,
                        current_network_gas_price,
                        gas_price_factor_percentage
                    );

                calculated_gas_price
            }
            BaseGasPrice::Eip1559MaxPriorityFeePerGas => {
                let (_, max_priority_fee_per_gas) =
                    client.provider().estimate_eip1559_fees(None).await?;
                let gas_price_factor_percentage =
                    U256::from(config.ethereum.gas_escalator_increase) + U256::from(100);
                let (calculated_gas_price, _) = max_priority_fee_per_gas
                    .mul(gas_price_factor_percentage)
                    .div_mod(U256::from(100));

                tracing::debug!("⛽ Calculated gas price: {:?} (max priority fee per gas: {:?}, factor : {:?}%)",
                        calculated_gas_price,
                        max_priority_fee_per_gas,
                        gas_price_factor_percentage);

                calculated_gas_price
            }
        },
    };
    tracing::debug!("⛽ Using calculated gas price: {:?}", gas_price);

    {
        let span = trace_span!("gateway-contract-call");
        let _guard = span.enter();
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
        };
    };
    tracing::debug!("🍻 handle_event_decryption exit");
    Ok(())
}

#[tracing::instrument(skip(client, config, blockchain))]
async fn decrypt(
    client: Arc<Box<dyn InternalMiddleware>>,
    config: &GatewayConfig,
    external_ct_handles: Vec<U256>,
    block_number: u64,
    blockchain: Arc<dyn Blockchain>,
) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
    let mut typed_cts = Vec::new();

    // get actual ct value from the external source (e.g. fhvem) for every external handle
    for external_ct_handle in external_ct_handles {
        let mut external_ct_handle_bytes = [0u8; 32];
        external_ct_handle.to_big_endian(&mut external_ct_handle_bytes);
        let external_handle_vec = external_ct_handle_bytes.to_vec();

        let client = Arc::clone(&client);
        let (ct_bytes, fhe_type) =
            <EthereumConfig as Into<Box<dyn CiphertextProvider>>>::into(config.clone().ethereum)
                .get_ciphertext(
                    client,
                    external_handle_vec.clone(),
                    Some(BlockId::from(block_number)),
                )
                .await?;
        typed_cts.push((ct_bytes, fhe_type, external_handle_vec));
    }

    // Get chain-id and verifying contract for EIP-712 signature
    let mut chain_id_bytes = vec![0u8; 32];
    config.parse_chain_id().to_big_endian(&mut chain_id_bytes);

    // Ensure we are using EIP-55 encoded addresses; expected by KMS core during signature generation.
    let kms_verifier_address =
        alloy_primitives::Address::from_slice(&config.ethereum.kmsverifier_vc_address.0)
            .to_string();
    let acl_address =
        alloy_primitives::Address::from_slice(&config.ethereum.acl_address.0).to_string();

    let domain = Eip712DomainMsg {
        name: config.ethereum.kmsverifier_name.clone(),
        version: config.ethereum.kmsverifier_version.clone(),
        chain_id: chain_id_bytes,
        verifying_contract: kms_verifier_address,
        salt: config.parse_eip712_salt(),
    };

    blockchain.decrypt(typed_cts, domain, acl_address).await
}

#[tracing::instrument(skip(config, ct_provider, middleware, blockchain))]
pub(crate) async fn handle_reencryption_event(
    event: &ApiReencryptValues,
    config: &GatewayConfig,
    ct_provider: Arc<Box<dyn CiphertextProvider>>,
    middleware: Arc<Box<dyn InternalMiddleware>>,
    blockchain: Arc<dyn Blockchain>,
) -> anyhow::Result<Vec<ReencryptResponseValues>> {
    let start = tokio::time::Instant::now();
    let chain_id = middleware.get_chainid().await?;
    let external_ct_handle = event.ciphertext_handle.0.clone();

    let (ciphertext, fhe_type) = ct_provider
        .get_ciphertext(middleware, external_ct_handle.clone(), None)
        .await?;

    // check the format EIP-55
    _ = alloy_primitives::Address::parse_checksummed(&event.client_address, None)?;
    _ = alloy_primitives::Address::parse_checksummed(&event.eip712_verifying_contract, None)?;

    // sanity check that the U256 and byte chain_id are identical
    if config.parse_chain_id() != chain_id {
        let err_str = format!(
            "chain_id mismatch: {:?} vs. {:?}",
            config.parse_chain_id(),
            chain_id
        );
        tracing::error!(err_str);
        return Err(anyhow::anyhow!(err_str));
    }

    let acl_address =
        alloy_primitives::Address::from_slice(&config.ethereum.acl_address.0).to_string();

    let response = blockchain
        .reencrypt(
            event.signature.0.clone(),
            event.client_address.clone(),
            event.enc_key.0.clone(),
            external_ct_handle,
            fhe_type,
            ciphertext,
            event.eip712_verifying_contract.clone(),
            chain_id,
            config.parse_eip712_salt(),
            acl_address,
        )
        .await;
    let duration = start.elapsed();
    tracing::info!(
        "⏱️ KMS Response Time elapsed for reencryption: {:?}",
        duration
    );
    response
}

#[tracing::instrument(skip(config, blockchain, middleware, ciphertext_provider))]
pub(crate) async fn handle_verify_proven_ct_event(
    event: &ApiVerifyProvenCtValues,
    config: &GatewayConfig,
    middleware: Arc<Box<dyn InternalMiddleware>>,
    blockchain: Arc<dyn Blockchain>,
    ciphertext_provider: Arc<Box<dyn CiphertextProvider>>,
) -> anyhow::Result<VerifyProvenCtResponseToClient> {
    let start = tokio::time::Instant::now();
    let chain_id = middleware.get_chainid().await?;

    // check the format EIP-55
    _ = alloy_primitives::Address::parse_checksummed(&event.contract_address, None)?;
    _ = alloy_primitives::Address::parse_checksummed(&event.caller_address, None)?;

    // sanity check that the U256 and byte chain_id are identical
    if config.parse_chain_id() != chain_id {
        let err_str = format!(
            "chain_id mismatch: {:?} vs. {:?}",
            config.parse_chain_id(),
            chain_id
        );
        tracing::error!(err_str);
        return Err(anyhow::anyhow!(err_str));
    }

    let mut chain_id_bytes = vec![0u8; 32];
    chain_id.to_big_endian(&mut chain_id_bytes);

    let kms_verifier_address =
        alloy_primitives::Address::from_slice(&config.ethereum.kmsverifier_vc_address.0)
            .to_string();
    let acl_address =
        alloy_primitives::Address::from_slice(&config.ethereum.acl_address.0).to_string();
    let domain = Eip712DomainMsg {
        name: config.ethereum.kmsverifier_name.clone(),
        version: config.ethereum.kmsverifier_version.clone(),
        chain_id: chain_id_bytes,
        verifying_contract: kms_verifier_address,
        salt: config.parse_eip712_salt(),
    };

    let verify_proven_ct_response_builder = blockchain
        .verify_proven_ct(
            event.caller_address.clone(),
            event.contract_address.clone(),
            event.key_id.clone(),
            event.crs_id.clone(),
            event.ct_proof.0.clone(),
            domain,
            acl_address,
        )
        .await?;
    let duration = start.elapsed();
    tracing::info!(
        "⏱️ KMS Response Time elapsed for verify proven ct: {:?}",
        duration
    );

    ciphertext_provider
        .put_ciphertext(event, verify_proven_ct_response_builder)
        .await
}

#[tracing::instrument(skip(blockchain))]
pub(crate) async fn handle_keyurl_event(
    blockchain: Arc<dyn Blockchain>,
) -> anyhow::Result<KeyUrlResponseValues> {
    let start = tokio::time::Instant::now();
    let response = blockchain.keyurl().await;
    let duration = start.elapsed();
    tracing::info!("⏱️ KMS Response Time elapsed for KeyUrl: {:?}", duration);
    response
}

pub(crate) async fn mock_provider(
    config: &GatewayConfig,
) -> anyhow::Result<(
    SignerMiddleware<Provider<MockProvider>, Wallet<SigningKey>>,
    MockProvider,
)> {
    let wallet = WalletManager::default().wallet;
    let (provider, mock) = Provider::mocked();
    let provider = SignerMiddleware::new(
        provider.clone(),
        wallet.with_chain_id(config.ethereum.chain_id),
    );
    Ok((provider, mock))
}

pub(crate) async fn http_provider(
    config: &GatewayConfig,
) -> anyhow::Result<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>> {
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Http>::connect(&config.ethereum.http_url).await;
    let provider = SignerMiddleware::new(
        provider.clone(),
        wallet.with_chain_id(config.ethereum.chain_id),
    );
    Ok(provider)
}

async fn _ws_provider(
    config: &GatewayConfig,
) -> anyhow::Result<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>> {
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Ws>::connect(&config.ethereum.wss_url)
        .await
        .context("Failed to connect to WSS")?;
    let provider = SignerMiddleware::new(
        provider.clone(),
        wallet.with_chain_id(config.ethereum.chain_id),
    );
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use ethers::abi::encode;
    use ethers::abi::Token;
    use ethers::prelude::*;
    use std::str::FromStr;

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

    #[test]
    fn encode_h160() {
        let add1 =
            ethers::types::H160::from_str("000000000000000000000000000000000000005d").unwrap();
        let add2 =
            ethers::types::H160::from_str("ffe0000000000000022200000000000000000151").unwrap();

        let str1 = hex::encode(add1);
        let str2 = hex::encode(add2);

        assert_eq!(str1, "000000000000000000000000000000000000005d");
        assert_eq!(str2, "ffe0000000000000022200000000000000000151");
    }
}
