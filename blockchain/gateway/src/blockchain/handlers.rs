use crate::blockchain::blockchain_impl;
use crate::blockchain::ciphertext_provider::CiphertextProvider;
use crate::blockchain::handlers::k256::ecdsa::SigningKey;
use crate::common::provider::GatewayContract;
use crate::config::BaseGasPrice;
use crate::config::EthereumConfig;
use crate::config::GatewayConfig;
use crate::events::manager::ApiReencryptValues;
use crate::events::manager::ApiZkpValues;
use crate::events::manager::DecryptionEvent;
use crate::util::wallet::WalletManager;
use anyhow::Context;
use ethers::abi::encode;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::FheKeyUrlInfo;
use events::kms::KeyUrlInfo;
use events::kms::KeyUrlResponseValues;
use events::kms::ReencryptResponseValues;
use events::kms::VerfKeyUrlInfo;
use events::kms::ZkpResponseValues;
use events::HexVector;
use kms_lib::kms::Eip712DomainMsg;
use kms_lib::kms::ParamChoice;
use kms_lib::rpc::rpc_types::PubDataType;
use std::collections::HashMap;
use std::ops::Mul;
use std::path::MAIN_SEPARATOR_STR;
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
    external_ct_handles: Vec<U256>,
    block_number: u64,
) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
    let mut typed_cts = Vec::new();

    // get actual ct value from the external source (e.g. fhvem) for every external handle
    for external_ct_handle in external_ct_handles {
        let mut external_ct_handle_bytes = [0u8; 32];
        external_ct_handle.to_big_endian(&mut external_ct_handle_bytes);
        let external_handle_vec = external_ct_handle_bytes.to_vec();

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
    let chain_id_be = config.ethereum.chain_id.to_be_bytes();
    let mut chain_id_bytes = vec![0u8; 32];
    chain_id_bytes[24..].copy_from_slice(&chain_id_be);

    let vc_hex = hex::encode(config.ethereum.kmsverifier_vc_address);
    let acl_address = hex::encode(config.ethereum.acl_address);
    let domain = Eip712DomainMsg {
        name: config.ethereum.kmsverifier_name.clone(),
        version: config.ethereum.kmsverifier_version.clone(),
        chain_id: chain_id_bytes,
        verifying_contract: vc_hex,
        salt: vec![],
    };

    blockchain_impl(config)
        .await
        .decrypt(typed_cts, domain, acl_address)
        .await
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

    let acl_address = hex::encode(config.ethereum.acl_address);

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

pub(crate) async fn handle_zkp_event(
    event: &ApiZkpValues,
    config: &GatewayConfig,
) -> anyhow::Result<Vec<ZkpResponseValues>> {
    let client = Arc::new(http_provider(config).await?);
    let start = std::time::Instant::now();
    let chain_id = client.provider().get_chainid().await?;

    // check the format EIP-55
    _ = alloy_primitives::Address::parse_checksummed(&event.client_address, None)?;
    _ = alloy_primitives::Address::parse_checksummed(&event.caller_address, None)?;

    // Get chain-id and verifying contract for EIP-712 signature
    let chain_id_be = config.ethereum.chain_id.to_be_bytes();
    let mut chain_id_bytes = vec![0u8; 32];
    chain_id_bytes[24..].copy_from_slice(&chain_id_be);

    // sanity check that the U256 and byte chain_id are identical
    if U256::from_big_endian(&chain_id_bytes) != chain_id {
        let err_str = format!("chain_id mismatch: {:?} vs. {:?}", chain_id, chain_id_bytes);
        tracing::error!(err_str);
        return Err(anyhow::anyhow!(err_str));
    }

    let vc_hex = hex::encode(config.ethereum.kmsverifier_vc_address);
    let acl_address = hex::encode(config.ethereum.acl_address);
    let domain = Eip712DomainMsg {
        name: config.ethereum.kmsverifier_name.clone(),
        version: config.ethereum.kmsverifier_version.clone(),
        chain_id: chain_id_bytes,
        verifying_contract: vc_hex,
        salt: vec![],
    };

    let response = blockchain_impl(config)
        .await
        .zkp(
            event.client_address.clone(),
            event.caller_address.clone(),
            event.ct_proof.0.clone(),
            event.max_num_bits,
            domain,
            acl_address,
        )
        .await;
    let duration = start.elapsed();
    tracing::info!("⏱️ KMS Response Time elapsed for ZKP: {:?}", duration);
    response
}

pub(crate) async fn handle_keyurl_event(
    config: &GatewayConfig,
) -> anyhow::Result<KeyUrlResponseValues> {
    let start = std::time::Instant::now();
    // TODO placeholder for calling the blockchain to get key ids
    // let client = Arc::new(http_provider(config).await?);
    // let chain_id = client.provider().get_chainid().await?;
    // let response = blockchain_impl(config)
    //     .await
    //     .keyurl(
    //         ...
    //         chain_id,
    //     )
    //     .await;

    let fhe_public_key = get_fhe_key_info(
        PubDataType::PublicKey,
        &config.kms.public_storage,
        &config.kms.key_id,
    )?;
    let fhe_server_key = get_fhe_key_info(
        PubDataType::ServerKey,
        &config.kms.public_storage,
        &config.kms.key_id,
    )?;
    let fhe_url_info = FheKeyUrlInfo::new(fhe_public_key, fhe_server_key);
    let verf_key_info = get_verf_key_info(&config.kms.public_storage, &config.kms.key_id)?;

    let crs = get_crs_info(&config.kms.public_storage, &config.kms.crs_ids)?;
    let response = KeyUrlResponseValues::new(vec![fhe_url_info], crs, verf_key_info);

    let duration = start.elapsed();
    tracing::info!("⏱️ KMS Response Time elapsed for KeyUrl: {:?}", duration);
    Ok(response)
}

fn get_fhe_key_info(
    data_type: PubDataType,
    storage_urls: &HashMap<u32, String>,
    data_id: &str,
) -> anyhow::Result<KeyUrlInfo> {
    let mut urls = Vec::new();
    let mut signatures = Vec::new();
    for (i, base_url) in storage_urls {
        let type_string = data_type.to_string();
        let parsed_base_url = base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
        let url = format!("{parsed_base_url}{MAIN_SEPARATOR_STR}PUB-p{i}{MAIN_SEPARATOR_STR}{type_string}{MAIN_SEPARATOR_STR}{data_id}");
        urls.push(url);
        // TODO placerholder to be replaced with ASC data
        let sig = HexVector::from_hex("00112233445566778899aabbccddeeff")?;
        signatures.push(sig);
    }
    Ok(KeyUrlInfo::new(
        HexVector::from_hex(data_id)?,
        ParamChoice::Default.into(), // TODO should come from blockchain
        urls,
        signatures,
    ))
}

fn get_verf_key_info(
    storage_urls: &HashMap<u32, String>,
    data_id: &str,
) -> anyhow::Result<Vec<VerfKeyUrlInfo>> {
    let mut res = Vec::new();
    for (i, base_url) in storage_urls {
        let parsed_base_url = base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
        let verf_key = PubDataType::VerfKey.to_string();
        let verf_addr = PubDataType::VerfAddress.to_string();
        let key_url = format!("{parsed_base_url}{MAIN_SEPARATOR_STR}PUB-p{i}{MAIN_SEPARATOR_STR}{verf_key}{MAIN_SEPARATOR_STR}{data_id}");
        let addr_url = format!("{parsed_base_url}{MAIN_SEPARATOR_STR}PUB-p{i}{MAIN_SEPARATOR_STR}{verf_addr}{MAIN_SEPARATOR_STR}{data_id}");
        res.push(VerfKeyUrlInfo::new(
            HexVector::from_hex(data_id)?,
            *i,
            key_url,
            addr_url,
        ))
    }
    Ok(res)
}

fn get_crs_info(
    storage_urls: &HashMap<u32, String>,
    crs_ids: &HashMap<u32, String>,
) -> anyhow::Result<HashMap<u32, KeyUrlInfo>> {
    let mut res = HashMap::new();
    for (max_bits, crs_id) in crs_ids {
        let mut urls = Vec::new();
        let mut signatures = Vec::new();
        for (i, base_url) in storage_urls {
            let crs_type = PubDataType::CRS.to_string();
            let parsed_base_url = base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
            let crs_url = format!("{parsed_base_url}{MAIN_SEPARATOR_STR}PUB-p{i}{MAIN_SEPARATOR_STR}{crs_type}{MAIN_SEPARATOR_STR}{crs_id}");
            urls.push(crs_url);
            // TODO placerholder to be replaced with ASC data
            signatures.push(HexVector::from_hex("00112233445566778899aabbccddeeff")?);
        }
        res.insert(
            *max_bits,
            KeyUrlInfo::new(
                HexVector::from_hex(crs_id)?,
                ParamChoice::Default.into(), // TODO placeholder
                urls,
                signatures,
            ),
        );
    }
    Ok(res)
}

async fn http_provider(
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
    use crate::blockchain::handlers::get_crs_info;
    use crate::blockchain::handlers::get_verf_key_info;

    use super::get_fhe_key_info;
    use ethers::abi::encode;
    use ethers::abi::Token;
    use ethers::prelude::*;
    use events::HexVector;
    use kms_lib::kms::ParamChoice;
    use kms_lib::rpc::rpc_types::PubDataType;
    use std::collections::HashMap;
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

    #[test]
    fn sunshine_fhe_key_info() {
        let key_id = "00112233445566778899aabbccddeeff0011223344";
        let storages_urls: HashMap<u32, String> = HashMap::from([
            (1, "http://127.0.0.1:8081".to_string()),
            (2, "http://127.0.0.1:8082".to_string()),
            (3, "http://127.0.0.1:8083".to_string()),
            (4, "http://127.0.0.1:8084".to_string()),
        ]);
        let fhe_server_key =
            get_fhe_key_info(PubDataType::ServerKey, &storages_urls, key_id).unwrap();
        assert_eq!(fhe_server_key.data_id().to_hex(), key_id);
        assert_eq!(fhe_server_key.param_choice(), ParamChoice::Default as i32);
        assert_eq!(fhe_server_key.urls().len(), 4);
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8081/PUB-p1/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8082/PUB-p2/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8083/PUB-p3/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8084/PUB-p4/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
    }

    #[test]
    fn sunshine_verf_key_info() {
        let key_id = "00112233445566778899aabbccddeeff0011223344";
        let storages_urls: HashMap<u32, String> = HashMap::from([
            (1, "http://127.0.0.1:8081".to_string()),
            (2, "http://127.0.0.1:8082".to_string()),
            (3, "http://127.0.0.1:8083".to_string()),
            (4, "http://127.0.0.1:8084".to_string()),
        ]);
        let verf_key_info = get_verf_key_info(&storages_urls, key_id).unwrap();
        assert_eq!(verf_key_info.len(), storages_urls.len());
        for cur_info in verf_key_info {
            assert_eq!(cur_info.key_id().to_hex(), key_id);
            assert!(cur_info.server_id() >= 1);
            assert!(cur_info.server_id() <= storages_urls.len() as u32);
            assert_eq!(cur_info.verf_public_key_address(),
                &format!("http://127.0.0.1:808{}/PUB-p{}/VerfAddress/00112233445566778899aabbccddeeff0011223344", cur_info.server_id(), cur_info.server_id())
                    .to_string()
            );
            assert_eq!(cur_info.verf_public_key_url(),
                &format!("http://127.0.0.1:808{}/PUB-p{}/VerfKey/00112233445566778899aabbccddeeff0011223344", cur_info.server_id(), cur_info.server_id())
                    .to_string()
            );
        }
    }

    #[test]
    fn sunshine_crs_info() {
        let storages_urls: HashMap<u32, String> = HashMap::from([
            (1, "http://127.0.0.1:8081".to_string()),
            (2, "http://127.0.0.1:8082".to_string()),
            (3, "http://127.0.0.1:8083".to_string()),
            (4, "http://127.0.0.1:8084".to_string()),
        ]);
        let crs_ids: HashMap<u32, String> = HashMap::from([
            (
                128,
                "00112233445566778899aabbccddeeff0011223311".to_string(),
            ),
            (
                256,
                "00112233445566778899aabbccddeeff0011223322".to_string(),
            ),
        ]);
        let crs_info = get_crs_info(&storages_urls, &crs_ids).unwrap();
        assert_eq!(crs_info.len(), crs_ids.len());
        for (cur_id, cur_info) in &crs_info {
            assert_eq!(crs_ids[cur_id], cur_info.data_id().to_hex());
            assert_eq!(storages_urls.len(), cur_info.signatures().len());
            assert_eq!(ParamChoice::Default as i32, cur_info.param_choice());
            // TODO placeholder for now
            assert!(cur_info
                .signatures()
                .contains(&HexVector::from_hex("00112233445566778899aabbccddeeff").unwrap()));
        }
        for cur_server_id in storages_urls.keys() {
            assert!(crs_info[&128].urls().contains(
                &format!(
                    "http://127.0.0.1:808{}/PUB-p{}/CRS/00112233445566778899aabbccddeeff0011223311",
                    cur_server_id, cur_server_id
                )
                .to_string()
            ));
            assert!(crs_info[&256].urls().contains(
                &format!(
                    "http://127.0.0.1:808{}/PUB-p{}/CRS/00112233445566778899aabbccddeeff0011223322",
                    cur_server_id, cur_server_id
                )
                .to_string()
            ));
        }
    }
}
