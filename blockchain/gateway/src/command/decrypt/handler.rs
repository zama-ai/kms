use crate::command::ciphertext_provider;
use crate::command::decrypt::handler::k256::ecdsa::SigningKey;
use crate::command::decrypt::operations::get_decryption_strategy;
use crate::common::config::oracle_predeploy_address;
use crate::common::provider::EventDecryptionFilter;
use crate::common::provider::OraclePredeploy;
use crate::util::wallet::WalletManager;
use ethers::abi::encode;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::FheType;
use std::sync::Arc;

#[retrying::retry(stop=(attempts(5)|duration(20)),wait=fixed(5))]
pub(crate) async fn handle_event_decryption(
    client: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
    ev: &Arc<EventDecryptionFilter>,
    block_number: u64,
) -> anyhow::Result<()> {
    println!("🍻🍻🍻 handle_event_decryption enter");
    let mut tokens: Vec<Token> = Vec::with_capacity(ev.cts.len());
    let client_clone = Arc::clone(client);
    let ev_clone: Arc<EventDecryptionFilter> = Arc::clone(ev);
    let _handle = tokio::spawn(async move {
        for (i, ct) in ev_clone.cts.iter().enumerate() {
            let token = decrypt(
                &client_clone,
                ev_clone.request_id,
                ct.ct_handle,
                ct.ct_type,
                i as i64,
                block_number,
            )
            .await
            .unwrap();
            tokens.push(token);
        }

        let wallet = WalletManager::default().wallet;
        let provider = Provider::<Ws>::connect(crate::common::config::ethereum_wss_url())
            .await
            .unwrap();
        let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
        let provider = Arc::new(provider);
        let contract = OraclePredeploy::new(oracle_predeploy_address(), Arc::clone(&provider));

        tracing::info!("Fulfilling request: {:?}", ev_clone.request_id);
        match contract
            .fulfill_request(ev_clone.request_id, encode(&tokens).into())
            .send()
            .await
        {
            Ok(pending_tx) => match pending_tx.await {
                Ok(receipt) => {
                    tracing::info!("Transaction receipt: {:?}", receipt);
                }
                Err(e) => {
                    tracing::error!("Failed to await transaction receipt: {:?}", e);
                }
            },
            Err(e) => {
                tracing::error!("Failed to send fulfill_request transaction: {:?}", e);
            }
        }
    });
    println!("🍻🍻🍻 handle_event_decryption exit");
    Ok(())
}

async fn decrypt(
    client: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
    request_id: U256,
    ct_handle: U256,
    ct_type: u8,
    _ct_index: i64,
    block_number: u64,
) -> Result<Token, Box<dyn std::error::Error>> {
    let mut ct_handle_bytes = [0u8; 32];
    ct_handle.to_big_endian(&mut ct_handle_bytes);
    let ct_bytes = ciphertext_provider::get()
        .get_ciphertext(client, ct_handle_bytes.to_vec(), block_number)
        .await?;
    tracing::debug!("Got ct bytes of length: {}", ct_bytes.len());
    tracing::trace!("ct_bytes: 0x{}", hex::encode(&ct_bytes));
    tracing::info!("🚀 request_id: {}, ct_type: {}", request_id, ct_type,);
    Ok(get_decryption_strategy()
        .await
        .decrypt(ct_bytes, FheType::from(ct_type))
        .await?)
}
