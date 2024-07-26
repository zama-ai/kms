//! # KMS Blockchain Client Implementation
//!
//! This module provides a comprehensive set of tools and structures for interacting with blockchain-based
//! contracts, specifically targeting the CosmWasm smart contracts within the Cosmos SDK. It includes functionality
//! for cryptographic operations, RPC communications, and transaction handling.
use crate::cosmos::account::AccountId;
use crate::crypto::signing_key::SigningKey;
use crate::errors::Error;
use crate::prost::ext::MessageExt as _;
use base64::{engine::general_purpose, Engine as _};
use cosmos_proto::messages::cosmos::auth::v1beta1::{
    query_client::QueryClient, BaseAccount, QueryAccountRequest, QueryAccountResponse,
};
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_proto::messages::cosmos::base::v1beta1::Coin;
use cosmos_proto::messages::cosmos::tx::v1beta1::mode_info::{Single, Sum};
use cosmos_proto::messages::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_proto::messages::cosmos::tx::v1beta1::{
    AuthInfo, BroadcastTxRequest, Fee, ModeInfo, SignDoc, SignerInfo, TxBody, TxRaw,
};
use cosmos_proto::messages::cosmwasm::wasm::v1::MsgExecuteContract;
use events::kms::KmsMessage;
use prost_types::Any;
use std::str;
use std::str::FromStr;
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use typed_builder::TypedBuilder;

/// Default chain ID used for initializing the blockchain client in a test environment.
const DEFAULT_CHAIN_ID: &str = "testing";

/// Bech32 prefix to be used for generating account addresses from public keys.
const ACCOUNT_PREFIX: &str = "wasm";

/// Denomination for transaction fees and balances.
const DENOM: &str = "ucosm";

#[derive(Clone, Debug, TypedBuilder)]
pub struct ProtoCoin {
    pub denom: String,
    pub amount: u64,
}

#[derive(TypedBuilder, Clone, Debug)]
pub struct ExecuteContractRequest {
    message: KmsMessage,
    gas_limit: u64,
    #[builder(setter(strip_option), default)]
    funds: Option<Vec<ProtoCoin>>,
}

#[derive(TypedBuilder)]
pub struct ClientBuilder<'a> {
    grpc_addresses: Vec<&'a str>,
    contract_address: &'a str,
    #[builder(default = None)]
    mnemonic_wallet: Option<&'a str>,
    #[builder(default = None)]
    bip32_private_key: Option<&'a str>,
    #[builder(default = None, setter(strip_option))]
    chain_id: Option<&'a str>,
    #[builder(default = None, setter(strip_option))]
    coin_denom: Option<&'a str>,
    #[builder(default = 0.01)]
    gas_price: f64,
}

impl TryFrom<ClientBuilder<'_>> for Client {
    type Error = Error;
    fn try_from(value: ClientBuilder) -> Result<Self, Self::Error> {
        let sender_key = value
            .mnemonic_wallet
            .map(SigningKey::key_from_mnemonic)
            .or_else(|| value.bip32_private_key.map(SigningKey::from_bip32))
            .transpose()?
            .ok_or_else(|| {
                Error::PrivateKeyMissing("No private key provided for wallet".to_string())
            })?;

        tracing::info!(
            "Wallet private key initialized successfully {:?}",
            sender_key.public_key().account_id(ACCOUNT_PREFIX)?
        );

        if value.grpc_addresses.is_empty() {
            return Err(Error::GrpcClientCreateError(
                "No gRPC addresses provided".to_string(),
            ));
        }
        let endpoints = value
            .grpc_addresses
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| {
                Error::GrpcClientCreateError(format!("Error connecting to blockchain {:?}", e))
            })?;
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let client = Channel::balance_list(endpoints);

        tracing::info!("gRPC client initialized successfully");

        let chain_id = value.chain_id.unwrap_or(DEFAULT_CHAIN_ID).to_string();

        let coin_denom = value.coin_denom.unwrap_or(DENOM).to_string();

        let contract_address = AccountId::from_str(value.contract_address)?;

        let gas_price = value.gas_price;

        Ok(Client {
            client,
            sender_key,
            chain_id,
            coin_denom,
            contract_address,
            gas_price,
        })
    }
}

/// A client for interacting with CosmWasm smart contracts via Cosmos SDK's Tendermint protocol.
pub struct Client {
    client: Channel,
    sender_key: SigningKey,
    contract_address: AccountId,
    coin_denom: String,
    chain_id: String,
    gas_price: f64,
}

impl Client {
    pub fn builder<'a>() -> ClientBuilderBuilder<'a> {
        ClientBuilder::builder()
    }

    /// Queries the blockchain for the account details of the sender.
    async fn query_account(&self) -> Result<BaseAccount, Error> {
        let mut query = QueryClient::new(self.client.clone());
        let query_req = QueryAccountRequest {
            address: self
                .sender_key
                .public_key()
                .account_id(ACCOUNT_PREFIX)?
                .to_string(),
        };
        let resp: QueryAccountResponse = query.account(query_req).await?.into_inner();
        let resp_acc: BaseAccount = resp
            .account
            .ok_or_else(|| Error::InvalidAccount("Account not found in chain".to_string()))?
            .to_msg()?;
        Ok(resp_acc)
    }

    /// Executes a transaction on the blockchain by broadcasting a signed transaction message.
    ///
    /// # Arguments
    /// * `msg_payload` - The payload of the message to be executed.
    /// * `metadata` - Metadata required for executing the transaction.
    ///
    /// # Returns
    /// A `Result` containing either the transaction response from the blockchain or an error.
    #[tracing::instrument(skip(self, request))]
    pub async fn execute_contract(
        &mut self,
        request: ExecuteContractRequest,
    ) -> Result<TxResponse, Error> {
        let account = self.query_account().await?;

        let msg_payload = request
            .message
            .to_json()
            .map(|msg| msg.to_string().as_bytes().to_vec())
            .map_err(|e| Error::ExecuteContractRequestError(e.to_string()))?;

        let gas_limit = request.gas_limit;

        let gas_price = self.gas_price;

        let funds = request.funds;

        let tx_bytes = self
            .prepare_msg(&account, &msg_payload, gas_limit, gas_price, funds)
            .await?;

        let mut tx_client = ServiceClient::new(self.client.clone());

        let broadcast = BroadcastTxRequest { tx_bytes, mode: 2 };

        tracing::info!("Broadcasting transaction to blockchain for excuting contract",);

        let result = tx_client
            .broadcast_tx(broadcast)
            .await
            .map(|r| r.into_inner())?;

        if let Some(ref tx) = result.tx_response {
            if tx.code != 0 {
                return Err(Error::ExecutionContractError(format!(
                    "Execution contract failed with error code {:?} and message {:?}",
                    tx.code, tx.raw_log
                )));
            }
            tracing::info!("Transaction broadcasted successfully");
            Ok(tx.clone())
        } else {
            return Err(Error::ExecutionContractError(
                "No transaction response received".to_string(),
            ));
        }
    }

    /// Prepares a transaction message for execution on the blockchain.
    async fn prepare_msg(
        &self,
        account: &BaseAccount,
        msg_payload: &[u8],
        gas_limit: u64,
        gas_price: f64,
        funds: Option<Vec<ProtoCoin>>,
    ) -> Result<Vec<u8>, Error> {
        let sender_public_key = self.sender_key.public_key();
        let sender_account_id = sender_public_key.account_id(ACCOUNT_PREFIX)?;

        let funds = funds
            .unwrap_or_default()
            .iter()
            .map(|coin| Coin {
                denom: coin.denom.clone(),
                amount: coin.amount.to_string(),
            })
            .collect::<Vec<Coin>>();

        let msg = MsgExecuteContract {
            sender: sender_account_id.to_string(),
            contract: self.contract_address.to_string(),
            msg: msg_payload.to_vec(),
            funds,
        };

        let message = Any::from_msg(&msg)?;

        let tx_body = TxBody {
            messages: vec![message],
            memo: String::new(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
        };

        let body_bytes = tx_body.to_bytes()?;

        let fee_amount = (gas_price * gas_limit as f64).ceil();

        let fee = Fee {
            amount: vec![Coin {
                denom: self.coin_denom.clone(),
                amount: fee_amount.to_string(),
            }],
            gas_limit,
            payer: "".to_string(),
            granter: "".to_string(),
        };

        let signer_info = SignerInfo {
            public_key: Some(sender_public_key.into()),
            mode_info: Some(ModeInfo {
                sum: Some(Sum::Single(Single { mode: 1 })),
            }),
            sequence: account.sequence,
        };

        #[allow(deprecated)]
        let auth_info = AuthInfo {
            signer_infos: vec![signer_info],
            fee: Some(fee),
            tip: None,
        };

        let auth_info_bytes = auth_info.to_bytes()?;

        let sign_doc = SignDoc {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth_info_bytes.clone(),
            chain_id: self.chain_id.clone(),
            account_number: account.account_number,
        };

        let sign_doc_bytes = sign_doc.to_bytes()?;
        let signature = self.sender_key.sign(&sign_doc_bytes)?;

        let tx_raw = TxRaw {
            body_bytes,
            auth_info_bytes,
            signatures: vec![signature.to_vec()],
        };

        let tx_bytes_raw = tx_raw.to_bytes()?;
        tracing::info!("Body Raw bytes length: {:?}", tx_bytes_raw.len());

        tracing::debug!(
            "TxRaw to be broadcasted: {:?}",
            general_purpose::STANDARD.encode(&tx_bytes_raw)
        );

        Ok(tx_bytes_raw)
    }
}
