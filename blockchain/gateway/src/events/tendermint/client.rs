use super::bip::derive_key;
use super::error::Error;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tendermint::chain;
use cosmrs::AccountId;
use cosmrs::{
    crypto::secp256k1,
    rpc,
    tx::{self, AccountNumber, Fee, Msg, SignDoc, SignerInfo},
    Coin,
};
use events::kms::DecryptValues;
use events::kms::FheType;
use events::kms::KmsMessage;
use events::kms::OperationValue;
use rpc::endpoint::broadcast::tx_commit::Response;
use serde_json::json;
use std::str;
use std::str::FromStr;

/// Default chain ID used for initializing the blockchain client in a test environment.
const DEFAULT_CHAIN_ID: &str = "testing";

/// Bech32 prefix to be used for generating account addresses from public keys.
const ACCOUNT_PREFIX: &str = "wasm";

/// Denomination for transaction fees and balances.
const DENOM: &str = "ucosm";

/// BIP-0044 path for deriving the cryptographic keys from a mnemonic.
const COSMOS_KEY_PATH: &str = "m/44'/118'/0'/0/0";

/// Struct holding metadata required for transaction execution.
pub struct Metadata {
    /// Sequence number of the transaction within the current account.
    pub sequence_number: u64,
    /// Gas limit set for the execution of the transaction.
    pub gas_limit: u64,
}

/// A client for interacting with CosmWasm smart contracts via Cosmos SDK's Tendermint protocol.
pub struct Client {
    rpc_client: rpc::HttpClient,
    sender_key: secp256k1::SigningKey,
    contract_address: AccountId,
    chain_id: chain::Id,
    account_number: AccountNumber,
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Arguments
    /// * `rpc_address` - Endpoint for the RPC client.
    /// * `contract_address` - Bech32 encoded address of the contract.
    /// * `sender_key` - Signing key of the sender.
    /// * `chain_id` - Chain ID for the blockchain network.
    /// * `account_number` - Account number for the sender's account.
    ///
    /// # Returns
    /// An instance of `Client`.
    pub fn new(
        rpc_address: &str,
        contract_address: &str,
        sender_key: secp256k1::SigningKey,
        chain_id: Option<String>,
        account_number: AccountNumber,
    ) -> Self {
        let rpc_client = rpc::HttpClient::new(rpc_address).unwrap();
        let contract_address = AccountId::from_str(contract_address).unwrap();
        let chain_id = chain_id
            .unwrap_or_else(|| DEFAULT_CHAIN_ID.to_string())
            .parse()
            .unwrap();
        Client {
            rpc_client,
            sender_key,
            contract_address,
            chain_id,
            account_number,
        }
    }

    /// Derives a signing key from a mnemonic using a specified key derivation path.
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic seed phrase.
    ///
    /// # Returns
    /// A `secp256k1::SigningKey` derived from the mnemonic.
    pub fn key_from_mnemonic(mnemonic: &str) -> secp256k1::SigningKey {
        let pk = derive_key(COSMOS_KEY_PATH, mnemonic, "").unwrap();
        secp256k1::SigningKey::from_slice(&pk).unwrap()
    }

    /// Sends a decryption request to the smart contract and awaits its response.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data.
    /// * `fhe_type` - The type of fully homomorphic encryption used.
    /// * `metadata` - Transaction metadata including gas and sequence number.
    ///
    /// # Returns
    /// A `Result` containing either the contract's response or an error.
    pub async fn decrypt_request(
        &self,
        ciphertext: Vec<u8>,
        fhe_type: &str,
        metadata: &Metadata,
    ) -> Result<Response, Error> {
        let _msg_payload = json!({
          "decrypt": {
            "ciphertext": ciphertext,
            "fhe_type": fhe_type.to_string()
          }
        })
        .to_string();

        let operation_response = OperationValue::Decrypt(
            DecryptValues::builder()
                .ciphertext(ciphertext.clone())
                .fhe_type(FheType::Euint8)
                .version(1)
                .key_id(vec![1, 2, 3])
                .randomness(vec![1, 2, 3])
                .build(),
        );

        let msg = KmsMessage::builder()
            .proof(vec![1, 2, 3])
            .value(operation_response)
            .build();

        let msg_payload = msg
            .to_json()
            .map(|msg| msg.to_string().as_bytes().to_vec())
            .unwrap();

        //let response = client.execute_contract(request).await.unwrap();

        self.execute(&msg_payload, metadata).await
    }

    /// Sends a response to a decryption request back to the smart contract.
    ///
    /// # Arguments
    /// * `txn_id` - Transaction ID of the decryption request.
    /// * `plaintext` - The decrypted data.
    /// * `metadata` - Transaction metadata including gas and sequence number.
    ///
    /// # Returns
    /// A `Result` containing either the contract's response or an error.
    pub async fn decrypt_response(
        &self,
        txn_id: Vec<u8>,
        plaintext: Vec<u8>,
        metadata: &Metadata,
    ) -> Result<Response, Error> {
        let msg_payload = json!({
          "decrypt_response": {
            "txn_id": txn_id,
            "plaintext": plaintext,
          }
        })
        .to_string();
        self.execute(msg_payload.as_bytes(), metadata).await
    }

    /// Executes a transaction on the blockchain by broadcasting a signed transaction message.
    ///
    /// # Arguments
    /// * `msg_payload` - The payload of the message to be executed.
    /// * `metadata` - Metadata required for executing the transaction.
    ///
    /// # Returns
    /// A `Result` containing either the transaction response from the blockchain or an error.
    pub async fn execute(
        &self,
        msg_payload: &[u8],
        metadata: &Metadata,
    ) -> Result<Response, Error> {
        let sender_public_key = self.sender_key.public_key();
        let sender_account_id = sender_public_key
            .account_id(ACCOUNT_PREFIX)
            .map_err(|e| Error::AccountIdParseError(e.to_string()))?;

        let execute = MsgExecuteContract {
            sender: sender_account_id.clone(),
            contract: self.contract_address.clone(),
            msg: msg_payload.to_vec(),
            funds: vec![],
        }
        .to_any()
        .map_err(|e| Error::MsgExecuteError(e.to_string()))?;

        let tx_body = tx::BodyBuilder::new().msg(execute).finish();

        let denom = DENOM
            .parse()
            .map_err(|_| Error::Unknown("Error parsing DENOM".to_string()))?;
        let fee = Fee::from_amount_and_gas(
            Coin {
                amount: metadata.gas_limit.into(),
                denom,
            },
            metadata.gas_limit,
        );

        let auth_info =
            SignerInfo::single_direct(Some(sender_public_key), metadata.sequence_number)
                .auth_info(fee);
        let sign_doc = SignDoc::new(&tx_body, &auth_info, &self.chain_id, self.account_number)
            .map_err(|e| Error::SignDocError(e.to_string()))?;

        let tx_raw = sign_doc
            .sign(&self.sender_key)
            .map_err(|e| Error::SignDocError(e.to_string()))?;

        let tx_commit_response = tx_raw
            .broadcast_commit(&self.rpc_client)
            .await
            .map_err(|e| Error::BlockchainTransactionError(e.to_string()))?;

        if tx_commit_response.check_tx.code.is_err() {
            return Err(Error::CheckTxError(format!(
                "{:?}",
                tx_commit_response.check_tx.log
            )));
        }
        if tx_commit_response.tx_result.code.is_err() {
            return Err(Error::TxResultError(format!(
                "{:?}",
                tx_commit_response.tx_result.log
            )));
        }

        Ok(tx_commit_response)
    }
}
