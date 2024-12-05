use async_trait::async_trait;
use events::kms::{
    CrsGenResponseValues, DecryptResponseValues, KeyGenPreprocResponseValues, KeyGenResponseValues,
    KmsConfig, KmsEvent, KmsMessage, OperationValue, ReencryptResponseValues, TransactionId,
    VerifyProvenCtResponseValues,
};
use strum_macros::{Display, EnumString};

#[derive(Default, PartialEq, Eq)]
pub struct BlockchainOperationVal {
    pub tx_id: TransactionId,
}

#[derive(Default, PartialEq, Eq)]
pub struct DecryptResponseVal {
    pub decrypt_response: DecryptResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq)]
pub struct ReencryptResponseVal {
    pub reencrypt_response: ReencryptResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq)]
pub struct VerifyProvenCtResponseVal {
    pub verify_proven_ct_response: VerifyProvenCtResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq)]
pub struct KeyGenPreprocResponseVal {
    pub keygen_preproc_response: KeyGenPreprocResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq)]
pub struct KeyGenResponseVal {
    pub keygen_response: KeyGenResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq)]
pub struct CrsGenResponseVal {
    pub crs_gen_response: CrsGenResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(EnumString, Display, PartialEq, Eq)]
pub enum KmsOperationResponse {
    DecryptResponse(DecryptResponseVal),
    ReencryptResponse(ReencryptResponseVal),
    VerifyProvenCtResponse(VerifyProvenCtResponseVal),
    KeyGenPreprocResponse(KeyGenPreprocResponseVal),
    KeyGenResponse(KeyGenResponseVal),
    CrsGenResponse(CrsGenResponseVal),
}

impl KmsOperationResponse {
    pub fn txn_id(&self) -> &TransactionId {
        match self {
            KmsOperationResponse::DecryptResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::ReencryptResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::VerifyProvenCtResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::KeyGenPreprocResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::KeyGenResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::CrsGenResponse(val) => &val.operation_val.tx_id,
        }
    }

    pub fn txn_id_hex(&self) -> String {
        self.txn_id().to_hex()
    }
}

impl From<KmsOperationResponse> for KmsMessage {
    fn from(value: KmsOperationResponse) -> Self {
        match value {
            KmsOperationResponse::DecryptResponse(val) => KmsMessage::builder()
                .value(val.decrypt_response)
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::ReencryptResponse(val) => KmsMessage::builder()
                .value(val.reencrypt_response)
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::VerifyProvenCtResponse(val) => KmsMessage::builder()
                .value(val.verify_proven_ct_response)
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::KeyGenPreprocResponse(val) => KmsMessage::builder()
                .value(val.keygen_preproc_response)
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::KeyGenResponse(val) => KmsMessage::builder()
                .value(val.keygen_response)
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::CrsGenResponse(val) => KmsMessage::builder()
                .value(val.crs_gen_response)
                .txn_id(val.operation_val.tx_id)
                .build(),
        }
    }
}

#[async_trait]
pub trait Blockchain {
    /// Execute a smart contract with the result of a KMS operation.
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()>;

    /// Make a query (read only) request to the KMS blockchain
    /// to fetch the operation value that corresponds to a specific event.
    async fn get_operation_value(&self, event: &KmsEvent) -> anyhow::Result<OperationValue>;

    /// Fetch the configuration contract from the KMS blockchain.
    ///
    /// Note that this method may be called automatically by the
    /// [SubscriptionHandler], which is an extra round-trip,
    /// since some KMS operations needs this information.
    async fn get_kms_configuration(&self) -> anyhow::Result<KmsConfig>;

    /// Get the public key of the wallet used to interact with the KMS BC
    async fn get_public_key(&self) -> kms_blockchain_client::crypto::pubkey::PublicKey;
}
