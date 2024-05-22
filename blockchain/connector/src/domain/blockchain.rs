use async_trait::async_trait;
use events::kms::{
    CrsGenResponseValues, DecryptResponseValues, KeyGenPreprocResponseValues, KeyGenResponseValues,
    KmsEvent, KmsEventMessage, KmsOperation, OperationValue, Proof, ReencryptResponseValues,
    TransactionId,
};
use strum_macros::{Display, EnumString};

#[derive(Default, PartialEq, Eq)]
pub struct BlockchainOperationVal {
    pub tx_id: TransactionId,
    pub proof: Proof,
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
    KeyGenPreprocResponse(KeyGenPreprocResponseVal),
    KeyGenResponse(KeyGenResponseVal),
    CrsGenResponse(CrsGenResponseVal),
}

impl KmsOperationResponse {
    pub fn txn_id(&self) -> &TransactionId {
        match self {
            KmsOperationResponse::DecryptResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::ReencryptResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::KeyGenPreprocResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::KeyGenResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::CrsGenResponse(val) => &val.operation_val.tx_id,
        }
    }

    pub fn txn_id_hex(&self) -> String {
        self.txn_id().to_hex()
    }
}

impl From<KmsOperationResponse> for KmsEventMessage {
    fn from(value: KmsOperationResponse) -> Self {
        match value {
            KmsOperationResponse::DecryptResponse(val) => KmsEventMessage::builder()
                .value(val.decrypt_response)
                .event(
                    KmsEvent::builder()
                        .operation(KmsOperation::DecryptResponse)
                        .txn_id(val.operation_val.tx_id)
                        .proof(val.operation_val.proof)
                        .build(),
                )
                .build(),
            KmsOperationResponse::ReencryptResponse(val) => KmsEventMessage::builder()
                .value(val.reencrypt_response)
                .event(
                    KmsEvent::builder()
                        .operation(KmsOperation::ReencryptResponse)
                        .txn_id(val.operation_val.tx_id)
                        .proof(val.operation_val.proof)
                        .build(),
                )
                .build(),
            KmsOperationResponse::KeyGenPreprocResponse(val) => KmsEventMessage::builder()
                .value(val.keygen_preproc_response)
                .event(
                    KmsEvent::builder()
                        .operation(KmsOperation::KeyGenPreprocResponse)
                        .txn_id(val.operation_val.tx_id)
                        .proof(val.operation_val.proof)
                        .build(),
                )
                .build(),
            KmsOperationResponse::KeyGenResponse(val) => KmsEventMessage::builder()
                .value(val.keygen_response)
                .event(
                    KmsEvent::builder()
                        .operation(KmsOperation::KeyGenResponse)
                        .txn_id(val.operation_val.tx_id)
                        .proof(val.operation_val.proof)
                        .build(),
                )
                .build(),
            KmsOperationResponse::CrsGenResponse(val) => KmsEventMessage::builder()
                .value(val.crs_gen_response)
                .event(
                    KmsEvent::builder()
                        .operation(KmsOperation::CrsGenResponse)
                        .txn_id(val.operation_val.tx_id)
                        .proof(val.operation_val.proof)
                        .build(),
                )
                .build(),
        }
    }
}

#[async_trait]
pub trait Blockchain {
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()>;
    async fn get_operation_value(&self, event: &KmsEvent) -> anyhow::Result<OperationValue>;
}
