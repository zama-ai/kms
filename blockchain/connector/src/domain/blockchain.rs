use async_trait::async_trait;
use events::kms::{
    CrsGenResponseValues, DecryptResponseValues, KeyGenPreprocResponseValues, KeyGenResponseValues,
    KmsEvent, KmsOperationAttribute, ReencryptResponseValues, TransactionId,
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

impl From<KmsOperationResponse> for KmsEvent {
    fn from(value: KmsOperationResponse) -> Self {
        match value {
            KmsOperationResponse::DecryptResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::DecryptResponse(val.decrypt_response))
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::ReencryptResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::ReencryptResponse(
                    val.reencrypt_response,
                ))
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::KeyGenPreprocResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::KeyGenPreprocResponse(
                    KeyGenPreprocResponseValues {},
                ))
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::KeyGenResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::KeyGenResponse(val.keygen_response))
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::CrsGenResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::CrsGenResponse(val.crs_gen_response))
                .txn_id(val.operation_val.tx_id)
                .build(),
        }
    }
}

#[async_trait]
pub trait Blockchain {
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()>;
}
