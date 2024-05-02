use async_trait::async_trait;
use events::kms::{
    CsrGenResponseValues, DecryptResponseValues, KeyGenResponseValues, KmsEvent,
    KmsOperationAttribute, ReencryptResponseValues, TransactionId,
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
pub struct KeyGenResponseVal {
    pub keygen_response: KeyGenResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq)]
pub struct CsrGenResponseVal {
    pub csr_gen_response: CsrGenResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(EnumString, Display, PartialEq, Eq)]
pub enum KmsOperationResponse {
    DecryptResponse(DecryptResponseVal),
    ReencryptResponse(ReencryptResponseVal),
    KeyGenResponse(KeyGenResponseVal),
    CsrGenResponse(CsrGenResponseVal),
}

impl KmsOperationResponse {
    pub fn txn_id(&self) -> &TransactionId {
        match self {
            KmsOperationResponse::DecryptResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::ReencryptResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::KeyGenResponse(val) => &val.operation_val.tx_id,
            KmsOperationResponse::CsrGenResponse(val) => &val.operation_val.tx_id,
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
            KmsOperationResponse::KeyGenResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::KeyGenResponse(val.keygen_response))
                .txn_id(val.operation_val.tx_id)
                .build(),
            KmsOperationResponse::CsrGenResponse(val) => KmsEvent::builder()
                .operation(KmsOperationAttribute::CsrGenResponse(val.csr_gen_response))
                .txn_id(val.operation_val.tx_id)
                .build(),
        }
    }
}

#[async_trait]
pub trait Blockchain {
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()>;
}
