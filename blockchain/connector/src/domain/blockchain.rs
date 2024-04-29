use async_trait::async_trait;
use events::kms::{
    CsrGenResponseValues, DecryptResponseValues, KeyGenResponseValues, ReencryptResponseValues,
};
use serde::Serialize;
use strum_macros::{Display, EnumString};

#[derive(Default, PartialEq, Eq, Serialize)]
pub struct BlockchainOperationVal {
    pub tx_id: String,
}

#[derive(Default, PartialEq, Eq, Serialize)]
pub struct DecryptResponseVal {
    pub decrypt_response: DecryptResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq, Serialize)]
pub struct ReencryptResponseVal {
    pub reencrypt_response: ReencryptResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq, Serialize)]
pub struct KeyGenResponseVal {
    pub keygen_response: KeyGenResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(Default, PartialEq, Eq, Serialize)]
pub struct CsrGenResponseVal {
    pub csr_gen_response: CsrGenResponseValues,
    pub operation_val: BlockchainOperationVal,
}

#[derive(EnumString, Display, PartialEq, Eq, Serialize)]
pub enum KmsOperationResponse {
    DecryptResponse(DecryptResponseVal),
    ReencryptResponse(ReencryptResponseVal),
    KeyGenResponse(KeyGenResponseVal),
    CsrGenResponse(CsrGenResponseVal),
}

#[async_trait]
pub trait Blockchain {
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()>;
}
