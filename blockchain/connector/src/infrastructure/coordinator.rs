use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KeyGenResponseVal, KmsOperationResponse,
    ReencryptResponseVal,
};
use crate::domain::kms::{CsrGenVal, DecryptVal, KeyGenVal, Kms, ReencryptVal};
use async_trait::async_trait;
use events::kms::{DecryptResponseValues, KeyGenResponseValues, ReencryptResponseValues};
use typed_builder::TypedBuilder;

#[derive(Clone, TypedBuilder)]
pub struct KmsCoordinator {}
impl KmsCoordinator {
    pub(crate) async fn new(_clone: crate::conf::ConnectorConfig) -> Result<Self, anyhow::Error> {
        Ok(KmsCoordinator {})
    }
}

#[async_trait]
impl Kms for DecryptVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        // TODO: Implement this
        Ok(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
            decrypt_response: DecryptResponseValues::builder()
                .plaintext(
                    "This is a mocked response of decyprt request"
                        .as_bytes()
                        .to_vec(),
                )
                .build(),
            operation_val: BlockchainOperationVal {
                tx_id: self.operation_val.tx_id.clone(),
            },
        }))
    }
}

#[async_trait]
impl Kms for ReencryptVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        Ok(KmsOperationResponse::ReencryptResponse(
            ReencryptResponseVal {
                reencrypt_response: ReencryptResponseValues::builder()
                    .cyphertext([9; 10].to_vec())
                    .build(),
                operation_val: BlockchainOperationVal {
                    tx_id: self.operation_val.tx_id.clone(),
                },
            },
        ))
    }
}

#[async_trait]
impl Kms for KeyGenVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        Ok(KmsOperationResponse::KeyGenResponse(KeyGenResponseVal {
            keygen_response: KeyGenResponseValues::builder()
                .key([9; 10].to_vec())
                .build(),
            operation_val: BlockchainOperationVal {
                tx_id: self.operation_val.tx_id.clone(),
            },
        }))
    }
}

#[async_trait]
impl Kms for CsrGenVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        Ok(KmsOperationResponse::CsrGenResponse(
            crate::domain::blockchain::CsrGenResponseVal {
                csr_gen_response: events::kms::CsrGenResponseValues::builder()
                    .csr([9; 10].to_vec())
                    .build(),
                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                    tx_id: self.operation_val.tx_id.clone(),
                },
            },
        ))
    }
}
