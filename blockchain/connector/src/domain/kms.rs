use crate::infrastructure::coordinator::KmsCoordinator;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use events::kms::{DecryptValues, KmsEvent, KmsOperationAttribute, ReencryptValues};

use super::blockchain::KmsOperationResponse;

pub struct KmsOperationVal {
    pub kms_client: KmsCoordinator,
    pub tx_id: String,
}

pub struct DecryptVal {
    pub decrypt: DecryptValues,
    pub operation_val: KmsOperationVal,
}

pub struct ReencryptVal {
    pub reencrypt: ReencryptValues,
    pub operation_val: KmsOperationVal,
}

pub struct KeyGenVal {
    pub operation_val: KmsOperationVal,
}

pub struct CsrGenVal {
    pub operation_val: KmsOperationVal,
}

#[enum_dispatch]
pub enum KmsOperationRequest {
    Reencrypt(ReencryptVal),
    Decrypt(DecryptVal),
    KeyGen(KeyGenVal),
    CsrGen(CsrGenVal),
}

pub fn create_kms_operation(
    event: KmsEvent,
    kms_client: KmsCoordinator,
) -> anyhow::Result<KmsOperationRequest> {
    let operation_val = KmsOperationVal {
        tx_id: event.txn_id.clone(),
        kms_client,
    };
    let request = match event.operation {
        KmsOperationAttribute::Reencrypt(reencrypt) => {
            KmsOperationRequest::Reencrypt(ReencryptVal {
                reencrypt,
                operation_val,
            })
        }
        KmsOperationAttribute::Decrypt(decrypt) => KmsOperationRequest::Decrypt(DecryptVal {
            decrypt,
            operation_val,
        }),
        KmsOperationAttribute::KeyGen => KmsOperationRequest::KeyGen(KeyGenVal { operation_val }),
        KmsOperationAttribute::CsrGen => KmsOperationRequest::CsrGen(CsrGenVal { operation_val }),
        _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
    };
    Ok(request)
}

#[async_trait]
#[enum_dispatch(KmsOperationRequest)]
pub trait Kms {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse>;
}

pub trait KmsClient {}
