use events::kms::{KmsEvent, OperationValue};
use tonic::async_trait;

use super::blockchain::KmsOperationResponse;

#[async_trait]
pub trait Kms {
    async fn run(
        &self,
        event: KmsEvent,
        operation: OperationValue,
    ) -> anyhow::Result<KmsOperationResponse>;
}
