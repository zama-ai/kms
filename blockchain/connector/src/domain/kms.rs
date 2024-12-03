use events::kms::{KmsConfig, KmsEvent, OperationValue};
use tonic::async_trait;

use super::blockchain::KmsOperationResponse;

#[async_trait]
pub trait Kms {
    async fn run(
        &self,
        event: KmsEvent,
        operation: OperationValue,
        config: Option<KmsConfig>,
    ) -> anyhow::Result<KmsOperationResponse>;
}
