use events::kms::KmsEvent;
use tonic::async_trait;

use super::blockchain::KmsOperationResponse;

#[async_trait]
pub trait KmsOperation {
    async fn run(&self, event: KmsEvent) -> anyhow::Result<KmsOperationResponse>;
}
