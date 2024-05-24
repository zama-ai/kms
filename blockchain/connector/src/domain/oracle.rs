use events::kms::KmsEvent;

#[async_trait::async_trait]
pub trait Oracle {
    async fn respond(&self, event: KmsEvent) -> anyhow::Result<()>;
}
