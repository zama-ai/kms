use events::kms::KmsEvent;

#[async_trait::async_trait]
pub trait Oracle {
    async fn respond(&self, event: KmsEvent, height_of_event: u64) -> anyhow::Result<()>;
}
