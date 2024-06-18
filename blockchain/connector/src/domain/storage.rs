use async_trait::async_trait;

#[async_trait]
pub trait Storage {
    async fn get_ciphertext(&self, handle: Vec<u8>) -> anyhow::Result<Vec<u8>>;
}
