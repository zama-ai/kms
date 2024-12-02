use crate::conf::StoreConfig;
use crate::domain::storage::Storage;
use byteorder::{BigEndian, ByteOrder};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct KVStore {
    config: StoreConfig,
}

impl KVStore {
    pub(crate) fn new(config: StoreConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Storage for KVStore {
    async fn get_ciphertext(&self, handle: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let identifier = hex::encode(handle);
        tracing::info!("📦 Retrieving ciphertext: {}", identifier);

        // Create an HTTP client
        let client = Client::new();

        let size_hex = &identifier[..8];
        let hash = &identifier[8..];

        // Decode the size
        let size_bytes = hex::decode(size_hex).unwrap();
        let data_size = BigEndian::read_u32(&size_bytes);
        tracing::info!("Data size: {}", data_size);
        // Send a GET request to the Actix web service
        let response = client
            .get(format!("{}/store/{}", self.config.url, identifier))
            .send()
            .await?;

        let status = response.status();
        let response_text = response.text().await.unwrap_or_else(|_| String::new());
        if status != StatusCode::OK || response_text.is_empty() {
            anyhow::bail!("Invalid response: status={status} text={response_text}");
        }

        // Print the response
        tracing::debug!("Response: {}", response_text);
        // Decode the hex response to bytes
        let response_bytes = hex::decode(response_text)?;

        tracing::info!("Verifying...");
        // verify the size of the data
        anyhow::ensure!(
            response_bytes.len() as u32 == data_size,
            "Data size and hash verification failed."
        );

        // verify the hash of the data
        let mut hasher = Sha256::new();
        hasher.update(&response_bytes);
        let result = hasher.finalize();
        let hex_hash = hex::encode(result);
        anyhow::ensure!(hash == hex_hash, "Data size and hash verification failed.");
        tracing::info!("Data size and hash verified successfully.");

        //let response_bytes = bincode::serialize(&response_bytes).expect("cks serialization");
        Ok(response_bytes)
    }
}
