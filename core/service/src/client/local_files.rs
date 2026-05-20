use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;

/// Writes a generic serialized value to a local file for client-side workflows.
pub async fn write_element<T: Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    if let Some(parent) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let serialized_data = bc2wrap::serialize(element)?;
    tokio::fs::write(file_path, serialized_data.as_slice()).await?;
    Ok(())
}

/// Reads a generic serialized value from a local file for client-side workflows.
pub async fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    let serialized = tokio::fs::read(file_path).await?;
    Ok(bc2wrap::deserialize_unsafe(serialized.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::{read_element, write_element};

    #[tokio::test]
    async fn write_and_read_element_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cipher.bin");
        let message = "hello".to_string();

        write_element(&file_path, &message).await.unwrap();
        let round_trip: String = read_element(&file_path).await.unwrap();

        assert_eq!(round_trip, message);
    }

    #[tokio::test]
    async fn read_element_missing_file_errors() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("missing.bin");

        let result: anyhow::Result<String> = read_element(&file_path).await;

        assert!(result.is_err());
    }
}
