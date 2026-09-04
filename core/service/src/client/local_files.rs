use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::BufWriter;
use std::path::Path;

fn serialize_into_file<T: Serialize>(file_path: &Path, element: &T) -> anyhow::Result<()> {
    let parent = file_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut writer = BufWriter::new(tempfile::NamedTempFile::new_in(parent)?);
    bc2wrap::serialize_into(element, &mut writer)?;
    let temp_file = writer
        .into_inner()
        .map_err(|err| anyhow::anyhow!("failed to flush temporary file: {err}"))?;
    temp_file
        .persist(file_path)
        .map_err(|err| anyhow::anyhow!("failed to persist {}: {err}", file_path.display()))?;
    Ok(())
}

/// Writes a generic serialized value to a local file for client-side workflows.
///
/// The serialized data is streamed through a sibling temporary file and atomically
/// moved into place, so the destination remains intact if serialization fails.
pub async fn write_element<T: Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    let file_path = file_path.as_ref();
    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    serialize_into_file(file_path, element)
}

/// Writes an owned value on Tokio's blocking pool and returns its ownership.
///
/// This variant keeps serialization and file IO off the async worker without cloning
/// large values. The destination remains intact if serialization fails.
pub async fn write_element_owned<T: Serialize + Send + 'static, P: AsRef<Path>>(
    file_path: P,
    element: T,
) -> anyhow::Result<T> {
    let file_path = file_path.as_ref().to_path_buf();
    let task_path = file_path.clone();
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = task_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serialize_into_file(&task_path, &element)?;
        Ok(element)
    })
    .await
    .map_err(|err| {
        anyhow::anyhow!(
            "failed to join file write task for {}: {err}",
            file_path.display()
        )
    })?
}

/// Reads a generic serialized value from a local file for client-side
/// workflows. File size is capped to 2GB.
pub async fn read_element<T: DeserializeOwned + Serialize + Send + 'static, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    let file_path = file_path.as_ref().to_path_buf();
    let task_path = file_path.clone();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&task_path)?;
        Ok(bc2wrap::deserialize_from(file)?)
    })
    .await
    .map_err(|err| {
        anyhow::anyhow!(
            "failed to join file read task for {}: {err}",
            file_path.display()
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::{read_element, write_element, write_element_owned};
    use serde::Serialize;

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

    #[tokio::test]
    async fn write_element_preserves_bincode_encoding() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cipher.bin");
        let element = vec![42_u8; 128 * 1024];
        let expected = bc2wrap::serialize(&element).unwrap();

        let returned = write_element_owned(&file_path, element.clone())
            .await
            .unwrap();

        assert_eq!(returned, element);
        assert_eq!(tokio::fs::read(file_path).await.unwrap(), expected);
    }

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(2)?;
            tuple.serialize_element(&vec![42_u8; 128 * 1024])?;
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    #[tokio::test]
    async fn write_element_preserves_destination_on_serialization_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cipher.bin");
        let original = b"existing ciphertext";
        tokio::fs::write(&file_path, original).await.unwrap();

        let result = write_element_owned(&file_path, FailingSerialize).await;

        assert!(result.is_err());
        assert_eq!(tokio::fs::read(file_path).await.unwrap(), original);
    }
}
