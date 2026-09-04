pub mod random_free_port;
pub mod test_logging;

use serde::{Serialize, de::DeserializeOwned};
use std::{io::BufWriter, path::Path};

/// Writes a generic serialized value to a local file.
///
/// The serialized data is streamed through a sibling temporary file and atomically
/// moved into place, so the destination remains intact if serialization fails.
pub fn write_element<T: Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    let file_path = file_path.as_ref();
    let parent = file_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

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

/// Reads a generic serialized value from a local file.
pub fn read_element<T: DeserializeOwned, P: AsRef<Path>>(file_path: P) -> anyhow::Result<T> {
    Ok(bc2wrap::deserialize_from(std::fs::File::open(file_path)?)?)
}

/// Writes an owned value on Tokio's blocking pool and returns its ownership.
///
/// This function keeps serialization and file I/O off the async worker without cloning large
/// values. The destination remains intact if serialization fails.
pub async fn write_element_owned<T: Serialize + Send + 'static, P: AsRef<Path>>(
    file_path: P,
    element: T,
) -> anyhow::Result<T> {
    let file_path = file_path.as_ref().to_path_buf();
    let task_path = file_path.clone();
    tokio::task::spawn_blocking(move || {
        write_element(&task_path, &element)?;
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

/// Reads a generic serialized value on Tokio's blocking pool.
///
/// Decoding uses the 2 GiB limit from [`bc2wrap::deserialize_from`].
pub async fn read_element_async<T: DeserializeOwned + Send + 'static, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    let file_path = file_path.as_ref().to_path_buf();
    let task_path = file_path.clone();
    tokio::task::spawn_blocking(move || read_element(task_path))
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to join file read task for {}: {err}",
                file_path.display()
            )
        })?
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn read_write_element() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("element.bin");
        let msg = "I am a teacup!".to_owned();

        write_element(&file_path, &msg).unwrap();
        let read_element: String = read_element(&file_path).unwrap();

        assert_eq!(read_element, msg);
    }

    #[test]
    fn write_element_preserves_bincode_encoding() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("element.bin");
        let element = vec![42_u8; 128 * 1024];
        let expected = bc2wrap::serialize(&element).unwrap();

        write_element(&file_path, &element).unwrap();

        assert_eq!(std::fs::read(file_path).unwrap(), expected);
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

    #[test]
    fn write_element_preserves_destination_on_serialization_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("element.bin");
        let original = b"existing element";
        std::fs::write(&file_path, original).unwrap();

        let result = write_element(&file_path, &FailingSerialize);

        assert!(result.is_err());
        assert_eq!(std::fs::read(file_path).unwrap(), original);
    }

    #[tokio::test]
    async fn async_read_element_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("element.bin");
        let message = "hello".to_string();

        write_element(&file_path, &message).unwrap();
        let round_trip: String = read_element_async(&file_path).await.unwrap();

        assert_eq!(round_trip, message);
    }

    #[tokio::test]
    async fn async_read_element_missing_file_errors() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("missing.bin");

        let result: anyhow::Result<String> = read_element_async(&file_path).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn write_element_owned_returns_element() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("element.bin");
        let element = vec![42_u8; 128 * 1024];

        let returned = write_element_owned(&file_path, element.clone())
            .await
            .unwrap();

        assert_eq!(returned, element);
        let round_trip: Vec<u8> = read_element_async(file_path).await.unwrap();
        assert_eq!(round_trip, element);
    }
}
