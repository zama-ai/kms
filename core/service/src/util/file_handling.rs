use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{Unversionize, Versionize};

use crate::consts::SAFE_SER_SIZE_LIMIT;

/// Write some text data to a file without serialization.
pub async fn write_text<P: AsRef<Path>>(file_path: P, text: &str) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(file_path, text).await?;
    Ok(())
}

/// This is a wrapper around safe_serialize versioned for the async use case.
pub async fn safe_write_element_versioned<
    T: Serialize + Versionize + Named + Send,
    P: AsRef<Path>,
>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(p).await?
    };
    let mut serialized_data = Vec::new();
    safe_serialize(element, &mut serialized_data, SAFE_SER_SIZE_LIMIT)?;
    tokio::fs::write(file_path, serialized_data.as_slice()).await?;
    Ok(())
}

pub async fn safe_read_element_versioned<
    T: DeserializeOwned + Unversionize + Named + Send,
    P: AsRef<Path>,
>(
    file_path: P,
) -> anyhow::Result<T> {
    let mut buf = std::io::Cursor::new(tokio::fs::read(file_path).await?);
    safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
}

/// Writing a generic element to a file by serializing it. This is hidden behind the testing flag to ensure only the safe and versioned writing method
/// is used in production code.
#[cfg(any(test, feature = "testing"))]
pub async fn write_element<T: serde::Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(p).await?
    };
    let serialized_data = bc2wrap::serialize(element)?;
    tokio::fs::write(file_path, serialized_data.as_slice()).await?;
    Ok(())
}

/// Reading a generic element to a file. This is hidden behind the testing flag to ensure only the safe and versioned reading method
/// is used in production code.
#[cfg(any(test, feature = "testing"))]
pub async fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    let read_element = tokio::fs::read(file_path).await?;
    Ok(bc2wrap::deserialize(read_element.as_slice())?)
}

#[cfg(test)]
mod tests {
    use crate::util::file_handling::{read_element, write_element, write_text};
    use tokio::fs::remove_file;

    #[tokio::test]
    async fn read_write_text() {
        let msg = "Jeg ælsker ☕!".to_owned();
        let file_name = tempfile::tempdir()
            .unwrap()
            .path()
            .join("read-write-test.txt");
        write_text(&file_name, &msg.clone()).await.unwrap();
        let read_element: String =
            String::from_utf8(tokio::fs::read(&file_name).await.unwrap()).unwrap();
        assert_eq!(read_element, msg);
    }

    #[tokio::test]
    async fn read_write_element() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element.bin".to_string();
        write_element(file_name.clone(), &msg.clone())
            .await
            .unwrap();
        let read_element: String = read_element(file_name.clone()).await.unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).await.unwrap();
    }
}
