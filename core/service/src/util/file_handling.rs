use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use tfhe::named::Named;
use tfhe::safe_deserialization::{safe_deserialize_versioned, safe_serialize_versioned};
use tfhe::{Unversionize, Versionize};

use crate::consts::SAFE_SER_SIZE_LIMIT;

// // TODO remove this file and use ddec instead or vice versa

/// Same method as [write_as_json] but async and hence can be used for multi-threaded writes.
pub async fn write_as_json<T: Serialize>(file_path: &str, to_store: &T) -> anyhow::Result<()> {
    let json_data = serde_json::to_string(&to_store)?;
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(path, json_data.as_bytes()).await?;
    Ok(())
}

/// Read a json file and deserialize it into an object.
pub async fn read_as_json<T: DeserializeOwned>(file_path: &str) -> anyhow::Result<T> {
    let read_json = tokio::fs::read(file_path).await?;
    let res = serde_json::from_slice::<T>(&read_json)?;
    Ok(res)
}

/// Serialize and write an element to a file.
pub async fn write_element<T: Serialize>(file_path: &str, element: &T) -> anyhow::Result<()> {
    let mut serialized_data = Vec::new();
    let _ = bincode::serialize_into(&mut serialized_data, &element);
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(path, serialized_data.as_slice()).await?;
    Ok(())
}

/// This is a wrapper around safe_serialize_versioned for the async use case.
pub async fn safe_write_element_versioned<T: Versionize + Named + Send>(
    file_path: &str,
    element: &T,
) -> anyhow::Result<()> {
    let mut serialized_data = Vec::new();
    safe_serialize_versioned(element, &mut serialized_data, SAFE_SER_SIZE_LIMIT)?;

    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(path, serialized_data.as_slice()).await?;
    Ok(())
}

pub async fn write_text(file_path: &str, text: &str) -> anyhow::Result<()> {
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(path, text).await?;
    Ok(())
}
/// Write bytes to a filepath.
/// The function will create the necessary directories in the path in order to write the [bytes].
/// If the file already exists then it will be COMPLETELY OVERWRITTEN without warning.
pub async fn write_bytes<S: AsRef<std::ffi::OsStr> + ?Sized, B: AsRef<[u8]>>(
    file_path: &S,
    bytes: B,
) -> anyhow::Result<()> {
    let path = Path::new(file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(path, bytes).await?;
    Ok(())
}
/// Read an element from `file_path` and deserialize it to the return type.
pub async fn read_element<T: DeserializeOwned>(file_path: &str) -> anyhow::Result<T> {
    let read_element = tokio::fs::read(file_path).await?;
    Ok(bincode::deserialize_from(read_element.as_slice())?)
}

pub async fn safe_read_element_versioned<T: Unversionize + Named + Send>(
    file_path: &str,
) -> anyhow::Result<T> {
    let mut buf = std::io::Cursor::new(tokio::fs::read(file_path).await?);
    safe_deserialize_versioned(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::read_as_json;
    use crate::util::file_handling::{read_element, write_as_json, write_element};
    use serde::{Deserialize, Serialize};
    use serial_test::serial;
    use tokio::fs::remove_file;

    #[tokio::test]
    #[serial]
    async fn read_write_element_async() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element_async.bin".to_string();
        write_element(&file_name, &msg.clone()).await.unwrap();
        let read_element: String = read_element(&file_name).await.unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn read_write_json_async() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Test {
            key: u32,
        }
        let test_struct = Test { key: 42 };
        let file_name = "temp/test_json_async.json".to_string();
        write_as_json(&file_name, &test_struct).await.unwrap();
        let read_json = read_as_json(&file_name).await.unwrap();
        assert_eq!(test_struct, read_json);
        remove_file(file_name).await.unwrap();
    }
}
