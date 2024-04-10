use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;

// TODO remove this file and use ddec instead or vice versa
pub fn write_as_json<T: serde::Serialize>(file_path: String, to_store: &T) -> anyhow::Result<()> {
    let json_data = serde_json::to_string(&to_store)?;
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?
    };
    std::fs::write(path, json_data.as_bytes())?;
    Ok(())
}

pub fn read_as_json<T: DeserializeOwned>(file_path: String) -> anyhow::Result<T> {
    let read_json = std::fs::read(file_path.clone())?;
    let res = serde_json::from_slice::<T>(&read_json)?;
    Ok(res)
}

pub fn write_element<T: serde::Serialize>(file_path: String, element: &T) -> anyhow::Result<()> {
    let mut serialized_data = Vec::new();
    let _ = bincode::serialize_into(&mut serialized_data, &element);
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?
    };
    std::fs::write(path, serialized_data.as_slice())?;
    Ok(())
}

pub fn write_bytes<B: AsRef<[u8]>>(file_path: String, bytes: B) -> anyhow::Result<()> {
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?
    };
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn read_element<T: DeserializeOwned + Serialize>(file_path: &str) -> anyhow::Result<T> {
    let read_element = std::fs::read(file_path)?;
    Ok(bincode::deserialize_from(read_element.as_slice())?)
}

/// Same method as [write_as_json] but async and hence can be used for multi-threaded writes.
pub async fn write_as_json_async<T: serde::Serialize>(
    file_path: String,
    to_store: &T,
) -> anyhow::Result<()> {
    let json_data = serde_json::to_string(&to_store)?;
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?
    };
    tokio::fs::write(path, json_data.as_bytes()).await?;
    Ok(())
}

/// Same method as [read_as_json] but async and hence can be used for multi-threaded reads.
pub async fn read_as_json_async<T: DeserializeOwned>(file_path: String) -> anyhow::Result<T> {
    let read_json = tokio::fs::read(file_path.clone()).await?;
    let res = serde_json::from_slice::<T>(&read_json)?;
    Ok(res)
}

/// Same method as [write_element] but async and hence can be used for multi-threaded writes.
pub async fn write_element_async<T: serde::Serialize>(
    file_path: String,
    element: &T,
) -> anyhow::Result<()> {
    let mut serialized_data = Vec::new();
    let _ = bincode::serialize_into(&mut serialized_data, &element);
    let path = Path::new(&file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?
    };
    tokio::fs::write(path, serialized_data.as_slice()).await?;
    Ok(())
}

/// Same method as [read_element] but async and hence can be used for multi-threaded reads.
pub async fn read_element_async<T: DeserializeOwned + Serialize>(
    file_path: String,
) -> anyhow::Result<T> {
    let read_element = tokio::fs::read(file_path.clone()).await?;
    Ok(bincode::deserialize_from(read_element.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::read_as_json_async;
    use crate::file_handling::{
        read_as_json, read_element, read_element_async, write_as_json, write_as_json_async,
        write_element, write_element_async,
    };
    use serde::{Deserialize, Serialize};
    use serial_test::serial;
    use std::fs::remove_file;

    #[test]
    #[serial]
    fn read_write_element() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element.bin".to_string();
        write_element(file_name.clone(), &msg.clone()).unwrap();
        let read_element: String = read_element(&file_name).unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).unwrap();
    }

    #[test]
    #[serial]
    fn read_write_json() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Test {
            key: u32,
        }
        let test_struct = Test { key: 42 };
        let file_name = "temp/test_json_async.json".to_string();
        write_as_json(file_name.clone(), &test_struct).unwrap();
        let read_json = read_as_json(file_name.clone()).unwrap();
        assert_eq!(test_struct, read_json);
        remove_file(file_name).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn read_write_element_async() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element_async.bin".to_string();
        write_element_async(file_name.clone(), &msg.clone())
            .await
            .unwrap();
        let read_element: String = read_element_async(file_name.clone()).await.unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).unwrap();
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
        write_as_json_async(file_name.clone(), &test_struct)
            .await
            .unwrap();
        let read_json = read_as_json_async(file_name.clone()).await.unwrap();
        assert_eq!(test_struct, read_json);
        remove_file(file_name).unwrap();
    }
}
