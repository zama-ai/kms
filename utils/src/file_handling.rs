use std::fs::File;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tfhe_safe_serialize::{Named, safe_deserialize, safe_serialize};
use tfhe_versionable::{Unversionize, Versionize};

// TODO(dp): this is the third copy of this constant in the code base. Where is the best canonical place for it?
const SAFE_SER_SIZE_LIMIT: u64 = 1024 * 1024 * 1024 * 2;

/// Write some bytes to a file without serialization. Works for ASCII text without extra thought too.
pub async fn write_bytes<P: AsRef<Path>>(file_path: P, bytes: &[u8]) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(file_path, bytes).await?;
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
    let mut buf = std::io::Cursor::new(tokio::fs::read(file_path.as_ref()).await.map_err(|e| {
        anyhow::anyhow!(
            "failed to read file path at {} due to {e}",
            file_path.as_ref().display()
        )
    })?);
    safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
}

/// Write a serialized generic element to a file. NOTE: not versioned.
pub fn write_element<T: serde::Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        std::fs::create_dir_all(p)?
    };
    // Serialize straight into the file to avoid buffering the whole serialized element in memory.
    bc2wrap::serialize_into(element, &mut File::create(file_path)?)?;
    Ok(())
}

/// Read a serialized generic element from a file. NOTE: not versioned.
pub fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    Ok(bc2wrap::deserialize_from(File::open(file_path)?)?)
}

#[cfg(test)]
mod tests {
    use crate::file_handling::write_bytes;
    use crate::{read_element, write_element};
    use tokio::fs::remove_file;

    #[tokio::test]
    async fn read_write_text() {
        let msg = "Jeg ælsker ☕!".to_owned();
        let file_name = tempfile::tempdir()
            .unwrap()
            .path()
            .join("read-write-test.txt");
        write_bytes(&file_name, msg.as_bytes()).await.unwrap();
        let read_element: String =
            String::from_utf8(tokio::fs::read(&file_name).await.unwrap()).unwrap();
        assert_eq!(read_element, msg);
    }

    #[tokio::test]
    async fn read_write_element() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element.bin".to_string();
        write_element(file_name.clone(), &msg.clone()).unwrap();
        let read_element: String = read_element(file_name.clone()).unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).await.unwrap();
    }
}
