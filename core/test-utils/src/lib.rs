pub mod random_free_port;
pub mod test_logging;

use serde::de::DeserializeOwned;
use std::{fs::File, path::Path};

/// Helper method to write a generic element to a file for tests or benchmarks.
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

/// Helper method to read a generic element from a file for tests or benchmarks.
pub fn read_element<T: DeserializeOwned, P: AsRef<Path>>(file_path: P) -> anyhow::Result<T> {
    Ok(bc2wrap::deserialize_from(File::open(file_path)?)?)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn read_write_element() {
        use std::fs::remove_file;

        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element.bin".to_string();
        write_element(file_name.clone(), &msg.clone()).unwrap();
        let read_element: String = read_element(file_name.clone()).unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).unwrap();
    }
}
