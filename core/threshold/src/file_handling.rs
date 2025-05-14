pub mod tests {
    use serde::{de::DeserializeOwned, Serialize};
    use std::path::Path;

    /// Helper method to write a generic element to a file for tests or benchmarks.
    pub fn write_element<T: serde::Serialize, P: AsRef<Path>>(
        file_path: P,
        element: &T,
    ) -> anyhow::Result<()> {
        // Create the parent directories of the file path if they don't exist
        if let Some(p) = file_path.as_ref().parent() {
            std::fs::create_dir_all(p)?
        };
        let mut serialized_data = Vec::new();
        bincode::serialize_into(&mut serialized_data, &element)?;
        std::fs::write(file_path, serialized_data.as_slice())?;
        Ok(())
    }

    /// Helper method to read a generic element from a file for tests or benchmarks.
    pub fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
        file_path: P,
    ) -> anyhow::Result<T> {
        let read_element = std::fs::read(file_path)?;
        Ok(bincode::deserialize_from(read_element.as_slice())?)
    }

    #[cfg(test)]
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
