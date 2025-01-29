use std::{fs::File, io::Write, path::Path};

use serde::{de::DeserializeOwned, Serialize};

pub fn write_as_json<T: serde::Serialize, P: AsRef<Path>>(
    file_path: &P,
    to_store: &T,
) -> anyhow::Result<()> {
    let json_data = serde_json::to_string(&to_store)?;
    let mut file = File::create(file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

pub fn read_as_json<T: DeserializeOwned, P: AsRef<Path>>(file_path: &P) -> anyhow::Result<T> {
    let read_json = std::fs::read(file_path)?;
    let res = serde_json::from_slice::<T>(&read_json)?;
    Ok(res)
}

pub fn write_element<T: serde::Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    let mut serialized_data = Vec::new();
    let _ = bincode::serialize_into(&mut serialized_data, &element);
    let mut file = File::create(file_path)?;
    file.write_all(serialized_data.as_slice())?;
    Ok(())
}

pub fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    let read_element = std::fs::read(file_path)?;
    Ok(bincode::deserialize_from(read_element.as_slice())?)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::fs::remove_file;

    use crate::file_handling::{read_as_json, read_element, write_as_json, write_element};

    #[test]
    fn read_write_element() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element.bin".to_string();
        write_element(file_name.clone(), &msg.clone()).unwrap();
        let read_element: String = read_element(file_name.clone()).unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).unwrap();
    }

    #[test]
    fn read_write_json() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Test {
            key: u32,
        }
        let test_struct = Test { key: 42 };
        let file_name = "temp/test_json.json";
        write_as_json(&file_name, &test_struct).unwrap();
        let read_json = read_as_json(&file_name).unwrap();
        assert_eq!(test_struct, read_json);
        remove_file(file_name).unwrap();
    }
}
