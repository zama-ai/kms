mod file_handling;

pub use crate::file_handling::{
    read_element, safe_read_element_versioned, safe_write_element_versioned, write_bytes,
    write_element,
};
