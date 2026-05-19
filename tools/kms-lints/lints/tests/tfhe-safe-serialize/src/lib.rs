#![allow(unused_variables)]

#[derive(Debug)]
pub struct Error;

pub trait ParameterSetConformant {
    type ParameterSet;
}

pub fn safe_serialize<T: ?Sized>(
    object: &T,
    writer: impl std::io::Write,
    serialized_size_limit: u64,
) -> Result<(), Error> {
    Ok(())
}

pub fn safe_serialized_size<T: ?Sized>(object: &T) -> Result<u64, Error> {
    Ok(0)
}

pub fn safe_deserialize<T>(
    reader: impl std::io::Read,
    deserialized_size_limit: u64,
) -> Result<T, Error> {
    panic!("test fixture does not execute")
}

pub fn safe_deserialize_conformant<T: ParameterSetConformant>(
    reader: impl std::io::Read,
    deserialized_size_limit: u64,
    parameter_set: &T::ParameterSet,
) -> Result<T, Error> {
    panic!("test fixture does not execute")
}
