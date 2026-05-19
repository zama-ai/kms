#![allow(dead_code, unused_variables)]

use std::io::Cursor;

use tfhe_safe_serialize::{
    ParameterSetConformant, safe_deserialize, safe_deserialize_conformant, safe_serialize,
};

struct LocalPayload {
    _value: u64,
}

struct ConformantPayload {
    _value: u64,
}

impl ParameterSetConformant for ConformantPayload {
    type ParameterSet = ();
}

fn generic_encode<T>(value: &T) {
    let mut writer = Vec::new();
    let _ = safe_serialize(value, &mut writer, 1024);
}

fn generic_decode<T>(bytes: &[u8]) -> Result<T, tfhe_safe_serialize::Error> {
    safe_deserialize(Cursor::new(bytes), 1024)
}

fn ignored_size<T>(value: &T) {
    let _ = tfhe_safe_serialize::safe_serialized_size(value);
}

fn main() {
    let payload = LocalPayload { _value: 7 };
    let mut writer = Vec::new();
    let _ = safe_serialize(&payload, &mut writer, 1024);

    use tfhe_safe_serialize::safe_serialize as encode;
    let _ = encode(&payload, Vec::new(), 1024);

    let string = String::from("foreign");
    let _ = safe_serialize(&string, Vec::new(), 1024);

    let tuple = (1_u64, 2_u64);
    let _ = safe_serialize(&tuple, Vec::new(), 1024);

    let primitive = 9_u64;
    let _ = safe_serialize(&primitive, Vec::new(), 1024);

    let bytes: &[u8] = &[];
    let _: LocalPayload = safe_deserialize(Cursor::new(bytes), 1024).unwrap();
    let _: LocalPayload = generic_decode(bytes).unwrap();

    let parameter_set = ();
    let _: ConformantPayload =
        safe_deserialize_conformant(Cursor::new(bytes), 1024, &parameter_set).unwrap();

    generic_encode(&payload);
    ignored_size(&payload);
}
