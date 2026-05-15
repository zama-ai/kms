#![allow(dead_code, unused_variables)]

mod bc2wrap {
    pub mod error {
        #[derive(Debug)]
        pub struct EncodeError;

        #[derive(Debug)]
        pub struct DecodeError;
    }

    pub fn serialize<T: ?Sized>(_value: &T) -> Result<Vec<u8>, error::EncodeError> {
        Ok(Vec::new())
    }

    pub fn serialize_into<T: ?Sized, W>(
        _value: &T,
        _writer: &mut W,
    ) -> Result<usize, error::EncodeError> {
        Ok(0)
    }

    pub fn deserialize_safe<T>(_bytes: &[u8]) -> Result<T, error::DecodeError> {
        panic!("test fixture does not execute")
    }

    pub fn deserialize_unsafe<T>(_bytes: &[u8]) -> Result<T, error::DecodeError> {
        panic!("test fixture does not execute")
    }
}

mod vault {
    pub mod storage {
        #[derive(Clone, Copy)]
        pub enum PubDataType {
            PublicKey,
        }

        #[derive(Clone, Copy)]
        pub enum PrivDataType {
            FheKeyInfo,
        }

        pub struct Storage;

        pub async fn store_versioned_at_request_id<S, T>(
            _storage: &mut S,
            _request_id: &u64,
            _data: &T,
            _data_type: &str,
        ) -> Result<(), ()> {
            Ok(())
        }

        pub async fn store_versioned_at_request_and_epoch_id<S, T>(
            _storage: &mut S,
            _request_id: &u64,
            _epoch_id: &u64,
            _data: &T,
            _data_type: &str,
        ) -> Result<(), ()> {
            Ok(())
        }

        pub async fn read_versioned_at_request_id<S, T>(
            _storage: &S,
            _request_id: &u64,
            _data_type: &str,
        ) -> Result<T, ()> {
            panic!("test fixture does not execute")
        }

        pub async fn read_versioned_at_request_and_epoch_id<S, T>(
            _storage: &S,
            _request_id: &u64,
            _epoch_id: &u64,
            _data_type: &str,
        ) -> Result<T, ()> {
            panic!("test fixture does not execute")
        }

        pub mod crypto_material {
            pub mod base {
                use super::super::{PrivDataType, PubDataType};

                pub struct StorageRoot;

                impl StorageRoot {
                    pub async fn write_all<PubData, PrivData>(
                        &self,
                        _request_id: &u64,
                        _epoch_id: Option<&u64>,
                        _pub_data: Option<(&PubData, PubDataType)>,
                        _priv_data: Option<(&PrivData, PrivDataType)>,
                        _update_backup: bool,
                        _op_metric_tag: &'static str,
                    ) -> Result<(), ()> {
                        Ok(())
                    }
                }
            }
        }
    }
}

struct LocalPayload {
    _value: u64,
}

struct LocalStoragePayload {
    _value: u64,
}

struct LocalPublicMaterial {
    _value: u64,
}

struct LocalPrivateMaterial {
    _value: u64,
}

trait RoundTrip: Sized {
    fn decode(bytes: &[u8]) -> Result<Self, bc2wrap::error::DecodeError>;
}

impl RoundTrip for LocalPayload {
    fn decode(bytes: &[u8]) -> Result<Self, bc2wrap::error::DecodeError> {
        bc2wrap::deserialize_safe(bytes)
    }
}

fn generic_sink<T>(value: &T) {
    let _ = bc2wrap::serialize(value);
}

async fn generic_storage_sink<T>(storage: &mut vault::storage::Storage, value: &T) {
    let request_id = 7;
    let _ =
        vault::storage::store_versioned_at_request_id(storage, &request_id, value, "generic").await;
}

async fn storage_sinks() {
    use vault::storage::crypto_material::base::StorageRoot;
    use vault::storage::{
        PrivDataType, PubDataType, Storage, read_versioned_at_request_and_epoch_id,
        read_versioned_at_request_id, store_versioned_at_request_and_epoch_id,
        store_versioned_at_request_id,
    };

    let mut storage = Storage;
    let storage_root = StorageRoot;
    let request_id = 7;
    let epoch_id = 11;
    let payload = LocalStoragePayload { _value: 13 };
    let public_material = LocalPublicMaterial { _value: 17 };
    let private_material = LocalPrivateMaterial { _value: 19 };

    let _ = store_versioned_at_request_id(&mut storage, &request_id, &payload, "payload").await;
    let _ = store_versioned_at_request_and_epoch_id(
        &mut storage,
        &request_id,
        &epoch_id,
        &payload,
        "payload",
    )
    .await;

    let _: LocalPayload = read_versioned_at_request_id(&storage, &request_id, "payload")
        .await
        .unwrap();
    let _: LocalStoragePayload =
        read_versioned_at_request_and_epoch_id(&storage, &request_id, &epoch_id, "payload")
            .await
            .unwrap();

    let _ = storage_root
        .write_all::<LocalPublicMaterial, LocalPrivateMaterial>(
            &request_id,
            Some(&epoch_id),
            Some((&public_material, PubDataType::PublicKey)),
            Some((&private_material, PrivDataType::FheKeyInfo)),
            false,
            "fixture",
        )
        .await;

    generic_storage_sink(&mut storage, &payload).await;
}

fn main() {
    let payload = LocalPayload { _value: 7 };
    let _ = bc2wrap::serialize(&payload);

    use bc2wrap::serialize as encode;
    let _ = encode(&payload);

    let mut writer: Vec<u8> = Vec::new();
    let _ = bc2wrap::serialize_into(&payload, &mut writer);

    let string = String::from("foreign");
    let _ = bc2wrap::serialize(&string);

    let tuple = (1_u64, 2_u64);
    let _ = bc2wrap::serialize(&tuple);

    let bytes = [];
    let _: LocalPayload = bc2wrap::deserialize_safe(&bytes).unwrap();
    let _: LocalPayload = bc2wrap::deserialize_unsafe(&bytes).unwrap();
    let _ = LocalPayload::decode(&bytes);

    generic_sink(&payload);
}
