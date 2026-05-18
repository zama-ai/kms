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
        pub trait Storage {
            fn store_data<T>(
                &mut self,
                _data: &T,
                _request_id: &u64,
                _data_type: &str,
            ) -> Result<(), ()>;
        }

        pub trait StorageExt: Storage {
            fn store_data_at_epoch<T>(
                &mut self,
                _data: &T,
                _request_id: &u64,
                _epoch_id: &u64,
                _data_type: &str,
            ) -> Result<(), ()>;
        }

        pub trait StorageReader {
            fn read_data<T>(&self, _request_id: &u64, _data_type: &str) -> Result<T, ()>;
        }

        pub trait StorageReaderExt: StorageReader {
            fn read_data_at_epoch<T>(
                &self,
                _request_id: &u64,
                _epoch_id: &u64,
                _data_type: &str,
            ) -> Result<T, ()>;
        }

        pub struct MemoryStorage;

        impl Storage for MemoryStorage {
            fn store_data<T>(
                &mut self,
                _data: &T,
                _request_id: &u64,
                _data_type: &str,
            ) -> Result<(), ()> {
                Ok(())
            }
        }

        impl StorageExt for MemoryStorage {
            fn store_data_at_epoch<T>(
                &mut self,
                _data: &T,
                _request_id: &u64,
                _epoch_id: &u64,
                _data_type: &str,
            ) -> Result<(), ()> {
                Ok(())
            }
        }

        impl StorageReader for MemoryStorage {
            fn read_data<T>(&self, _request_id: &u64, _data_type: &str) -> Result<T, ()> {
                panic!("test fixture does not execute")
            }
        }

        impl StorageReaderExt for MemoryStorage {
            fn read_data_at_epoch<T>(
                &self,
                _request_id: &u64,
                _epoch_id: &u64,
                _data_type: &str,
            ) -> Result<T, ()> {
                panic!("test fixture does not execute")
            }
        }

        pub fn store_versioned_at_request_id<S, T>(
            storage: &mut S,
            request_id: &u64,
            data: &T,
            data_type: &str,
        ) -> Result<(), ()>
        where
            S: Storage,
        {
            storage.store_data(data, request_id, data_type)
        }

        pub fn store_versioned_at_request_and_epoch_id<S, T>(
            storage: &mut S,
            request_id: &u64,
            epoch_id: &u64,
            data: &T,
            data_type: &str,
        ) -> Result<(), ()>
        where
            S: StorageExt,
        {
            storage.store_data_at_epoch(data, request_id, epoch_id, data_type)
        }

        pub fn read_versioned_at_request_id<S, T>(
            storage: &S,
            request_id: &u64,
            data_type: &str,
        ) -> Result<T, ()>
        where
            S: StorageReader,
        {
            storage.read_data(request_id, data_type)
        }

        pub fn read_versioned_at_request_and_epoch_id<S, T>(
            storage: &S,
            request_id: &u64,
            epoch_id: &u64,
            data_type: &str,
        ) -> Result<T, ()>
        where
            S: StorageReaderExt,
        {
            storage.read_data_at_epoch(request_id, epoch_id, data_type)
        }
    }
}

struct LocalPayload {
    _value: u64,
}

struct LocalStoragePayload {
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

fn generic_storage_sink<T>(storage: &mut vault::storage::MemoryStorage, value: &T) {
    let request_id = 7;
    let _ = vault::storage::store_versioned_at_request_id(storage, &request_id, value, "generic");
}

fn storage_sinks() {
    use vault::storage::{
        MemoryStorage, read_versioned_at_request_and_epoch_id, read_versioned_at_request_id,
        store_versioned_at_request_and_epoch_id, store_versioned_at_request_id,
    };

    let mut storage = MemoryStorage;
    let request_id = 7;
    let epoch_id = 11;
    let payload = LocalStoragePayload { _value: 13 };

    let _ = store_versioned_at_request_id(&mut storage, &request_id, &payload, "payload");
    let _ = store_versioned_at_request_and_epoch_id(
        &mut storage,
        &request_id,
        &epoch_id,
        &payload,
        "payload",
    );

    let _: LocalPayload = read_versioned_at_request_id(&storage, &request_id, "payload").unwrap();
    let _: LocalStoragePayload =
        read_versioned_at_request_and_epoch_id(&storage, &request_id, &epoch_id, "payload")
            .unwrap();

    generic_storage_sink(&mut storage, &payload);
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
    storage_sinks();
}
