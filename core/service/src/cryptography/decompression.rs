use anyhow::anyhow;
use serde::de::DeserializeOwned;
use tfhe::integer::ciphertext::Expandable;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_deserialize;
use tfhe::{CompressedCiphertextList as HLCompressedCiphertextList, Unversionize, Versionize};

use crate::anyhow_error_and_log;
use crate::consts::SAFE_SER_SIZE_LIMIT;

pub fn deserialize<T: Named + Versionize + Unversionize + DeserializeOwned>(
    bytes: &[u8],
) -> anyhow::Result<T> {
    let r = safe_deserialize::<T>(std::io::Cursor::new(bytes), SAFE_SER_SIZE_LIMIT);
    r.map_err(|err| anyhow!("{}", err))
}

pub fn from_bytes<T>(key: &Option<DecompressionKey>, bytes: &[u8]) -> anyhow::Result<T>
where
    T: Expandable + Named + Versionize + Unversionize + DeserializeOwned,
{
    // see https://github.com/zama-ai/fhevm-backend/blob/main/fhevm-engine/fhevm-engine-common/src/types.rs
    let list = match deserialize::<HLCompressedCiphertextList>(bytes) {
        Ok(list) => list,
        Err(err) => {
            tracing::info!(
                "Cannot deserialized compressed ciphertext due to: {}, fallback to non compressed",
                err
            );
            return deserialize::<T>(bytes);
        }
    };
    let (list, _tag) = list.into_raw_parts();
    if list.len() != 1 {
        return Err(anyhow_error_and_log("User compact list are not supported."));
    }
    let Some(key) = key else {
        return Err(anyhow_error_and_log("Decompression key is not configured."));
    };
    let uncompressed = match list.get::<T>(0, key) {
        Ok(Some(uncompressed)) => uncompressed,
        Ok(None) => {
            // should not happen since len was checked to be 1
            return Err(anyhow_error_and_log("No element 0 in compressed list."));
        }
        Err(err) => {
            let msg = format!("Invalid element 0 in compressed list, {}", err);
            return Err(anyhow_error_and_log(msg));
        }
    };
    anyhow::Ok(uncompressed)
}

pub mod test_tools {
    use serde::Serialize;
    use tfhe::integer::ciphertext::{CompressedCiphertextListBuilder, Compressible};
    use tfhe::integer::compression_keys::CompressionKey;
    use tfhe::named::Named;
    use tfhe::{CompressedCiphertextList as HLCompressedCiphertextList, Versionize};

    use crate::consts::SAFE_SER_SIZE_LIMIT;

    fn safe_serialize_versioned<T>(ct: &T) -> Vec<u8>
    where
        T: Serialize + Versionize + Named,
    {
        let mut serialized_ct = Vec::new();
        tfhe::safe_serialization::safe_serialize(ct, &mut serialized_ct, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        serialized_ct
    }

    pub fn compress_serialize_versioned<T>(
        ciphertext: T,
        compression_key: &CompressionKey,
    ) -> Vec<u8>
    where
        T: Versionize + Named + Compressible,
    {
        let compressed = CompressedCiphertextListBuilder::new()
            .push(ciphertext)
            .build(compression_key);
        let hl_compressed =
            HLCompressedCiphertextList::from_raw_parts(compressed, tfhe::Tag::default());
        safe_serialize_versioned(&hl_compressed)
    }
}

#[cfg(test)]
mod test {
    use crate::consts::SAFE_SER_SIZE_LIMIT;

    use super::from_bytes;
    use super::test_tools::compress_serialize_versioned;
    use tfhe::integer::bigint::StaticUnsignedBigInt;
    use tfhe::integer::ciphertext::{CompressedCiphertextListBuilder, Compressible};
    use tfhe::named::Named;
    use tfhe::prelude::{FheDecrypt, FheEncrypt};
    use tfhe::shortint::parameters::{COMP_PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_2_CARRY_2};
    use tfhe::{generate_keys, ClientKey};
    use tfhe::{
        FheBool, FheUint1024, FheUint128, FheUint16, FheUint2048, FheUint256, FheUint32, FheUint4,
        FheUint512, FheUint64, FheUint8,
    };
    use tfhe::{Unversionize, Versionize};

    use tfhe::integer::ciphertext::Expandable;
    use tfhe::CompressedCiphertextList as HLCompressedCiphertextList;

    fn max_val(num_bits: usize) -> StaticUnsignedBigInt<1> {
        StaticUnsignedBigInt::from([(2_u128.pow(num_bits as u32) - 1) as u64; 1])
    }

    #[test]
    fn test_bad_ciphertext() {
        let config = tfhe::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = None;
        let not_compressed = FheUint4::encrypt(0_u32, &client_key);
        let compressed = CompressedCiphertextListBuilder::new()
            .push(not_compressed.clone())
            .push(not_compressed)
            .build(&compression_key.unwrap());
        let hl_compressed =
            HLCompressedCiphertextList::from_raw_parts(compressed, tfhe::Tag::default());

        let mut bytes = Vec::new();
        tfhe::safe_serialization::safe_serialize(&hl_compressed, &mut bytes, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        let result = from_bytes::<FheUint4>(&decompression_key, &bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_bad_fhe_type() {
        let config = tfhe::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = server_key.clone().into_raw_parts().3;
        let not_compressed = FheUint4::encrypt(0_u32, &client_key);
        let compressed = compress_serialize_versioned(not_compressed, &compression_key.unwrap());
        let result = from_bytes::<FheUint8>(&decompression_key, &compressed);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_decomp_key() {
        let config = tfhe::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = None;
        let not_compressed = FheUint4::encrypt(0_u32, &client_key);
        let compressed = compress_serialize_versioned(not_compressed, &compression_key.unwrap());
        let result = from_bytes::<FheUint4>(&decompression_key, &compressed);
        assert!(result.is_err());
    }

    #[test]
    fn test_tolerate_non_compressed() {
        let config = tfhe::ConfigBuilder::default().build();
        let (client_key, _) = generate_keys(config);
        let clear = 15_u8;
        let not_compressed = FheUint4::encrypt(clear, &client_key);

        let mut bytes = Vec::new();
        tfhe::safe_serialization::safe_serialize(&not_compressed, &mut bytes, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        let result = from_bytes::<FheUint4>(&None, &bytes);
        assert!(result.is_ok());

        let mut bytes2 = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &result.unwrap(),
            &mut bytes2,
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        assert!(bytes2 == bytes);
    }

    #[test]
    fn test_4b() {
        test_integer_ok::<1, FheUint4>(max_val(FheUint4::num_bits()));
    }

    #[test]
    fn test_8b() {
        test_integer_ok::<1, FheUint8>(max_val(FheUint8::num_bits()));
    }

    #[test]
    fn test_16b() {
        test_integer_ok::<1, FheUint16>(max_val(FheUint16::num_bits()));
    }

    #[test]
    fn test_32b() {
        test_integer_ok::<1, FheUint32>(max_val(FheUint32::num_bits()));
    }

    #[test]
    fn test_64b() {
        test_integer_ok::<1, FheUint64>(max_val(FheUint64::num_bits()));
    }

    #[test]
    fn test_128b() {
        let clear = StaticUnsignedBigInt::from([18446744073709551615; 2]);
        test_integer_ok::<2, FheUint128>(clear);
    }

    #[test]
    fn test_256b() {
        let clear = StaticUnsignedBigInt::from([18446744073709551615; 4]);
        test_integer_ok::<4, FheUint256>(clear);
    }

    #[test]
    fn test_512b() {
        let clear = StaticUnsignedBigInt::from([18446744073709551615; 8]);
        test_integer_ok::<8, FheUint512>(clear);
    }

    #[test]
    fn test_1024b() {
        let clear = StaticUnsignedBigInt::from([18446744073709551615; 16]);
        test_integer_ok::<16, FheUint1024>(clear);
    }

    #[test]
    fn test_2048b() {
        let clear = StaticUnsignedBigInt::from([18446744073709551615; 32]);
        test_integer_ok::<32, FheUint2048>(clear);
    }

    fn test_integer_ok<
        const N: usize,
        T: Expandable
            + FheEncrypt<StaticUnsignedBigInt<N>, ClientKey>
            + FheDecrypt<StaticUnsignedBigInt<N>>
            + Clone
            + Compressible
            + serde::de::DeserializeOwned
            + serde::Serialize
            + Named
            + Versionize
            + Unversionize,
    >(
        clear_value: StaticUnsignedBigInt<N>,
    ) {
        let config = tfhe::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = server_key.clone().into_raw_parts().3;
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());
        let not_compressed = T::encrypt(clear_value, &client_key);
        let compressed = compress_serialize_versioned(not_compressed, &compression_key.unwrap());
        let result = from_bytes::<T>(&decompression_key, &compressed);
        let result = match result {
            Ok(result) => result,
            Err(err) => panic!("{:?}", err),
        };
        let decrypted: StaticUnsignedBigInt<N> = result.decrypt(&client_key);
        assert_eq!(decrypted, clear_value);
    }

    #[test]
    fn test_bool() {
        let clear_value = true;
        let config = tfhe::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = server_key.clone().into_raw_parts().3;
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());
        let not_compressed = FheBool::encrypt(clear_value, &client_key);
        let compressed = compress_serialize_versioned(not_compressed, &compression_key.unwrap());
        let result = from_bytes::<FheBool>(&decompression_key, &compressed);
        let result = match result {
            Ok(result) => result,
            Err(err) => panic!("{:?}", err),
        };
        let decrypted: bool = result.decrypt(&client_key);
        assert_eq!(decrypted, clear_value);
    }
}
