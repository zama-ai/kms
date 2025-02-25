use anyhow::anyhow;
use serde::de::DeserializeOwned;
use tfhe::integer::ciphertext::Expandable;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_deserialize;
use tfhe::{CompressedCiphertextList as HLCompressedCiphertextList, Unversionize, Versionize};

use crate::anyhow_error_and_log;
use crate::consts::SAFE_SER_SIZE_LIMIT;

pub fn tfhe_safe_deserialize<T: Named + Versionize + Unversionize + DeserializeOwned>(
    bytes: &[u8],
) -> anyhow::Result<T> {
    let r = safe_deserialize::<T>(std::io::Cursor::new(bytes), SAFE_SER_SIZE_LIMIT);
    r.map_err(|err| anyhow!("{}", err))
}

pub fn tfhe_safe_deserialize_and_uncompress<T>(
    key: &DecompressionKey,
    bytes: &[u8],
) -> anyhow::Result<T>
where
    T: Expandable + Named + Versionize + Unversionize + DeserializeOwned,
{
    let list = tfhe_safe_deserialize::<HLCompressedCiphertextList>(bytes)?;
    let (list, _tag) = list.into_raw_parts();
    if list.len() != 1 {
        let msg = format!("Unexpected size of compressed list: {}.", list.len());
        return Err(anyhow_error_and_log(msg));
    }
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
    use tfhe::named::Named;
    use tfhe::{CompressedCiphertextListBuilder, HlCompressible, Versionize};

    use crate::consts::SAFE_SER_SIZE_LIMIT;

    pub fn safe_serialize_versioned<T>(ct: &T) -> Vec<u8>
    where
        T: Serialize + Versionize + Named,
    {
        let mut serialized_ct = Vec::new();
        tfhe::safe_serialization::safe_serialize(ct, &mut serialized_ct, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        serialized_ct
    }

    /// Before calling this function,
    /// `server_key` needs to be set beforehand.
    pub fn compress_serialize_versioned<T>(ciphertext: T) -> Vec<u8>
    where
        T: Versionize + Named + HlCompressible,
    {
        // TODO should we trust tfhe-rs to pick the right compression key?
        let hl_compressed = CompressedCiphertextListBuilder::new()
            .push(ciphertext)
            .build()
            .unwrap();
        safe_serialize_versioned(&hl_compressed)
    }
}

#[cfg(test)]
mod test {
    use crate::consts::SAFE_SER_SIZE_LIMIT;
    use crate::cryptography::decompression::tfhe_safe_deserialize;

    use super::test_tools::{compress_serialize_versioned, safe_serialize_versioned};
    use super::tfhe_safe_deserialize_and_uncompress;
    use distributed_decryption::execution::tfhe_internals::parameters::{
        DKGParams, PARAMS_TEST_BK_SNS,
    };
    use tfhe::integer::bigint::StaticUnsignedBigInt;
    use tfhe::integer::ciphertext::Expandable;
    use tfhe::named::Named;
    use tfhe::prelude::{CiphertextList, FheDecrypt, FheEncrypt};
    use tfhe::set_server_key;
    use tfhe::shortint::parameters::{
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    };
    use tfhe::CompactPublicKey;
    use tfhe::CompressedCiphertextListBuilder;
    use tfhe::ConfigBuilder;
    use tfhe::{generate_keys, ClientKey, HlCompressible};
    use tfhe::{
        FheBool, FheUint1024, FheUint128, FheUint16, FheUint2048, FheUint256, FheUint32, FheUint4,
        FheUint512, FheUint64, FheUint8,
    };
    use tfhe::{Unversionize, Versionize};

    fn max_val(num_bits: usize) -> StaticUnsignedBigInt<1> {
        StaticUnsignedBigInt::from([(2_u128.pow(num_bits as u32) - 1) as u64; 1])
    }

    #[test]
    fn test_bad_ciphertext() {
        let config = tfhe::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        .build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);
        let not_compressed = FheUint4::encrypt(0_u32, &client_key);
        let hl_compressed = CompressedCiphertextListBuilder::new()
            .push(not_compressed.clone())
            .push(not_compressed)
            .build()
            .unwrap();

        let mut bytes = Vec::new();
        tfhe::safe_serialization::safe_serialize(&hl_compressed, &mut bytes, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        let result = tfhe_safe_deserialize::<FheUint4>(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_bad_fhe_type() {
        let config = tfhe::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        .build();
        let (client_key, server_key) = generate_keys(config);
        let decompression_key = server_key.clone().into_raw_parts().3.unwrap();
        let not_compressed = FheUint4::encrypt(0_u32, &client_key);

        set_server_key(server_key);
        let compressed = compress_serialize_versioned(not_compressed);

        let result =
            tfhe_safe_deserialize_and_uncompress::<FheUint8>(&decompression_key, &compressed);
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
        let result = tfhe_safe_deserialize::<FheUint4>(&bytes);
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
            + HlCompressible
            + serde::de::DeserializeOwned
            + serde::Serialize
            + Named
            + Versionize
            + Unversionize,
    >(
        clear_value: StaticUnsignedBigInt<N>,
    ) {
        let config = tfhe::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = server_key.clone().into_raw_parts().3;
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());
        let not_compressed = T::encrypt(clear_value, &client_key);

        set_server_key(server_key);
        let compressed = compress_serialize_versioned(not_compressed);

        let result =
            tfhe_safe_deserialize_and_uncompress::<T>(&decompression_key.unwrap(), &compressed);
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
        let config = tfhe::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        .build();
        let (client_key, server_key) = generate_keys(config);
        let compression_key = server_key.clone().into_raw_parts().2;
        let decompression_key = server_key.clone().into_raw_parts().3;
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());
        let not_compressed = FheBool::encrypt(clear_value, &client_key);

        set_server_key(server_key);
        let compressed = compress_serialize_versioned(not_compressed);

        let result = tfhe_safe_deserialize_and_uncompress::<FheBool>(
            &decompression_key.unwrap(),
            &compressed,
        );
        let result = match result {
            Ok(result) => result,
            Err(err) => panic!("{:?}", err),
        };
        let decrypted: bool = result.decrypt(&client_key);
        assert_eq!(decrypted, clear_value);
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[test]
    fn test_full_chain_client_copro_kms_uint8(#[case] default_config: bool) {
        let config = if default_config {
            ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
                .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
                .build()
        } else {
            let DKGParams::WithSnS(params) = PARAMS_TEST_BK_SNS else {
                panic!("");
            };
            ConfigBuilder::with_custom_parameters(params.regular_params.ciphertext_parameters)
                .enable_compression(
                    params
                        .regular_params
                        .compression_decompression_parameters
                        .unwrap(),
                )
                .use_dedicated_compact_public_key_parameters(
                    params
                        .regular_params
                        .dedicated_compact_public_key_parameters
                        .unwrap(),
                )
                .build()
        };
        let (client_key, server_key) = generate_keys(config);
        let clear_value = 255_u8;
        let decompression_key = server_key.clone().into_raw_parts().3;
        let compression_key = server_key.clone().into_raw_parts().2;
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());
        set_server_key(server_key.clone());

        // CLIENT like part
        let compact_key = CompactPublicKey::new(&client_key);
        let mut builder = tfhe::ProvenCompactCiphertextList::builder(&compact_key);
        let not_compressed = builder.push(clear_value).build();

        // COPRO like part
        let expander = not_compressed.expand().unwrap();
        // TODO: use verify_and_expand instead
        let not_compressed = expander.get::<FheUint8>(0).unwrap().unwrap();
        let not_compressed = not_compressed.reverse_bits();
        let compressed = CompressedCiphertextListBuilder::new()
            .push(not_compressed.clone())
            .build()
            .unwrap();
        let compressed = safe_serialize_versioned(&compressed);

        // KMS like part
        let result = tfhe_safe_deserialize_and_uncompress::<FheUint8>(
            &decompression_key.unwrap(),
            &compressed,
        );
        let result = match result {
            Ok(result) => result,
            Err(err) => panic!("{:?}", err),
        };
        let decrypted: u8 = result.decrypt(&client_key);

        assert_eq!(decrypted, clear_value.reverse_bits());
    }
}
