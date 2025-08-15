use super::*;
use crate::cryptography::internal_crypto_types::{
    PrivateSigKey, PublicSigKey, SigncryptionKeyPair, SigncryptionPrivKey, SigncryptionPubKey,
    UnifiedPrivateEncKey, UnifiedSigncryptionKeyPair, UnifiedSigncryptionKeyPairOwned,
};
use crate::cryptography::internal_crypto_types::{Signature, UnifiedPublicEncKey};
use crate::cryptography::signcryption::{
    decrypt_signcryption_with_link, insecure_decrypt_ignoring_signature, internal_verify_sig,
};
use crate::engine::validation::{
    check_ext_user_decryption_signature, validate_user_decrypt_responses_against_request,
    DSEP_USER_DECRYPTION,
};
use crate::{anyhow_error_and_log, some_or_err};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
#[cfg(feature = "non-wasm")]
use futures_util::future::{try_join_all, TryFutureExt};
use itertools::Itertools;
use kms_grpc::kms::v1::{
    TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse, UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::{fhe_types_to_num_blocks, UserDecryptionLinker};
use rand::SeedableRng;
use std::collections::HashMap;
use std::num::Wrapping;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::FheTypes;
use threshold_fhe::algebra::base_ring::{Z128, Z64};
use threshold_fhe::algebra::error_correction::MemoizedExceptionals;
use threshold_fhe::algebra::galois_rings::degree_4::ResiduePolyF4;
use threshold_fhe::algebra::structure_traits::{BaseRing, ErrorCorrect, Ring};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::endpoints::reconstruct::{
    combine_decryptions, reconstruct_packed_message,
};
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::sharing::shamir::{
    fill_indexed_shares, reconstruct_w_errors_sync, ShamirSharings,
};
use threshold_fhe::execution::tfhe_internals::parameters::{
    AugmentedCiphertextParameters, DKGParams,
};
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::consts::SAFE_SER_SIZE_LIMIT;
        use crate::consts::{DEFAULT_PROTOCOL, DEFAULT_URL, MAX_TRIES};
        use crate::cryptography::signcryption::ephemeral_encryption_key_generation;
        use crate::engine::base::compute_handle;
        use crate::engine::base::BaseKmsStruct;
        use crate::engine::base::DSEP_PUBDATA_CRS;
        use crate::engine::base::DSEP_PUBDATA_KEY;
        use crate::engine::traits::BaseKms;
        use crate::engine::validation::validate_public_decrypt_responses_against_request;
        use crate::engine::validation::DSEP_PUBLIC_DECRYPTION;
        use crate::vault::storage::{
            crypto_material::{
                get_client_signing_key, get_client_verification_key, get_core_verification_key,
            },
            Storage, StorageReader,
        };
        use kms_grpc::kms::v1::{
            CrsGenRequest, CrsGenResult, FheParameter, KeyGenPreprocRequest, KeyGenRequest, KeyGenResult,
            KeySetAddedInfo, KeySetConfig, PublicDecryptionRequest, PublicDecryptionResponse,
            TypedCiphertext,
        };
        use kms_grpc::rpc_types::{
            alloy_to_protobuf_domain, PubDataType, PublicKeyType, WrappedPublicKeyOwned,
        };
        use kms_grpc::RequestId;
        use std::fmt;
        use tfhe::zk::CompactPkeCrs;
        use tfhe::ServerKey;
        use tfhe_versionable::{Unversionize, Versionize};
        use threshold_fhe::hashing::DomainSep;
        use tonic::transport::Channel;
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::pb::HealthCheckRequest;
        use tonic_health::ServingStatus;
    }
}

impl Client {
    /// Generates a key gen request.
    ///
    /// The key generated will then be stored under the request_id handle.
    /// In the threshold case, we also need to reference the preprocessing we want to consume via
    /// its [`RequestId`] it can be set to None in the centralized case
    #[cfg(feature = "non-wasm")]
    pub fn key_gen_request(
        &self,
        request_id: &RequestId,
        preproc_id: Option<RequestId>,
        param: Option<FheParameter>,
        keyset_config: Option<KeySetConfig>,
        keyset_added_info: Option<KeySetAddedInfo>,
        eip712_domain: Eip712Domain,
    ) -> anyhow::Result<KeyGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => FheParameter::Default.into(),
        };
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let prep_id = preproc_id.map(|res| res.into());
        Ok(KeyGenRequest {
            params: parsed_param,
            preproc_id: prep_id,
            request_id: Some((*request_id).into()),
            domain: Some(alloy_to_protobuf_domain(&eip712_domain)?),
            keyset_config,
            keyset_added_info,
        })
    }

    // NOTE: we're not checking it against the request
    // since this part of the client is only used for testing
    // see https://github.com/zama-ai/kms-core/issues/911
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_key_gen_resp<R: StorageReader>(
        &self,
        resp: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<(WrappedPublicKeyOwned, ServerKey)> {
        let pk = some_or_err(
            self.retrieve_public_key(resp, storage).await?,
            "Could not validate public key".to_string(),
        )?;
        let server_key: ServerKey = match self.retrieve_server_key(resp, storage).await? {
            Some(server_key) => server_key,
            None => {
                return Err(anyhow_error_and_log("Could not validate server key"));
            }
        };
        Ok((pk, server_key))
    }

    #[cfg(feature = "non-wasm")]
    pub fn preproc_request(
        &self,
        request_id: &RequestId,
        param: Option<FheParameter>,
        keyset_config: Option<KeySetConfig>,
    ) -> anyhow::Result<KeyGenPreprocRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        Ok(KeyGenPreprocRequest {
            params: param.unwrap_or_default().into(),
            keyset_config,
            request_id: Some((*request_id).into()),
        })
    }

    /// Retrieve and validate a server key based on the result from storage.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_server_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<ServerKey>> {
        if let Some(server_key) = self
            .retrieve_key(key_gen_result, PubDataType::ServerKey, storage)
            .await?
        {
            Ok(Some(server_key))
        } else {
            Ok(None)
        }
    }

    /// Retrieve and validate a public key based on the result from storage.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_public_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<WrappedPublicKeyOwned>> {
        // first we need to read the key type
        let request_id = some_or_err(
            key_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?
        .into();
        tracing::debug!(
            "getting public key metadata using storage {} with request id {}",
            storage.info(),
            &request_id
        );
        let pk_type: PublicKeyType = crate::vault::storage::read_versioned_at_request_id(
            storage,
            &request_id,
            &PubDataType::PublicKeyMetadata.to_string(),
        )
        .await?;
        tracing::debug!(
            "getting wrapped public key using storage {} with request id {}",
            storage.info(),
            &request_id
        );
        let wrapped_pk = match pk_type {
            PublicKeyType::Compact => self
                .retrieve_key(key_gen_result, PubDataType::PublicKey, storage)
                .await?
                .map(WrappedPublicKeyOwned::Compact),
        };
        Ok(wrapped_pk)
    }

    /// Retrieve and validate a decompression key based on the result from storage.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_decompression_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<tfhe::integer::compression_keys::DecompressionKey>> {
        let decompression_key = self
            .retrieve_key(key_gen_result, PubDataType::DecompressionKey, storage)
            .await?;
        Ok(decompression_key)
    }

    #[cfg(feature = "non-wasm")]
    pub(crate) async fn retrieve_key<
        S: serde::de::DeserializeOwned
            + serde::Serialize
            + Versionize
            + Unversionize
            + tfhe::named::Named
            + Send,
        R: StorageReader,
    >(
        &self,
        key_gen_result: &KeyGenResult,
        key_type: PubDataType,
        storage: &R,
    ) -> anyhow::Result<Option<S>> {
        let pki = some_or_err(
            key_gen_result.key_results.get(&key_type.to_string()),
            format!("Could not find key of type {key_type}"),
        )?;
        let request_id = some_or_err(
            key_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?;
        let key: S = self.get_key(&request_id.into(), key_type, storage).await?;
        let key_handle = compute_handle(&key)?;
        if key_handle != pki.key_handle {
            tracing::warn!(
                "Computed key handle {} of retrieved key does not match expected key handle {}",
                key_handle,
                pki.key_handle,
            );
            return Ok(None);
        }
        if self
            .verify_server_signature(&DSEP_PUBDATA_KEY, &key_handle, &pki.signature)
            .is_err()
        {
            tracing::warn!(
                "Could not verify server signature for key handle {}",
                key_handle,
            );
            return Ok(None);
        }
        Ok(Some(key))
    }

    /// Get a key from a public storage depending on the data type
    #[cfg(feature = "non-wasm")]
    pub(crate) async fn get_key<
        S: serde::de::DeserializeOwned + Unversionize + tfhe::named::Named + Send,
        R: StorageReader,
    >(
        &self,
        key_id: &RequestId,
        key_type: PubDataType,
        storage: &R,
    ) -> anyhow::Result<S> {
        storage.read_data(key_id, &key_type.to_string()).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::test_tools::ServerHandle;
    use super::Client;
    use crate::client::test_tools::check_port_is_closed;
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingUserDecryptionTranscript;
    use crate::client::{await_server_ready, get_health_client, get_status};
    use crate::client::{ParsedUserDecryptionRequest, ServerIdentities};
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::consts::DEFAULT_PARAM;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::consts::MAX_TRIES;
    use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
    use crate::consts::{DEFAULT_AMOUNT_PARTIES, TEST_CENTRAL_KEY_ID};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_KEY_ID_4P};
    use crate::consts::{DEFAULT_THRESHOLD, TEST_THRESHOLD_KEY_ID_10P};
    use crate::consts::{PRSS_INIT_REQ_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID};
    use crate::cryptography::internal_crypto_types::{PrivateSigKey, Signature};
    use crate::cryptography::internal_crypto_types::{
        UnifiedPrivateEncKey, UnifiedPublicEncKey, WrappedDKGParams,
    };
    use crate::dummy_domain;
    use crate::engine::base::{compute_handle, derive_request_id, BaseKmsStruct, DSEP_PUBDATA_CRS};
    #[cfg(feature = "slow_tests")]
    use crate::engine::centralized::central_kms::tests::get_default_keys;
    use crate::engine::centralized::central_kms::RealCentralizedKms;
    use crate::engine::threshold::service::RealThresholdKms;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::engine::threshold::service::ThresholdFheKeys;
    use crate::engine::traits::BaseKms;
    use crate::engine::validation::DSEP_USER_DECRYPTION;
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::max_threshold;
    use crate::util::key_setup::test_tools::{
        compute_cipher_from_stored_key, purge, EncryptionConfig, TestingPlaintext,
    };
    use crate::util::rate_limiter::RateLimiterConfig;
    use crate::vault::storage::crypto_material::get_core_signing_key;
    #[cfg(feature = "insecure")]
    use crate::vault::storage::delete_all_at_request_id;
    use crate::vault::storage::{file::FileStorage, StorageType};
    use crate::vault::storage::{make_storage, StorageReader};
    use crate::vault::Vault;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use kms_grpc::kms::v1::CrsGenRequest;
    use kms_grpc::kms::v1::{
        Empty, FheParameter, InitRequest, KeySetAddedInfo, KeySetConfig, KeySetType,
        TypedCiphertext, TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse,
    };
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
    use kms_grpc::rpc_types::{fhe_types_to_num_blocks, PrivDataType};
    use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType};
    use kms_grpc::RequestId;
    use serial_test::serial;
    use std::collections::{hash_map::Entry, HashMap};
    use std::str::FromStr;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use std::sync::Arc;
    use tfhe::core_crypto::prelude::{
        decrypt_lwe_ciphertext, divide_round, ContiguousEntityContainer, LweCiphertextOwned,
    };
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use tfhe::integer::compression_keys::DecompressionKey;
    use tfhe::prelude::ParameterSetConformant;
    use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
    use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
    use tfhe::shortint::server_key::ModulusSwitchConfiguration;
    use tfhe::zk::CompactPkeCrs;
    use tfhe::Tag;
    use tfhe::{FheTypes, ProvenCompactCiphertextList};
    use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
    use threshold_fhe::execution::runtime::party::Role;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
    #[cfg(feature = "wasm_tests")]
    use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
    use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;
    use threshold_fhe::networking::grpc::GrpcServer;
    use tokio::task::JoinSet;
    use tonic::server::NamedService;
    use tonic::transport::Channel;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::HealthCheckRequest;

    // Time to sleep to ensure that previous servers and tests have shut down properly.
    const TIME_TO_SLEEP_MS: u64 = 500;

    pub(crate) fn check_conformance(server_key: tfhe::ServerKey, client_key: tfhe::ClientKey) {
        let pbs_params = client_key.computation_parameters();
        let int_server_key: &tfhe::integer::ServerKey = server_key.as_ref();
        let shortint_server_key: &tfhe::shortint::ServerKey = int_server_key.as_ref();
        let max_degree = shortint_server_key.max_degree; // we don't really check the max degree
        assert!(shortint_server_key.is_conformant(&(pbs_params, max_degree)));

        match &shortint_server_key.atomic_pattern {
            AtomicPatternServerKey::Standard(atomic_pattern) => {
                match &atomic_pattern.bootstrapping_key {
                    tfhe::shortint::server_key::ShortintBootstrappingKey::Classic {
                        bsk: _bsk,
                        modulus_switch_noise_reduction_key,
                    } => {
                        match modulus_switch_noise_reduction_key {
                            // Check that we can decrypt this key to 0
                            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(key) => {
                                let zeros_ct = &key.modulus_switch_zeros;
                                let (
                                    client_key,
                                    _compact_client_key,
                                    _compression_key,
                                    _noise_squashing_key,
                                    _noise_squashing_compression_key,
                                    _tag,
                                ) = client_key.into_raw_parts();

                                let client_key = client_key.into_raw_parts().atomic_pattern;

                                //NOTE: Small workaround to cope with tfhe-rs change to the ClientKey decryption
                                //to fetch the key based on the ctxt's PBSOrder and not the key's EncryptionKeyChoice
                                let lwe_secret_key = if let AtomicPatternClientKey::Standard(
                                    client_key,
                                ) = client_key
                                {
                                    let (_, lwe_sk, _, _) = client_key.into_raw_parts();
                                    lwe_sk
                                } else {
                                    panic!("Expected Standard AtomicPatternClientKey");
                                };

                                let message_space_size = pbs_params.message_modulus().0
                                    * pbs_params.carry_modulus().0
                                    * 2;
                                let delta = 1u64 << (u64::BITS - (message_space_size).ilog2());
                                // We need to make a reference ciphertext to convert
                                // the zero ciphertexts into a Ciphertext Type
                                for ct in zeros_ct.iter() {
                                    let ctt = LweCiphertextOwned::from_container(
                                        ct.into_container().to_vec(),
                                        ct.ciphertext_modulus(),
                                    );

                                    let pt = decrypt_lwe_ciphertext(&lwe_secret_key, &ctt);
                                    // This is enough as this is expected to be a fresh encryption of 0
                                    let pt = divide_round(pt.0, delta) % message_space_size;
                                    assert_eq!(pt, 0);
                                }
                            }
                            //In case of Standard or CenteredMeanNoiseReduction, we don't have a modulus switch key so do nothing
                            ModulusSwitchConfiguration::Standard => {}
                            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => {}
                        }
                    }
                    _ => panic!("expected classic bsk"),
                }
            }
            AtomicPatternServerKey::KeySwitch32(_) => {
                panic!("Unsuported AtomicPatternServerKey::KeySwitch32")
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsuported AtomicPatternServerKey::Dynamic")
            }
        }
    }

    // check that the server keys stored under the IDs `key_id_base` and `key_id_with_sns_compression`
    // are identical except for the sns compression key
    pub(crate) async fn identical_keys_except_sns_compression_from_storage<R: StorageReader>(
        internal_client: &Client,
        storage: &R,
        key_id_base: &RequestId,
        key_id_with_sns_compression: &RequestId,
    ) {
        let server_key_base: tfhe::ServerKey = internal_client
            .get_key(key_id_base, PubDataType::ServerKey, storage)
            .await
            .unwrap();

        let server_key_sns: tfhe::ServerKey = internal_client
            .get_key(key_id_with_sns_compression, PubDataType::ServerKey, storage)
            .await
            .unwrap();

        identical_keys_except_sns_compression(server_key_base, server_key_sns).await
    }

    // check that the two keys are identical except for the sns compression key
    pub(crate) async fn identical_keys_except_sns_compression(
        server_key_base: tfhe::ServerKey,
        server_key_sns: tfhe::ServerKey,
    ) {
        let server_key_base_parts = server_key_base.into_raw_parts();
        let server_key_sns_parts = server_key_sns.into_raw_parts();

        // 5 should be sns compression
        assert!(server_key_sns_parts.5.is_some());

        // we can't compare keys directly, so we serialize them
        assert_eq!(
            bc2wrap::serialize(&server_key_base_parts.0).unwrap(),
            bc2wrap::serialize(&server_key_sns_parts.0).unwrap()
        );

        assert_ne!(
            bc2wrap::serialize(&server_key_base_parts.5).unwrap(),
            bc2wrap::serialize(&server_key_sns_parts.5).unwrap(),
        )
    }
}
