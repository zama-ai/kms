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
    #[cfg(feature = "non-wasm")]
    pub fn crs_gen_request(
        &self,
        request_id: &RequestId,
        max_num_bits: Option<u32>,
        param: Option<FheParameter>,
        eip712_domain: Eip712Domain,
    ) -> anyhow::Result<CrsGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => FheParameter::Default.into(),
        };
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        Ok(CrsGenRequest {
            params: parsed_param,
            max_num_bits,
            request_id: Some((*request_id).into()),
            domain: Some(alloy_to_protobuf_domain(&eip712_domain)?),
        })
    }

    /// Process a vector of CRS generation results along with a storage reader for each result.
    ///
    /// In the ideal scenario, the generated CRS should be the same
    /// for all parties. But if there are adversaries, this might not
    /// be the case. In addition to checking the digests and signatures,
    /// This function takes care of finding the CRS that is returned by
    /// the majority and ensuring that this involves agreement by at least
    /// `min_agree_count` of the parties.
    #[cfg(feature = "non-wasm")]
    pub async fn process_distributed_crs_result<S: StorageReader>(
        &self,
        request_id: &RequestId,
        res_storage: Vec<(CrsGenResult, S)>,
        min_agree_count: u32,
    ) -> anyhow::Result<CompactPkeCrs> {
        let mut verifying_pks = std::collections::HashSet::new();
        // counter of digest (digest -> usize)
        let mut hash_counter_map = HashMap::new();
        // map of digest -> public parameter
        let mut pp_map = HashMap::new();

        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let res_len = res_storage.len();
        for (result, storage) in res_storage {
            let (pp_w_id, info) = if let Some(info) = result.crs_results {
                let pp: CompactPkeCrs = storage
                    .read_data(request_id, &PubDataType::CRS.to_string())
                    .await?;
                (pp, info)
            } else {
                tracing::warn!("empty SignedPubDataHandle");
                continue;
            };

            // check the result matches our request ID
            if request_id.as_str()
                != result
                    .request_id
                    .ok_or_else(|| anyhow_error_and_log("request ID missing"))?
                    .request_id
            {
                tracing::warn!("request ID mismatch; discarding the CRS");
                continue;
            }

            // check the digest
            let hex_digest = compute_handle(&pp_w_id)?;
            if info.key_handle != hex_digest {
                tracing::warn!("crs_handle does not match the computed digest; discarding the CRS");
                continue;
            }

            // check the signature
            match self.find_verifying_public_key(&DSEP_PUBDATA_CRS, &hex_digest, &info.signature) {
                Some(pk) => {
                    verifying_pks.insert(pk);
                }
                None => {
                    tracing::warn!("Signature could not be verified for a CRS");
                    // do not insert
                    continue;
                }
            }

            // put the result in a hash map so that we can check for majority
            match hash_counter_map.get_mut(&hex_digest) {
                Some(v) => {
                    *v += 1;
                }
                None => {
                    hash_counter_map.insert(hex_digest.clone(), 1usize);
                }
            }
            pp_map.insert(hex_digest, pp_w_id);
        }

        tracing::info!(
            "CRS map contains {} entries, should contain {} entries",
            pp_map.len(),
            res_len
        );
        // find the digest that has the most votes
        let (h, c) = hash_counter_map
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .ok_or_else(|| anyhow_error_and_log("logic error: hash_counter_map is empty"))?;

        if c < min_agree_count as usize {
            return Err(anyhow_error_and_log(format!(
                "No consensus on CRS digest! {c} < {min_agree_count}"
            )));
        }

        if verifying_pks.len() < min_agree_count as usize {
            Err(anyhow_error_and_log(format!(
                "Not enough signatures on CRS results! {} < {}",
                verifying_pks.len(),
                min_agree_count
            )))
        } else {
            Ok(some_or_err(
                pp_map.remove(&h),
                "No public parameter found in the result map".to_string(),
            )?)
        }
    }

    /// Retrieve and validate a CRS based on the result from a server.
    /// The method will return the CRS if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual CRS
    /// handle.
    // NOTE: we're not checking it against the request
    // since this part of the client is only used for testing
    // see https://github.com/zama-ai/kms-core/issues/911
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_crs_resp<R: StorageReader>(
        &self,
        crs_gen_result: &CrsGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<CompactPkeCrs>> {
        let crs_info = some_or_err(
            crs_gen_result.crs_results.clone(),
            "Could not find CRS info".to_string(),
        )?;
        let request_id = some_or_err(
            crs_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?;
        let pp = self.get_crs(&request_id.into(), storage).await?;
        let crs_handle = compute_handle(&pp)?;
        if crs_handle != crs_info.key_handle {
            tracing::warn!(
                "Computed crs handle {} of retrieved crs does not match expected crs handle {}",
                crs_handle,
                crs_info.key_handle,
            );
            return Ok(None);
        }
        if self
            .verify_server_signature(&DSEP_PUBDATA_CRS, &crs_handle, &crs_info.signature)
            .is_err()
        {
            tracing::warn!(
                "Could not verify server signature for crs handle {}",
                crs_handle,
            );
            return Ok(None);
        }
        Ok(Some(pp))
    }

    /// Get a CRS from a public storage
    #[cfg(feature = "non-wasm")]
    pub async fn get_crs<R: StorageReader>(
        &self,
        crs_id: &RequestId,
        storage: &R,
    ) -> anyhow::Result<CompactPkeCrs> {
        let pp: CompactPkeCrs = storage
            .read_data(crs_id, &PubDataType::CRS.to_string())
            .await?;
        Ok(pp)
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
    pub(crate) fn verify_pp(dkg_params: &DKGParams, pp: &CompactPkeCrs) {
        let dkg_params_handle = dkg_params.get_params_basics_handle();

        let cks = tfhe::integer::ClientKey::new(dkg_params_handle.to_classic_pbs_parameters());

        // If there is indeed a dedicated compact pk, we need to generate the corresponding
        // keys to expand when encrypting later on
        let pk = if dkg_params_handle.has_dedicated_compact_pk_params() {
            // Generate the secret key PKE encrypts to
            let compact_private_key = tfhe::integer::public_key::CompactPrivateKey::new(
                dkg_params_handle.get_compact_pk_enc_params(),
            );
            // Generate the corresponding public key
            let pk = tfhe::integer::public_key::CompactPublicKey::new(&compact_private_key);
            tfhe::CompactPublicKey::from_raw_parts(pk, Tag::default())
        } else {
            let cks = cks.clone().into_raw_parts();
            let pk = tfhe::shortint::CompactPublicKey::new(&cks);
            let pk = tfhe::integer::CompactPublicKey::from_raw_parts(pk);

            tfhe::CompactPublicKey::from_raw_parts(pk, Tag::default())
        };

        let max_msg_len = pp.max_num_messages().0;
        let msgs = (0..max_msg_len)
            .map(|i| i as u64 % dkg_params_handle.get_message_modulus().0)
            .collect::<Vec<_>>();

        let metadata = vec![23_u8, 42];
        let mut compact_list_builder = ProvenCompactCiphertextList::builder(&pk);
        for msg in msgs {
            compact_list_builder.push_with_num_bits(msg, 64).unwrap();
        }
        let proven_ct = compact_list_builder
            .build_with_proof_packed(pp, &metadata, tfhe::zk::ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_ct.verify(pp, &pk, &metadata).is_valid());
    }
}
