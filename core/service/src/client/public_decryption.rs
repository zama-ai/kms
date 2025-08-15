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
    /// Creates a decryption request to send to the KMS servers.
    ///
    /// The key_id should be the request ID of the key generation
    /// request that generated the key which should be used for public decryption
    #[cfg(feature = "non-wasm")]
    pub fn public_decryption_request(
        &mut self,
        ciphertexts: Vec<TypedCiphertext>,
        domain: &Eip712Domain,
        request_id: &RequestId,
        key_id: &RequestId,
    ) -> anyhow::Result<PublicDecryptionRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let req = PublicDecryptionRequest {
            ciphertexts,
            key_id: Some((*key_id).into()),
            domain: Some(domain_msg),
            request_id: Some((*request_id).into()),
            extra_data: vec![],
        };
        Ok(req)
    }

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid and at least [min_agree_count] agree on the result.
    /// Returns `None` if validation fails.
    ///
    /// __NOTE__: If the original request is not provided, we can __not__ check
    /// that the response correctly contains the digest of the request.
    #[cfg(feature = "non-wasm")]
    pub fn process_decryption_resp(
        &self,
        request: Option<PublicDecryptionRequest>,
        agg_resp: &[PublicDecryptionResponse],
        min_agree_count: u32,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        use crate::engine::validation::select_most_common_public_dec;

        validate_public_decrypt_responses_against_request(
            self.get_server_pks()?,
            request,
            agg_resp,
            min_agree_count,
        )?;

        let pivot_payload = some_or_err(
            select_most_common_public_dec(min_agree_count as usize, agg_resp),
            "No elements in public decryption response".to_string(),
        )?;

        for cur_resp in agg_resp {
            let cur_payload = some_or_err(
                cur_resp.payload.to_owned(),
                "No payload in current response!".to_string(),
            )?;
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };

            // Observe that it has already been verified in [self.validate_meta_data] that server
            // verification key is in the set of permissible keys
            let cur_verf_key: PublicSigKey = bc2wrap::deserialize(&cur_payload.verification_key)?;
            BaseKmsStruct::verify_sig(
                &DSEP_PUBLIC_DECRYPTION,
                &bc2wrap::serialize(&cur_payload)?,
                &sig,
                &cur_verf_key,
            )
            .inspect_err(|e| {
                tracing::warn!("Signature on received response is not valid! {}", e);
            })?;
        }
        Ok(pivot_payload.plaintexts)
    }
}
