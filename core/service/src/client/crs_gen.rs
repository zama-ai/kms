use std::collections::HashMap;

use crate::client::client_wasm::Client;
use crate::engine::base::safe_serialize_hash_element_versioned;
use crate::engine::base::DSEP_PUBDATA_CRS;
use crate::engine::validation::parse_optional_proto_request_id;
use crate::engine::validation::RequestIdParsingErr;
use crate::vault::storage::StorageReader;
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use kms_grpc::kms::v1::{CrsGenRequest, CrsGenResult, FheParameter};
use kms_grpc::rpc_types::{alloy_to_protobuf_domain, PubDataType};
use kms_grpc::solidity_types::CrsgenVerification;
use kms_grpc::RequestId;
use tfhe::zk::CompactPkeCrs;
use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;

impl Client {
    pub fn crs_gen_request(
        &self,
        request_id: &RequestId,
        max_num_bits: Option<u32>,
        param: Option<FheParameter>,
        eip712_domain: &Eip712Domain,
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
            domain: Some(alloy_to_protobuf_domain(eip712_domain)?),
            context_id: None,
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
    pub async fn process_distributed_crs_result<S: StorageReader>(
        &self,
        request_id: &RequestId,
        res_storage: Vec<(CrsGenResult, S)>,
        domain: &Eip712Domain,
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
            let pp: CompactPkeCrs = storage
                .read_data(request_id, &PubDataType::CRS.to_string())
                .await?;

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
            let actual_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &pp)?;
            if result.crs_digest != actual_digest {
                tracing::warn!("crs_handle does not match the computed digest; discarding the CRS");
                continue;
            }

            let max_num_bits = max_num_bits_from_crs(&pp);

            // check the signature
            match self.find_verifying_address(
                &CrsgenVerification::new(request_id, max_num_bits, actual_digest.clone()),
                domain,
                &result.external_signature,
            ) {
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
            match hash_counter_map.get_mut(&actual_digest) {
                Some(v) => {
                    *v += 1;
                }
                None => {
                    hash_counter_map.insert(actual_digest.clone(), 1usize);
                }
            }
            pp_map.insert(actual_digest, pp);
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
    pub async fn process_get_crs_resp<R: StorageReader>(
        &self,
        crs_gen_result: &CrsGenResult,
        domain: &Eip712Domain,
        storage: &R,
    ) -> anyhow::Result<Option<CompactPkeCrs>> {
        let request_id = parse_optional_proto_request_id(
            &crs_gen_result.request_id,
            RequestIdParsingErr::Other("invalid request ID while processing CRS".to_string()),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let pp = self.get_crs(&request_id, storage).await?;
        let actual_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &pp)?;
        if actual_digest != crs_gen_result.crs_digest {
            tracing::warn!(
                "Computed crs handle {} of retrieved crs does not match expected crs handle {}",
                hex::encode(&actual_digest),
                hex::encode(&crs_gen_result.crs_digest),
            );
            return Ok(None);
        }

        let max_num_bits = max_num_bits_from_crs(&pp);
        if self
            .verify_external_signature(
                &CrsgenVerification::new(&request_id, max_num_bits, actual_digest.clone()),
                domain,
                &crs_gen_result.external_signature,
            )
            .is_err()
        {
            tracing::warn!(
                "Could not verify server signature for crs handle {}",
                hex::encode(&actual_digest),
            );
            return Ok(None);
        }
        Ok(Some(pp))
    }

    /// Get a CRS from a public storage
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
    use tfhe::zk::CompactPkeCrs;
    use tfhe::ProvenCompactCiphertextList;
    use tfhe::Tag;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;

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
