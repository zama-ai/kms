use std::io::Cursor;

use crate::client::client_wasm::Client;
use crate::engine::base::DSEP_PUBDATA_KEY;
use crate::engine::base::safe_serialize_hash_element_versioned;
use crate::engine::validation::RequestIdParsingErr;
use crate::engine::validation::parse_optional_grpc_request_id;
use crate::vault::storage::StorageReader;
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use hashing::SAFE_SER_SIZE_LIMIT;
use hashing::hash_element;
use kms_grpc::ContextId;
use kms_grpc::RequestId;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::NewMpcEpochRequest;
use kms_grpc::kms::v1::PreviousEpochInfo;
use kms_grpc::kms::v1::{
    FheParameter, KeyGenPreprocRequest, KeyGenPreprocResult, KeyGenRequest, KeyGenResult,
    KeySetAddedInfo, KeySetConfig,
};
use kms_grpc::rpc_types::{PubDataType, alloy_to_protobuf_domain};
use kms_grpc::solidity_types::{KeygenVerification, PrepKeygenVerification};
use tfhe::CompactPublicKey;
use tfhe::ServerKey;
use tfhe::safe_serialization::safe_deserialize;
use tfhe_versionable::{Unversionize, Versionize};

impl Client {
    /// Generates a key gen request.
    ///
    /// The key generated will then be stored under the request_id handle.
    /// We need to reference the preprocessing we want to consume via
    /// its [`RequestId`]. In theory this is not needed in the centralized case
    /// but we still require it so that it is consistent with the threshold case.
    #[allow(clippy::too_many_arguments)]
    pub fn key_gen_request(
        &self,
        request_id: &RequestId,
        preproc_id: &RequestId,
        context_id: Option<&ContextId>,
        epoch_id: Option<&EpochId>,
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
        if !preproc_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The preprocessing id format is not valid {preproc_id}"
            )));
        }

        Ok(KeyGenRequest {
            params: Some(parsed_param),
            preproc_id: Some((*preproc_id).into()),
            request_id: Some((*request_id).into()),
            domain: Some(alloy_to_protobuf_domain(&eip712_domain)?),
            keyset_config,
            keyset_added_info,
            context_id: context_id.map(|id| (*id).into()),
            epoch_id: epoch_id.map(|id| (*id).into()),
            extra_data: vec![],
        })
    }

    pub fn preproc_request(
        &self,
        request_id: &RequestId,
        param: Option<FheParameter>,
        context_id: Option<&ContextId>,
        epoch_id: Option<&EpochId>,
        keyset_config: Option<KeySetConfig>,
        domain: &Eip712Domain,
    ) -> anyhow::Result<KeyGenPreprocRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain = alloy_to_protobuf_domain(domain)?;

        Ok(KeyGenPreprocRequest {
            params: param.unwrap_or_default().into(),
            keyset_config,
            request_id: Some((*request_id).into()),
            context_id: context_id.map(|id| (*id).into()),
            domain: Some(domain),
            epoch_id: epoch_id.map(|id| (*id).into()),
        })
    }

    #[cfg(feature = "insecure")]
    #[allow(clippy::too_many_arguments)]
    pub fn partial_preproc_request(
        &self,
        request_id: &RequestId,
        param: Option<FheParameter>,
        context_id: Option<&ContextId>,
        epoch_id: Option<&EpochId>,
        keyset_config: Option<KeySetConfig>,
        domain: &Eip712Domain,
        partial_params: Option<kms_grpc::kms::v1::PartialKeyGenPreprocParams>,
    ) -> anyhow::Result<kms_grpc::kms::v1::PartialKeyGenPreprocRequest> {
        let base_request = self.preproc_request(
            request_id,
            param,
            context_id,
            epoch_id,
            keyset_config,
            domain,
        )?;

        Ok(kms_grpc::kms::v1::PartialKeyGenPreprocRequest {
            base_request: Some(base_request),
            partial_params,
        })
    }

    pub fn new_epoch_request(
        &self,
        to_context_id: &ContextId,
        to_epoch_id: &EpochId,
        previous_epoch: Option<PreviousEpochInfo>,
        domain: Option<&Eip712Domain>,
    ) -> anyhow::Result<NewMpcEpochRequest> {
        Ok(NewMpcEpochRequest {
            context_id: Some((*to_context_id).into()),
            epoch_id: Some((*to_epoch_id).into()),
            previous_epoch,
            domain: domain.map(alloy_to_protobuf_domain).transpose()?,
        })
    }

    pub fn process_preproc_response(
        &self,
        preproc_id: &RequestId,
        domain: &Eip712Domain,
        resp: &KeyGenPreprocResult,
    ) -> anyhow::Result<()> {
        let sol_type = PrepKeygenVerification::new(preproc_id);
        let req_id_from_resp = parse_optional_grpc_request_id(
            &resp.preprocessing_id,
            RequestIdParsingErr::Other("cannot parse preprocessing ID".to_string()),
        )?;
        if *preproc_id != req_id_from_resp {
            return Err(anyhow_error_and_log(format!(
                "Preprocessing ID in preprocessing result {} does not match the provided preprocessing ID {}",
                req_id_from_resp, preproc_id
            )));
        }

        self.verify_external_signature(&sol_type, domain, &resp.external_signature)
    }

    // TODO(zama-ai/kms-internal#2727)
    // this only checks the signature is valid against one of the server addresses
    // we should fix it so that it does a proper verification
    pub async fn retrieve_server_key_and_public_key<R: StorageReader>(
        &self,
        preproc_id: &RequestId,
        key_id: &RequestId,
        key_gen_result: &KeyGenResult,
        domain: &Eip712Domain,
        _extra_data: Vec<u8>,
        storage: &R,
    ) -> anyhow::Result<(ServerKey, CompactPublicKey)> {
        let req_id = parse_optional_grpc_request_id(
            &key_gen_result.request_id,
            RequestIdParsingErr::Other("invalid request id".into()),
        )?;
        let srv_data_type = PubDataType::ServerKey.to_string();
        let pbl_data_type = PubDataType::PublicKey.to_string();
        let (srvk_bytes, pblk_bytes) = tokio::try_join!(
            storage.load_bytes(&req_id, &srv_data_type),
            storage.load_bytes(&req_id, &pbl_data_type),
        )?;
        let server_key_digest = hash_element(&DSEP_PUBDATA_KEY, &srvk_bytes);
        let public_key_digest = hash_element(&DSEP_PUBDATA_KEY, &pblk_bytes);

        let expected_server_key_digest = key_gen_result.key_digests.first().ok_or_else(|| {
            anyhow::anyhow!(
                "Server key digest not found in key generation result for key ID {}",
                key_id
            )
        })?;
        assert_eq!(
            expected_server_key_digest.key_type,
            PubDataType::ServerKey.to_string(),
            "Expected a ServerKey key type for the first key digest, got {}",
            expected_server_key_digest.key_type
        );
        let expected_public_key_digest = key_gen_result.key_digests.get(1).ok_or_else(|| {
            anyhow::anyhow!(
                "Public key digest not found in key generation result for key ID {}",
                key_id
            )
        })?;
        assert_eq!(
            expected_public_key_digest.key_type,
            PubDataType::PublicKey.to_string(),
            "Expected a PublicKey key type for the second key digest, got {}",
            expected_public_key_digest.key_type
        );

        if server_key_digest != *expected_server_key_digest.digest {
            return Err(anyhow::anyhow!(
                "Computed server key digest {} of retrieved server key does not match expected key handle {}",
                hex::encode(&server_key_digest),
                hex::encode(&expected_server_key_digest.digest),
            ));
        }
        if public_key_digest != *expected_public_key_digest.digest {
            return Err(anyhow::anyhow!(
                "Computed public key digest {} of retrieved public key does not match expected key handle {}",
                hex::encode(&public_key_digest),
                hex::encode(&expected_public_key_digest.digest),
            ));
        }

        let actual_preproc_id: RequestId = some_or_err(
            key_gen_result.preprocessing_id.clone(),
            "Key generation result does not contain a preprocessing ID".to_string(),
        )?
        .try_into()?;

        let actual_key_id: RequestId = some_or_err(
            key_gen_result.request_id.clone(),
            "Key generation result does not contain a request ID".to_string(),
        )?
        .try_into()?;

        if *preproc_id != actual_preproc_id {
            return Err(anyhow::anyhow!(
                "Preprocessing ID in key generation result does not match the provided preprocessing ID"
            ));
        }

        if *key_id != actual_key_id {
            return Err(anyhow::anyhow!(
                "Key ID in key generation result does not match the provided key ID"
            ));
        }

        let sol_type = KeygenVerification::new_uncompressed(
            preproc_id,
            key_id,
            server_key_digest,
            public_key_digest,
            // TODO: reenable for RFC005
            // extra_data,
        );

        self.verify_external_signature(&sol_type, domain, &key_gen_result.external_signature)?;
        let server_key = safe_deserialize(Cursor::new(&srvk_bytes), SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let public_key = safe_deserialize(Cursor::new(&pblk_bytes), SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok((server_key, public_key))
    }

    /// Retrieve a compressed keyset and its associated CompactPublicKey from storage.
    /// This method retrieves the `CompressedXofKeySet` and the `CompactPublicKey`, verifies
    /// that both digests match those in `key_gen_result.key_digests`, and verifies the
    /// EIP712 signature over both digests.
    ///
    /// Note: when the compressed keyset was produced by a migration keygen (UseExisting),
    /// the stored CompactPublicKey is the OLD one from the prior keyset rather than the one
    /// obtained by decompressing the new compressed keyset. Callers that want the signed
    /// public key should use the one returned here, not one derived from the keyset.
    pub async fn retrieve_compressed_keyset<R: StorageReader>(
        &self,
        preproc_id: &RequestId,
        key_id: &RequestId,
        key_gen_result: &KeyGenResult,
        domain: &Eip712Domain,
        _extra_data: Vec<u8>,
        storage: &R,
    ) -> anyhow::Result<(tfhe::xof_key_set::CompressedXofKeySet, CompactPublicKey)> {
        let (compressed_keyset, compressed_keyset_digest): (
            tfhe::xof_key_set::CompressedXofKeySet,
            Vec<u8>,
        ) = self
            .retrieve_key_no_verification(key_gen_result, PubDataType::CompressedXofKeySet, storage)
            .await?;

        let (compact_public_key, public_key_digest): (CompactPublicKey, Vec<u8>) = self
            .retrieve_key_no_verification(key_gen_result, PubDataType::PublicKey, storage)
            .await?;

        let actual_preproc_id: RequestId = some_or_err(
            key_gen_result.preprocessing_id.clone(),
            "Key generation result does not contain a preprocessing ID".to_string(),
        )?
        .try_into()?;

        let actual_key_id: RequestId = some_or_err(
            key_gen_result.request_id.clone(),
            "Key generation result does not contain a request ID".to_string(),
        )?
        .try_into()?;

        if *preproc_id != actual_preproc_id {
            return Err(anyhow::anyhow!(
                "Preprocessing ID in key generation result does not match the provided preprocessing ID"
            ));
        }

        if *key_id != actual_key_id {
            return Err(anyhow::anyhow!(
                "Key ID in key generation result does not match the provided key ID"
            ));
        }

        let sol_type = KeygenVerification::new_compressed(
            preproc_id,
            key_id,
            compressed_keyset_digest,
            public_key_digest,
            // TODO: reenable for RFC005
            // extra_data,
        );

        self.verify_external_signature(&sol_type, domain, &key_gen_result.external_signature)?;

        Ok((compressed_keyset, compact_public_key))
    }

    /// Retrieve and validate a decompression key based on the result from storage.
    /// Returns an error if the stored key's digest does not match the digest in
    /// `key_gen_result.key_digests`.
    pub async fn retrieve_decompression_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<tfhe::integer::compression_keys::DecompressionKey> {
        let (decompression_key, _digest) = self
            .retrieve_key_no_verification(key_gen_result, PubDataType::DecompressionKey, storage)
            .await?;
        Ok(decompression_key)
    }

    pub(crate) async fn retrieve_key_no_verification<
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
    ) -> anyhow::Result<(S, Vec<u8>)> {
        let mut key_digests = key_gen_result.key_digests.clone();
        let key_type_s = key_type.to_string();
        let key_digest = key_digests
            .extract_if(.., |kd| kd.key_type == key_type_s)
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("Key type {key_type} not found in key generation result")
            })?;

        let request_id = parse_optional_grpc_request_id(
            &key_gen_result.request_id,
            RequestIdParsingErr::Other("invalid request ID while retrieving key".to_string()),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let key: S = self.get_key(&request_id, key_type, storage).await?;
        let actual_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &key)?;

        if actual_digest != *key_digest.digest {
            return Err(anyhow::anyhow!(
                "Computed {key_type} digest {} does not match expected digest {}",
                hex::encode(&actual_digest),
                hex::encode(&key_digest.digest),
            ));
        }
        Ok((key, actual_digest))
    }

    /// Get a key from a public storage depending on the data type
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
    use tfhe::core_crypto::prelude::{
        ContiguousEntityContainer, LweCiphertextOwned, decrypt_lwe_ciphertext, divide_round,
    };
    use tfhe::prelude::{ParameterSetConformant, Tagged};
    use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
    use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    use tfhe::shortint::server_key::ModulusSwitchConfiguration;

    pub(crate) fn check_conformance(server_key: tfhe::ServerKey, client_key: tfhe::ClientKey) {
        let pbs_params = client_key.computation_parameters();
        let int_server_key: &tfhe::integer::ServerKey = server_key.as_ref();
        let shortint_server_key: &tfhe::shortint::ServerKey = int_server_key.as_ref();
        let max_degree = shortint_server_key.max_degree; // we don't really check the max degree
        assert!(shortint_server_key.is_conformant(&(pbs_params, max_degree)));
        assert_eq!(server_key.tag(), client_key.tag());

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
                                    _rerand_parameters,
                                    _oprf_private_key,
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
}
