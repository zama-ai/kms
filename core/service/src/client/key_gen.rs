use crate::client::client_wasm::Client;
use crate::engine::base::compute_handle;
use crate::engine::base::DSEP_PUBDATA_KEY;
use crate::engine::validation::parse_optional_proto_request_id;
use crate::engine::validation::RequestIdParsingErr;
use crate::vault::storage::StorageReader;
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use kms_grpc::kms::v1::{
    FheParameter, KeyGenPreprocRequest, KeyGenRequest, KeyGenResult, KeySetAddedInfo, KeySetConfig,
};
use kms_grpc::rpc_types::{
    alloy_to_protobuf_domain, PubDataType, PublicKeyType, WrappedPublicKeyOwned,
};
use kms_grpc::RequestId;
use tfhe::ServerKey;
use tfhe_versionable::{Unversionize, Versionize};

impl Client {
    /// Generates a key gen request.
    ///
    /// The key generated will then be stored under the request_id handle.
    /// In the threshold case, we also need to reference the preprocessing we want to consume via
    /// its [`RequestId`] it can be set to None in the centralized case
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
    pub async fn retrieve_public_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<WrappedPublicKeyOwned>> {
        // first we need to read the key type
        let request_id = parse_optional_proto_request_id(
            &key_gen_result.request_id,
            RequestIdParsingErr::Other("invalid ID while retrieving public key".to_string()),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
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
        let request_id = parse_optional_proto_request_id(
            &key_gen_result.request_id,
            RequestIdParsingErr::Other("invalid request ID while retrieving key".to_string()),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key: S = self.get_key(&request_id, key_type, storage).await?;
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
    use crate::vault::storage::StorageReader;

    use crate::client::client_wasm::Client;
    use kms_grpc::rpc_types::PubDataType;
    use kms_grpc::RequestId;
    use tfhe::core_crypto::prelude::{
        decrypt_lwe_ciphertext, divide_round, ContiguousEntityContainer, LweCiphertextOwned,
    };
    use tfhe::prelude::ParameterSetConformant;
    use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
    use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    use tfhe::shortint::server_key::ModulusSwitchConfiguration;

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
