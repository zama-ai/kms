use super::rpc_types::{
    compute_external_pt_signature, protobuf_to_alloy_domain, BaseKms, PrivDataType,
    PublicParameterWithParamID, SignedPubDataHandleInternal, CURRENT_FORMAT_VERSION,
};
use crate::conf::centralized::CentralizedConfig;
#[cfg(any(test, feature = "testing"))]
use crate::consts::{DEFAULT_PARAM_PATH, TEST_PARAM_PATH};
use crate::cryptography::central_kms::verify_eip712;
use crate::cryptography::central_kms::{
    async_generate_crs, async_generate_fhe_keys, async_reencrypt, central_decrypt, BaseKmsStruct,
    SoftwareKms,
};
use crate::cryptography::internal_crypto_types::PublicEncKey;
use crate::cryptography::signcryption::serialize_hash_element;
use crate::kms::core_service_endpoint_server::{CoreServiceEndpoint, CoreServiceEndpointServer};
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, FheType, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenRequest,
    KeyGenResult, ParamChoice, ReencryptionRequest, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId, SignedPubDataHandle, TypedCiphertext, ZkVerifyRequest,
    ZkVerifyResponse, ZkVerifyResponsePayload,
};
use crate::rpc::rpc_types::{PubDataType, WrappedPublicKey, WrappedPublicKeyOwned};
use crate::storage::{
    delete_at_request_id, delete_pk_at_request_id, read_pk_at_request_id, store_pk_at_request_id,
    store_versioned_at_request_id,
};
use crate::storage::{read_versioned_at_request_id, Storage};
use crate::util::file_handling::read_as_json;
use crate::util::meta_store::{handle_res_mapping, HandlerStatus};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log, top_n_chars};
use alloy_primitives::Address;
use alloy_sol_types::Eip712Domain;
use conf_trace::telemetry::accept_trace;
use conf_trace::telemetry::make_span;
use conf_trace::telemetry::record_trace_id;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use tfhe::zk::CompactPkePublicParams;
use tfhe::ProvenCompactCiphertextList;
use tokio::sync::{Mutex, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tower_http::trace::TraceLayer;

pub async fn server_handle<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    config: CentralizedConfig,
    public_storage: PubS,
    private_storage: PrivS,
) -> anyhow::Result<()> {
    let socket = config.get_socket_addr()?;
    let kms = SoftwareKms::new(config.param_file_map, public_storage, private_storage).await?;
    tracing::info!("Starting centralized KMS server ...");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<CoreServiceEndpointServer<SoftwareKms<PubS, PrivS>>>()
        .await;

    let trace_request = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace)
        .map_request(record_trace_id);

    Server::builder()
        .layer(trace_request)
        .add_service(
            CoreServiceEndpointServer::new(kms)
                .max_decoding_message_size(config.grpc_max_message_size)
                .max_encoding_message_size(config.grpc_max_message_size),
        )
        .add_service(health_service)
        .serve(socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl<
        PubS: Storage + std::marker::Sync + std::marker::Send + 'static,
        PrivS: Storage + std::marker::Sync + std::marker::Send + 'static,
    > CoreServiceEndpoint for SoftwareKms<PubS, PrivS>
{
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting init on centralized kms is not suported".to_string(),
        )
    }

    #[tracing::instrument(skip(self, _request))]
    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc on centralized kms is not suported".to_string(),
        )
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_preproc_status(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc status on centralized kms is not suported".to_string(),
        )
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.key_gen(request).await
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        self.get_key_gen_result(request).await
    }

    /// starts the centralized KMS key generation
    #[tracing::instrument(skip(self, request))]
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let req_id = tonic_some_or_err(
            inner.request_id,
            "No request ID present in request".to_string(),
        )?;
        validate_request_id(&req_id)?;
        let (params, _) = tonic_handle_potential_err(
            retrieve_parameters_sync(inner.params, self.param_file_map.clone()).await,
            "Parameter choice is not recognized".to_string(),
        )?;
        {
            let mut guarded_meta_store = self.key_meta_map.write().await;
            // Insert [HandlerStatus::Started] into the meta store. Note that this will fail if the request ID is already in the meta store
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert key generation into meta store".to_string(),
            )?;
        }

        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let meta_store = Arc::clone(&self.key_meta_map);
        let fhe_keys = Arc::clone(&self.fhe_keys);
        let sk = Arc::clone(&self.base_kms.sig_key);

        let _handle = tokio::spawn(async move {
            {
                {
                    // Check if the key already exists
                    let key_handles = fhe_keys.read().await;
                    if key_handles.contains_key(&req_id) {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Error(format!(
                                "Failed key generation: Key with ID {req_id} already exists!"
                            )),
                        );
                        return;
                    }
                }
                let (fhe_key_set, key_info) = match async_generate_fhe_keys(&sk, params, None).await
                {
                    Ok((fhe_key_set, key_info)) => (fhe_key_set, key_info),
                    Err(_e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Error(format!(
                                "Failed key generation: Key with ID {req_id}!"
                            )),
                        );
                        return;
                    }
                };

                let mut pub_storage = public_storage.lock().await;
                let mut priv_storage = private_storage.lock().await;
                //Try to store the new data
                if store_versioned_at_request_id(
                    &mut (*priv_storage),
                    &req_id,
                    &key_info,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await
                .is_ok()
                    && store_pk_at_request_id(
                        &mut (*pub_storage),
                        &req_id,
                        WrappedPublicKey::Compact(&fhe_key_set.public_key),
                    )
                    .await
                    .is_ok()
                    && store_versioned_at_request_id(
                        &mut (*pub_storage),
                        &req_id,
                        &fhe_key_set.server_key,
                        &PubDataType::ServerKey.to_string(),
                    )
                    .await
                    .is_ok()
                {
                    {
                        let mut fhe_key_map = fhe_keys.write().await;
                        // If something is already in the map, then there is a bug as we already checked for the key not existing
                        fhe_key_map.insert(req_id.clone(), key_info.clone());
                    };
                    {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Done(key_info.public_key_info.to_owned()),
                        );
                    }
                } else {
                    tracing::error!("Could not store all the key data from request ID {req_id}. Deleting any dangling data.");
                    // Try to delete stored data to avoid anything dangling
                    // Ignore any failure to delete something since it might be because the data did not get created
                    // In any case, we can't do much.
                    let _ = delete_pk_at_request_id(&mut (*pub_storage), &req_id).await;
                    let _ = delete_at_request_id(
                        &mut (*pub_storage),
                        &req_id,
                        &PubDataType::ServerKey.to_string(),
                    )
                    .await;
                    let _ = delete_at_request_id(
                        &mut (*pub_storage),
                        &req_id,
                        &PubDataType::SnsKey.to_string(),
                    )
                    .await;
                    let _ = delete_at_request_id(
                        &mut (*priv_storage),
                        &req_id,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await;
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Error(format!(
                                "Failed key generation: Key with ID {req_id}, could not insert result persistant storage!"
                            )),
                        );
                }
            }
        });

        Ok(Response::new(Empty {}))
    }

    /// tries to retrieve the result of a previously started key generation
    #[tracing::instrument(skip(self, request))]
    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let pub_key_handles = {
            let guarded_meta_store = self.key_meta_map.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Key generation",
            )?
        };
        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id),
            key_results: convert_key_response(pub_key_handles),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let (ciphertext, fhe_type, link, client_enc_key, client_address, key_id, request_id) =
            tonic_handle_potential_err(
                validate_reencrypt_req(&inner).await,
                format!("Invalid key in request {:?}", inner),
            )?;
        {
            let mut guarded_meta_store = self.reenc_meta_map.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&request_id),
                "Could not insert reencryption into meta store".to_string(),
            )?;
        }

        let meta_store = Arc::clone(&self.reenc_meta_map);
        let fhe_keys = Arc::clone(&self.fhe_keys);
        let sig_key = Arc::clone(&self.base_kms.sig_key);
        let mut rng = self.base_kms.new_rng().await;

        // we do not need to hold the handle,
        // the result of the computation is tracked by the reenc_meta_store
        let _handle = tokio::spawn(async move {
            let fhe_keys_rlock = fhe_keys.read().await;
            let keys = match fhe_keys_rlock.get(&key_id) {
                Some(keys) => keys,
                None => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Error(format!(
                            "Failed reencryption: Key with ID {key_id} does not exist!"
                        )),
                    );
                    return;
                }
            };
            tracing::info!(
                "Starting reencryption using key_id {} for request ID {}",
                &key_id,
                &request_id
            );
            match async_reencrypt::<PubS, PrivS>(
                &keys.client_key,
                &sig_key,
                &mut rng,
                &ciphertext,
                fhe_type,
                &link,
                &client_enc_key,
                &client_address,
            )
            .await
            {
                Ok(raw_decryption) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Done((fhe_type, link, raw_decryption)),
                    );
                }
                Result::Err(e) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Error(format!("Failed reencryption: {e}")),
                    );
                }
            }
        });
        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;

        let (fhe_type, req_digest, partial_dec) = {
            let guarded_meta_store = self.reenc_meta_map.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Reencryption",
            )?
        };

        let server_verf_key = self.get_serialized_verf_key();
        let payload = ReencryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            signcrypted_ciphertext: partial_dec,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: server_verf_key,
            party_id: 1, // In the centralized KMS, the server ID is always 1
            degree: 0, // In the centralized KMS, the degree is always 0 since result is a constant
        };

        // sign the response
        let sig_payload_vec = tonic_handle_potential_err(
            bincode::serialize(&payload),
            format!("Could not convert payload to bytes {:?}", payload),
        )?;

        let sig = tonic_handle_potential_err(
            self.sign(&sig_payload_vec),
            format!("Could not sign payload {:?}", payload),
        )?;

        Ok(Response::new(ReencryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(payload),
        }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        tracing::info!("Received a new request!");
        let start = std::time::Instant::now();
        let inner = request.into_inner();
        tracing::info!("Request ID: {:?}", inner.request_id);
        tracing::debug!("#CTs: {}", inner.ciphertexts.len());

        let (ciphertexts, req_digest, key_id, request_id, eip712_domain, acl_address) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )?;

        tracing::info!(
            "Decrypting {:?} ciphertexts using key: {:?}",
            ciphertexts.len(),
            key_id.request_id
        );

        {
            let mut guarded_meta_store = self.dec_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&request_id),
                "Could not insert decryption into meta store".to_string(),
            )?;
        }

        let meta_store = Arc::clone(&self.dec_meta_store);
        let fhe_keys = Arc::clone(&self.fhe_keys);
        let sigkey = Arc::clone(&self.base_kms.sig_key);

        // we do not need to hold the handle,
        // the result of the computation is tracked by the dec_meta_store
        let _handle = tokio::spawn(async move {
            let fhe_keys_rlock = fhe_keys.read().await;
            let keys = match fhe_keys_rlock.get(&key_id) {
                Some(keys) => keys.clone(),
                None => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Error(format!(
                            "Failed decryption: Key with ID {key_id} does not exist!"
                        )),
                    );
                    return;
                }
            };
            tracing::info!(
                "Starting decryption using key_id {} for request ID {}",
                &key_id,
                &request_id
            );

            let ext_handles_bytes = ciphertexts
                .iter()
                .map(|c| c.external_handle.to_owned())
                .collect::<Vec<_>>();

            // run the computation in a separate rayon thread to avoid blocking the tokio runtime
            let (send, recv) = tokio::sync::oneshot::channel();
            rayon::spawn(move || {
                let decryptions = central_decrypt::<PubS, PrivS>(&keys.client_key, &ciphertexts);
                let _ = send.send(decryptions);
            });
            let decryptions = recv.await;

            match decryptions {
                Ok(Ok(pts)) => {
                    // sign the plaintexts and handles for external verification (in the fhevm)
                    let external_sig =
                        if let (Some(domain), Some(acl_address)) = (eip712_domain, acl_address) {
                            compute_external_pt_signature(
                                &sigkey,
                                ext_handles_bytes,
                                &pts,
                                domain,
                                acl_address,
                            )
                        } else {
                            vec![]
                        };

                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Done((req_digest.clone(), pts, external_sig)),
                    );
                    tracing::info!(
                        "⏱️ Core Event Time for decryption computation: {:?}",
                        start.elapsed()
                    );
                }
                Err(e) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Error(format!("Error collecting decrypt result: {:?}", e)),
                    );
                }
                Ok(Err(e)) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Error(format!("Error during decryption computation: {}", e)),
                    );
                }
            }
        });

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;

        let (req_digest, plaintexts, external_signature) = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Decryption",
            )?
        };

        // serialize plaintexts to return as payload
        let pt_payload = tonic_handle_potential_err(
            plaintexts
                .iter()
                .map(bincode::serialize)
                .collect::<Result<Vec<Vec<u8>>, _>>(),
            "Error serializing plaintexts in get_result()".to_string(),
        )?;

        let server_verf_key = self.get_serialized_verf_key();

        // the payload to be signed for verification inside the KMS
        let kms_sig_payload = DecryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            plaintexts: pt_payload,
            verification_key: server_verf_key,
            digest: req_digest,
            external_signature: Some(external_signature),
        };

        let kms_sig_payload_vec = tonic_handle_potential_err(
            bincode::serialize(&kms_sig_payload),
            format!("Could not convert payload to bytes {:?}", kms_sig_payload),
        )?;

        // sign the decryption result with the central KMS key
        let sig = tonic_handle_potential_err(
            self.sign(&kms_sig_payload_vec),
            format!("Could not sign payload {:?}", kms_sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(kms_sig_payload),
        }))
    }

    /// starts the centralized CRS generation
    #[tracing::instrument(skip(self, request))]
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(inner.request_id, "Request ID is not set".to_string())?;
        validate_request_id(&request_id)?;
        let (params, param_choice) = tonic_handle_potential_err(
            retrieve_parameters_sync(inner.params, self.param_file_map.clone()).await,
            "Parameter choice is not recognized".to_string(),
        )?;
        {
            let mut guarded_meta_store = self.crs_meta_map.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&request_id),
                "Could not insert CRS generation into meta store".to_string(),
            )?;
        }

        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let meta_store = Arc::clone(&self.crs_meta_map);
        let sk = Arc::clone(&self.base_kms.sig_key);
        let rng = self.base_kms.new_rng().await;

        let _handle = tokio::spawn(async move {
            {
                let (pp, crs_info) =
                    match async_generate_crs(&sk, rng, param_choice, params, inner.max_num_bits)
                        .await
                    {
                        Ok((pp, crs_info)) => (pp, crs_info),
                        Err(_) => {
                            let mut guarded_meta_store = meta_store.write().await;
                            let _ = guarded_meta_store.update(
                                &request_id,
                                HandlerStatus::Error(format!(
                                    "Failed CRS generation for CRS with ID {request_id}!"
                                )),
                            );
                            return;
                        }
                    };
                let mut pub_storage = public_storage.lock().await;
                let mut priv_storage = private_storage.lock().await;
                //Try to store the new data
                if store_versioned_at_request_id(
                    &mut (*priv_storage),
                    &request_id,
                    &crs_info,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await
                .is_ok()
                    && store_versioned_at_request_id(
                        &mut (*pub_storage),
                        &request_id,
                        &pp,
                        &PubDataType::CRS.to_string(),
                    )
                    .await
                    .is_ok()
                {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(&request_id, HandlerStatus::Done(crs_info));
                } else {
                    tracing::error!("Could not store all the CRS data from request ID {request_id}. Deleting any dangling data.");
                    // Try to delete stored data to avoid anything dangling
                    // Ignore any failure to delete something since it might be because the data did not get created
                    // In any case, we can't do much.
                    let _ = delete_at_request_id(
                        &mut (*pub_storage),
                        &request_id,
                        &PubDataType::CRS.to_string(),
                    )
                    .await;
                    let _ = delete_at_request_id(
                        &mut (*priv_storage),
                        &request_id,
                        &PrivDataType::CrsInfo.to_string(),
                    )
                    .await;
                    {
                        let mut guarded_meta_store = meta_store.write().await;
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Error(format!(
                                "Failed to store CRS data to public storage for ID {}",
                                request_id
                            )),
                        );
                    }
                }
            }
        });
        Ok(Response::new(Empty {}))
    }

    /// tries to retrieve a previously generated CRS
    #[tracing::instrument(skip(self, request))]
    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let crs_info = {
            let guarded_meta_store = self.crs_meta_map.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "CRS",
            )?
        };

        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(crs_info.into()),
        }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn zk_verify(
        &self,
        request: Request<ZkVerifyRequest>,
    ) -> Result<Response<Empty>, Status> {
        let meta_store = Arc::clone(&self.zk_payload_meta_map);

        // Check well-formedness of the request and return an error early if there's an error
        let request_id = request
            .get_ref()
            .request_id
            .as_ref()
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "missing request ID".to_string(),
                )
            })?
            .clone();
        validate_request_id(&request_id)?;

        let public_storage = Arc::clone(&self.public_storage);
        let param_file_map = Arc::clone(&self.param_file_map);

        non_blocking_zk_verify(
            meta_store,
            public_storage,
            param_file_map,
            request_id.clone(),
            request.into_inner(),
        )
        .await
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("non_blocking_zk_verify failed for request_id {request_id} ({e})"),
            )
        })?;

        Ok(Response::new(Empty {}))
    }

    async fn get_zk_verify_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ZkVerifyResponse>, Status> {
        let meta_store = Arc::clone(&self.zk_payload_meta_map);
        get_zk_verify_result(self, meta_store, request).await
    }
}

pub(crate) async fn non_blocking_zk_verify<PubS>(
    meta_store: Arc<RwLock<crate::util::meta_store::MetaStore<ZkVerifyResponsePayload>>>,
    public_storage: Arc<Mutex<PubS>>,
    param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>,
    request_id: RequestId,
    request: ZkVerifyRequest,
) -> anyhow::Result<()>
where
    PubS: Storage + Sync + Send + 'static,
{
    {
        let mut guarded_meta_store = meta_store.write().await;
        guarded_meta_store.insert(&request_id)?;
    }
    let _handle = tokio::spawn(async move {
        let res = zk_verify(request, public_storage, param_file_map).await;

        let mut guarded_meta_store = meta_store.write().await;
        match res {
            Ok(inner_res) => {
                tracing::debug!("storing zk result for request_id {}", request_id);
                let _ = guarded_meta_store.update(&request_id, HandlerStatus::Done(inner_res));
            }
            Err(e) => {
                let _ = guarded_meta_store.update(
                    &request_id,
                    HandlerStatus::Error(format!(
                        "Zk verification failed for ID {} with error {e}",
                        request_id
                    )),
                );
            }
        }
    });
    Ok(())
}

pub(crate) async fn get_zk_verify_result<KMS>(
    base_kms: &KMS,
    meta_store: Arc<RwLock<crate::util::meta_store::MetaStore<ZkVerifyResponsePayload>>>,
    request: Request<RequestId>,
) -> Result<Response<ZkVerifyResponse>, Status>
where
    KMS: BaseKms,
{
    let request_id = request.into_inner();
    validate_request_id(&request_id)?;
    let payload: ZkVerifyResponsePayload = {
        let guarded_meta_store = meta_store.read().await;
        handle_res_mapping(
            guarded_meta_store.retrieve(&request_id).cloned(),
            &request_id,
            "ZK",
        )?
    };

    let sig_payload_vec = tonic_handle_potential_err(
        bincode::serialize(&payload),
        format!("Could not convert payload to bytes {:?}", payload),
    )?;

    let sig = tonic_handle_potential_err(
        base_kms.sign(&sig_payload_vec),
        format!("Could not sign payload {:?}", payload),
    )?;

    Ok(Response::new(ZkVerifyResponse {
        payload: Some(payload),
        signature: sig.sig.to_vec(),
    }))
}

// NOTE: this does not have the signature
async fn zk_verify<PubS>(
    inner: ZkVerifyRequest,
    public_storage: Arc<Mutex<PubS>>,
    param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>,
) -> anyhow::Result<ZkVerifyResponsePayload>
where
    PubS: Storage + Sync + Send + 'static,
{
    let crs_handle = tonic_some_or_err(inner.crs_handle, "CRS handle is not set".to_string())?;
    validate_request_id(&crs_handle)?;

    let key_handle = tonic_some_or_err(inner.key_handle, "Key handle is not set".to_string())?;
    validate_request_id(&key_handle)?;

    let request_id = tonic_some_or_err(inner.request_id, "Key handle is not set".to_string())?;
    validate_request_id(&request_id)?;

    tracing::info!("starting proof verification for request {}", request_id);
    let proven_ct: ProvenCompactCiphertextList = bincode::deserialize(&inner.ct_bytes)
        .inspect_err(|e| {
            tracing::error!("could not deserialize the ciphertext list ({e})");
        })?;

    let pub_storage = public_storage.lock().await;
    let pp_with_id: PublicParameterWithParamID =
        read_versioned_at_request_id(&(*pub_storage), &crs_handle, &PubDataType::CRS.to_string())
            .await
            .inspect_err(|e| {
                tracing::error!("Failed to read CRS with the handle {} ({e})", crs_handle);
            })?;

    let wrapped_pk = read_pk_at_request_id(&(*pub_storage), &key_handle)
        .await
        .inspect_err(|e| {
            tracing::error!("Failed to fetch pk with handle {} ({e})", key_handle);
        })?;

    let (params, _) = retrieve_parameters_sync(pp_with_id.param_id, param_file_map.clone())
        .await
        .inspect_err(|e| {
            tracing::error!(
                "Parameter {} choice is not recognized ({e})",
                pp_with_id.param_id
            );
        })?;
    let pp = pp_with_id
        .pp
        .try_into_tfhe_zk_pok_pp(&params.ciphertext_parameters)
        .inspect_err(|e| {
            tracing::error!("could not cast pp for handle {} ({e})", crs_handle);
        })?;
    let (send, recv) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let out = verify_and_hash(&proven_ct, &pp, &wrapped_pk);
        let _ = send.send(out);
    });
    let res = recv.await.inspect_err(|e| {
        tracing::error!("channel error for key handle {} ({e})", key_handle);
    })?;

    match res {
        Ok(ct_digest) => {
            tracing::info!("finishing proof verification for request {}", request_id);
            let payload = ZkVerifyResponsePayload {
                request_id: Some(request_id),
                contract_address: inner.contract_address,
                client_address: inner.client_address,
                ct_digest,
            };

            Ok(payload)
        }
        Err(e) => {
            tracing::error!(
                "zk verification failed for ciphertext request: {} ({e})",
                request_id
            );
            Err(e)
        }
    }
}

fn verify_and_hash(
    proven_ct: &ProvenCompactCiphertextList,
    pp: &CompactPkePublicParams,
    wrapped_pk: &WrappedPublicKeyOwned,
) -> anyhow::Result<Vec<u8>> {
    match wrapped_pk {
        WrappedPublicKeyOwned::Compact(pk) => {
            if let tfhe::zk::ZkVerificationOutCome::Invalid = proven_ct.verify(pp, pk, &[]) {
                return Err(anyhow::anyhow!("zk verification failed"));
            }
        }
    }
    serialize_hash_element(proven_ct)
}

/// Validates a request ID and returns an appropriate tonic error if it is invalid.
pub(crate) fn validate_request_id(request_id: &RequestId) -> Result<(), Status> {
    if !request_id.is_valid() {
        tracing::warn!(
            "The value {} is not a valid request ID!",
            request_id.to_string()
        );
        return Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("The value {} is not a valid request ID!", request_id),
        ));
    }
    Ok(())
}

/// Helper method which takes a [HashMap<PubDataType, SignedPubDataHandle>] and returns
/// [HashMap<String, SignedPubDataHandle>] by applying the [ToString] function on [PubDataType] for each element in the map.
/// The function is needed since protobuf does not support enums in maps.
pub(crate) fn convert_key_response(
    key_info_map: HashMap<PubDataType, SignedPubDataHandleInternal>,
) -> HashMap<String, SignedPubDataHandle> {
    key_info_map
        .into_iter()
        .map(|(key_type, key_info)| {
            let key_type = key_type.to_string();
            (key_type, key_info.into())
        })
        .collect()
}

#[cfg(any(test, feature = "testing"))]
pub(crate) fn default_param_file_map() -> HashMap<String, String> {
    HashMap::from_iter(vec![
        (
            ParamChoice::as_str_name(&ParamChoice::Test).to_string(),
            TEST_PARAM_PATH.to_string(),
        ),
        (
            ParamChoice::as_str_name(&ParamChoice::Default).to_string(),
            DEFAULT_PARAM_PATH.to_string(),
        ),
    ])
}

pub(crate) async fn retrieve_parameters(
    param_choice: i32,
    param_file_map: &HashMap<ParamChoice, String>,
) -> anyhow::Result<(NoiseFloodParameters, ParamChoice)> {
    let param_choice = ParamChoice::try_from(param_choice)?;
    let param_path = param_file_map
        .get(&param_choice)
        .ok_or_else(|| anyhow::anyhow!("parameter does not exist"))?;
    let params: NoiseFloodParameters = read_as_json(param_path).await?;
    Ok((params, param_choice))
}

pub(crate) async fn retrieve_parameters_sync(
    param_choice: i32,
    param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>,
) -> anyhow::Result<(NoiseFloodParameters, ParamChoice)> {
    let guarded_map = param_file_map.read().await;
    retrieve_parameters(param_choice, &guarded_map).await
}

/// Validates a reencryption request and returns ciphertext, FheType, request digest, client
/// encryption key, client verification key, key_id and request_id if valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
pub async fn validate_reencrypt_req(
    req: &ReencryptionRequest,
) -> anyhow::Result<(
    Vec<u8>,
    FheType,
    Vec<u8>,
    PublicEncKey,
    alloy_primitives::Address,
    RequestId,
    RequestId,
)> {
    let payload = tonic_some_ref_or_err(
        req.payload.as_ref(),
        format!("The request {:?} does not have a payload", req),
    )?;
    let request_id =
        tonic_some_or_err(req.request_id.clone(), "Request ID is not set".to_string())?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "The value {} is not a valid request ID!",
            request_id
        )));
    }
    if payload.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            payload.version, CURRENT_FORMAT_VERSION
        )));
    }

    let client_verf_key =
        alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

    match verify_eip712(req) {
        Ok(()) => {
            tracing::debug!("🔒 Signature verified successfully");
        }
        Err(e) => {
            return Err(anyhow_error_and_log(format!(
                "Signature verification failed with error {e} for request: {req:?}"
            )));
        }
    }

    let ciphertext = payload
        .ciphertext
        .clone()
        .ok_or_else(|| anyhow_error_and_log(format!("Missing ciphertext in request {:?}", req)))?;
    let fhe_type = payload.fhe_type();
    let link = req.compute_link_checked()?;
    let client_enc_key: PublicEncKey = bincode::deserialize(&payload.enc_key)?;
    let key_id = tonic_some_or_err(
        payload.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    Ok((
        ciphertext,
        fhe_type,
        link,
        client_enc_key,
        client_verf_key,
        key_id,
        request_id,
    ))
}

/// Validates a decryption request and unpacks and returns
/// the ciphertext, FheType, digest, key_id and request_id if it is valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub(crate) fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    RequestId,
    RequestId,
    Option<Eip712Domain>,
    Option<Address>,
)> {
    let key_id = tonic_some_or_err(
        req.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    if req.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            req.version, CURRENT_FORMAT_VERSION
        )));
    }
    let serialized_req = tonic_handle_potential_err(
        bincode::serialize(&req),
        format!("Could not serialize payload {:?}", req),
    )?;
    let req_digest = tonic_handle_potential_err(
        BaseKmsStruct::digest(&serialized_req),
        format!("Could not hash payload {:?}", req),
    )?;
    let request_id =
        tonic_some_or_err(req.request_id.clone(), "Request ID is not set".to_string())?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "The value {} is not a valid request ID!",
            request_id
        )));
    }

    let eip712_domain = if let Some(domain) = req.domain.as_ref() {
        protobuf_to_alloy_domain(domain).ok()
    } else {
        None
    };

    let acl_address = if let Some(address) = req.acl_address.as_ref() {
        Address::from_str(address).ok()
    } else {
        None
    };

    Ok((
        req.ciphertexts.clone(),
        req_digest,
        key_id,
        request_id,
        eip712_domain,
        acl_address,
    ))
}

pub fn process_response<T: fmt::Debug>(resp: anyhow::Result<Option<T>>) -> Result<T, Status> {
    match resp {
        Ok(None) => {
            tracing::warn!("A request failed validation");
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                format!("The request failed validation: {}", resp.unwrap_err()),
            ))
        }
        Ok(Some(resp)) => Ok(resp),
        Err(e) => {
            tracing::error!("An internal error happened while handle a request: {}", e);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                format!("Internal server error: {}", e),
            ))
        }
    }
}

pub fn tonic_some_or_err<T>(input: Option<T>, error: String) -> Result<T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

pub fn tonic_some_ref_or_err<T>(input: Option<&T>, error: String) -> Result<&T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

pub fn tonic_handle_potential_err<T, E: ToString>(
    resp: Result<T, E>,
    error: String,
) -> Result<T, tonic::Status> {
    resp.map_err(|e| {
        let msg = format!("{}: {}", error, e.to_string());
        tracing::warn!(msg);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(msg))
    })
}
