use super::rpc_types::{
    protobuf_to_alloy_domain, BaseKms, DecryptionRequestSerializable, PrivDataType,
    ReencryptionRequestSigPayload, CURRENT_FORMAT_VERSION,
};
use crate::cryptography::central_kms::{async_decrypt, async_reencrypt, CompMap};
use crate::cryptography::central_kms::{async_generate_crs, compute_info};
use crate::kms::{KeyGenPreprocRequest, KeyGenPreprocStatus};
use crate::rpc::rpc_types::DecryptionResponseSigPayload;
use crate::storage::{store_request_id, FileStorage, PublicStorage};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log};
use crate::{
    consts::{DEFAULT_PARAM_PATH, TEST_PARAM_PATH},
    kms::RequestId,
};
use crate::{
    cryptography::central_kms::KmsFheKeyHandles,
    kms::{
        CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, FheType, KeyGenRequest,
        KeyGenResult, ParamChoice, ReencryptionRequest, ReencryptionResponse,
    },
};
use crate::{
    cryptography::central_kms::{async_generate_fhe_keys, BaseKmsStruct, SoftwareKms},
    kms::FhePubKeyInfo,
};
use crate::{
    cryptography::der_types::{PublicEncKey, PublicSigKey},
    kms::Empty,
};
use crate::{kms::coordinator_endpoint_server::CoordinatorEndpoint, rpc::rpc_types::PubDataType};
use crate::{
    kms::coordinator_endpoint_server::CoordinatorEndpointServer, util::file_handling::read_as_json,
};
use alloy_sol_types::SolStruct;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub async fn server_handle<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
>(
    socket: SocketAddr,
    public_storage: PubS,
    private_storage: PrivS,
) -> anyhow::Result<()> {
    let kms = SoftwareKms::new(public_storage, private_storage)?;
    tracing::info!("Starting centralized KMS server ...");

    Server::builder()
        .add_service(CoordinatorEndpointServer::new(kms))
        .serve(socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl<
        PubS: PublicStorage + std::marker::Sync + std::marker::Send + 'static,
        PrivS: PublicStorage + std::marker::Sync + std::marker::Send + 'static,
    > CoordinatorEndpoint for SoftwareKms<PubS, PrivS>
{
    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc on centralized kms is not suported".to_string(),
        )
    }

    async fn get_preproc_status(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc status on centralized kms is not suported".to_string(),
        )
    }

    /// starts the centralized KMS key generation
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id,
            "No request ID present in request".to_string(),
        )?;
        validate_request_id(&request_id)?;
        {
            let key_handles = self.key_handles.lock().await;
            if key_handles.contains_key(&request_id) {
                tracing::warn!(
                    "Keys with request ID {} already exist!",
                    request_id.to_string()
                );
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("Keys with request ID {} already exist!", request_id),
                ));
            }
        }

        let mut key_gen_map = self.key_gen_map.lock().await;
        if key_gen_map.contains_key(&request_id) {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!(
                    "A key generation request with request ID {} is already being processed!",
                    request_id
                ),
            ));
        }
        let params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;
        let future_keys = tokio::spawn(async_generate_fhe_keys(params));

        key_gen_map.insert(request_id, future_keys);

        Ok(Response::new(Empty {}))
    }

    /// tries to retrieve the result of a previously started key generation
    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let pub_key_handles = match self.check_key_generation_process(request_id.clone()).await {
            Ok(result) => match result {
                Some(handles) => handles,
                None => {
                    return Err(tonic::Status::new(
                        tonic::Code::Unavailable,
                        format!(
                            "The keys with request ID {} have not been generated yet, but are in progress!",
                            request_id
                        ),
                    ));
                }
            },
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Could not generate key with request ID {}!", request_id),
                ));
            }
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
        let (
            ciphertext,
            fhe_type,
            req_digest,
            client_enc_key,
            client_verf_key,
            servers_needed,
            key_id,
            request_id,
        ) = tonic_handle_potential_err(
            validate_reencrypt_req(&inner).await,
            format!("Invalid key in request {:?}", inner),
        )?;
        let mut reenc_map = self.reenc_map.lock().await;
        if reenc_map.get(&request_id).is_some() {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!(
                    "A reencryption request with request ID {} is already being processed!",
                    request_id
                ),
            ));
        }
        let key_info = self.key_handles.lock().await;
        let client_key = tonic_some_or_err(
            key_info.get(&key_id),
            format!("The request ID {} does not exist", key_id),
        )?
        .client_key
        .clone();
        let mut rng = tonic_handle_potential_err(
            self.base_kms.new_rng(),
            "Could not get handle on RNG".to_string(),
        )?;
        let sig_key = self.base_kms.sig_key.clone();
        let future_reenc = tokio::spawn(async move {
            (
                (servers_needed, fhe_type, req_digest.clone()),
                async_reencrypt::<PubS, PrivS>(
                    &client_key,
                    &sig_key,
                    &mut rng,
                    &ciphertext,
                    fhe_type,
                    &req_digest,
                    &client_enc_key,
                    &client_verf_key,
                )
                .await,
            )
        });
        reenc_map.insert(request_id, future_reenc);
        Ok(Response::new(Empty {}))
    }

    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;

        let ((servers_needed, fhe_type, req_digest), partial_dec) =
            SoftwareKms::<FileStorage, FileStorage>::process_decryption(
                &self.reenc_map,
                request_id.clone(),
            )
            .await?;

        let server_verf_key = tonic_handle_potential_err(
            to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;

        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            signcrypted_ciphertext: partial_dec,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: server_verf_key,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        tracing::info!("Received a new request!");
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, _servers_needed, key_id, request_id) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )?;
        let mut decrypt_map = self.decrypt_map.lock().await;
        if decrypt_map.get(&request_id).is_some() {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!(
                    "A decryption request with request ID {} is already being processed!",
                    request_id
                ),
            ));
        }
        let key_info = self.key_handles.lock().await;
        let client_key = tonic_some_or_err(
            key_info.get(&key_id),
            format!("The request ID {} does not exist", key_id),
        )?
        .client_key
        .clone();
        let future_plaintext = tokio::spawn(async move {
            (
                req_digest,
                async_decrypt::<PubS, PrivS>(&client_key, &ciphertext, fhe_type).await,
            )
        });

        decrypt_map.insert(request_id, future_plaintext);
        Ok(Response::new(Empty {}))
    }

    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let (req_digest, plaintext) = SoftwareKms::<FileStorage, FileStorage>::process_decryption(
            &self.decrypt_map,
            request_id.clone(),
        )
        .await?;

        let server_verf_key = tonic_handle_potential_err(
            to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;
        let sig_payload = DecryptionResponseSigPayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: 1,
            plaintext,
            verification_key: server_verf_key,
            digest: req_digest,
        };

        let sig_payload_vec = tonic_handle_potential_err(
            to_vec(&sig_payload),
            format!("Could not convert payload to bytes {:?}", sig_payload),
        )?;

        let sig = tonic_handle_potential_err(
            self.sign(&sig_payload_vec),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload.into()),
        }))
    }

    /// starts the centralized CRS generation
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_ref_or_err(
            inner.request_id.as_ref(),
            "Request ID is not set".to_string(),
        )?;
        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not valid!", request_id),
            ));
        }
        // ensure that the CRS under that handle does not exist yet
        {
            let crs_handles = self.crs_handles.lock().await;
            if crs_handles.contains_key(request_id) {
                tracing::warn!(
                    "CRS with request ID {} already exist!",
                    request_id.to_string()
                );
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("CRS with request ID {} already exist!", request_id),
                ));
            }
        }
        let mut crs_gen_map = self.crs_gen_map.lock().await;
        if crs_gen_map.get(request_id).is_some() {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!(
                    "A CRS generation request with request ID {} is already being processed!",
                    request_id
                ),
            ));
        }
        let params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;

        let rng = tonic_handle_potential_err(
            self.base_kms.new_rng(),
            "Could not generate RNG for CRS generation".to_string(),
        )?;

        let future_crs = tokio::spawn(async_generate_crs(rng, params));
        crs_gen_map.insert(request_id.clone(), future_crs);

        Ok(Response::new(Empty {}))
    }

    /// tries to retrieve a previously generated CRS
    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
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

        let crs_info = match self.check_crs_generation_process(request_id.clone()).await {
            Ok(result) => match result {
                Some(handles) => handles,
                None => {
                    return Err(tonic::Status::new(
                        tonic::Code::Unavailable,
                        format!(
                            "The CRS with request ID {} has not been generated yet, but is in progress!",
                            request_id
                        ),
                    ));
                }
            },
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Could not generate CRS with request ID {}!", request_id),
                ));
            }
        };

        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(crs_info),
        }))
    }
}

impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    SoftwareKms<PubS, PrivS>
{
    /// check if CRS for a given request ID have been generated
    ///
    /// TODO: this could be merged to some degree with [check_key_generation_process]
    async fn check_crs_generation_process(
        &self,
        request_id: RequestId,
    ) -> anyhow::Result<Option<FhePubKeyInfo>> {
        // Lock both maps since otherwise we might end up in a race condition where the handle is removed from crs_gen_map but
        // the result of the task is not stored, hence a malicious repeated call for generation could cause two processes with the
        // same request_ID to occur. Thus leading to unexpected and incorrect behaviour.
        let mut crs_handles = self.crs_handles.lock().await;
        let mut crs_gen_map = self.crs_gen_map.lock().await;
        let crs_gen_handle = crs_gen_map.remove(&request_id);
        // Handle the four different cases:
        // 1. Request ID exists and is being generated but is not finished yet
        // 2. Request ID exists and generation has finished, but not been processed yet
        // 3. Request ID exists, generation has finished and the generated keys have allready been processed
        // 4. Request ID does not exist
        // TODO add tests for each fo these cases
        match crs_gen_handle {
            Some(crs_gen_handle) => {
                if !crs_gen_handle.is_finished() {
                    // Case 1: The request ID is currently generating but not finished yet
                    // Reinsert the handle into the genration map
                    crs_gen_map.insert(request_id, crs_gen_handle);
                    return Ok(None);
                }

                // Case 2: The key generation is finished, so we can now generate the key information
                let pp = crs_gen_handle.await??;
                let crs_info = compute_info(self, &pp)?;
                // Insert the key information into the map of keys
                crs_handles.insert(request_id.clone(), crs_info.clone());
                {
                    let mut pub_storage = self.public_storage.lock().await;
                    store_request_id(
                        &mut (*pub_storage),
                        &request_id,
                        &pp,
                        &PubDataType::CRS.to_string(),
                    )?;
                }
                {
                    let mut priv_storage = self.private_storage.lock().await;
                    store_request_id(
                        &mut (*priv_storage),
                        &request_id,
                        &crs_info,
                        &PrivDataType::CrsInfo.to_string(),
                    )?;
                }
                Ok(Some(crs_info))
            }
            None => {
                match crs_handles.get(&request_id) {
                    Some(handles) => {
                        // Case 3: Request is not in crs generation map, so check if it is already done
                        Ok(Some(handles.clone()))
                    }
                    None => {
                        // Case 4: The request ID is completely unknown!
                        Err(anyhow_error_and_log(format!(
                            "The keys with request ID {} were not found!",
                            request_id
                        )))
                    }
                }
            }
        }
    }

    /// check if the key for a given request ID have been generated
    ///
    /// TODO: this could be merged to some degree with [check_crs_generation_process]
    async fn check_key_generation_process(
        &self,
        request_id: RequestId,
    ) -> anyhow::Result<Option<HashMap<PubDataType, FhePubKeyInfo>>> {
        // Lock both maps since otherwise we might end up in a race condition where the handle is removed from key_gen_map but
        // the result of the task is not stored, hence a malicious repeated call for generation could cause two processes with the
        // same request_ID to occur. Thus leading to unexpected and incorrect behaviour.
        let mut key_handles = self.key_handles.lock().await;
        let mut key_gen_map = self.key_gen_map.lock().await;
        let key_gen_handle = key_gen_map.remove(&request_id);
        // Handle the four different cases:
        // 1. Request ID exists and is being generated but is not finished yet
        // 2. Request ID exists and generation has finished, but not been processed yet
        // 3. Request ID exists, generation has finished and the generated keys have allready been processed
        // 4. Request ID does not exist
        // TODO add tests for each fo these cases
        match key_gen_handle {
            Some(key_gen_handle) => {
                if !key_gen_handle.is_finished() {
                    // Case 1: The request ID is currently generating but not finished yet
                    key_gen_map.insert(request_id, key_gen_handle);
                    return Ok(None);
                }
                // Case 2: The key generation is finished, so we can now generate the key information
                let (client_key, pub_keys) = key_gen_handle.await?;
                let new_key_info = KmsFheKeyHandles::new(self, client_key, &pub_keys)?;
                // Insert the key information into the map of keys
                key_handles.insert(request_id.clone(), new_key_info.clone());
                {
                    let mut pub_storage = self.public_storage.lock().await;
                    store_request_id(
                        &mut (*pub_storage),
                        &request_id,
                        &pub_keys.public_key,
                        &PubDataType::PublicKey.to_string(),
                    )?;
                    store_request_id(
                        &mut (*pub_storage),
                        &request_id,
                        &pub_keys.server_key,
                        &PubDataType::ServerKey.to_string(),
                    )?;
                }
                {
                    let mut priv_storage = self.private_storage.lock().await;
                    let _ = &store_request_id(
                        &mut (*priv_storage),
                        &request_id,
                        &new_key_info,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )?;
                }
                Ok(Some(new_key_info.public_key_info))
            }
            None => {
                match key_handles.get(&request_id) {
                    Some(handles) => {
                        // Case 3: Request is not in key generation map, so check if it is already done
                        Ok(Some(handles.public_key_info.clone()))
                    }
                    None => {
                        // Case 4: The request ID is completely unknown!
                        Err(anyhow_error_and_log(format!(
                            "The keys with request ID {} were not found!",
                            request_id
                        )))
                    }
                }
            }
        }
    }

    /// Process a request for getting the decryption or reencryption.
    /// Takes as input a map of decryption or reencryption processes and checks whether they are done.
    /// If they are done, it returns the result and removes them from the map, otherwise it returns an informative tonic error.
    async fn process_decryption<Aux>(
        handle_map: &CompMap<(Aux, anyhow::Result<Vec<u8>>)>,
        request_id: RequestId,
    ) -> Result<(Aux, Vec<u8>), Status> {
        // We remove the handle and thus must remember to reinsert it again if it is not fully processed
        let mut unwrapped_handle_map = handle_map.lock().await;
        let handle = unwrapped_handle_map.remove(&request_id);

        // Handle decryption based on the 3 possible cases:
        // Case 1: The request ID is currently being processed but not finished yet
        // Case 2: The request ID is finished and the result is available
        // Case 3: The request ID does not exist (either it is already completed or never existed)
        let (aux, decryption) = match handle {
            Some(inner_handle) => {
                if !inner_handle.is_finished() {
                    // Case 1: The request ID is currently being processed but not finished yet
                    // Reinsert the handle
                    unwrapped_handle_map.insert(request_id.clone(), inner_handle);
                    return Err(tonic::Status::new(
                        tonic::Code::Unavailable,
                        format!(
                            "The decryption of request with ID {} has not been generated yet, but is in progress!",
                            request_id
                        ),
                    ));
                }
                // Case 2: The request is finished
                match inner_handle.await {
                    // Everything is OK so we return the result
                    // TODO related to issue https://github.com/zama-ai/kms-core/issues/462 : we need at some point to consider caching
                    Ok((aux, Ok(result))) => (aux, result),
                    // Something went wrong with the decryption so we return an error
                    _ => {
                        tracing::error!("Could not decrypt ciphertext for request {request_id}!");
                        return Err(tonic::Status::new(
                            tonic::Code::Internal,
                            "Could not decrypt ciphertext!",
                        ));
                    }
                }
            }
            // Case 3: The request ID is not in the map. Either it has never been started or already returned.
            None => {
                return Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!(
                        "Decryption request with ID {} either never existed or no longer exists!",
                        request_id
                    ),
                ));
            }
        };
        Ok((aux, decryption))
    }
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

/// Helper method which takes a [HashMap<PubDataType, FhePubKeyInfo>] and returns
/// [HashMap<String, FhePubKeyInfo>] by applying the [ToString] function on [PubDataType] for each element in the map.
/// The function is needed since protobuf does not support enums in maps.
pub fn convert_key_response(
    key_info_map: HashMap<PubDataType, FhePubKeyInfo>,
) -> HashMap<String, FhePubKeyInfo> {
    key_info_map
        .into_iter()
        .map(|(key_type, key_info)| {
            let key_type = key_type.to_string();
            (key_type, key_info)
        })
        .collect()
}

pub(crate) fn retrieve_parameters(param_choice: i32) -> anyhow::Result<NoiseFloodParameters> {
    let param_choice = ParamChoice::try_from(param_choice)?;
    let param_path = match param_choice {
        ParamChoice::Test => TEST_PARAM_PATH,
        ParamChoice::Default => DEFAULT_PARAM_PATH,
    };
    let params: NoiseFloodParameters = read_as_json(param_path.to_owned())?;
    Ok(params)
}

/// Validates a reencryption request and returns ciphertext, FheType, request digest, client encryption key, client verification key,
/// servers_needed key_id and request_id if valid.
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
    PublicSigKey,
    u32,
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
    let key_id = tonic_some_or_err(
        payload.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    let sig_payload: ReencryptionRequestSigPayload = payload.clone().try_into()?;
    let sig_payload_serialized = to_vec(&sig_payload)?;
    let domain = protobuf_to_alloy_domain(tonic_some_ref_or_err(
        req.domain.as_ref(),
        "domain not found".to_string(),
    )?)?;
    let req_digest = sig_payload.eip712_signing_hash(&domain).to_vec();
    tonic_handle_potential_err(
        BaseKmsStruct::digest(&sig_payload_serialized),
        format!("Could not hash payload {:?}", req),
    )?;
    let fhe_type = payload.fhe_type();
    let client_verf_key: PublicSigKey = tonic_handle_potential_err(
        from_bytes(&payload.verification_key),
        format!("Invalid verification key in request {:?}", req),
    )?;
    let client_enc_key: PublicEncKey = from_bytes(&sig_payload.enc_key)?;
    if !BaseKmsStruct::verify_sig_eip712(
        &sig_payload,
        &domain,
        &from_bytes(&req.signature)?,
        &client_verf_key,
    ) {
        return Err(anyhow_error_and_warn_log(format!(
            "Could not validate signature in request {:?}",
            req
        )));
    }
    Ok((
        payload.ciphertext.clone(),
        fhe_type,
        req_digest,
        client_enc_key,
        client_verf_key,
        payload.servers_needed,
        key_id,
        request_id,
    ))
}

/// Validates a decryption request and unpacks and returns
/// the ciphertext, FheType, digest, servers_needed, key_id and request_id if it is valid.
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub(crate) fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(Vec<u8>, FheType, Vec<u8>, u32, RequestId, RequestId)> {
    let key_id = tonic_some_or_err(
        req.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    let ciphertext = req.ciphertext.clone();
    if req.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            req.version, CURRENT_FORMAT_VERSION
        )));
    }
    let fhetype = req.fhe_type();
    let req_serialized: DecryptionRequestSerializable = tonic_handle_potential_err(
        req.clone().try_into(),
        format!(
            "Could not make signature payload from protobuf request {:?}",
            req
        ),
    )?;
    let serialized_req = tonic_handle_potential_err(
        to_vec(&req_serialized),
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
    Ok((
        ciphertext,
        fhetype,
        req_digest,
        req.servers_needed,
        key_id,
        request_id,
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

/// Take the max(20, s.len()) characters of s.
fn top_n_chars(mut s: String) -> String {
    let n = std::cmp::max(s.len(), 20);
    _ = s.split_off(n);
    s
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

pub fn tonic_handle_potential_err<T, E>(
    resp: Result<T, E>,
    error: String,
) -> Result<T, tonic::Status> {
    resp.map_err(|_| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}
