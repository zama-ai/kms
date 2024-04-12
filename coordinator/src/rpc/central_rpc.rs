use super::rpc_types::{
    protobuf_to_alloy_domain, BaseKms, DecryptionRequestSerializable,
    ReencryptionRequestSigPayload, CURRENT_FORMAT_VERSION,
};
use crate::storage::PublicStorage;
use crate::{
    anyhow_error_and_log,
    cryptography::central_kms::{
        async_generate_fhe_keys, gen_centralized_crs, BaseKmsStruct, CrsHashMap, SoftwareKms,
        SoftwareKmsKeys,
    },
    kms::FhePubKeyInfo,
};
use crate::{anyhow_error_and_warn_log, storage::DevStorage};
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
    cryptography::der_types::{PublicEncKey, PublicSigKey},
    kms::Empty,
};
use crate::{kms::coordinator_endpoint_server::CoordinatorEndpoint, rpc::rpc_types::PubDataType};
use crate::{
    kms::coordinator_endpoint_server::CoordinatorEndpointServer, util::file_handling::read_as_json,
};
use crate::{
    rpc::rpc_types::{DecryptionResponseSigPayload, Kms},
    storage::store_public_keys,
};
use aes_prng::AesRng;
use alloy_sol_types::SolStruct;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use rand::SeedableRng;
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub async fn server_handle(
    socket: SocketAddr,
    kms_keys: SoftwareKmsKeys,
    crs_store: Option<CrsHashMap>,
) -> anyhow::Result<()> {
    let storage = DevStorage::default();
    let kms = SoftwareKms::new(storage, kms_keys.key_info, kms_keys.sig_sk, crs_store);
    tracing::info!("Starting centralized KMS server ...");

    Server::builder()
        .add_service(CoordinatorEndpointServer::new(kms))
        .serve(socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl<S: PublicStorage + std::marker::Sync + std::marker::Send + 'static> CoordinatorEndpoint
    for SoftwareKms<S>
{
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set".to_string(),
        )?;
        // TODO validate that the request ID is valid
        if tonic_handle_potential_err(
            self.storage.data_exits(&request_id, PubDataType::PublicKey),
            "Could not validate if the public key exist".to_string(),
        )? || tonic_handle_potential_err(
            self.storage.data_exits(&request_id, PubDataType::ServerKey),
            "Could not validate if the server key exist".to_string(),
        )? || tonic_handle_potential_err(
            self.storage.data_exits(&request_id, PubDataType::SnsKey),
            "Could not validate if the SnS key exist".to_string(),
        )? {
            tracing::warn!(
                "Keys with request ID {} already exist!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!("Keys withrequest ID {} already exist!", request_id),
            ));
        }
        let params = tonic_handle_potential_err(
            retrieve_paramters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;
        let future_keys = tokio::spawn(async_generate_fhe_keys(params));
        let mut key_gen_map = tonic_handle_potential_err(
            self.key_gen_map.lock(),
            "Could not get handle on key generation map".to_string(),
        )?;
        key_gen_map.insert(request_id.to_string(), future_keys);

        Ok(Response::new(Empty {}))
    }

    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
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
        let pub_key_handles = match self.process_key_generation(request_id.clone()).await {
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

    // TODO also make async
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let inner = request.into_inner();
        let (
            ciphertext,
            fhe_type,
            req_digest,
            client_enc_key,
            client_verf_key,
            servers_needed,
            key_id,
        ) = tonic_handle_potential_err(
            validate_reencrypt_req(&inner).await,
            format!("Invalid key in request {:?}", inner),
        )?;
        let return_cipher = process_response(Kms::reencrypt(
            self,
            &ciphertext,
            fhe_type,
            &req_digest,
            &client_enc_key,
            &client_verf_key,
            &key_id,
        ))?;
        // Observe that shares_needed should be part of the signcrypted response or request to
        // ensure a single server cannot default to a single share
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: tonic_handle_potential_err(
                to_vec(&self.get_verf_key()),
                "Could not serialize server verification key".to_string(),
            )?,
        }))
    }

    // TODO also make async
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        tracing::info!("Received a new request!");
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, servers_needed, key_handle) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner).await,
                format!("Invalid key in request {:?}", inner),
            )?;
        let plaintext = tonic_handle_potential_err(
            Kms::decrypt(self, &ciphertext, fhe_type, &key_handle),
            format!("Decryption failed for request {:?}", inner),
        )?;
        let plaintext_bytes = tonic_handle_potential_err(
            to_vec(&plaintext),
            format!(
                "Could not convert plaintext to bytes in request {:?}",
                inner
            ),
        )?;
        let server_verf_key = tonic_handle_potential_err(
            to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;
        let sig_payload = DecryptionResponseSigPayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            plaintext: plaintext_bytes,
            verification_key: server_verf_key,
            digest: req_digest,
        };
        let sig = tonic_handle_potential_err(
            self.sign(&sig_payload),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload.into()),
        }))
    }

    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        // TODO update in same manner as key generation
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
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
        if tonic_handle_potential_err(
            self.storage.data_exits(&request_id, PubDataType::CRS),
            "Could not validate the existance of the CRS".to_string(),
        )? {
            tracing::warn!(
                "A CRS with request ID {} already exist - cannot create it again!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!(
                    "A CRS with request ID {} already exist - cannot create it again!",
                    request_id
                ),
            ));
        }

        let params = tonic_handle_potential_err(
            retrieve_paramters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;

        // generate the CRS
        let mut rng = AesRng::from_entropy();
        let crs = gen_centralized_crs(&params, &mut rng);

        // let _crs_uri = tonic_handle_potential_err(
        //     store_crs(self, &crs, &request_id),
        //     format!("Failed to store CRS from request {:?}", inner),
        // )?;

        let mut crs_store = tonic_handle_potential_err(
            self.crs_store.lock(),
            "Could not get handle for storing CRS".to_string(),
        )?;
        crs_store.insert(request_id.to_string(), crs);

        Ok(Response::new(Empty {}))
    }

    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
        // TODO update in same manner as key generation
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not allowed!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not allowed!", request_id),
            ));
        }
        if !tonic_handle_potential_err(
            self.storage.data_exits(&request_id, PubDataType::CRS),
            "Could not check if CRS exists".to_string(),
        )? {
            tracing::warn!(
                "CRS with request ID {} does not exist!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("CRS with request ID {} does not exist!", request_id),
            ));
        }
        todo!()
        // Ok(Response::new(CrsGenResult {
        //     request_id: todo!(),
        //     crs_uri: todo!(),
        //     crs_handle: todo!(),
        //     signature: todo!(),
        // }))
    }
}

impl<S: PublicStorage> SoftwareKms<S> {
    async fn process_key_generation(
        &self,
        request_id: RequestId,
    ) -> anyhow::Result<Option<HashMap<PubDataType, FhePubKeyInfo>>> {
        let key_gen_handle = {
            let mut key_gen_map = self
                .key_gen_map
                .lock()
                .map_err(|e| anyhow::anyhow!(format!("Could not get key generation map: {}", e)))?;
            key_gen_map.remove(&request_id.to_string())
        };
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
                    {
                        // Reinsert the handle
                        let mut key_gen_map = self.key_gen_map.lock().map_err(|e| {
                            anyhow::anyhow!(format!("Could not get key generation map: {}", e))
                        })?;
                        key_gen_map.insert(request_id.to_string(), key_gen_handle);
                    }
                    return Ok(None);
                }
                // Case 2: The key generation is finished, so we can now generate the key information
                let (client_key, pub_keys) = key_gen_handle.await?;
                let new_key_info = KmsFheKeyHandles::new(self, client_key, &pub_keys)?;
                // Insert the key information into the map of keys
                {
                    let mut key_handles = self
                        .key_handles
                        .lock()
                        .map_err(|e| anyhow::anyhow!(format!("Could not get client map: {}", e)))?;
                    key_handles.insert(request_id.to_string(), new_key_info.clone());
                }
                store_public_keys(
                    &self.storage,
                    request_id,
                    &new_key_info.public_key_info,
                    &pub_keys,
                )?;
                Ok(Some(new_key_info.public_key_info))
            }
            None => {
                let key_handles = self
                    .key_handles
                    .lock()
                    .map_err(|e| anyhow::anyhow!(format!("Could not get client map: {}", e)))?;
                match key_handles.get(&request_id.to_string()) {
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

fn retrieve_paramters(param_choice: i32) -> anyhow::Result<NoiseFloodParameters> {
    let param_choice = ParamChoice::try_from(param_choice)?;
    let param_path = match param_choice {
        ParamChoice::Test => TEST_PARAM_PATH,
        ParamChoice::Default => DEFAULT_PARAM_PATH,
    };
    let params: NoiseFloodParameters = read_as_json(param_path.to_owned())?;
    Ok(params)
}

/// Returns ciphertext, FheType, digest, client encryption key, client verification key,
/// servers_needed key_handle.
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
    String,
)> {
    let payload = tonic_some_or_err(
        req.payload.clone(),
        format!("The request {:?} does not have a payload", req),
    )?;
    if payload.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            payload.version, CURRENT_FORMAT_VERSION
        )));
    }
    let sig_payload: ReencryptionRequestSigPayload = payload.clone().try_into()?;
    let sig_payload_serialized = to_vec(&sig_payload)?;
    let domain = protobuf_to_alloy_domain(&tonic_some_or_err(
        req.domain.clone(),
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
        payload.ciphertext,
        fhe_type,
        req_digest,
        client_enc_key,
        client_verf_key,
        payload.servers_needed,
        payload.key_id,
    ))
}

/// Returns ciphertext, FheType, digest, servers_needed, key_id.
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
pub async fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(Vec<u8>, FheType, Vec<u8>, u32, String)> {
    let key_id = req.key_id.clone();
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
    Ok((ciphertext, fhetype, req_digest, req.servers_needed, key_id))
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

pub fn tonic_some_or_err<T: fmt::Debug>(
    input: Option<T>,
    error: String,
) -> Result<T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}

pub fn tonic_handle_potential_err<T, E>(
    resp: Result<T, E>,
    error: String,
) -> Result<T, tonic::Status> {
    resp.map_err(|_| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}
