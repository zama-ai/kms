use super::rpc_types::{BaseKms, DecryptionRequestSerializable, ReencryptionRequestSigPayload};
use crate::anyhow_error_and_warn_log;
use crate::core::der_types::{PublicEncKey, PublicSigKey};
use crate::core::kms_core::{
    generate_fhe_keys, BaseKmsStruct, FheKeys, FhePublicKeySet, SignedFhePublicKeySet, SoftwareKms,
    SoftwareKmsKeys,
};
use crate::file_handling::read_as_json;
use crate::kms::kms_endpoint_server::{KmsEndpoint, KmsEndpointServer};
use crate::kms::{
    DecryptionRequest, DecryptionResponse, FheType, GetAllKeysRequest, GetAllKeysResponse,
    GetKeyRequest, KeyGenRequest, KeyResponse, ParamChoice, ReencryptionRequest,
    ReencryptionResponse,
};
use crate::rpc::rpc_types::{DecryptionResponseSigPayload, Kms};
use crate::setup_rpc::{DEFAULT_PARAM_PATH, KEY_PATH_PREFIX, TEST_PARAM_PATH};
use distributed_decryption::{file_handling::write_element, lwe::ThresholdLWEParameters};
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::{fmt, fs};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use url::Url;

pub static CURRENT_FORMAT_VERSION: u32 = 1;

pub async fn server_handle(url_str: &str, kms_keys: SoftwareKmsKeys) -> anyhow::Result<()> {
    let url = Url::parse(url_str)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(anyhow::anyhow!(
            "Invalid scheme in URL. Only http and https are supported."
        ));
    }
    let host_str = url.host_str().ok_or("Invalid host in URL.");
    let port = url.port_or_known_default().ok_or("Invalid port in URL.");
    let socket: SocketAddr = format!("{}:{}", host_str.unwrap(), port.unwrap()).parse()?;

    let kms = SoftwareKms::new(kms_keys.fhe_keys, kms_keys.sig_sk);
    tracing::info!("Starting centralized KMS server ...");
    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl KmsEndpoint for SoftwareKms {
    async fn key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<KeyResponse>, Status> {
        let inner = request.into_inner();
        if !validate_user_input(&inner.key_handle) {
            tracing::warn!("Key handle {} is not allowed!", inner.key_handle);
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Key handle {} is not allowed!", inner.key_handle),
            ));
        }
        if keys_exists(&inner.key_handle) {
            tracing::warn!("Keys with handle {} already exist!", inner.key_handle);
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!("Keys with handle {} already exist!", inner.key_handle),
            ));
        }
        let params = handle_potential_err(
            retrieve_paramters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;
        let keys = generate_fhe_keys(params);
        let pk_uri = handle_potential_err(
            store_keys(self, &keys, &inner.key_handle),
            format!("Failed to store generated keys from request {:?}", inner),
        )?;
        let mut fhe_keys = handle_potential_err(
            self.fhe_keys.lock(),
            "Could not get handle on fhe keys".to_string(),
        )?;
        fhe_keys.insert(inner.key_handle, keys);
        Ok(Response::new(KeyResponse { key_uri: pk_uri }))
    }

    async fn get_all_keys(
        &self,
        _request: Request<GetAllKeysRequest>,
    ) -> Result<Response<GetAllKeysResponse>, Status> {
        let fhe_keys = handle_potential_err(
            self.fhe_keys.lock(),
            "Could not get handle on fhe keys".to_string(),
        )?;
        let all_keys = handle_potential_err(
            get_all_key_uris(&fhe_keys),
            "Could not get the URIs for all keys".to_string(),
        )?;
        Ok(Response::new(GetAllKeysResponse { handles: all_keys }))
    }

    async fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> Result<Response<KeyResponse>, Status> {
        let inner = request.into_inner();
        if !validate_user_input(&inner.key_handle) {
            tracing::warn!("Key handle {} is not allowed!", inner.key_handle);
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Key handle {} is not allowed!", inner.key_handle),
            ));
        }
        if !keys_exists(&inner.key_handle) {
            tracing::warn!("Keys with handle {} does not exist!", inner.key_handle);
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("Keys with handle {} does not exist!", inner.key_handle),
            ));
        }
        Ok(Response::new(KeyResponse {
            key_uri: pub_key_path(&inner.key_handle),
        }))
    }

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
            key_handle,
        ) = handle_potential_err(
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
            &key_handle,
        ))?;
        // Observe that shares_needed should be part of the signcrypted response or request to
        // ensure a single server cannot default to a single share
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: handle_potential_err(
                to_vec(&self.get_verf_key()),
                "Could not serialize server verification key".to_string(),
            )?,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        tracing::info!("Received a new request!");
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, servers_needed, key_handle) = handle_potential_err(
            validate_decrypt_req(&inner).await,
            format!("Invalid key in request {:?}", inner),
        )?;
        let plaintext = handle_potential_err(
            Kms::decrypt(self, &ciphertext, fhe_type, &key_handle),
            format!("Decryption failed for request {:?}", inner),
        )?;
        let plaintext_bytes = handle_potential_err(
            to_vec(&plaintext),
            format!(
                "Could not convert plaintext to bytes in request {:?}",
                inner
            ),
        )?;
        let server_verf_key = handle_potential_err(
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
        let sig = handle_potential_err(
            self.sign(&sig_payload),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload.into()),
        }))
    }
}

pub fn pub_key_path(key_handle: &str) -> String {
    format!("{}/{}-public.bin", KEY_PATH_PREFIX, key_handle)
}

pub fn priv_key_path(key_handle: &str) -> String {
    format!("{}/{}-private.bin", KEY_PATH_PREFIX, key_handle)
}

fn keys_exists(key_handle: &str) -> bool {
    let private_key_path = pub_key_path(key_handle);
    let public_key_path = priv_key_path(key_handle);
    Path::new(&private_key_path).exists() || Path::new(&public_key_path).exists()
}

/// Store generated keys by writing them to the file system and returning the path of the public
/// keys. Note that this is only for developer version for a more secure deployment without Nitro
/// keys should instead be stored in environment variables.
fn store_keys<K: BaseKms>(kms: &K, keys: &FheKeys, key_handle: &str) -> anyhow::Result<String> {
    fs::create_dir_all(KEY_PATH_PREFIX)?;
    let private_key_path = format!("{}/{}-private.bin", KEY_PATH_PREFIX, key_handle);
    write_element(private_key_path, &keys.client_key)?;
    let pk_keys: FhePublicKeySet = keys.try_into()?;
    let signed_pks = SignedFhePublicKeySet::new(pk_keys, kms)?;
    let public_key_path = format!("{}/{}-public.bin", KEY_PATH_PREFIX, key_handle);
    write_element(public_key_path.clone(), &signed_pks)?;
    Ok(public_key_path)
}

fn get_all_key_uris(
    fhe_keys: &HashMap<String, FheKeys>,
) -> anyhow::Result<HashMap<String, String>> {
    let mut res = HashMap::with_capacity(fhe_keys.len());
    for key_handle in fhe_keys.keys() {
        res.insert(key_handle.to_string(), pub_key_path(key_handle));
    }
    Ok(res)
}

fn retrieve_paramters(param_choice: i32) -> anyhow::Result<ThresholdLWEParameters> {
    let param_choice = ParamChoice::try_from(param_choice)?;
    let param_path = match param_choice {
        ParamChoice::Test => TEST_PARAM_PATH,
        ParamChoice::Default => DEFAULT_PARAM_PATH,
    };
    let params: ThresholdLWEParameters = read_as_json(param_path.to_owned())?;
    Ok(params)
}

/// Validates if a user-specified string is valid.
/// By valid we mean if it is alphanumeric. This is done to ensure it can be part of a valid
/// path, without risk of path-traversal attacks.
fn validate_user_input(input: &str) -> bool {
    for cur_char in input.chars() {
        if !cur_char.is_ascii_alphanumeric() {
            return false;
        }
    }
    true
}

/// Returns ciphertext, FheType, digest, client encryption key, client verification key,
/// servers_needed key_handle.
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key is needed.
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
    let payload = some_or_err(
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
    let req_digest = handle_potential_err(
        BaseKmsStruct::digest(&sig_payload_serialized),
        format!("Could not hash payload {:?}", req),
    )?;
    let fhe_type = payload.fhe_type();
    let client_verf_key: PublicSigKey = handle_potential_err(
        from_bytes(&payload.verification_key),
        format!("Invalid verification key in request {:?}", req),
    )?;
    let client_enc_key: PublicEncKey = from_bytes(&sig_payload.enc_key)?;
    if !BaseKmsStruct::verify_sig(&sig_payload, &from_bytes(&req.signature)?, &client_verf_key) {
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
        payload.key_handle,
    ))
}

/// Returns ciphertext, FheType, digest, servers_needed, key_handle
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key is needed.
pub async fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(Vec<u8>, FheType, Vec<u8>, u32, String)> {
    let key_handle = req.key_handle.clone();
    let ciphertext = req.ciphertext.clone();
    if req.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            req.version, CURRENT_FORMAT_VERSION
        )));
    }
    let fhetype = req.fhe_type();
    let req_serialized: DecryptionRequestSerializable = handle_potential_err(
        req.clone().try_into(),
        format!(
            "Could not make signature payload from protobuf request {:?}",
            req
        ),
    )?;
    let serialized_req = handle_potential_err(
        to_vec(&req_serialized),
        format!("Could not serialize payload {:?}", req),
    )?;
    let req_digest = handle_potential_err(
        BaseKmsStruct::digest(&serialized_req),
        format!("Could not hash payload {:?}", req),
    )?;
    Ok((
        ciphertext,
        fhetype,
        req_digest,
        req.servers_needed,
        key_handle,
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

pub fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> Result<T, Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}

pub fn handle_potential_err<T, E>(resp: Result<T, E>, error: String) -> Result<T, Status> {
    resp.map_err(|_| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}
