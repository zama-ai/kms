use super::rpc_types::{
    protobuf_to_alloy_domain, BaseKms, DecryptionRequestSerializable,
    ReencryptionRequestSigPayload, CURRENT_FORMAT_VERSION,
};
use crate::anyhow_error_and_warn_log;
use crate::consts::{CRS_PATH_PREFIX, DEFAULT_PARAM_PATH, KEY_PATH_PREFIX, TEST_PARAM_PATH};
use crate::core::der_types::{PublicEncKey, PublicSigKey};
use crate::core::kms_core::{
    gen_centralized_crs, generate_fhe_keys, BaseKmsStruct, CrsHashMap, SignedCRS,
    SignedFhePublicKeySet, SoftwareKms, SoftwareKmsKeys,
};
use crate::file_handling::read_as_json;
use crate::kms::kms_endpoint_server::{KmsEndpoint, KmsEndpointServer};
use crate::kms::{
    CrsCeremonyRequest, CrsHandle, CrsResponse, DecryptionRequest, DecryptionResponse, FheType,
    GetAllKeysRequest, GetAllKeysResponse, GetKeyRequest, KeyGenRequest, KeyResponse, ParamChoice,
    ReencryptionRequest, ReencryptionResponse,
};
use crate::rpc::rpc_types::{DecryptionResponseSigPayload, Kms};
use crate::setup_rpc::FhePrivateKey;
use aes_prng::AesRng;
use alloy_sol_types::SolStruct;
use distributed_decryption::{
    execution::{
        endpoints::keygen::PubKeySet, tfhe_internals::parameters::NoiseFloodParameters,
        zk::ceremony::PublicParameter,
    },
    file_handling::write_element,
};
use rand::SeedableRng;
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::{fmt, fs};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub async fn server_handle(
    socket: SocketAddr,
    kms_keys: SoftwareKmsKeys,
    crs_store: Option<CrsHashMap>,
) -> anyhow::Result<()> {
    let kms = SoftwareKms::new(kms_keys.client_keys, kms_keys.sig_sk, crs_store);
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
        let params = tonic_handle_potential_err(
            retrieve_paramters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;
        let (client_key, pub_keys) = generate_fhe_keys(params);
        let pk_uri = tonic_handle_potential_err(
            store_keys(self, &client_key, &pub_keys, &inner.key_handle),
            format!("Failed to store generated keys from request {:?}", inner),
        )?;
        let mut client_key_map = tonic_handle_potential_err(
            self.client_keys.lock(),
            "Could not get handle on fhe keys".to_string(),
        )?;
        client_key_map.insert(inner.key_handle, client_key);
        Ok(Response::new(KeyResponse { key_uri: pk_uri }))
    }

    async fn get_all_keys(
        &self,
        _request: Request<GetAllKeysRequest>,
    ) -> Result<Response<GetAllKeysResponse>, Status> {
        let client_keys = tonic_handle_potential_err(
            self.client_keys.lock(),
            "Could not get handle on fhe keys".to_string(),
        )?;
        let all_keys = tonic_handle_potential_err(
            get_all_key_uris(&client_keys),
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
            verification_key: tonic_handle_potential_err(
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

    async fn crs_ceremony(
        &self,
        request: Request<CrsCeremonyRequest>,
    ) -> Result<Response<CrsResponse>, Status> {
        let inner = request.into_inner();
        let handle = inner.crs_handle.as_str();

        // ensure the handle is valid
        if !validate_user_input(handle) {
            tracing::warn!("CRS handle {} is not allowed!", handle);
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("CRS handle {} is not allowed!", handle),
            ));
        }

        // ensure that the CRS under that handle does not exist yet
        if crs_exists(handle) {
            tracing::warn!(
                "CRS with handle {} already exist - cannot create it again!",
                handle
            );
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!(
                    "CRS with handle {} already exist - cannot create it again!",
                    handle
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

        let crs_uri = tonic_handle_potential_err(
            store_crs(self, &crs, handle),
            format!("Failed to store CRS from request {:?}", inner),
        )?;

        let mut crs_store = tonic_handle_potential_err(
            self.crs_store.lock(),
            "Could not get handle for storing CRS".to_string(),
        )?;
        crs_store.insert(handle.to_string(), crs);

        Ok(Response::new(CrsResponse { crs_uri }))
    }

    async fn crs_request(
        &self,
        request: Request<CrsHandle>,
    ) -> Result<Response<CrsResponse>, Status> {
        let inner = request.into_inner();

        if !validate_user_input(&inner.crs_handle) {
            tracing::warn!("CRS handle {} is not allowed!", inner.crs_handle);
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("CRS handle {} is not allowed!", inner.crs_handle),
            ));
        }
        if !crs_exists(&inner.crs_handle) {
            tracing::warn!("CRS with handle {} does not exist!", inner.crs_handle);
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("CRS with handle {} does not exist!", inner.crs_handle),
            ));
        }
        Ok(Response::new(CrsResponse {
            crs_uri: crs_path(&inner.crs_handle),
        }))
    }
}

pub fn pub_key_path(key_handle: &str) -> String {
    format!("{}/{}-public.bin", KEY_PATH_PREFIX, key_handle)
}

pub fn priv_key_path(key_handle: &str) -> String {
    format!("{}/{}-private.bin", KEY_PATH_PREFIX, key_handle)
}

pub fn crs_path(crs_handle: &str) -> String {
    format!("{}/{}-crs.bin", CRS_PATH_PREFIX, crs_handle)
}

fn keys_exists(key_handle: &str) -> bool {
    let private_key_path = pub_key_path(key_handle);
    let public_key_path = priv_key_path(key_handle);
    Path::new(&private_key_path).exists() || Path::new(&public_key_path).exists()
}

fn crs_exists(crs_handle: &str) -> bool {
    let crs_path = crs_path(crs_handle);
    Path::new(&crs_path).exists()
}

/// Store generated keys by writing them to the file system and returning the path of the public
/// keys. Note that this is only for developer version for a more secure deployment without Nitro
/// keys should instead be stored in environment variables.
fn store_keys<K: BaseKms>(
    kms: &K,
    client_key: &FhePrivateKey,
    pub_fhe_keys: &PubKeySet,
    key_handle: &str,
) -> anyhow::Result<String> {
    fs::create_dir_all(KEY_PATH_PREFIX)?;
    let private_key_path = format!("{}/{}-private.bin", KEY_PATH_PREFIX, key_handle);
    write_element(private_key_path, &client_key)?;
    let signed_pks = SignedFhePublicKeySet::new(pub_fhe_keys.to_owned(), kms)?;
    let public_key_path = format!("{}/{}-public.bin", KEY_PATH_PREFIX, key_handle);
    write_element(public_key_path.clone(), &signed_pks)?;
    Ok(public_key_path)
}

/// Store generated CRS by signing it and writing it to the file system, returning the path to it.
fn store_crs<K: BaseKms>(
    kms: &K,
    crs: &PublicParameter,
    crs_handle: &str,
) -> anyhow::Result<String> {
    fs::create_dir_all(CRS_PATH_PREFIX)?;
    let crs_path = format!("{}/{}-crs.bin", CRS_PATH_PREFIX, crs_handle);
    let signed_crs = SignedCRS::new(crs, kms)?;
    write_element(crs_path.clone(), &signed_crs)?;

    Ok(crs_path)
}

fn get_all_key_uris(
    client_keys: &HashMap<String, FhePrivateKey>,
) -> anyhow::Result<HashMap<String, String>> {
    let mut res = HashMap::with_capacity(client_keys.len());
    for key_handle in client_keys.keys() {
        res.insert(key_handle.to_string(), pub_key_path(key_handle));
    }
    Ok(res)
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
        payload.key_handle,
    ))
}

/// Returns ciphertext, FheType, digest, servers_needed, key_handle
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
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
