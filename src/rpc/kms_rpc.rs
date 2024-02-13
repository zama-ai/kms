use super::rpc_types::{BaseKms, ReencryptionRequestSigPayload};
use crate::core::der_types::{PublicEncKey, PublicSigKey, Signature};
use crate::core::kms_core::{BaseKmsStruct, SoftwareKms, SoftwareKmsKeys};
use crate::file_handling::read_element;
use crate::kms::kms_endpoint_server::{KmsEndpoint, KmsEndpointServer};
use crate::kms::{
    DecryptionRequest, DecryptionResponse, FheType, Proof, ReencryptionRequest,
    ReencryptionResponse,
};
use crate::rpc::rpc_types::{
    DecryptionRequestSigPayload, DecryptionResponseSigPayload, Kms, LightClientCommitResponse,
};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log};
use serde_asn1_der::{from_bytes, to_vec};
use std::fmt::{self};
use std::net::SocketAddr;
use tendermint::AppHash;
use tonic::transport::Server;
use tonic::{Code, Request, Response, Status};
use url::Url;

pub async fn server_handle(url_str: &str, key_path: String) -> anyhow::Result<()> {
    let url = Url::parse(url_str)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(anyhow::anyhow!(
            "Invalid scheme in URL. Only http and https are supported."
        ));
    }
    let host_str = url.host_str().ok_or("Invalid host in URL.");
    let port = url.port_or_known_default().ok_or("Invalid port in URL.");
    let socket: SocketAddr = format!("{}:{}", host_str.unwrap(), port.unwrap()).parse()?;

    let keys: SoftwareKmsKeys = read_element(key_path)?;
    let kms = SoftwareKms::new(keys.fhe_sk, keys.sig_sk);
    tracing::info!("Starting centralized KMS server ...");
    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl KmsEndpoint for SoftwareKms {
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, client_enc_key, client_verf_key, shares_needed) =
            handle_potential_err(
                validate_reencrypt_req(&inner).await,
                format!("Invalid key in request {:?}", inner),
            )?;
        let return_cipher = process_response(Kms::reencrypt(
            self,
            &ciphertext,
            fhe_type,
            req_digest.clone(),
            &client_enc_key,
            &client_verf_key,
        ))?;
        // Observe that shares_needed should be part of the signcrypted response or request to
        // ensure a single server cannot default to a single share
        Ok(Response::new(ReencryptionResponse {
            shares_needed,
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
        let (ciphertext, fhe_type, req_digest, randomness, shares_needed) = handle_potential_err(
            validate_decrypt_req(&inner).await,
            format!("Invalid key in request {:?}", inner),
        )?;
        let plaintext = handle_potential_err(
            Kms::decrypt(self, &ciphertext, fhe_type),
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
            shares_needed,
            plaintext: plaintext_bytes,
            verification_key: server_verf_key,
            digest: req_digest,
            randomness,
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

/// Returns ciphertext, FheType, digest, client encryption key, client verification key, shars
/// needed
pub async fn validate_reencrypt_req(
    req: &ReencryptionRequest,
) -> anyhow::Result<(Vec<u8>, FheType, Vec<u8>, PublicEncKey, PublicSigKey, u32)> {
    let payload = some_or_err(
        req.payload.clone(),
        format!("The request {:?} does not have a payload", req),
    )?;
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
    if !verify_client_key(&client_verf_key) {
        return Err(anyhow_error_and_warn_log(format!("Request invalid since client is not permitted to decrypt specific ciphertext in request {:?}", req)));
    }
    let client_enc_key: PublicEncKey = from_bytes(&sig_payload.enc_key)?;
    let proof = match payload.proof {
        Some(proof) => proof,
        None => return Err(anyhow_error_and_log("Proof not present".to_owned())),
    };
    verify_proof(&proof).await?;
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
        payload.shares_needed,
    ))
}

/// Returns ciphertext, FheType, digest, randomness, shares_needed
pub async fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(Vec<u8>, FheType, Vec<u8>, Vec<u8>, u32)> {
    let req_clone = req.clone();
    let payload = some_or_err(
        req.payload.clone(),
        format!("The request {:?} does not have a payload", req_clone),
    )?;
    let fhetype = payload.fhe_type();
    let sig_payload: DecryptionRequestSigPayload = handle_potential_err(
        payload.clone().try_into(),
        format!(
            "Could not make signature payload from protobuf request {:?}",
            req_clone
        ),
    )?;
    let client_verf_key: PublicSigKey = handle_potential_err(
        from_bytes(&sig_payload.verification_key),
        format!("Invalid client verification key in request {:?}", req_clone),
    )?;
    if !verify_client_key(&client_verf_key) {
        return Err(anyhow_error_and_warn_log(format!("Request invalid since client is not permitted to decrypt specific ciphertext in request {:?}", req_clone)));
    }
    verify_proof(&some_or_err(
        payload.proof,
        format!("Proof not present in request {:?}", req_clone),
    )?)
    .await?;
    let signature: Signature = handle_potential_err(
        from_bytes(&req_clone.signature),
        format!("Invalid signature in request {:?}", req_clone),
    )?;
    if !BaseKmsStruct::verify_sig(&sig_payload, &signature, &client_verf_key) {
        return Err(anyhow_error_and_warn_log(format!(
            "Could not validate signature in request {:?}",
            req_clone
        )));
    }
    let payload_serialized = handle_potential_err(
        to_vec(&sig_payload),
        format!("Could not serialize payload {:?}", req_clone),
    )?;
    let req_digest = handle_potential_err(
        BaseKmsStruct::digest(&payload_serialized),
        format!("Could not hash payload {:?}", req_clone),
    )?;
    Ok((
        payload.ciphertext,
        fhetype,
        req_digest,
        payload.randomness,
        payload.shares_needed,
    ))
}

fn verify_client_key(_key: &PublicSigKey) -> bool {
    // TODO
    true
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

pub fn handle_potential_err<T: fmt::Debug, E>(
    resp: Result<T, E>,
    error: String,
) -> Result<T, Status> {
    resp.map_err(|_| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}

async fn verify_proof(_proof: &Proof) -> Result<(), Status> {
    // let _root: AppHash = get_state_root(proof.height).await?;
    // TODO: verify `proof` against `root`
    Ok(())
}

#[allow(dead_code)]
async fn get_state_root(height: u32) -> Result<AppHash, Status> {
    let response = reqwest::get(format!("http://127.0.0.1:8888/commit?height={}", height)) // assumes light client local service is up and running
        .await
        .or(Err(Status::new(
            Code::Unavailable,
            "unable to reach light client",
        )))?
        .json::<LightClientCommitResponse>()
        .await
        .or(Err(Status::new(
            Code::Unavailable,
            "unable to deserialize light client response",
        )))?;

    Ok(response.result.signed_header.header.app_hash)
}
