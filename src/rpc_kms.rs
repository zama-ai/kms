use std::fmt::{self};

use crate::{
    core::{
        der_types::{KeyAddress, PublicEncKey, Signature},
        kms_core::SoftwareKms,
    },
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse,
        DecryptionResponsePayload, FheType, Proof, ReencryptionRequest, ReencryptionResponse,
    },
    rpc_types::{Kms, LightClientCommitResponse},
};
use serde_asn1_der::from_bytes;
use tendermint::AppHash;
use tonic::{Code, Request, Response, Status};

#[tonic::async_trait]
impl KmsEndpoint for SoftwareKms {
    // TODO We might also need to add contract to the elements
    async fn validate_and_reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();
        let req_clone = req.clone();
        let payload = some_or_err(
            req.payload,
            format!("The request {:?} does not have a payload", req_clone),
        )?;
        let payload_clone = payload.clone();
        let fhe_type = payload.fhe_type();
        let address: KeyAddress = handle_potential_err(
            payload.address.try_into(),
            format!("Invalid address in request {:?}", req_clone),
        )?;
        if !verify_client_address(&address) {
            tracing::warn!("Request invalid since client is not permitted to decrypt specific ciphertext in request {:?}", req_clone);
            return Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ));
        }
        verify_proof(some_or_err(
            payload.proof,
            format!("Proof not present in request {:?}", req_clone),
        )?)
        .await?;

        let signature: Signature = handle_potential_err(
            from_bytes(&payload.ciphertext),
            format!("Invalid key in request {:?}", req_clone),
        )?;

        if !Kms::verify_sig(self, &payload_clone, &signature, &address) {
            return Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ));
        }

        let client_enc_key: PublicEncKey = handle_potential_err(
            from_bytes(&payload.enc_key),
            format!("Invalid key in request {:?}", req_clone),
        )?;
        let return_cipher = process_response(Kms::validate_and_reencrypt(
            self,
            &payload.ciphertext,
            fhe_type,
            &client_enc_key,
            &address,
        ))?;
        Ok(Response::new(ReencryptionResponse {
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            digest: todo!(),
            address: todo!(),
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let req = request.into_inner();
        let payload = some_or_err(
            req.clone().payload,
            format!("The request {:?} does not have a payload", req),
        )?;
        let fhe_type = payload.fhe_type();
        let address: KeyAddress = handle_potential_err(
            payload.address.try_into(),
            format!("Invalid address in request {:?}", req),
        )?;
        if !verify_client_address(&address) {
            tracing::warn!("Request invalid since client is not permitted to decrypt specific ciphertext in request {:?}", req);
            return Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ));
        }
        verify_proof(some_or_err(
            payload.proof,
            format!("Proof not present in request {:?}", req),
        )?)
        .await?;
        // TODO verify signature on request
        let (sig, plaintext) = handle_potential_err(
            Kms::decrypt(self, &payload.ciphertext, FheType::Euint8),
            format!("Decryption failed for request {:?}", req),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig,
            payload: Some(DecryptionResponsePayload {
                fhe_type: fhe_type.into(),
                plaintext,
                address: todo!(),
                digest: todo!(),
                randomness: todo!(),
            }),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();
        let payload = some_or_err(
            req.clone().payload,
            format!("The request {:?} does not have a payload", req),
        )?;
        let fhe_type = payload.fhe_type();
        let address: KeyAddress = handle_potential_err(
            payload.address.try_into(),
            format!("Invalid address in request {:?}", req),
        )?;
        if !verify_client_address(&address) {
            tracing::warn!("Request invalid since client is not permitted to decrypt specific ciphertext in request {:?}", req);
            return Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ));
        }
        let client_enc_key: PublicEncKey = handle_potential_err(
            from_bytes(&payload.enc_key),
            format!("Invalid key in request {:?}", req),
        )?;
        verify_proof(some_or_err(
            payload.proof,
            format!("Proof not present in request {:?}", req),
        )?)
        .await?;

        let return_cipher = process_response(Kms::reencrypt(
            self,
            &payload.ciphertext,
            FheType::Euint8,
            &client_enc_key,
            &address,
        ))?;
        Ok(Response::new(ReencryptionResponse {
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            address: todo!(),
            digest: todo!(),
        }))
    }
}

fn verify_client_address(_address: &KeyAddress) -> bool {
    // TODO
    true
}

fn process_response<T: fmt::Debug>(resp: anyhow::Result<Option<T>>) -> Result<T, Status> {
    match resp {
        Ok(None) => {
            tracing::warn!("A request failed validation");
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                "The request failed validation".to_string(),
            ))
        }
        Ok(Some(resp)) => Ok(resp),
        Err(e) => {
            tracing::error!("An internal error happened while handle a request: {}", e);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Internal server error".to_string(),
            ))
        }
    }
}

fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> Result<T, Status> {
    match input {
        Some(input) => Ok(input),
        None => {
            tracing::warn!(error);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ))
        }
    }
}

fn handle_potential_err<T: fmt::Debug, E>(resp: Result<T, E>, error: String) -> Result<T, Status> {
    match resp {
        Ok(resp) => Ok(resp),
        Err(_) => {
            tracing::warn!(error);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ))
        }
    }
}

async fn verify_proof(proof: Proof) -> Result<(), Status> {
    let _root: AppHash = get_state_root(proof.height).await?;
    // TODO: verify `proof` against `root`
    Ok(())
}

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
