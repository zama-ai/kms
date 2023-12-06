use std::fmt;

use crate::{
    core::{kms_core::SoftwareKms, request::ClientRequest},
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse, FheType, Proof,
        ReencryptionRequest, ReencryptionResponse,
    },
    rpc_types::{Kms, LightClientCommitResponse},
};
use serde_asn1_der::from_bytes;
use tendermint::AppHash;
use tonic::{Code, Request, Response, Status};

#[tonic::async_trait]
impl KmsEndpoint for SoftwareKms {
    async fn validate_and_reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.clone().proof.unwrap()).await?;
        let internal_request: ClientRequest = match from_bytes(&req.request) {
            Ok(client_request) => client_request,
            Err(e) => {
                tracing::error!("{}", e);
                return Err(tonic::Status::new(
                    tonic::Code::Aborted,
                    "Invalid request".to_string(),
                ));
            }
        };
        let return_cipher = process_response(Kms::validate_and_reencrypt(
            self,
            &req.ciphertext,
            req.fhe_type(),
            &internal_request,
        ))?;
        Ok(Response::new(ReencryptionResponse {
            reencrypted_ciphertext: return_cipher,
            fhe_type: req.fhe_type,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.proof.unwrap()).await?;
        let (sig, plaintext) =
            handle_potential_err(Kms::decrypt(self, &req.ciphertext, FheType::Euint8))?;
        Ok(Response::new(DecryptionResponse {
            signature: sig,
            fhe_type: req.fhe_type,
            plaintext,
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();
        let internal_request: ClientRequest = match from_bytes(&req.request) {
            Ok(client_request) => client_request,
            Err(e) => {
                tracing::error!("{}", e);
                return Err(tonic::Status::new(
                    tonic::Code::Aborted,
                    "Invalid request".to_string(),
                ));
            }
        };
        verify_proof(req.proof.unwrap()).await?;

        let return_cipher = process_response(Kms::reencrypt(
            self,
            &req.ciphertext,
            FheType::Euint8,
            &internal_request,
        ))?;
        Ok(Response::new(ReencryptionResponse {
            reencrypted_ciphertext: return_cipher,
            fhe_type: req.fhe_type,
        }))
    }
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

fn handle_potential_err<T: fmt::Debug>(resp: anyhow::Result<T>) -> Result<T, Status> {
    match resp {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!("An internal error happened while handle a request: {}", e);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Internal server error".to_string(),
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
