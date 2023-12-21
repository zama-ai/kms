use crate::{
    core::{
        der_types::{PublicEncKey, PublicSigKey, Signature},
        kms_core::SoftwareKms,
    },
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse,
        DecryptionResponsePayload, Proof, ReencryptionRequest, ReencryptionResponse,
    },
    rpc::rpc_types::{Kms, LightClientCommitResponse},
};
use serde_asn1_der::{from_bytes, to_vec};
use std::fmt::{self};
use tendermint::AppHash;
use tonic::{Code, Request, Response, Status};

#[tonic::async_trait]
impl KmsEndpoint for SoftwareKms {
    // TODO We might also need to add contract to the elements
    async fn reencrypt(
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
        let client_verf_key: PublicSigKey = handle_potential_err(
            from_bytes(&payload.verification_key),
            format!("Invalid verification key in request {:?}", req_clone),
        )?;
        if !verify_client_key(&client_verf_key) {
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
            from_bytes(&req_clone.signature),
            format!("Invalid signature in request {:?}", req_clone),
        )?;
        if !Kms::verify_sig(self, &payload_clone, &signature, &client_verf_key) {
            return Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ));
        }

        let client_enc_key: PublicEncKey = handle_potential_err(
            from_bytes(&payload.enc_key),
            format!("Invalid key in request {:?}", req_clone),
        )?;
        let payload_serialized = handle_potential_err(
            to_vec(&payload_clone),
            format!("Could not serialize payload {:?}", req_clone),
        )?;
        let req_digest = handle_potential_err(
            SoftwareKms::digest(&payload_serialized),
            format!("Could not hash payload {:?}", req_clone),
        )?;
        let return_cipher = process_response(Kms::reencrypt(
            self,
            &payload.ciphertext,
            fhe_type,
            req_digest.clone(),
            &client_enc_key,
            &client_verf_key,
        ))?;
        Ok(Response::new(ReencryptionResponse {
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: handle_potential_err(
                to_vec(&Kms::get_verf_key(self)),
                "Could not serialize server verification key".to_string(),
            )?,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        tracing::info!("Received a new request!");
        let req = request.into_inner();
        let req_clone = req.clone();
        let payload = some_or_err(
            req.clone().payload,
            format!("The request {:?} does not have a payload", req_clone),
        )?;
        let payload_clone = payload.clone();
        let fhe_type = payload.fhe_type();
        let client_verf_key: PublicSigKey = handle_potential_err(
            from_bytes(&payload.verification_key),
            format!("Invalid client verification key in request {:?}", req_clone),
        )?;
        if !verify_client_key(&client_verf_key) {
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
            from_bytes(&req_clone.signature),
            format!("Invalid signature in request {:?}", req_clone),
        )?;
        if !Kms::verify_sig(self, &payload_clone, &signature, &client_verf_key) {
            return Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Invalid request".to_string(),
            ));
        }
        let payload_serialized = handle_potential_err(
            to_vec(&payload_clone),
            format!("Could not serialize payload {:?}", req_clone),
        )?;
        let req_digest = handle_potential_err(
            SoftwareKms::digest(&payload_serialized),
            format!("Could not hash payload {:?}", req_clone),
        )?;
        let plaintext = handle_potential_err(
            Kms::decrypt(self, &payload.ciphertext, payload_clone.fhe_type()),
            format!("Decryption failed for request {:?}", req),
        )?;
        let server_verf_key = handle_potential_err(
            to_vec(&Kms::get_verf_key(self)),
            "Could not serialize server verification key".to_string(),
        )?;
        let payload_resp = DecryptionResponsePayload {
            fhe_type: fhe_type.into(),
            plaintext,
            verification_key: server_verf_key,
            digest: req_digest,
            randomness: payload_clone.randomness,
        };
        let sig = handle_potential_err(
            Kms::sign(self, &payload_resp),
            format!("Could not sign payload {:?}", payload_resp),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(payload_resp),
        }))
    }
}

fn verify_client_key(_address: &PublicSigKey) -> bool {
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

pub fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> Result<T, Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}

fn handle_potential_err<T: fmt::Debug, E>(resp: Result<T, E>, error: String) -> Result<T, Status> {
    resp.map_err(|_| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, "Invalid request".to_string())
    })
}

async fn verify_proof(_proof: Proof) -> Result<(), Status> {
    // let _root: AppHash = get_state_root(proof.height).await?;
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
