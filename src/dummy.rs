use tendermint::AppHash;
use tonic::{Code, Request, Response, Status};

use crate::{
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse, Proof,
        ReencryptionRequest, ReencryptionResponse,
    },
    types::{Kms, Signature},
};

use crate::types::LightClientCommitResponse;
#[derive(Default, Debug)]
pub struct DummyKms {}

impl Kms for DummyKms {
    // TODO: perform decryption
    fn decrypt(&self, _ct: &[u8]) -> DecryptionResponse {
        let plaintext: u32 = 1337;
        let signature = self.sign(&plaintext.to_le_bytes());

        DecryptionResponse {
            plaintext,
            signature,
        }
    }

    // TODO: perform reencryption
    fn reencrypt(&self, ct: &[u8]) -> ReencryptionResponse {
        let reencrypted_ciphertext = ct.to_vec();
        let signature = self.sign(ct);

        ReencryptionResponse {
            reencrypted_ciphertext,
            signature,
        }
    }
}

#[tonic::async_trait]
impl KmsEndpoint for DummyKms {
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.proof.unwrap()).await?;

        let res = Kms::decrypt(self, &req.ciphertext);

        Ok(Response::new(res))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.proof.unwrap()).await?;

        let res = Kms::reencrypt(self, &req.ciphertext);

        Ok(Response::new(res))
    }
}

impl DummyKms {
    // TODO: sign the message
    fn sign(&self, _msg: &[u8]) -> Signature {
        Vec::from("sig")
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
