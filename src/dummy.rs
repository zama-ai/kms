use tendermint::AppHash;
use tfhe::{
    generate_keys, prelude::FheDecrypt, ClientKey, Config, ConfigBuilder, FheBool, FheUint16,
    FheUint32, FheUint8,
};

use tonic::{Code, Request, Response, Status};

use crate::{
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse, FheType, Proof,
        ReencryptionRequest, ReencryptionResponse,
    },
    types::{Kms, Signature},
};

use crate::types::LightClientCommitResponse;

/// KMS which does not do signatures or encryption of requests or responses but only does FHE decryption
#[derive(Clone, Debug)]
pub struct DummyKms {
    pub config: Config,
    secret_key: ClientKey,
}

impl Default for DummyKms {
    fn default() -> Self {
        let config = ConfigBuilder::all_disabled()
            .enable_default_integers()
            .build();
        let (secret_key, _server_key) = generate_keys(config.clone());
        Self { config, secret_key }
    }
}
impl Kms for DummyKms {
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<DecryptionResponse> {
        match fhe_type {
            FheType::Bool => {
                let cipher: FheBool = bincode::deserialize(ct)?;
                let plaintext: bool = cipher.decrypt(&self.secret_key);
                Ok(DecryptionResponse {
                    signature: Vec::new(),
                    fhe_type: fhe_type.into(),
                    plaintext: plaintext as u32,
                })
            }
            FheType::Euint8 => {
                let cipher: FheUint8 = bincode::deserialize(ct)?;
                let plaintext: u8 = cipher.decrypt(&self.secret_key);
                Ok(DecryptionResponse {
                    signature: Vec::new(),
                    fhe_type: fhe_type.into(),
                    plaintext: plaintext as u32,
                })
            }
            FheType::Euint16 => {
                let cipher: FheUint16 = bincode::deserialize(ct)?;
                let plaintext: u16 = cipher.decrypt(&self.secret_key);
                Ok(DecryptionResponse {
                    signature: Vec::new(),
                    fhe_type: fhe_type.into(),
                    plaintext: plaintext as u32,
                })
            }
            FheType::Euint32 => {
                let cipher: FheUint32 = bincode::deserialize(ct)?;
                let plaintext: u32 = cipher.decrypt(&self.secret_key);
                Ok(DecryptionResponse {
                    signature: Vec::new(),
                    fhe_type: fhe_type.into(),
                    plaintext: plaintext as u32,
                })
            }
        }
    }

    // TODO: perform reencryption
    fn reencrypt(&self, ct: &[u8], _ct_type: FheType) -> anyhow::Result<ReencryptionResponse> {
        let reencrypted_ciphertext = ct.to_vec();
        let signature = self.sign(ct);

        Ok(ReencryptionResponse {
            reencrypted_ciphertext,
            signature,
        })
    }
}

impl DummyKms {
    pub fn new(secret_key: ClientKey, config: Config) -> Self {
        DummyKms { config, secret_key }
    }

    // TODO: sign the message
    fn sign(&self, _msg: &[u8]) -> Signature {
        Vec::from("sig")
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
        // TODO the request needs to have the type
        let res = Kms::decrypt(self, &req.ciphertext, FheType::Euint8);

        Ok(Response::new(res.unwrap()))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.proof.unwrap()).await?;

        let res = Kms::reencrypt(self, &req.ciphertext, FheType::Euint8);

        Ok(Response::new(res.unwrap()))
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

#[cfg(test)]
mod tests {
    use tfhe::{
        prelude::{FheDecrypt, FheEncrypt},
        FheUint8,
    };

    use crate::{dummy::DummyKms, kms::FheType, types::Kms};

    #[test]
    fn sunshine_decrypt() {
        let msg = 42_u8;
        let kms = DummyKms::default();

        let ct = FheUint8::encrypt(msg, &kms.secret_key);
        let dec: u8 = ct.decrypt(&kms.secret_key);
        assert_eq!(dec, msg);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let response = kms.decrypt(&serialized_ct, FheType::Euint8).unwrap();
        assert_eq!(response.fhe_type, FheType::Euint8 as i32);
        assert_eq!(response.plaintext as u8, msg);
    }
}
