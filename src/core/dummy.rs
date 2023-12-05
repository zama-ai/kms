use crate::{
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse, FheType, Proof,
        ReencryptionRequest, ReencryptionResponse,
    },
    rpc_types::{Kms, LightClientCommitResponse},
};

use super::{
    der_types::{PrivateSigKey, PublicSigKey},
    request::ClientRequest,
    signcryption::{sign, signcrypt},
};

use k256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::{rand_core::CryptoRngCore, ChaCha20Rng};
use serde::{Deserialize, Serialize};
use serde_asn1_der::{from_bytes, to_vec};
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tendermint::AppHash;
use tfhe::{
    generate_keys, prelude::FheDecrypt, ClientKey, Config, FheBool, FheUint16, FheUint32, FheUint8,
    PublicKey, ServerKey,
};

use tonic::{Code, Request, Response, Status};

pub const DEFAULT_KMS_KEY_PATH: &str = "temp/kms-keys.bin";

pub type FhePublicKey = tfhe::PublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

pub fn gen_sig_keys(rng: &mut impl CryptoRngCore) -> (PublicSigKey, PrivateSigKey) {
    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
}

pub fn gen_kms_keys(config: Config, rng: &mut impl CryptoRngCore) -> KmsKeys {
    let (fhe_sk, fhe_server_key) = generate_keys(config.clone());
    let fhe_pk = PublicKey::new(&fhe_sk);
    let (sig_pk, sig_sk) = gen_sig_keys(rng);
    KmsKeys {
        config,
        fhe_pk,
        fhe_sk,
        sig_pk,
        sig_sk,
        fhe_server_key,
    }
}

#[derive(Serialize, Deserialize)]
pub struct KmsKeys {
    pub config: Config,
    pub fhe_pk: FhePublicKey,
    pub fhe_sk: FhePrivateKey,
    pub fhe_server_key: ServerKey,
    pub sig_pk: PublicSigKey,
    pub sig_sk: PrivateSigKey,
}

/// KMS which does not do signatures or encryption of requests or responses but only does FHE decryption
#[derive(Debug)]
pub struct DummyKms {
    pub config: Config,
    fhe_dec_key: ClientKey,
    sig_key: PrivateSigKey,
    rng: Arc<Mutex<ChaCha20Rng>>,
}

impl Kms for DummyKms {
    fn validate_and_reencrypt(
        &self,
        request: &ReencryptionRequest,
    ) -> anyhow::Result<Option<ReencryptionResponse>> {
        let internal_request: ClientRequest = from_bytes(&request.request)?;
        if !internal_request.verify(&request.ciphertext)? {
            // TODO do we want a signed repsonse of failure linked to the request??
            Ok(None)
        } else {
            Ok(Kms::reencrypt(
                self,
                &request.ciphertext,
                request.fhe_type(),
                &internal_request,
            )?)
        }
    }

    fn validate_and_decrypt(
        &self,
        request: &DecryptionRequest,
    ) -> anyhow::Result<Option<DecryptionResponse>> {
        let internal_request: ClientRequest = from_bytes(&request.request)?;
        if !internal_request.verify(&request.ciphertext)? {
            // TODO do we want a signed repsonse of failure linked to the request??
            Ok(None)
        } else {
            let mut resp = Kms::decrypt(self, &request.ciphertext, request.fhe_type())?;
            let sig = sign(
                &plaintext_to_vec(resp.plaintext, request.fhe_type()),
                &self.sig_key,
            )?;
            resp.signature = to_vec(&sig)?;
            Ok(Some(resp))
        }
    }

    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<DecryptionResponse> {
        let plaintext = self.raw_decryption(ct, fhe_type)?;
        Ok(DecryptionResponse {
            signature: Vec::new(),
            fhe_type: fhe_type.into(),
            plaintext,
        })
    }

    fn reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        client_req: &ClientRequest,
    ) -> anyhow::Result<Option<ReencryptionResponse>> {
        if !client_req.verify(&ct)? {
            // TODO do we want a signed repsonse of failure linked to the request??
            return Ok(None);
        }
        let dec_resp = Kms::decrypt(self, ct, fhe_type)?;
        let msg = plaintext_to_vec(dec_resp.plaintext, fhe_type);
        // TODO what is the right way of doing this without panic
        let mut current_rng = self.rng.lock().unwrap();
        let mut rng_clone = current_rng.clone();
        let enc_res = signcrypt(
            &mut rng_clone,
            &msg,
            &client_req.payload.client_signcryption_key,
            &self.sig_key,
        )?;
        *current_rng = rng_clone;

        Ok(Some(ReencryptionResponse {
            reencrypted_ciphertext: to_vec(&enc_res)?,
            fhe_type: fhe_type.into(),
        }))
    }
}

impl DummyKms {
    pub fn new(config: Config, fhe_dec_key: ClientKey, sig_key: PrivateSigKey) -> Self {
        DummyKms {
            config,
            rng: Arc::new(Mutex::new(ChaCha20Rng::from_entropy())),
            fhe_dec_key,
            sig_key,
        }
    }

    fn raw_decryption(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<u32> {
        Ok(match fhe_type {
            FheType::Bool => {
                let cipher: FheBool = bincode::deserialize(ct)?;
                let plaintext: bool = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
            FheType::Euint8 => {
                let cipher: FheUint8 = bincode::deserialize(ct)?;
                let plaintext: u8 = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
            FheType::Euint16 => {
                let cipher: FheUint16 = bincode::deserialize(ct)?;
                let plaintext: u16 = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
            FheType::Euint32 => {
                let cipher: FheUint32 = bincode::deserialize(ct)?;
                let plaintext: u32 = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
        })
    }
}
fn plaintext_to_vec(plaintext: u32, fhe_type: FheType) -> Vec<u8> {
    match fhe_type {
        FheType::Bool => {
            vec![plaintext as u8]
        }
        FheType::Euint8 => {
            vec![plaintext as u8]
        }
        FheType::Euint16 => plaintext.to_be_bytes().to_vec(),
        FheType::Euint32 => plaintext.to_be_bytes().to_vec(),
    }
}

#[allow(dead_code)]
fn vec_to_plaintext(msg: &[u8], fhe_type: FheType) -> anyhow::Result<u32> {
    Ok(match fhe_type {
        FheType::Bool => msg[0] as u32,
        FheType::Euint8 => msg[0] as u32,
        FheType::Euint16 => u16::from_be_bytes(msg.try_into()?) as u32,
        FheType::Euint32 => u32::from_be_bytes(msg.try_into()?),
    })
}

#[tonic::async_trait]
impl KmsEndpoint for DummyKms {
    async fn validate_and_reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.clone().proof.unwrap()).await?;
        // TODO the request needs to have the type
        let res = Kms::validate_and_reencrypt(self, &req);
        process_response(res)
    }

    async fn validate_and_decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.clone().proof.unwrap()).await?;
        // TODO the request needs to have the type
        let res = Kms::validate_and_decrypt(self, &req);
        process_response(res)
    }

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

        let res = Kms::reencrypt(self, &req.ciphertext, FheType::Euint8, &internal_request);
        process_response(res)
    }
}

fn process_response<T: fmt::Debug>(req: anyhow::Result<Option<T>>) -> Result<Response<T>, Status> {
    match req {
        Ok(None) => {
            tracing::warn!("The following request failed validation: {:?}", req);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                "The request failed validation".to_string(),
            ))
        }
        Ok(Some(resp)) => Ok(Response::new(resp)),
        Err(e) => {
            tracing::error!("{}", e);
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ctor::ctor;

    use prost::Message;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_asn1_der::{from_bytes, to_vec};
    use tfhe::{prelude::FheEncrypt, ConfigBuilder, FheUint8};

    use crate::{
        core::{
            der_types::Cipher,
            dummy::{gen_sig_keys, vec_to_plaintext, DummyKms},
            request::ClientRequest,
            signcryption::validate_and_decrypt,
        },
        file_handling::{read_element, write_element},
        kms::{DecryptionRequest, FheType, ReencryptionRequest},
        rpc_types::Kms,
    };

    use super::{gen_kms_keys, KmsKeys, DEFAULT_KMS_KEY_PATH};

    #[ctor]
    #[test]
    fn ensure_keys_exist() {
        if !Path::new(DEFAULT_KMS_KEY_PATH).exists() {
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let config = ConfigBuilder::all_disabled()
                .enable_default_integers()
                .build();
            write_element(
                DEFAULT_KMS_KEY_PATH.to_string(),
                &gen_kms_keys(config, &mut rng),
            )
            .unwrap();
        }
    }

    #[test]
    fn sunshine_decrypt() {
        let msg = 42_u8;
        let keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
        let kms = DummyKms::new(keys.config, keys.fhe_sk.clone(), keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let response = kms.decrypt(&serialized_ct, FheType::Euint8).unwrap();
        assert_eq!(response.fhe_type, FheType::Euint8 as i32);
        assert_eq!(response.plaintext as u8, msg);
    }

    #[test]
    fn sunshine_rencrypt() {
        let msg = 42_u8;
        let kms_keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
        let kms = DummyKms::new(kms_keys.config, kms_keys.fhe_sk.clone(), kms_keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &kms_keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (_client_pk, client_sk) = gen_sig_keys(&mut rng);
        let (client_request, client_keys) =
            ClientRequest::new(&serialized_ct, &client_sk, &mut rng).unwrap();

        let response = kms
            .reencrypt(&serialized_ct, FheType::Euint8, &client_request)
            .unwrap()
            .unwrap();

        assert_eq!(response.fhe_type, FheType::Euint8 as i32);
        let cipher: Cipher = from_bytes(&response.reencrypted_ciphertext).unwrap();
        let decrypted_msg = vec_to_plaintext(
            &validate_and_decrypt(&cipher, &client_keys, &kms_keys.sig_pk)
                .unwrap()
                .unwrap(),
            response.fhe_type(),
        )
        .unwrap();
        assert_eq!(decrypted_msg as u8, msg);
    }

    #[test]
    fn sunshine_validate_decrypt() {
        let msg = 42_u8;
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
        let kms = DummyKms::new(keys.config, keys.fhe_sk.clone(), keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let (_client_pk, client_sk) = gen_sig_keys(&mut rng);
        let (client_request, _client_keys) =
            ClientRequest::new(&serialized_ct, &client_sk, &mut rng).unwrap();
        let request = DecryptionRequest {
            fhe_type: FheType::Euint8.into(),
            ciphertext: serialized_ct,
            request: to_vec(&client_request).unwrap(),
            proof: None,
        };
        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();
        let response: crate::kms::DecryptionResponse =
            kms.validate_and_decrypt(&request).unwrap().unwrap();
        assert_eq!(response.fhe_type, FheType::Euint8 as i32);
        assert_eq!(response.plaintext as u8, msg);
    }

    #[test]
    fn sunshine_validate_reencrypt() {
        let msg = 42_u8;
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let kms_keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
        let kms = DummyKms::new(kms_keys.config, kms_keys.fhe_sk.clone(), kms_keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &kms_keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let (_client_pk, client_sk) = gen_sig_keys(&mut rng);
        let (client_request, client_keys) =
            ClientRequest::new(&serialized_ct, &client_sk, &mut rng).unwrap();

        let request = ReencryptionRequest {
            fhe_type: FheType::Euint8.into(),
            ciphertext: serialized_ct,
            request: to_vec(&client_request).unwrap(),
            proof: None,
        };
        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let response: crate::kms::ReencryptionResponse =
            kms.validate_and_reencrypt(&request).unwrap().unwrap();
        assert_eq!(response.fhe_type, FheType::Euint8 as i32);
        let cipher: Cipher = from_bytes(&response.reencrypted_ciphertext).unwrap();
        let decrypted_msg = vec_to_plaintext(
            &validate_and_decrypt(&cipher, &client_keys, &kms_keys.sig_pk)
                .unwrap()
                .unwrap(),
            response.fhe_type(),
        )
        .unwrap();
        assert_eq!(decrypted_msg as u8, msg);
    }
}
