use crate::setup_rpc::{DEFAULT_CIPHER_PATH, DEFAULT_CLIENT_KEY_PATH, DEFAULT_SERVER_KEY_PATH};
use kms::{
    core::{
        der_types::{Cipher, PublicEncKey, SigncryptionPair},
        kms_core::SoftwareKms,
        signcryption::{sign, verify_sig},
    },
    rpc::{kms_rpc::some_or_err, rpc_types::SigncryptionPayload},
};
use kms::{
    core::{
        der_types::{PrivateEncKey, SigncryptionPrivKey, SigncryptionPubKey},
        signcryption::validate_and_decrypt,
    },
    kms::{
        kms_endpoint_client::KmsEndpointClient, DecryptionRequest, DecryptionRequestPayload,
        FheType, Proof, ReencryptionResponse,
    },
};
use kms::{
    core::{
        der_types::{PrivateSigKey, PublicSigKey, Signature},
        signcryption::RND_SIZE,
    },
    kms::ReencryptionRequest,
};
use kms::{
    core::{kms_core::get_address, signcryption::encryption_key_generation},
    kms::DecryptionResponse,
};
use kms::{file_handling::read_element, kms::ReencryptionRequestPayload};
use rand::{RngCore, SeedableRng};
use rand_chacha::{rand_core::CryptoRngCore, ChaCha20Rng};
use serde_asn1_der::{from_bytes, to_vec};

mod setup_rpc;
/// This client serves test purposes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut kms_client = KmsEndpointClient::connect("http://0.0.0.0:50051").await?;
    let (ct, fhe_type): (Vec<u8>, FheType) = read_element(DEFAULT_CIPHER_PATH.to_string())?;
    let mut internal_client = Client::default();

    // DECRYPTION REQUEST
    let req = internal_client.decryption_request(ct.clone(), fhe_type)?;
    let response = kms_client.decrypt(tonic::Request::new(req.clone())).await?;
    tracing::debug!("DECRYPT RESPONSE={:?}", response);
    match internal_client.validate_decryption(Some(req), response.into_inner()) {
        Ok(Some((plaintext, return_type))) => {
            println!(
                "Decryption response is ok: {:?} of type {:?}",
                plaintext, return_type
            )
        }
        _ => println!("Decryption response is NOT valid"),
    };

    // REENCRYPTION REQUEST
    let (req, enc_pk, enc_sk) = internal_client.reencyption_request(ct, fhe_type)?;
    let response = kms_client
        .reencrypt(tonic::Request::new(req.clone()))
        .await?;
    tracing::debug!("REENCRYPT RESPONSE={:?}", response);
    match internal_client.validate_reencryption(Some(req), response.into_inner(), &enc_pk, &enc_sk)
    {
        Ok(Some((plaintext, return_type))) => {
            println!(
                "Reencryption response is ok: {:?} of type {:?}",
                plaintext, return_type
            )
        }
        _ => println!("Reencryption response is NOT valid"),
    };

    Ok(())
}

pub struct Client {
    rng: Box<dyn CryptoRngCore>,
    server_pk: PublicSigKey,
    client_pk: PublicSigKey,
    client_sk: PrivateSigKey,
}
impl Default for Client {
    fn default() -> Self {
        let (client_pk, client_sk): (PublicSigKey, PrivateSigKey) =
            read_element(DEFAULT_CLIENT_KEY_PATH.to_string()).unwrap();
        Self {
            rng: Box::new(ChaCha20Rng::from_entropy()),
            server_pk: read_element(DEFAULT_SERVER_KEY_PATH.to_string()).unwrap(),
            client_pk,
            client_sk,
        }
    }
}
impl Client {
    pub fn new(server_pk: PublicSigKey, client_pk: PublicSigKey, client_sk: PrivateSigKey) -> Self {
        Client {
            rng: Box::new(ChaCha20Rng::from_entropy()),
            server_pk,
            client_pk,
            client_sk,
        }
    }

    pub fn decryption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
    ) -> anyhow::Result<DecryptionRequest> {
        let mut randomness = Vec::with_capacity(RND_SIZE);
        self.rng.fill_bytes(&mut randomness);
        let payload = DecryptionRequestPayload {
            address: get_address(&self.client_pk).to_vec(),
            fhe_type: fhe_type.into(),
            ciphertext: ct,
            proof: Some(Proof {
                height: 0,
                merkle_patricia_proof: vec![],
            }),
            randomness,
        };
        let sig = sign(&to_vec(&payload)?, &self.client_sk)?;
        Ok(DecryptionRequest {
            signature: to_vec(&sig)?,
            payload: Some(payload),
        })
    }

    pub fn reencyption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
    ) -> anyhow::Result<(ReencryptionRequest, PublicEncKey, PrivateEncKey)> {
        let (enc_pk, enc_sk) = encryption_key_generation(&mut self.rng);
        let mut randomness = Vec::with_capacity(RND_SIZE);
        self.rng.fill_bytes(&mut randomness);
        let payload = ReencryptionRequestPayload {
            enc_key: to_vec(&enc_pk)?,
            address: get_address(&self.client_pk).to_vec(),
            fhe_type: fhe_type.into(),
            ciphertext: ct,
            proof: Some(Proof {
                height: 0,
                merkle_patricia_proof: vec![],
            }),
            randomness,
        };
        let sig = sign(&to_vec(&payload)?, &self.client_sk)?;
        Ok((
            ReencryptionRequest {
                signature: to_vec(&sig)?,
                payload: Some(payload),
            },
            enc_pk,
            enc_sk,
        ))
    }

    pub fn validate_decryption(
        &self,
        request: Option<DecryptionRequest>,
        resp: DecryptionResponse,
    ) -> anyhow::Result<Option<(u32, FheType)>> {
        let resp_payload = some_or_err(resp.payload, "No payload present in response".to_string())?;
        if let Some(req) = request {
            match req.payload {
                Some(req_payload) => {
                    if req_payload.randomness != resp_payload.randomness {
                        tracing::warn!(
                            "Server in decryption request is not using the requested randomness"
                        );
                        return Ok(None);
                    }
                    if get_address(&self.server_pk).to_vec() != resp_payload.address {
                        tracing::warn!("Server address is incorrect in decryption request");
                        return Ok(None);
                    }
                    if SoftwareKms::digest(&to_vec(&req_payload)?)? != resp_payload.digest {
                        tracing::warn!(
                            "The decryption response is not linked to the correct request"
                        );
                        return Ok(None);
                    }
                    if req_payload.fhe_type() != resp_payload.fhe_type() {
                        tracing::warn!("Fhe type in the decryption response is incorrect");
                        return Ok(None);
                    }
                }
                None => {
                    tracing::warn!("No payload in the decryption request!");
                    return Ok(None);
                }
            }
        }
        let sig = Signature {
            sig: k256::ecdsa::Signature::from_slice(&resp.signature)?,
            pk: self.server_pk.clone(),
        };
        if !verify_sig(&to_vec(&resp_payload)?, &sig, &self.server_pk) {
            tracing::warn!("Signature on received response is not valid!");
            return Ok(None);
        }
        Ok(Some((resp_payload.plaintext, resp_payload.fhe_type())))
    }

    pub fn validate_reencryption(
        &self,
        request: Option<ReencryptionRequest>,
        resp: ReencryptionResponse,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> anyhow::Result<Option<(u32, FheType)>> {
        if let Some(req) = request {
            match req.payload {
                Some(req_payload) => {
                    if get_address(&self.server_pk).to_vec() != resp.address {
                        tracing::warn!("Server address is incorrect in reencryption request");
                        return Ok(None);
                    }
                    if SoftwareKms::digest(&to_vec(&req_payload)?)? != resp.digest {
                        tracing::warn!(
                            "The reencryption response is not linked to the correct request"
                        );
                        return Ok(None);
                    }
                    if req_payload.fhe_type() != resp.fhe_type() {
                        tracing::warn!("Fhe type in the reencryption response is incorrect");
                        return Ok(None);
                    }
                }
                None => {
                    tracing::warn!("No payload in the reencryption request!");
                    return Ok(None);
                }
            }
        }
        // TODO for negative testing ensure this works with really large requests as I ended up in an inifinate loop at some point here
        let cipher: Cipher = from_bytes(&resp.signcrypted_ciphertext)?;
        let client_keys = SigncryptionPair {
            sk: SigncryptionPrivKey {
                signing_key: self.client_sk.clone(),
                decryption_key: enc_sk.clone(),
            },
            pk: SigncryptionPubKey {
                verification_key: self.client_pk.clone(),
                enc_key: enc_pk.clone(),
            },
        };
        let plaintext = match validate_and_decrypt(&cipher, &client_keys, &self.server_pk)? {
            Some(msg) => {
                // TODO ensure that the content of what is signed is actually used where needed
                let msg_payload: SigncryptionPayload = from_bytes(&msg)?;
                msg_payload.plaintext
            }
            None => {
                tracing::warn!("Could decrypt or validate signcrypted response");
                return Ok(None);
            }
        };
        Ok(Some((plaintext, resp.fhe_type())))
    }
}

#[cfg(test)]
mod tests {
    use kms::{
        file_handling::read_element,
        kms::{kms_endpoint_client::KmsEndpointClient, FheType},
    };
    use tokio::task::JoinHandle;
    use tonic::transport::Channel;

    use crate::{
        setup_rpc::{
            server_handle,
            tests::{DEFAULT_FHE_TYPE, DEFAULT_MSG},
            DEFAULT_CIPHER_PATH, DEFAULT_KMS_KEY_PATH,
        },
        Client,
    };

    static TEST_URL: &str = "0.0.0.0:50051";
    static TEST_URL_PROT: &str = "http://0.0.0.0:50051";

    async fn setup() -> (JoinHandle<()>, KmsEndpointClient<Channel>) {
        let server_handle = tokio::spawn(async {
            server_handle(TEST_URL.to_string(), DEFAULT_KMS_KEY_PATH.to_string()).await;
        });
        // Wait for the server to start
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channel = Channel::from_static(TEST_URL_PROT).connect().await.unwrap();
        let client = KmsEndpointClient::new(channel);
        (server_handle, client)
    }

    #[tokio::test]
    async fn test_decryption() {
        let (kms_server, mut kms_client) = setup().await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element(DEFAULT_CIPHER_PATH.to_string()).unwrap();
        let mut internal_client = Client::default();

        let req = internal_client
            .decryption_request(ct.clone(), fhe_type)
            .unwrap();
        let response = kms_client
            .decrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();

        let (plaintext, return_type) = internal_client
            .validate_decryption(Some(req), response.into_inner())
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, return_type);
        assert_eq!(DEFAULT_MSG as u32, plaintext);

        kms_server.abort();
    }

    #[tokio::test]
    async fn test_reencryption() {
        let (kms_server, mut kms_client) = setup().await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element(DEFAULT_CIPHER_PATH.to_string()).unwrap();
        let mut internal_client = Client::default();

        let (req, enc_pk, enc_sk) = internal_client.reencyption_request(ct, fhe_type).unwrap();
        let response = kms_client
            .reencrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();

        let (plaintext, return_type) = internal_client
            .validate_reencryption(Some(req), response.into_inner(), &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, return_type);
        assert_eq!(DEFAULT_MSG as u32, plaintext);

        kms_server.abort();
    }
}
