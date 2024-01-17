use std::collections::HashSet;

use crate::setup_rpc::{DEFAULT_CIPHER_PATH, DEFAULT_CLIENT_KEY_PATH, DEFAULT_SERVER_KEYS_PATH};
use kms::core::der_types::{
    Cipher, PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, Signature, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use kms::core::kms_core::SoftwareKms;
use kms::core::signcryption::{
    encryption_key_generation, sign, validate_and_decrypt, verify_sig, RND_SIZE,
};
use kms::file_handling::read_element;
use kms::kms::kms_endpoint_client::KmsEndpointClient;
use kms::kms::{
    AggregatedDecryptionRespone, AggregatedReencryptionRespone, DecryptionRequest, FheType,
    ReencryptionRequest,
};
use kms::rpc::kms_rpc::some_or_err;
use kms::rpc::rpc_types::{
    DecryptionRequestSigPayload, DecryptionResponseSigPayload, MetaResponse, Plaintext,
    ReencryptionRequestSigPayload, SigncryptionPayload,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::rand_core::CryptoRngCore;
use rand_chacha::ChaCha20Rng;
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
    let responses = AggregatedDecryptionRespone {
        responses: vec![response.into_inner()],
    };
    match internal_client.validate_decryption(Some(req), responses) {
        Ok(Some(plaintext)) => {
            println!(
                "Decryption response is ok: {:?} of type {:?}",
                plaintext.as_u32(),
                plaintext.fhe_type()
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
    let responses = AggregatedReencryptionRespone {
        responses: vec![response.into_inner()],
    };
    match internal_client.validate_reencryption(Some(req), responses, &enc_pk, &enc_sk) {
        Ok(Some(plaintext)) => {
            println!(
                "Reencryption response is ok: {:?} of type {:?}",
                plaintext.as_u32(),
                plaintext.fhe_type()
            )
        }
        _ => println!("Reencryption response is NOT valid"),
    };

    Ok(())
}

pub struct Client {
    rng: Box<dyn CryptoRngCore>,
    server_pks: HashSet<PublicSigKey>,
    client_pk: PublicSigKey,
    client_sk: PrivateSigKey,
    shares_needed: u32,
}
impl Default for Client {
    // TODO should 1 share needed be default?
    fn default() -> Self {
        let (client_pk, client_sk): (PublicSigKey, PrivateSigKey) =
            read_element(DEFAULT_CLIENT_KEY_PATH.to_string()).unwrap();
        Self {
            rng: Box::new(ChaCha20Rng::from_entropy()),
            server_pks: read_element(DEFAULT_SERVER_KEYS_PATH.to_string()).unwrap(),
            client_pk,
            client_sk,
            shares_needed: 1,
        }
    }
}
impl Client {
    pub fn new(
        server_pks: HashSet<PublicSigKey>,
        client_pk: PublicSigKey,
        client_sk: PrivateSigKey,
        shares_needed: u32,
    ) -> Self {
        Client {
            rng: Box::new(ChaCha20Rng::from_entropy()),
            server_pks,
            client_pk,
            client_sk,
            shares_needed,
        }
    }

    pub fn decryption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
    ) -> anyhow::Result<DecryptionRequest> {
        let mut randomness: Vec<u8> = Vec::with_capacity(RND_SIZE);
        self.rng.fill_bytes(&mut randomness);
        let sig_req = DecryptionRequestSigPayload {
            verification_key: to_vec(&self.client_pk)?,
            fhe_type,
            ciphertext: ct,
            randomness,
            height: 0,
            merkle_patricia_proof: vec![],
        };
        let sig = sign(&to_vec(&sig_req)?, &self.client_sk)?;
        Ok(DecryptionRequest {
            signature: to_vec(&sig)?,
            payload: Some(sig_req.into()),
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
        let sig_payload = ReencryptionRequestSigPayload {
            enc_key: to_vec(&enc_pk)?,
            verification_key: to_vec(&self.client_pk)?,
            fhe_type,
            ciphertext: ct,
            height: 0,
            merkle_patricia_proof: vec![],
            randomness,
        };
        let sig = sign(&to_vec(&sig_payload)?, &self.client_sk)?;
        Ok((
            ReencryptionRequest {
                signature: to_vec(&sig)?,
                payload: Some(sig_payload.into()),
            },
            enc_pk,
            enc_sk,
        ))
    }

    pub fn validate_decryption(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: AggregatedDecryptionRespone,
    ) -> anyhow::Result<Option<Plaintext>> {
        match request {
            Some(req) => match req.payload {
                Some(req_payload) => {
                    let pivot_resp = some_or_err(
                        some_or_err(
                            agg_resp.responses.first(),
                            "AggregatedDecryptionResponse is empty!".to_string(),
                        )?
                        .payload
                        .to_owned(),
                        "No payload in pivot response for decryption".to_string(),
                    )?;
                    let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.responses.len()); // = agg_resp.responses.iter().map(|resp| {
                    for resp in &agg_resp.responses {
                        resp_parsed_payloads.push(some_or_err(
                            resp.payload.to_owned(),
                            "No payload present in response".to_string(),
                        )?);
                    }
                    if !self.validate_meta_data(&pivot_resp, resp_parsed_payloads)? {
                        tracing::warn!("Received responses do not agree on meta-data!");
                        return Ok(None);
                    }
                    if req_payload.fhe_type() != pivot_resp.fhe_type() {
                        tracing::warn!("Fhe type in the decryption response is incorrect");
                        return Ok(None);
                    }
                    let sig_payload: DecryptionRequestSigPayload = req_payload.try_into()?;
                    if SoftwareKms::digest(&to_vec(&sig_payload)?)? != pivot_resp.digest {
                        tracing::warn!(
                            "The decryption response is not linked to the correct request"
                        );
                        return Ok(None);
                    }
                }
                None => {
                    tracing::warn!("No payload in the decryption request!");
                    return Ok(None);
                }
            },
            None => {
                tracing::warn!("No decryption request!");
                return Ok(None);
            }
        }
        let mut shares = Vec::with_capacity(agg_resp.responses.len());
        for cur_resp in agg_resp.responses {
            let cur_payload = some_or_err(
                cur_resp.payload,
                "No payload in current response!".to_string(),
            )?;
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };
            let sig_payload: DecryptionResponseSigPayload = cur_payload.into();
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&sig_payload.verification_key)?;
            if !verify_sig(&to_vec(&sig_payload)?, &sig, &cur_verf_key) {
                tracing::warn!("Signature on received response is not valid!");
                return Ok(None);
            }
            shares.push(sig_payload.plaintext);
        }
        let msg = self.reconstruct_message(shares)?;
        let plaintext: Plaintext = from_bytes(&msg)?;
        Ok(Some(plaintext))
    }

    pub fn validate_reencryption(
        &self,
        request: Option<ReencryptionRequest>,
        agg_resp: AggregatedReencryptionRespone,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> anyhow::Result<Option<Plaintext>> {
        match request {
            Some(req) => match req.payload {
                Some(req_payload) => {
                    let pivot_resp = some_or_err(
                        agg_resp.responses.first(),
                        "AggregatedReencryptionRespone is empty!".to_string(),
                    )?;
                    if !self.validate_meta_data(pivot_resp, agg_resp.responses.to_owned())? {
                        tracing::warn!("Received responses do not agree on meta-data!");
                        return Ok(None);
                    }
                    if req_payload.fhe_type() != pivot_resp.fhe_type() {
                        tracing::warn!("Fhe type in the reencryption response is incorrect");
                        return Ok(None);
                    }
                    let sig_payload: ReencryptionRequestSigPayload = req_payload.try_into()?;
                    if SoftwareKms::digest(&to_vec(&sig_payload)?)? != pivot_resp.digest {
                        tracing::warn!(
                            "The reencryption response is not linked to the correct request"
                        );
                        return Ok(None);
                    }
                }
                None => {
                    tracing::warn!("No payload in the reencryption request!");
                    return Ok(None);
                }
            },
            None => {
                tracing::warn!("No reencryption request!");
                return Ok(None);
            }
        }
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
        let mut shares = Vec::with_capacity(agg_resp.responses.len());
        for cur_resp in agg_resp.responses {
            let cur_cipher: Cipher = from_bytes(&cur_resp.signcrypted_ciphertext)?;
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&cur_resp.verification_key)?;
            shares.push(
                match validate_and_decrypt(&cur_cipher, &client_keys, &cur_verf_key)? {
                    Some(msg) => msg,
                    None => {
                        tracing::warn!("Could decrypt or validate signcrypted response");
                        return Ok(None);
                    }
                },
            );
        }
        let msg = self.reconstruct_message(shares)?;
        let resp_payload: SigncryptionPayload = from_bytes(&msg)?;
        Ok(Some(resp_payload.plaintext))
    }

    fn validate_meta_data<T: MetaResponse>(
        &self,
        pivot_resp: &T,
        responses: Vec<T>,
    ) -> anyhow::Result<bool> {
        // First check consistency between the pivot and the different responses
        for cur_resp in responses.iter() {
            if pivot_resp.fhe_type() != cur_resp.fhe_type() {
                tracing::warn!(
                    "Response from server with verification key {:?} gave fhe type {:?}, whereas the pivot server's fhe type is {:?} and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.fhe_type(),
                    cur_resp.fhe_type(),
                    cur_resp.verification_key()
                );
                return Ok(false);
            }
            if pivot_resp.shares_needed() != cur_resp.shares_needed() {
                tracing::warn!(
                    "Response from server with verification key {:?} say {:?} shares are needed for reconstruction, whereas the pivot server says {:?} shares are needed for reconstruction, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.shares_needed(),
                    cur_resp.shares_needed(),
                    cur_resp.verification_key()
                );
                return Ok(false);
            }
            if pivot_resp.digest() != cur_resp.digest() {
                tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.shares_needed(),
                    cur_resp.shares_needed(),
                    cur_resp.verification_key()
                );
                return Ok(false);
            }
            // TODO test that equality on option works as expected
            if pivot_resp.randomness() != cur_resp.randomness() {
                tracing::warn!(
                    "Response from server with verification key {:?} gave randomness {:?}, whereas the pivot server gave randomness {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.randomness(),
                    cur_resp.randomness(),
                    cur_resp.verification_key()
                );
                return Ok(false);
            }
            let resp_verf_key: PublicSigKey = from_bytes(&cur_resp.verification_key())?;
            if !&self.server_pks.contains(&resp_verf_key) {
                tracing::warn!("Server key is incorrect in reencryption request");
                return Ok(false);
            }
        }
        // Next check the data in the pivot
        if pivot_resp.shares_needed() < responses.len().try_into()? {
            tracing::warn!("Not enough shares to reconstruct. {:?} shares are needed, but only {:?} are present", pivot_resp.shares_needed(), responses.len());
            return Ok(false);
        }
        if pivot_resp.shares_needed() != self.shares_needed {
            tracing::warn!("Response says only {:?} shares are needed for reconstruction, but client is setup to require {:?} shares", pivot_resp.shares_needed(), self.shares_needed);
            return Ok(false);
        }

        Ok(true)
    }

    fn reconstruct_message(&self, shares: Vec<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
        if self.shares_needed == 1 {
            Ok(some_or_err(
                shares.first(),
                "No shares present. Cannot reconstruct".to_string(),
            )?
            .to_owned())
        } else {
            tracing::error!("Threshold reconstruction of plaintext is not implemented yet");
            todo!()
        }
    }
}

#[cfg(test)]
mod tests {
    use kms::file_handling::read_element;
    use kms::kms::kms_endpoint_client::KmsEndpointClient;
    use kms::kms::{AggregatedDecryptionRespone, AggregatedReencryptionRespone, FheType};
    use serial_test::serial;
    use tokio::task::JoinHandle;
    use tonic::transport::Channel;

    use crate::setup_rpc::tests::{DEFAULT_FHE_TYPE, DEFAULT_MSG};
    use crate::setup_rpc::{server_handle, DEFAULT_CIPHER_PATH, DEFAULT_KMS_KEY_PATH};
    use crate::Client;

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
    #[serial]
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

        let responses = AggregatedDecryptionRespone {
            responses: vec![response.into_inner()],
        };
        let plaintext = internal_client
            .validate_decryption(Some(req), responses)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(DEFAULT_MSG, plaintext.as_u8().unwrap());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
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

        let responses = AggregatedReencryptionRespone {
            responses: vec![response.into_inner()],
        };
        let plaintext = internal_client
            .validate_reencryption(Some(req), responses, &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(DEFAULT_MSG, plaintext.as_u8().unwrap());

        kms_server.abort();
    }

    // Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
    #[tokio::test]
    #[serial]
    async fn test_largecipher() {
        let (kms_server, mut kms_client) = setup().await;
        let ct = Vec::from([1_u8; 1000000]);
        let fhe_type = FheType::Euint32;
        let mut internal_client = Client::default();

        let (req, _enc_pk, _enc_sk) = internal_client.reencyption_request(ct, fhe_type).unwrap();
        let response = kms_client.reencrypt(tonic::Request::new(req.clone())).await;
        assert!(response.is_err());
        assert!(response
            .err()
            .unwrap()
            .message()
            .contains("Internal server error"));
        kms_server.abort();
    }
}
