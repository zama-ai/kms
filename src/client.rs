use crate::setup_rpc::{DEFAULT_CLIENT_KEY_PATH, DEFAULT_HL_CIPHER_PATH, DEFAULT_SERVER_KEYS_PATH};
use distributed_decryption::algebra::base_ring::Z128;
use distributed_decryption::algebra::residue_poly::ResiduePoly;
use distributed_decryption::error::error_handler::anyhow_error_and_log;
use distributed_decryption::execution::endpoints::decryption::reconstruct_message;
use distributed_decryption::execution::runtime::party::Role;
use distributed_decryption::execution::sharing::open::{
    fill_indexed_shares, reconstruct_w_errors_sync,
};
use distributed_decryption::execution::sharing::shamir::ShamirSharing;
use distributed_decryption::lwe::ThresholdLWEParameters;
use itertools::Itertools;
use kms::core::der_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, Signature, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use kms::core::kms_core::{decrypt_signcryption, BaseKmsStruct};
use kms::core::signcryption::{encryption_key_generation, sign, verify_sig, RND_SIZE};
use kms::file_handling::{read_as_json, read_element};
use kms::kms::kms_endpoint_client::KmsEndpointClient;
use kms::kms::{
    AggregatedDecryptionResponse, AggregatedReencryptionResponse, DecryptionRequest,
    DecryptionResponsePayload, FheType, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse,
};
use kms::rpc::kms_rpc::some_or_err;
use kms::rpc::rpc_types::{
    BaseKms, DecryptionRequestSigPayload, DecryptionResponseSigPayload, MetaResponse, Plaintext,
    ReencryptionRequestSigPayload,
};
use kms::threshold::threshold_kms::decrypted_blocks_to_raw_decryption;
use rand::{RngCore, SeedableRng};
use rand_chacha::rand_core::CryptoRngCore;
use rand_chacha::ChaCha20Rng;
use serde_asn1_der::{from_bytes, to_vec};
use setup_rpc::PARAM_PATH;
use std::collections::{HashMap, HashSet};
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

mod setup_rpc;

/// Retries a function a given number of times with a given interval between retries.
macro_rules! retry {
    ($f:expr, $count:expr, $interval:expr) => {{
        let mut retries = 0;
        let result = loop {
            let result = $f;
            if result.is_ok() {
                break result;
            } else if retries > $count {
                break result;
            } else {
                retries += 1;
                tokio::time::sleep(std::time::Duration::from_millis($interval)).await;
            }
        };
        result
    }};
    ($f:expr) => {
        retry!($f, 5, 100)
    };
}

/// This client serves test purposes.
/// URL format is without protocol e.g.: 0.0.0.0:50051
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::WARN))
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("Missing required argument: server URL. Please provide the server URL as the second argument.".into());
    }
    let url = &args[1];

    let mut kms_client = retry!(KmsEndpointClient::connect(url.to_owned()).await, 5, 100)?;

    let (ct, fhe_type): (Vec<u8>, FheType) = read_element(DEFAULT_HL_CIPHER_PATH.to_string())?;
    let mut internal_client = Client::default();

    // DECRYPTION REQUEST
    let req = internal_client.decryption_request(ct.clone(), fhe_type)?;
    let response = kms_client.decrypt(tonic::Request::new(req.clone())).await?;
    tracing::debug!("DECRYPT RESPONSE={:?}", response);
    let responses = AggregatedDecryptionResponse {
        responses: vec![response.into_inner()],
    };
    match internal_client.process_decryption_resp(Some(req), responses) {
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
    let responses = AggregatedReencryptionResponse {
        responses: HashMap::from([(1, response.into_inner())]),
    };
    match internal_client.process_reencryption_resp(Some(req), responses, &enc_pk, &enc_sk) {
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

/// Simple client to interact with the KMS servers. This can be seen as a proof-of-concept
/// and reference code for validating the KMS. The logic supplied by the client will be
/// distributed accross the aggregator/proxy and smart contracts.
pub struct Client {
    rng: Box<dyn CryptoRngCore>,
    server_pks: HashSet<PublicSigKey>,
    client_pk: PublicSigKey,
    client_sk: PrivateSigKey,
    shares_needed: u32,
    params: ThresholdLWEParameters,
}
impl Default for Client {
    /// Constructs a client for a centralized KMS based on default parameters and key paths.
    fn default() -> Self {
        let (client_pk, client_sk): (PublicSigKey, PrivateSigKey) =
            read_element(DEFAULT_CLIENT_KEY_PATH.to_string()).unwrap();
        let default_params: ThresholdLWEParameters = read_as_json(PARAM_PATH.to_owned()).unwrap();
        Self {
            rng: Box::new(ChaCha20Rng::from_entropy()),
            server_pks: read_element(DEFAULT_SERVER_KEYS_PATH.to_string()).unwrap(),
            client_pk,
            client_sk,
            shares_needed: 1,
            params: default_params,
        }
    }
}
impl Client {
    pub fn new(
        server_pks: HashSet<PublicSigKey>,
        client_pk: PublicSigKey,
        client_sk: PrivateSigKey,
        shares_needed: u32,
        params: ThresholdLWEParameters,
    ) -> Self {
        Client {
            rng: Box::new(ChaCha20Rng::from_entropy()),
            server_pks,
            client_pk,
            client_sk,
            shares_needed,
            params,
        }
    }

    /// Creates a decryption request to send to the KMS servers. This generates
    /// a signature payload containing the ciphertext, required number of shares,
    /// and other metadata. It signs this payload with the client's private key.
    /// Returns the full DecryptionRequest containing the signed payload to send
    /// to the servers.
    pub fn decryption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
    ) -> anyhow::Result<DecryptionRequest> {
        // Observe that this randomness can be reused across the servers since each server will have
        // a unique PK that is included in their response, hence it will still be validated
        // that each request contains a unique message to be signed hence ensuring CCA
        // security. TODO this argument should be validated
        let mut randomness: Vec<u8> = Vec::with_capacity(RND_SIZE);
        self.rng.fill_bytes(&mut randomness);
        let sig_req = DecryptionRequestSigPayload {
            shares_needed: self.shares_needed,
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

    /// Creates a reencryption request to send to the KMS servers. This generates
    /// an ephemeral reencryption key pair, signature payload containing the ciphertext,
    /// required number of shares, and other metadata. It signs this payload with
    /// the client's private key. Returns the full ReencryptionRequest containing
    /// the signed payload to send to the servers, along with the generated
    /// reencryption key pair.
    pub fn reencyption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
    ) -> anyhow::Result<(ReencryptionRequest, PublicEncKey, PrivateEncKey)> {
        let (enc_pk, enc_sk) = encryption_key_generation(&mut self.rng);
        let mut randomness = Vec::with_capacity(RND_SIZE);
        self.rng.fill_bytes(&mut randomness);
        let sig_payload = ReencryptionRequestSigPayload {
            shares_needed: self.shares_needed,
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

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid. Returns `None` if validation fails.
    pub fn process_decryption_resp(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: AggregatedDecryptionResponse,
    ) -> anyhow::Result<Option<Plaintext>> {
        if !self.validate_decryption_resp(request, &agg_resp)? {
            return Ok(None);
        }
        let pivot = some_or_err(
            agg_resp.responses.iter().last(),
            "No elements in decryption response".to_string(),
        )?;
        let pivot_payload = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response".to_string(),
        )?;
        for cur_resp in &agg_resp.responses {
            let cur_payload = some_or_err(
                cur_resp.payload.to_owned(),
                "No payload in current response!".to_string(),
            )?;
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };
            // Observe that the values contained in the pivot has already been validated to be
            // correct
            if cur_payload.digest != pivot_payload.digest
                || cur_payload.fhe_type()? != pivot_payload.fhe_type()?
                || cur_payload.plaintext != pivot_payload.plaintext
                || cur_payload.randomness != pivot_payload.randomness
                || cur_payload.shares_needed != pivot_payload.shares_needed
            {
                tracing::warn!("Some server did not provide the proper response!");
                return Ok(None);
            }
            let sig_payload: DecryptionResponseSigPayload = cur_payload.into();
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&sig_payload.verification_key)?;
            if !verify_sig(&to_vec(&sig_payload)?, &sig, &cur_verf_key) {
                tracing::warn!("Signature on received response is not valid!");
                return Ok(None);
            }
        }
        let serialized_plaintext = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response for decryption".to_owned(),
        )?
        .plaintext;
        let plaintext: Plaintext = from_bytes(&serialized_plaintext)?;
        Ok(Some(plaintext))
    }

    /// Processes the aggregated reencryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this. Validates the
    /// response matches the request, checks signatures, and handles both
    /// centralized and distributed cases.
    pub fn process_reencryption_resp(
        &self,
        request: Option<ReencryptionRequest>,
        agg_resp: AggregatedReencryptionResponse,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> anyhow::Result<Option<Plaintext>> {
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
        // Execute simplified and faster flow for the centralized case
        // Observe that we don't encode exactly the same in the centralized case and in the
        // distributed case. For the centralized case we directly encode the [Plaintext]
        // object whereas for the distributed we encode the plain text as a
        // Vec<ResiduePoly<Z128>>
        if agg_resp.responses.len() <= 1 {
            self.centralized_reencryption_resp(&agg_resp, &client_keys)
        } else {
            self.distributed_reencryption_resp(request, &agg_resp, &client_keys)
        }
    }

    /// Validates the aggregated decryption response by checking:
    /// - The responses agree on metadata like shares needed
    /// - The response matches the original request
    /// - Signatures on responses are valid
    ///
    /// Returns true if the response is valid, false otherwise
    fn validate_decryption_resp(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: &AggregatedDecryptionResponse,
    ) -> anyhow::Result<bool> {
        match request {
            Some(req) => match req.payload {
                Some(req_payload) => {
                    let resp_parsed_payloads = some_or_err(
                        self.validate_individual_dec_resp(req_payload.shares_needed, agg_resp)?,
                        "Could not validate the aggregated responses".to_string(),
                    )?;
                    let pivot_payload = resp_parsed_payloads[0].clone();
                    if req_payload.fhe_type() != pivot_payload.fhe_type()? {
                        tracing::warn!("Fhe type in the decryption response is incorrect");
                        return Ok(false);
                    }
                    let sig_payload: DecryptionRequestSigPayload = req_payload.try_into()?;
                    if BaseKmsStruct::digest(&to_vec(&sig_payload)?)? != pivot_payload.digest {
                        tracing::warn!(
                            "The decryption response is not linked to the correct request"
                        );
                        return Ok(false);
                    }
                    Ok(true)
                }
                None => {
                    tracing::warn!("No payload in the decryption request!");
                    Ok(false)
                }
            },
            None => {
                tracing::warn!("No decryption request!");
                Ok(false)
            }
        }
    }

    fn validate_individual_dec_resp(
        &self,
        shares_needed: u32,
        agg_resp: &AggregatedDecryptionResponse,
    ) -> anyhow::Result<Option<Vec<DecryptionResponsePayload>>> {
        if agg_resp.responses.is_empty() {
            tracing::warn!("AggregatedDecryptionResponse is empty!");
            return Ok(None);
        }
        // Pick a pivot response, in this case the last one
        let mut option_pivot_payload: Option<DecryptionResponsePayload> = None;
        let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.responses.len());
        for cur_resp in &agg_resp.responses {
            let cur_payload = match cur_resp.payload.clone() {
                Some(cur_payload) => cur_payload,
                None => {
                    tracing::warn!("No payload in current response from server!");
                    continue;
                }
            };
            // Set the first existing element as pivot
            let pivot_payload = match &option_pivot_payload {
                Some(pivot_payload) => pivot_payload,
                None => {
                    option_pivot_payload = Some(cur_payload.clone());
                    resp_parsed_payloads.push(cur_payload);
                    continue;
                }
            };
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };
            let sig_payload: DecryptionResponseSigPayload = cur_payload.clone().into();
            // Validate the signature on the response
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&sig_payload.verification_key)?;
            if !verify_sig(&to_vec(&sig_payload)?, &sig, &cur_verf_key) {
                tracing::warn!("Signature on received response is not valid!");
                continue;
            }
            // Validate that all the responses agree with the pivot on the static parts of the
            // response
            if !self.validate_meta_data(pivot_payload, &cur_payload)? {
                tracing::warn!("Some server did not provide the proper response!");
                continue;
            }
            resp_parsed_payloads.push(cur_payload);
        }

        if resp_parsed_payloads.len() < shares_needed as usize {
            tracing::warn!("Not enough correct responses to decrypt the data!");
            return Ok(None);
        }
        Ok(Some(resp_parsed_payloads))
    }

    /// Validates the aggregated reencryption responses received from the servers
    /// against the given reencryption request. Returns the validated responses
    /// mapped to the server ID on success.
    fn validate_reencryption_resp(
        &self,
        request: Option<ReencryptionRequest>,
        agg_resp: &AggregatedReencryptionResponse,
    ) -> anyhow::Result<
        Option<(
            ReencryptionRequestPayload,
            HashMap<u32, ReencryptionResponse>,
        )>,
    > {
        match request {
            Some(req) => match req.payload {
                Some(req_payload) => {
                    let resp_parsed = some_or_err(
                        self.validate_individual_reenc_resp(req_payload.shares_needed, agg_resp)?,
                        "Could not validate the aggregated responses".to_string(),
                    )?;
                    let pivot_resp = resp_parsed.values().collect_vec()[0];
                    if req_payload.fhe_type() != pivot_resp.fhe_type() {
                        tracing::warn!("Fhe type in the reencryption response is incorrect");
                        return Ok(None);
                    }
                    let sig_payload: ReencryptionRequestSigPayload = req_payload.try_into()?;
                    let req_digest = BaseKmsStruct::digest(&to_vec(&sig_payload)?)?;
                    if req_digest != pivot_resp.digest {
                        tracing::warn!(
                            "The reencryption response is not linked to the correct request"
                        );
                        return Ok(None);
                    }
                    Ok(Some((sig_payload.into(), resp_parsed)))
                }
                None => {
                    tracing::warn!("No payload in the reencryption request!");
                    Ok(None)
                }
            },
            None => {
                tracing::warn!("No reencryption request!");
                Ok(None)
            }
        }
    }

    fn validate_individual_reenc_resp(
        &self,
        shares_needed: u32,
        agg_resp: &AggregatedReencryptionResponse,
    ) -> anyhow::Result<Option<HashMap<u32, ReencryptionResponse>>> {
        if agg_resp.responses.is_empty() {
            tracing::warn!("AggregatedDecryptionResponse is empty!");
            return Ok(None);
        }
        // Pick a pivot response, in this case the last one
        let mut option_pivot: Option<&ReencryptionResponse> = None;
        let mut resp_parsed = HashMap::with_capacity(agg_resp.responses.len());
        for (cur_role, cur_resp) in &agg_resp.responses {
            // Set the first existing element as pivot
            let pivot_resp = match option_pivot {
                Some(pivot_resp) => pivot_resp,
                None => {
                    option_pivot = Some(cur_resp);
                    resp_parsed.insert(*cur_role, cur_resp.clone());
                    continue;
                }
            };
            // Validate that all the responses agree with the pivot on the static parts of the
            // response
            if !self.validate_meta_data(pivot_resp, cur_resp)? {
                tracing::warn!("Server {cur_role} did not provide the proper response!");
                continue;
            }
            resp_parsed.insert(*cur_role, cur_resp.clone());
        }
        if resp_parsed.len() < shares_needed as usize {
            tracing::warn!("Not enough correct responses to reencrypt the data!");
            return Ok(None);
        }
        Ok(Some(resp_parsed))
    }

    fn centralized_reencryption_resp(
        &self,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let resp = some_or_err(
            agg_resp.responses.values().last(),
            "Response does not exist".to_owned(),
        )?;
        let cur_verf_key: PublicSigKey = from_bytes(&resp.verification_key)?;
        match decrypt_signcryption(
            &resp.signcrypted_ciphertext,
            &resp.digest,
            client_keys,
            &cur_verf_key,
        )? {
            Some(decryption_share) => Ok(Some(decryption_share.try_into()?)),
            None => {
                tracing::warn!("Could decrypt or validate signcrypted response");
                Ok(None)
            }
        }
    }

    fn distributed_reencryption_resp(
        &self,
        request: Option<ReencryptionRequest>,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let (req_payload, validated_resps) = some_or_err(
            self.validate_reencryption_resp(request, agg_resp)?,
            "Could not validate request".to_owned(),
        )?;
        let sharings =
            self.recover_sharings(validated_resps, req_payload.fhe_type(), client_keys)?;
        let amount_shares = sharings.len();
        // TODO is this the optimal way of doing it?
        let mut decrypted_blocks = Vec::new();
        for cur_block_shares in sharings {
            if let Ok(Some(r)) = reconstruct_w_errors_sync(
                amount_shares,
                (req_payload.shares_needed - 1) as usize,
                (req_payload.shares_needed - 1) as usize,
                &cur_block_shares,
            ) {
                decrypted_blocks.push(r);
            } else {
                return Err(anyhow_error_and_log(
                    "Could not reconstruct all blocks".to_owned(),
                ));
            }
        }
        let recon_blocks = reconstruct_message(Some(decrypted_blocks), &self.params)?;
        Ok(Some(decrypted_blocks_to_raw_decryption(
            &self.params,
            req_payload.fhe_type(),
            recon_blocks,
        )?))
    }

    /// Decrypts the reencryption responses and decodes the responses onto the Shamir shares
    /// that the servers should have encrypted.
    fn recover_sharings(
        &self,
        agg_resp: HashMap<u32, ReencryptionResponse>,
        fhe_type: FheType,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<ShamirSharing<ResiduePoly<Z128>>>> {
        let num_blocks = num_blocks(fhe_type, self.params);
        let mut sharings = Vec::new();
        for _i in 0..num_blocks {
            sharings.push(ShamirSharing::new());
        }
        for (cur_role_id, cur_resp) in &agg_resp {
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&cur_resp.verification_key)?;
            match decrypt_signcryption(
                &cur_resp.signcrypted_ciphertext,
                &cur_resp.digest,
                client_keys,
                &cur_verf_key,
            )? {
                Some(decryption_share) => {
                    let cipher_blocks_share: Vec<ResiduePoly<Z128>> =
                        serde_asn1_der::from_bytes(&decryption_share.bytes)?;
                    let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                    for cur_block_share in cipher_blocks_share {
                        cur_blocks.push(cur_block_share);
                    }
                    fill_indexed_shares(
                        &mut sharings,
                        cur_blocks,
                        num_blocks,
                        Role::indexed_by_one(*cur_role_id as usize),
                    )?;
                }
                None => {
                    tracing::warn!("Could decrypt or validate signcrypted response");
                    fill_indexed_shares(
                        &mut sharings,
                        Vec::new(),
                        num_blocks,
                        Role::indexed_by_one(*cur_role_id as usize),
                    )?;
                }
            };
        }
        Ok(sharings)
    }

    fn validate_meta_data<T: MetaResponse>(
        &self,
        pivot_resp: &T,
        other_resp: &T,
    ) -> anyhow::Result<bool> {
        if pivot_resp.fhe_type()? != other_resp.fhe_type()? {
            tracing::warn!(
                    "Response from server with verification key {:?} gave fhe type {:?}, whereas the pivot server's fhe type is {:?} and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.fhe_type(),
                    other_resp.fhe_type(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.shares_needed() != other_resp.shares_needed() {
            tracing::warn!(
                    "Response from server with verification key {:?} say {:?} shares are needed for reconstruction, whereas the pivot server says {:?} shares are needed for reconstruction, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.shares_needed(),
                    other_resp.shares_needed(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.digest() != other_resp.digest() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.shares_needed(),
                    other_resp.shares_needed(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.randomness() != other_resp.randomness() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave randomness {:?}, whereas the pivot server gave randomness {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.randomness(),
                    other_resp.randomness(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        let resp_verf_key: PublicSigKey = from_bytes(&other_resp.verification_key())?;
        if !&self.server_pks.contains(&resp_verf_key) {
            tracing::warn!("Server key is incorrect in reencryption request");
            return Ok(false);
        }
        if pivot_resp.shares_needed() != self.shares_needed {
            tracing::warn!("Response says only {:?} shares are needed for reconstruction, but client is setup to require {:?} shares", pivot_resp.shares_needed(), self.shares_needed);
            return Ok(false);
        }

        Ok(true)
    }
}

/// Calculates the number of blocks needed to encode a message of the given FHE
/// type, based on the usable message modulus log from the
/// parameters. Rounds up to ensure enough blocks.
pub fn num_blocks(fhe_type: FheType, params: ThresholdLWEParameters) -> usize {
    match fhe_type {
        FheType::Bool => {
            8_usize.div_ceil(params.output_cipher_parameters.usable_message_modulus_log.0)
        }
        FheType::Euint8 => {
            8_usize.div_ceil(params.output_cipher_parameters.usable_message_modulus_log.0)
        }
        FheType::Euint16 => {
            16_usize.div_ceil(params.output_cipher_parameters.usable_message_modulus_log.0)
        }
        FheType::Euint32 => {
            32_usize.div_ceil(params.output_cipher_parameters.usable_message_modulus_log.0)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::setup_rpc::tests::{AMOUNT_PARTIES, DEFAULT_FHE_TYPE, DEFAULT_MSG, THRESHOLD};
    use crate::setup_rpc::{
        BASE_PORT, DEFAULT_CLIENT_KEY_PATH, DEFAULT_HL_CIPHER_PATH, DEFAULT_KMS_KEY_PATH,
        DEFAULT_LL_CIPHER_PATH, DEFAULT_PROT, DEFAULT_SERVER_KEYS_PATH, DEFAULT_URL, PARAM_PATH,
        THRESHOLD_KMS_KEY_PATH,
    };
    use crate::{num_blocks, Client};
    use distributed_decryption::lwe::ThresholdLWEParameters;
    use kms::core::der_types::{PrivateSigKey, PublicSigKey};
    use kms::file_handling::{read_as_json, read_element};
    use kms::kms::kms_endpoint_client::KmsEndpointClient;
    use kms::kms::{AggregatedDecryptionResponse, AggregatedReencryptionResponse, FheType};
    use kms::rpc::kms_rpc::server_handle;
    use kms::threshold::threshold_kms::threshold_server_handle;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::str::FromStr;
    use tokio::task::{JoinHandle, JoinSet};
    use tonic::transport::{Channel, Uri};

    async fn setup() -> (JoinHandle<()>, KmsEndpointClient<Channel>) {
        let server_handle = tokio::spawn(async {
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
            let _ = server_handle(url.as_str(), DEFAULT_KMS_KEY_PATH.to_string()).await;
        });
        // Wait for the server to start
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
        let uri = Uri::from_str(&url).unwrap();
        let channel = Channel::builder(uri).connect().await.unwrap();
        let client = KmsEndpointClient::new(channel);
        (server_handle, client)
    }

    async fn setup_threshold(
        amount: usize,
        threshold: u8,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, KmsEndpointClient<Channel>>,
    ) {
        let mut server_handles = HashMap::new();
        for i in 1..=amount {
            let key_path = format!("{THRESHOLD_KMS_KEY_PATH}-{i}.bin");
            let handle = tokio::spawn(async move {
                let _ = threshold_server_handle(
                    DEFAULT_URL.to_owned(),
                    BASE_PORT,
                    key_path,
                    amount,
                    threshold,
                    i,
                )
                .await;
            });
            server_handles.insert(i as u32, handle);
        }
        // Wait for the server to start
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let mut client_handles = HashMap::new();
        for i in 1..=amount {
            let port = BASE_PORT + i as u16;
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
            let uri = Uri::from_str(&url).unwrap();
            let channel = Channel::builder(uri).connect().await.unwrap();
            client_handles.insert(i as u32, KmsEndpointClient::new(channel));
        }
        (server_handles, client_handles)
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption() {
        let (kms_server, mut kms_client) = setup().await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element(DEFAULT_HL_CIPHER_PATH.to_string()).unwrap();
        let mut internal_client = Client::default();

        let req = internal_client
            .decryption_request(ct.clone(), fhe_type)
            .unwrap();
        let response = kms_client
            .decrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();

        let responses = AggregatedDecryptionResponse {
            responses: vec![response.into_inner()],
        };
        let plaintext = internal_client
            .process_decryption_resp(Some(req), responses)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(DEFAULT_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption() {
        let (kms_server, mut kms_client) = setup().await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element(DEFAULT_HL_CIPHER_PATH.to_string()).unwrap();
        let mut internal_client = Client::default();

        let (req, enc_pk, enc_sk) = internal_client.reencyption_request(ct, fhe_type).unwrap();
        let response = kms_client
            .reencrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();

        let responses = AggregatedReencryptionResponse {
            responses: HashMap::from([(1, response.into_inner())]),
        };
        let plaintext = internal_client
            .process_reencryption_resp(Some(req), responses, &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(DEFAULT_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_threshold() {
        let (kms_servers, kms_clients) = setup_threshold(AMOUNT_PARTIES, THRESHOLD as u8).await;
        let default_params: ThresholdLWEParameters = read_as_json(PARAM_PATH.to_owned()).unwrap();
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element(DEFAULT_LL_CIPHER_PATH.to_string()).unwrap();
        let (client_pk, client_sk): (PublicSigKey, PrivateSigKey) =
            read_element(DEFAULT_CLIENT_KEY_PATH.to_string()).unwrap();
        let server_pub_keys = read_element(DEFAULT_SERVER_KEYS_PATH.to_string()).unwrap();
        let mut internal_client = Client::new(
            server_pub_keys,
            client_pk,
            client_sk,
            (THRESHOLD as u32) + 1,
            default_params,
        );

        let req = internal_client.decryption_request(ct, fhe_type).unwrap();
        let mut tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            tasks.spawn(async move { cur_client.decrypt(tonic::Request::new(req_clone)).await });
        }
        let mut response_vec = Vec::new();
        while let Some(Ok(Ok(resp))) = tasks.join_next().await {
            response_vec.push(resp.into_inner());
        }
        let agg = AggregatedDecryptionResponse {
            responses: response_vec,
        };
        let plaintext = internal_client
            .process_decryption_resp(Some(req), agg)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(DEFAULT_MSG, plaintext.as_u8());
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption_threshold() {
        let (kms_servers, kms_clients) = setup_threshold(AMOUNT_PARTIES, THRESHOLD as u8).await;
        let default_params: ThresholdLWEParameters = read_as_json(PARAM_PATH.to_owned()).unwrap();
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element(DEFAULT_LL_CIPHER_PATH.to_string()).unwrap();
        let (client_pk, client_sk): (PublicSigKey, PrivateSigKey) =
            read_element(DEFAULT_CLIENT_KEY_PATH.to_string()).unwrap();
        let server_pub_keys = read_element(DEFAULT_SERVER_KEYS_PATH.to_string()).unwrap();
        let mut internal_client = Client::new(
            server_pub_keys,
            client_pk,
            client_sk,
            (THRESHOLD as u32) + 1,
            default_params,
        );

        let (req, enc_pk, enc_sk) = internal_client.reencyption_request(ct, fhe_type).unwrap();
        let mut tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            tasks.spawn(async move {
                (
                    i,
                    cur_client.reencrypt(tonic::Request::new(req_clone)).await,
                )
            });
        }
        let mut response_map = HashMap::new();
        while let Some(Ok(res)) = tasks.join_next().await {
            let (i, resp) = res;
            response_map.insert(i, resp.unwrap().into_inner());
        }
        let agg = AggregatedReencryptionResponse {
            responses: response_map,
        };
        let plaintext = internal_client
            .process_reencryption_resp(Some(req), agg, &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(DEFAULT_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(DEFAULT_MSG, plaintext.as_u8());
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());
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

    #[test]
    fn num_blocks_sunshine() {
        let params: ThresholdLWEParameters = read_as_json(PARAM_PATH.to_owned()).unwrap();
        let cur_type = FheType::Bool;
        // 2 bits per block, using Euint8 as internal representation
        assert_eq!(num_blocks(cur_type, params), 4);
        let cur_type = FheType::Euint8;
        // 2 bits per block
        assert_eq!(num_blocks(cur_type, params), 4);
        let cur_type = FheType::Euint16;
        // 2 bits per block
        assert_eq!(num_blocks(cur_type, params), 8);
        let cur_type = FheType::Euint32;
        // 2 bits per block
        assert_eq!(num_blocks(cur_type, params), 16);
    }
}
