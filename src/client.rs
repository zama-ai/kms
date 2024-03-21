use aes_prng::AesRng;
use distributed_decryption::algebra::base_ring::Z128;
use distributed_decryption::algebra::residue_poly::ResiduePoly;
use distributed_decryption::error::error_handler::anyhow_error_and_log;
use distributed_decryption::execution::endpoints::decryption::reconstruct_message;
use distributed_decryption::execution::runtime::party::Role;
use distributed_decryption::execution::sharing::open::{
    fill_indexed_shares, reconstruct_w_errors_sync,
};
use distributed_decryption::execution::sharing::shamir::ShamirSharings;
use distributed_decryption::lwe::ThresholdLWEParameters;
use itertools::Itertools;
use kms_lib::core::der_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, Signature, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use kms_lib::core::kms_core::{decrypt_signcryption, BaseKmsStruct};
use kms_lib::core::signcryption::{encryption_key_generation, sign, verify_sig, RND_SIZE};
use kms_lib::file_handling::read_element;
use kms_lib::kms::kms_endpoint_client::KmsEndpointClient;
use kms_lib::kms::{
    AggregatedDecryptionResponse, AggregatedReencryptionResponse, CrsCeremonyRequest, CrsHandle,
    DecryptionRequest, DecryptionResponsePayload, FheType, GetAllKeysRequest, GetKeyRequest,
    KeyGenRequest, ParamChoice, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse,
};
use kms_lib::rpc::kms_rpc::{some_or_err, CURRENT_FORMAT_VERSION};
use kms_lib::rpc::rpc_types::{
    BaseKms, DecryptionRequestSerializable, DecryptionResponseSigPayload, MetaResponse, Plaintext,
    ReencryptionRequestSigPayload,
};
use kms_lib::setup_rpc::{
    CentralizedTestingKeys, DEFAULT_CENTRAL_CT_PATH, DEFAULT_CENTRAL_KEYS_PATH, KEY_HANDLE,
};
use kms_lib::threshold::threshold_kms::decrypted_blocks_to_raw_decryption;
use rand::{RngCore, SeedableRng};
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::{HashMap, HashSet};
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

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
    let (ct, fhe_type): (Vec<u8>, FheType) = read_element(DEFAULT_CENTRAL_CT_PATH)?;
    let central_keys: CentralizedTestingKeys = read_element(DEFAULT_CENTRAL_KEYS_PATH)?;
    let mut internal_client = Client::new(
        HashSet::from_iter(central_keys.server_keys.iter().cloned()),
        central_keys.client_pk,
        central_keys.client_sk,
        1,
        central_keys.params,
    );

    // DECRYPTION REQUEST
    let req = internal_client.decryption_request(ct.clone(), fhe_type, None)?;
    let response = kms_client.decrypt(tonic::Request::new(req.clone())).await?;
    tracing::debug!("DECRYPT RESPONSE={:?}", response);
    let responses = AggregatedDecryptionResponse {
        responses: vec![response.into_inner()],
    };
    match internal_client.process_decryption_resp(Some(req), responses) {
        Ok(Some(plaintext)) => {
            tracing::info!(
                "Decryption response is ok: {:?} of type {:?}",
                plaintext.as_u32(),
                plaintext.fhe_type()
            )
        }
        _ => tracing::warn!("Decryption response is NOT valid"),
    };

    // REENCRYPTION REQUEST
    let (req, enc_pk, enc_sk) = internal_client.reencyption_request(ct, fhe_type, None)?;
    let response = kms_client
        .reencrypt(tonic::Request::new(req.clone()))
        .await?;
    tracing::debug!("REENCRYPT RESPONSE={:?}", response);
    let responses = AggregatedReencryptionResponse {
        responses: HashMap::from([(1, response.into_inner())]),
    };
    match internal_client.process_reencryption_resp(Some(req), responses, &enc_pk, &enc_sk) {
        Ok(Some(plaintext)) => {
            tracing::info!(
                "Reencryption response is ok: {:?} of type {:?}",
                plaintext.as_u32(),
                plaintext.fhe_type()
            )
        }
        _ => tracing::warn!("Reencryption response is NOT valid"),
    };

    Ok(())
}

/// Simple client to interact with the KMS servers. This can be seen as a proof-of-concept
/// and reference code for validating the KMS. The logic supplied by the client will be
/// distributed accross the aggregator/proxy and smart contracts.
/// TODO should probably aggregate the KmsEndpointClient to void having two client code bases
/// exposed in tests and MVP
pub struct Client {
    rng: Box<AesRng>,
    server_pks: HashSet<PublicSigKey>,
    client_pk: PublicSigKey,
    client_sk: PrivateSigKey,
    shares_needed: u32,
    params: ThresholdLWEParameters,
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
            rng: Box::new(AesRng::from_entropy()),
            server_pks,
            client_pk,
            client_sk,
            shares_needed,
            params,
        }
    }

    pub fn key_gen_request(
        &self,
        key_handle: &str,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<KeyGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };
        Ok(KeyGenRequest {
            key_handle: key_handle.to_string(),
            params: parsed_param,
        })
    }

    pub fn get_key_request(&self, key_handle: &str) -> anyhow::Result<GetKeyRequest> {
        Ok(GetKeyRequest {
            key_handle: key_handle.to_string(),
        })
    }

    pub fn crs_gen_request(
        &self,
        crs_handle: &str,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<CrsCeremonyRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };
        Ok(CrsCeremonyRequest {
            crs_handle: crs_handle.to_string(),
            params: parsed_param,
        })
    }

    pub fn get_crs_request(&self, crs_handle: &str) -> anyhow::Result<CrsHandle> {
        Ok(CrsHandle {
            crs_handle: crs_handle.to_string(),
        })
    }

    pub fn get_all_keys_request(&self) -> GetAllKeysRequest {
        GetAllKeysRequest {}
    }

    /// Creates a decryption request to send to the KMS servers.
    pub fn decryption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
        key_handle: Option<String>,
    ) -> anyhow::Result<DecryptionRequest> {
        // Observe that this randomness can be reused across the servers since each server will have
        // a unique PK that is included in their response, hence it will still be validated
        // that each request contains a unique message to be signed hence ensuring CCA
        // security. TODO this argument should be validated
        let mut randomness: Vec<u8> = Vec::with_capacity(RND_SIZE);
        let handle = key_handle.unwrap_or(KEY_HANDLE.to_string());
        self.rng.fill_bytes(&mut randomness);
        let serialized_req = DecryptionRequestSerializable {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: self.shares_needed,
            fhe_type,
            ciphertext: ct,
            randomness,
            key_handle: handle,
        };
        Ok(serialized_req.into())
    }

    /// Creates a reencryption request to send to the KMS servers. This generates
    /// an ephemeral reencryption key pair, signature payload containing the ciphertext,
    /// required number of shares, and other metadata. It signs this payload with
    /// the users's wallet private key. Returns the full ReencryptionRequest containing
    /// the signed payload to send to the servers, along with the generated
    /// reencryption key pair.
    pub fn reencyption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
        key_handle: Option<String>,
    ) -> anyhow::Result<(ReencryptionRequest, PublicEncKey, PrivateEncKey)> {
        let (enc_pk, enc_sk) = encryption_key_generation(&mut self.rng);
        let mut randomness = Vec::with_capacity(RND_SIZE);
        let handle = key_handle.unwrap_or(KEY_HANDLE.to_string());
        self.rng.fill_bytes(&mut randomness);
        let sig_payload = ReencryptionRequestSigPayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: self.shares_needed,
            enc_key: to_vec(&enc_pk)?,
            verification_key: to_vec(&self.client_pk)?,
            fhe_type,
            ciphertext: ct,
            randomness,
            key_handle: handle,
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
        // TODO pivot should actually be picked as the most common response instead of just an
        // arbitrary one. The same in reencryption
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
            // TODO I think this is redundant
            if cur_payload.digest != pivot_payload.digest
                || cur_payload.fhe_type()? != pivot_payload.fhe_type()?
                || cur_payload.plaintext != pivot_payload.plaintext
                || cur_payload.servers_needed != pivot_payload.servers_needed
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
            Some(req) => {
                let resp_parsed_payloads = some_or_err(
                    self.validate_individual_dec_resp(req.servers_needed, agg_resp)?,
                    "Could not validate the aggregated responses".to_string(),
                )?;
                let pivot_payload = resp_parsed_payloads[0].clone();
                if req.version != pivot_payload.version() {
                    tracing::warn!("Version in the decryption request is incorrect");
                    return Ok(false);
                }
                if req.fhe_type() != pivot_payload.fhe_type()? {
                    tracing::warn!("Fhe type in the decryption response is incorrect");
                    return Ok(false);
                }
                let sig_payload: DecryptionRequestSerializable = req.try_into()?;
                if BaseKmsStruct::digest(&to_vec(&sig_payload)?)? != pivot_payload.digest {
                    tracing::warn!("The decryption response is not linked to the correct request");
                    return Ok(false);
                }
                Ok(true)
            }
            None => {
                tracing::warn!("No payload in the decryption request!");
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
                        self.validate_individual_reenc_resp(req_payload.servers_needed, agg_resp)?,
                        "Could not validate the aggregated responses".to_string(),
                    )?;
                    let pivot_resp = resp_parsed.values().collect_vec()[0];
                    if req_payload.version != pivot_resp.version() {
                        tracing::warn!("Version in the reencryption request is incorrect");
                        return Ok(None);
                    }
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
        let mut decrypted_blocks = Vec::new();
        for cur_block_shares in sharings {
            if let Ok(Some(r)) = reconstruct_w_errors_sync(
                amount_shares,
                (req_payload.servers_needed - 1) as usize,
                (req_payload.servers_needed - 1) as usize,
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
    ) -> anyhow::Result<Vec<ShamirSharings<ResiduePoly<Z128>>>> {
        let num_blocks = num_blocks(fhe_type, self.params);
        let mut sharings = Vec::new();
        for _i in 0..num_blocks {
            sharings.push(ShamirSharings::new());
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
        if pivot_resp.version() != other_resp.version() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave version {:?}, whereas the pivot server's version is {:?}, and its verification key is {:?}.",
                    pivot_resp.verification_key(),
                    pivot_resp.version(),
                    other_resp.version(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
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
        if pivot_resp.servers_needed() != other_resp.servers_needed() {
            tracing::warn!(
                    "Response from server with verification key {:?} say {:?} shares are needed for reconstruction, whereas the pivot server says {:?} shares are needed for reconstruction, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.servers_needed(),
                    other_resp.servers_needed(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.digest() != other_resp.digest() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.servers_needed(),
                    other_resp.servers_needed(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        let resp_verf_key: PublicSigKey = from_bytes(&other_resp.verification_key())?;
        if !&self.server_pks.contains(&resp_verf_key) {
            tracing::warn!("Server key is incorrect in reencryption request");
            return Ok(false);
        }
        if pivot_resp.servers_needed() != self.shares_needed {
            tracing::warn!("Response says only {:?} shares are needed for reconstruction, but client is setup to require {:?} shares", pivot_resp.servers_needed(), self.shares_needed);
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
            8_usize.div_ceil(params.output_cipher_parameters.message_modulus_log() as usize)
        }
        FheType::Euint4 => {
            8_usize.div_ceil(params.output_cipher_parameters.message_modulus_log() as usize)
        }
        FheType::Euint8 => {
            8_usize.div_ceil(params.output_cipher_parameters.message_modulus_log() as usize)
        }
        FheType::Euint16 => {
            16_usize.div_ceil(params.output_cipher_parameters.message_modulus_log() as usize)
        }
        FheType::Euint32 => {
            32_usize.div_ceil(params.output_cipher_parameters.message_modulus_log() as usize)
        }
        FheType::Euint64 => {
            64_usize.div_ceil(params.output_cipher_parameters.message_modulus_log() as usize)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{num_blocks, Client};
    use distributed_decryption::lwe::ThresholdLWEParameters;
    use kms_lib::core::kms_core::{CrsHashMap, SignedCRS, SignedFhePublicKeySet, SoftwareKmsKeys};
    use kms_lib::file_handling::{read_as_json, read_element, read_element_async};
    use kms_lib::kms::kms_endpoint_client::KmsEndpointClient;
    use kms_lib::kms::{
        AggregatedDecryptionResponse, AggregatedReencryptionResponse, CrsHandle, FheType,
        ParamChoice,
    };
    use kms_lib::rpc::kms_rpc::{crs_path, priv_key_path, pub_key_path, server_handle};
    use kms_lib::setup_rpc::{
        CentralizedTestingKeys, ThresholdTestingKeys, AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT,
        DEFAULT_URL, KEY_HANDLE, TEST_CENTRAL_CRS_PATH, TEST_CENTRAL_CT_PATH,
        TEST_CENTRAL_KEYS_PATH, TEST_CRS_HANDLE, TEST_FHE_TYPE, TEST_MSG, TEST_PARAM_PATH,
        TEST_THRESHOLD_CT_PATH, TEST_THRESHOLD_KEYS_PATH, THRESHOLD,
    };
    #[cfg(feature = "slow_tests")]
    use kms_lib::setup_rpc::{
        DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CENTRAL_CT_PATH, DEFAULT_CENTRAL_KEYS_PATH,
        DEFAULT_CRS_HANDLE, DEFAULT_THRESHOLD_CT_PATH, DEFAULT_THRESHOLD_KEYS_PATH,
    };
    use kms_lib::threshold::threshold_kms::{threshold_server_init, threshold_server_start};
    use serial_test::serial;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::str::FromStr;
    use tokio::task::{JoinHandle, JoinSet};
    use tonic::transport::{Channel, Uri};

    async fn setup(
        kms_keys: SoftwareKmsKeys,
        crs_store: Option<CrsHashMap>,
    ) -> (JoinHandle<()>, KmsEndpointClient<Channel>) {
        let server_handle = tokio::spawn(async move {
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
            let _ = server_handle(url.as_str(), kms_keys, crs_store).await;
        });
        // We have to wait for the server to start since it will keep running in the background
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
        let uri = Uri::from_str(&url).unwrap();
        let channel = Channel::builder(uri).connect().await.unwrap();
        let client = KmsEndpointClient::new(channel);
        (server_handle, client)
    }

    /// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
    /// server, client end-point connection (which is needed to communicate with the server) and
    /// an internal client (for constructing requests and validating responses).
    async fn centralized_handles(
        centralized_key_path: &str,
        centralized_crs_path: Option<&str>,
    ) -> (JoinHandle<()>, KmsEndpointClient<Channel>, Client) {
        let keys: CentralizedTestingKeys = read_element(centralized_key_path).unwrap();

        // set crs_store if path is provided, else set it to None
        let crs_store =
            centralized_crs_path.map(|crs_path| read_element::<CrsHashMap>(crs_path).unwrap());

        let (kms_server, kms_client) = setup(keys.software_kms_keys, crs_store).await;
        let internal_client = Client::new(
            HashSet::from_iter(keys.server_keys.iter().cloned()),
            keys.client_pk,
            keys.client_sk,
            1,
            keys.params,
        );
        (kms_server, kms_client, internal_client)
    }

    async fn setup_threshold(
        amount: usize,
        threshold: u8,
        threshold_key_path_prefix: &str,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, KmsEndpointClient<Channel>>,
    ) {
        let mut handles = Vec::new();
        tracing::info!("Spawning servers..");
        for i in 1..=amount {
            let key_path = format!("{threshold_key_path_prefix}-{i}.bin");
            handles.push(tokio::spawn(async move {
                tracing::info!("Server {i} reading keys..");
                let keys: ThresholdTestingKeys =
                    read_element_async(key_path.to_string()).await.unwrap();
                tracing::info!("Server {i} read keys..");
                let server = threshold_server_init(
                    DEFAULT_URL.to_owned(),
                    BASE_PORT,
                    amount,
                    threshold,
                    i,
                    keys.kms_keys,
                )
                .await;
                (i, server)
            }));
        }
        // Wait for the server to start
        tracing::info!("Client waiting for server");
        let mut servers = Vec::with_capacity(amount);
        for cur_handle in handles {
            let (i, kms_server_res) = cur_handle.await.unwrap();
            match kms_server_res {
                Ok(kms_server) => servers.push((i, kms_server)),
                Err(e) => tracing::warn!("Failed to start server {i} with error {:?}", e),
            }
        }
        tracing::info!("Servers initialized. Starting servers...");
        let mut server_handles = HashMap::new();
        for (i, cur_server) in servers {
            let handle = tokio::spawn(async move {
                let _ =
                    threshold_server_start(DEFAULT_URL.to_owned(), BASE_PORT, i, cur_server).await;
            });
            server_handles.insert(i as u32, handle);
        }
        // We need to sleep as the servers keep running in the background and hence do not return
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut client_handles = HashMap::new();
        for i in 1..=amount {
            let port = BASE_PORT + i as u16;
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
            let uri = Uri::from_str(&url).unwrap();
            let channel = Channel::builder(uri).connect().await.unwrap();
            client_handles.insert(i as u32, KmsEndpointClient::new(channel));
        }
        tracing::info!("Client connected to servers");
        (server_handles, client_handles)
    }

    /// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
    /// of the servers, based on their ID, which starts from 1. A smiliar map is also returned
    /// is the client endpoints needed to talk with each of the servers, finally the internal
    /// client is returned (which is responsible for constructing requests and validating
    /// responses).
    async fn threshold_handles(
        threshold_key_path: &str,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, KmsEndpointClient<Channel>>,
        Client,
    ) {
        let (kms_servers, kms_clients) =
            setup_threshold(AMOUNT_PARTIES, THRESHOLD as u8, threshold_key_path).await;
        let keys: ThresholdTestingKeys = read_element_async(format!("{threshold_key_path}-1.bin"))
            .await
            .unwrap();
        let internal_client = Client::new(
            HashSet::from_iter(keys.server_keys.iter().cloned()),
            keys.client_pk,
            keys.client_sk,
            (THRESHOLD as u32) + 1,
            keys.params,
        );

        (kms_servers, kms_clients, internal_client)
    }

    #[tokio::test]
    #[serial]
    async fn test_key_gen_centralized() {
        key_gen_centralized(
            TEST_CENTRAL_KEYS_PATH,
            "someHandle",
            Some(ParamChoice::Test),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_key_gen_centralized() {
        key_gen_centralized(DEFAULT_CENTRAL_KEYS_PATH, "someHandle", None).await;
    }

    async fn key_gen_centralized(
        centralized_key_path: &str,
        key_handle: &str,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            centralized_handles(centralized_key_path, None).await;
        let ref_uri = pub_key_path(key_handle);
        // Remove the keys to ensure that the test is idempotent
        let _ = fs::remove_file(ref_uri.clone());
        let priv_uri = priv_key_path(key_handle);
        let _ = fs::remove_file(priv_uri);

        let gen_req = internal_client.key_gen_request(key_handle, params).unwrap();
        let gen_response = kms_client
            .key_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();
        let res_uri = gen_response.into_inner().key_uri;
        assert_eq!(res_uri, ref_uri);

        // Check that we can retrieve the key
        let get_req = internal_client.get_key_request(key_handle).unwrap();
        let get_response = kms_client
            .get_key(tonic::Request::new(get_req.clone()))
            .await
            .unwrap();
        let res_uri = get_response.into_inner().key_uri;
        assert_eq!(res_uri, ref_uri);

        // check that key signature is verified correctly
        let signed_key: SignedFhePublicKeySet = read_element(&res_uri).unwrap();
        let mut verified = false;

        // try verification with each of the server keys
        for vk in internal_client.server_pks {
            let v = signed_key.verify_signature(&vk);
            verified = verified || v;
        }

        // check that verification (with at least 1 server key) worked
        assert!(verified);

        kms_server.abort();
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_crs_gen_centralized() {
        crs_gen_centralized(
            DEFAULT_CENTRAL_KEYS_PATH,
            DEFAULT_CENTRAL_CRS_PATH,
            DEFAULT_CRS_HANDLE,
            Some(ParamChoice::Default),
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_crs_gen_centralized() {
        crs_gen_centralized(
            TEST_CENTRAL_KEYS_PATH,
            TEST_CENTRAL_CRS_PATH,
            TEST_CRS_HANDLE,
            Some(ParamChoice::Test),
        )
        .await;
    }

    /// test centralized crs generation
    async fn crs_gen_centralized(
        centralized_key_path: &str,
        centralized_crs_path: &str,
        crs_handle: &str,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            centralized_handles(centralized_key_path, Some(centralized_crs_path)).await;
        let ref_uri = crs_path(crs_handle);
        // Remove the keys to ensure that the test is idempotent
        let _ = fs::remove_file(ref_uri.clone());

        let ceremony_req = internal_client.crs_gen_request(crs_handle, params).unwrap();

        let gen_response = kms_client
            .crs_ceremony(tonic::Request::new(ceremony_req.clone()))
            .await
            .unwrap();
        let res_uri = gen_response.into_inner().crs_uri;
        assert_eq!(res_uri, ref_uri);

        // Check that we can retrieve the CRS under that handle
        let get_req = CrsHandle {
            crs_handle: crs_handle.to_string(),
        };
        let get_response = kms_client
            .crs_request(tonic::Request::new(get_req.clone()))
            .await
            .unwrap();
        let res_uri = get_response.into_inner().crs_uri;
        assert_eq!(res_uri, ref_uri);

        // check that CRS signature is verified correctly
        let signed_crs: SignedCRS = read_element(&res_uri).unwrap();
        let mut verified = false;

        // try verification with each of the server keys
        for vk in internal_client.server_pks {
            let v = signed_crs.verify_signature(&vk);
            verified = verified || v;
        }

        // check that verification (with at least 1 server key) worked
        assert!(verified);

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_get_all_keys_centralized() {
        get_all_keys_centralized(TEST_CENTRAL_KEYS_PATH, Some(ParamChoice::Test)).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_get_all_keys_centralized() {
        get_all_keys_centralized(DEFAULT_CENTRAL_KEYS_PATH, None).await;
    }

    async fn get_all_keys_centralized(centralized_key_path: &str, params: Option<ParamChoice>) {
        let ref_1 = pub_key_path("1");
        let ref_2 = pub_key_path("2");
        // Remove the keys to ensure that the test is idempotent in case they already exist
        let _ = fs::remove_file(ref_1.clone());
        let priv_uri_1 = priv_key_path("1");
        let _ = fs::remove_file(priv_uri_1);
        let _ = fs::remove_file(ref_2.clone());
        let priv_uri_2 = priv_key_path("2");
        let _ = fs::remove_file(priv_uri_2);

        let (kms_server, mut kms_client, internal_client) =
            centralized_handles(centralized_key_path, None).await;
        let gen_req = internal_client.key_gen_request("1", params).unwrap();
        let _ = kms_client
            .key_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();

        let gen_req = internal_client.key_gen_request("2", params).unwrap();
        let _ = kms_client
            .key_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();

        // Check that we can retrieve both keys
        let get_req = internal_client.get_all_keys_request();
        let get_response = kms_client
            .get_all_keys(tonic::Request::new(get_req.clone()))
            .await
            .unwrap();
        let res = get_response.into_inner().handles;
        assert_eq!(
            res.get(KEY_HANDLE).unwrap().to_owned(),
            pub_key_path(KEY_HANDLE)
        );
        assert_eq!(res.get("1").unwrap().to_owned(), pub_key_path("1"));
        assert_eq!(res.get("2").unwrap().to_owned(), pub_key_path("2"));
        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(TEST_CENTRAL_KEYS_PATH, TEST_CENTRAL_CT_PATH).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_decryption_centralized() {
        decryption_centralized(DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_CT_PATH).await;
    }
    // TODO speed up
    async fn decryption_centralized(centralized_key_path: &str, cipher_path: &str) {
        // TODO refactor with setup and teardown setting up servers that can be used to run tests in
        // parallel
        let (kms_server, mut kms_client, mut internal_client) =
            centralized_handles(centralized_key_path, None).await;
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();

        let req = internal_client
            .decryption_request(ct.clone(), fhe_type, None)
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
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized() {
        reencryption_centralized(TEST_CENTRAL_KEYS_PATH, TEST_CENTRAL_CT_PATH).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_reencryption_centralized() {
        reencryption_centralized(DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_CT_PATH).await;
    }

    async fn reencryption_centralized(centralized_key_path: &str, cipher_path: &str) {
        let (kms_server, mut kms_client, mut internal_client) =
            centralized_handles(centralized_key_path, None).await;
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();
        let (req, enc_pk, enc_sk) = internal_client
            .reencyption_request(ct, fhe_type, None)
            .unwrap();
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
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_threshold() {
        decryption_threshold(TEST_THRESHOLD_KEYS_PATH, TEST_THRESHOLD_CT_PATH).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_threshold() {
        decryption_threshold(DEFAULT_THRESHOLD_KEYS_PATH, DEFAULT_THRESHOLD_CT_PATH).await;
    }

    async fn decryption_threshold(threshold_key_path: &str, cipher_path: &str) {
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(threshold_key_path).await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element_async(cipher_path.to_string()).await.unwrap();

        let req = internal_client
            .decryption_request(ct, fhe_type, None)
            .unwrap();
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
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption_threshold() {
        reencryption_threshold(TEST_THRESHOLD_KEYS_PATH, TEST_THRESHOLD_CT_PATH).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_threshold() {
        reencryption_threshold(DEFAULT_THRESHOLD_KEYS_PATH, DEFAULT_THRESHOLD_CT_PATH).await;
    }

    async fn reencryption_threshold(threshold_key_path: &str, cipher_path: &str) {
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(threshold_key_path).await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element_async(cipher_path.to_string()).await.unwrap();

        let (req, enc_pk, enc_sk) = internal_client
            .reencyption_request(ct, fhe_type, None)
            .unwrap();
        let mut tasks = JoinSet::new();
        tracing::info!("Client did reencryption request");
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
        tracing::info!("Client issued reencrypt queries");
        let mut response_map = HashMap::new();
        while let Some(Ok(res)) = tasks.join_next().await {
            tracing::info!("Client got a response from {}", res.0);
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
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());
    }

    // Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn test_largecipher() {
        let keys: CentralizedTestingKeys = read_element(DEFAULT_CENTRAL_KEYS_PATH).unwrap();
        let (kms_server, mut kms_client) = setup(keys.software_kms_keys, None).await;
        let ct = Vec::from([1_u8; 1000000]);
        let fhe_type = FheType::Euint32;
        let mut internal_client = Client::new(
            HashSet::from_iter(keys.server_keys.iter().cloned()),
            keys.client_pk,
            keys.client_sk,
            1,
            keys.params,
        );

        let (req, _enc_pk, _enc_sk) = internal_client
            .reencyption_request(ct, fhe_type, None)
            .unwrap();
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
        let params: ThresholdLWEParameters = read_as_json(TEST_PARAM_PATH.to_owned()).unwrap();
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
