use crate::anyhow_error_and_log;
use crate::cryptography::internal_crypto_types::Signature;
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicSigKey};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use itertools::Itertools;
use kms_grpc::kms::v1::UserDecryptionRequest;
use kms_grpc::rpc_types::UserDecryptionLinker;
use rand::SeedableRng;
use std::collections::HashMap;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::consts::{DEFAULT_PROTOCOL, DEFAULT_URL, MAX_TRIES};
        use crate::engine::base::BaseKmsStruct;
        use crate::engine::traits::BaseKms;
        use crate::vault::storage::{
            crypto_material::{
                get_client_signing_key, get_client_verification_key, get_core_verification_key,
            },
            Storage, StorageReader,
        };
        use std::fmt;
        use threshold_fhe::hashing::DomainSep;
        use tonic::transport::Channel;
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::pb::HealthCheckRequest;
        use tonic_health::ServingStatus;
        use futures_util::future::{try_join_all, TryFutureExt};
    }
}

#[cfg(not(feature = "non-wasm"))]
pub mod js_api;

#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools;

pub mod crs_gen;
pub mod key_gen;
pub mod public_decryption;
pub mod user_decryption;

/// For user decryption, we only use the Addr variant,
/// for everything else, we use the Pk variant.
#[derive(Clone)]
pub enum ServerIdentities {
    Pks(HashMap<u32, PublicSigKey>),
    Addrs(HashMap<u32, alloy_primitives::Address>),
}

impl ServerIdentities {
    fn len(&self) -> usize {
        match &self {
            ServerIdentities::Pks(vec) => vec.len(),
            ServerIdentities::Addrs(vec) => vec.len(),
        }
    }
}

/// Core Client
///
/// Simple client to interact with the KMS servers. This can be seen as a proof-of-concept
/// and reference code for validating the KMS. The logic supplied by the client will be
/// distributed across the aggregator/proxy and smart contracts.
#[wasm_bindgen]
pub struct Client {
    // rng is never used when compiled to wasm
    #[cfg(feature = "non-wasm")]
    rng: Box<AesRng>,
    server_identities: ServerIdentities,
    client_address: alloy_primitives::Address,
    client_sk: Option<PrivateSigKey>,
    params: DKGParams,
    decryption_mode: DecryptionMode,
}

// This testing struct needs to be outside of js_api module
// since it is needed in the tests to generate the right files for js/wasm tests.
#[cfg(feature = "wasm_tests")]
#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestingUserDecryptionTranscript {
    // client
    server_addrs: HashMap<u32, alloy_primitives::Address>,
    client_address: alloy_primitives::Address,
    client_sk: Option<PrivateSigKey>,
    degree: u32,
    params: DKGParams,
    // example pt and ct
    fhe_types: Vec<i32>,
    pts: Vec<Vec<u8>>,
    cts: Vec<Vec<u8>>,
    // request
    request: Option<UserDecryptionRequest>,
    // We keep the unified keys here because for legacy tests we need to produce legacy transcripts
    eph_sk: crate::cryptography::internal_crypto_types::UnifiedPrivateEncKey,
    eph_pk: crate::cryptography::internal_crypto_types::UnifiedPublicEncKey,
    // response
    agg_resp: Vec<kms_grpc::kms::v1::UserDecryptionResponse>,
}

#[wasm_bindgen]
#[derive(serde::Serialize, Debug)]
pub struct CiphertextHandle(Vec<u8>);

impl CiphertextHandle {
    pub fn new(handle: Vec<u8>) -> Self {
        CiphertextHandle(handle)
    }
}

/// Validity of this struct is not checked.
#[wasm_bindgen]
pub struct ParsedUserDecryptionRequest {
    // We allow dead_code because these are required to parse from JSON
    #[allow(dead_code)]
    signature: Option<alloy_primitives::Signature>,
    #[allow(dead_code)]
    client_address: alloy_primitives::Address,
    enc_key: Vec<u8>,
    ciphertext_handles: Vec<CiphertextHandle>,
    eip712_verifying_contract: alloy_primitives::Address,
}

impl ParsedUserDecryptionRequest {
    pub fn new(
        signature: Option<alloy_primitives::Signature>,
        client_address: alloy_primitives::Address,
        enc_key: Vec<u8>,
        ciphertext_handles: Vec<CiphertextHandle>,
        eip712_verifying_contract: alloy_primitives::Address,
    ) -> Self {
        Self {
            signature,
            client_address,
            enc_key,
            ciphertext_handles,
            eip712_verifying_contract,
        }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }
}

pub(crate) fn hex_decode_js_err(msg: &str) -> Result<Vec<u8>, JsError> {
    if msg.len() >= 2 {
        if msg[0..2] == *"0x" {
            hex::decode(&msg[2..]).map_err(|e| JsError::new(&e.to_string()))
        } else {
            hex::decode(msg).map_err(|e| JsError::new(&e.to_string()))
        }
    } else {
        Err(JsError::new(
            "cannot decode hex string with fewer than 2 characters",
        ))
    }
}

// we need this type because the json fields are hex-encoded
// which cannot be converted to Vec<u8> automatically.
#[derive(serde::Serialize, serde::Deserialize)]
struct ParsedUserDecryptionRequestHex {
    signature: Option<String>,
    client_address: String,
    enc_key: String,
    ciphertext_handles: Vec<String>,
    eip712_verifying_contract: String,
}

impl TryFrom<&ParsedUserDecryptionRequestHex> for ParsedUserDecryptionRequest {
    type Error = JsError;

    fn try_from(req_hex: &ParsedUserDecryptionRequestHex) -> Result<Self, Self::Error> {
        let signature_buf = req_hex
            .signature
            .as_ref()
            .map(|sig| hex_decode_js_err(sig))
            .transpose()?;
        let signature = signature_buf
            .map(|buf| alloy_primitives::Signature::try_from(buf.as_slice()))
            .transpose()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let client_address =
            alloy_primitives::Address::parse_checksummed(&req_hex.client_address, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(&req_hex.eip712_verifying_contract, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let out = Self {
            signature,
            client_address,
            enc_key: hex_decode_js_err(&req_hex.enc_key)?,
            ciphertext_handles: req_hex
                .ciphertext_handles
                .iter()
                .map(|hdl_str| hex_decode_js_err(hdl_str).map(CiphertextHandle))
                .collect::<Result<Vec<_>, JsError>>()?,
            eip712_verifying_contract,
        };
        Ok(out)
    }
}

impl TryFrom<JsValue> for ParsedUserDecryptionRequest {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        // JsValue -> JsClientUserDecryptionRequestHex
        let req_hex: ParsedUserDecryptionRequestHex =
            serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&e.to_string()))?;

        // JsClientUserDecryptionRequestHex -> JsClientUserDecryptionRequest
        ParsedUserDecryptionRequest::try_from(&req_hex)
    }
}

impl From<&ParsedUserDecryptionRequest> for ParsedUserDecryptionRequestHex {
    fn from(value: &ParsedUserDecryptionRequest) -> Self {
        Self {
            signature: value
                .signature
                .as_ref()
                .map(|sig| hex::encode(sig.as_bytes())),
            client_address: value.client_address.to_checksum(None),
            enc_key: hex::encode(&value.enc_key),
            ciphertext_handles: value
                .ciphertext_handles
                .iter()
                .map(|hdl| hex::encode(&hdl.0))
                .collect::<Vec<_>>(),
            eip712_verifying_contract: value.eip712_verifying_contract.to_checksum(None),
        }
    }
}

impl TryFrom<&UserDecryptionRequest> for ParsedUserDecryptionRequest {
    type Error = anyhow::Error;

    fn try_from(value: &UserDecryptionRequest) -> Result<Self, Self::Error> {
        let domain = value
            .domain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing domain"))?;

        let client_address =
            alloy_primitives::Address::parse_checksummed(&value.client_address, None)?;

        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(domain.verifying_contract.clone(), None)?;

        let ciphertext_handles = value
            .typed_ciphertexts
            .iter()
            .map(|ct| CiphertextHandle(ct.external_handle.clone()))
            .collect::<Vec<_>>();

        let out = Self {
            signature: None,
            client_address,
            enc_key: value.enc_key.clone(),
            ciphertext_handles,
            eip712_verifying_contract,
        };
        Ok(out)
    }
}

/// Compute the link as (eip712_signing_hash(pk, domain) || hash(ciphertext handles)).
/// TODO
pub fn compute_link(
    req: &ParsedUserDecryptionRequest,
    domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    // check consistency
    let handles = req
        .ciphertext_handles
        .iter()
        .map(|x| alloy_primitives::FixedBytes::<32>::left_padding_from(&x.0))
        .collect::<Vec<_>>();

    let linker = UserDecryptionLinker {
        publicKey: req.enc_key.clone().into(),
        handles,
        userAddress: req.client_address,
    };

    let link = linker.eip712_signing_hash(domain).to_vec();

    Ok(link)
}

/// Client data type
///
/// Enum which represents the different kinds of public information that can be stored as part of key generation.
/// In practice this means the CRS and different types of public keys.
/// Data of this type is supposed to be readable by anyone on the internet
/// and stored on a medium that _may_ be susceptible to malicious modifications.
#[cfg(feature = "non-wasm")]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClientDataType {
    SigningKey, // Type of the client's signing key
    VerfKey,    // Type for the servers verification keys
}

#[cfg(feature = "non-wasm")]
impl fmt::Display for ClientDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientDataType::SigningKey => write!(f, "SigningKey"),
            ClientDataType::VerfKey => write!(f, "VerfKey"),
        }
    }
}

impl Client {
    /// Constructor method to be used for WASM and other situations where data cannot be directly loaded
    /// from a [PublicStorage].
    ///
    /// * `server_pks` - a set of tkms core public keys.
    /// * `client_address` - the client wallet address.
    /// * `client_sk` - client private key.
    ///   This is optional because sometimes the private signing key is kept
    ///   in a secure location, e.g., hardware wallet or web extension.
    ///   Calling functions that requires `client_sk` when it is None will return an error.
    /// * `params` - the FHE parameters.
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    pub fn new(
        server_pks: HashMap<u32, PublicSigKey>,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        let decryption_mode = decryption_mode.unwrap_or_default();
        Client {
            #[cfg(feature = "non-wasm")]
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_identities: ServerIdentities::Pks(server_pks),
            client_address,
            client_sk,
            params,
            decryption_mode,
        }
    }

    /// Helper method to create a client based on a specific type of storage for loading the keys.
    /// Observe that this method is decoupled from the [Client] to ensure wasm compliance as wasm cannot handle
    /// file reading or generic traits.
    ///
    /// * `client_storage` - the storage where the client's keys (for signing and verifying) are stored.
    /// * `pub_storages` - the storages where the public verification keys of the servers are stored. These must be unique.
    /// * `params` - the FHE parameters
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    #[cfg(feature = "non-wasm")]
    pub async fn new_client<ClientS: Storage, PubS: StorageReader>(
        client_storage: ClientS,
        pub_storages: HashMap<u32, PubS>,
        params: &DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> anyhow::Result<Client> {
        let pks = try_join_all(pub_storages.iter().map(|(party_id, cur_storage)| {
            get_core_verification_key(cur_storage).map_ok(|pk| (*party_id, pk))
        }))
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();

        let pks_unique_count = pks.values().unique().count();

        if pks_unique_count != pks.len() {
            return Err(anyhow_error_and_log(format!(
                "Duplicate public keys present in map: {} unique, {} total",
                pks_unique_count,
                pks.len()
            )));
        }

        let client_pk = get_client_verification_key(&client_storage).await?;
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());

        let client_sk = get_client_signing_key(&client_storage).await?;

        Ok(Client::new(
            pks,
            client_address,
            Some(client_sk),
            *params,
            decryption_mode,
        ))
    }

    /// Verify the signature received from the server on keys or other data objects.
    /// This verification will pass if one of the public keys can verify the signature.
    #[cfg(feature = "non-wasm")]
    fn verify_server_signature<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        data: &T,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        if self
            .find_verifying_public_key(dsep, data, signature)
            .is_some()
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("server signature verification failed"))
        }
    }

    /// Verify the signature received from the server on keys or other data objects
    /// and return the public key that verified the signature.
    #[cfg(feature = "non-wasm")]
    fn find_verifying_public_key<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        data: &T,
        signature: &[u8],
    ) -> Option<PublicSigKey> {
        let signature_struct: Signature = match bc2wrap::deserialize(signature) {
            Ok(signature_struct) => signature_struct,
            Err(_) => {
                tracing::error!("Could not deserialize signature");
                return None;
            }
        };

        let server_pks = match self.get_server_pks() {
            Ok(pks) => pks,
            Err(e) => {
                tracing::error!("failed to get server pks ({})", e);
                return None;
            }
        };

        for verf_key in server_pks.values() {
            let ok = BaseKmsStruct::verify_sig(dsep, &data, &signature_struct, verf_key).is_ok();
            if ok {
                return Some(verf_key.clone());
            }
        }
        None
    }

    pub fn get_server_pks(&self) -> anyhow::Result<&HashMap<u32, PublicSigKey>> {
        match &self.server_identities {
            ServerIdentities::Pks(inner) => Ok(inner),
            ServerIdentities::Addrs(_) => {
                Err(anyhow::anyhow!("expected public keys, got addresses"))
            }
        }
    }

    pub fn get_server_addrs(&self) -> HashMap<u32, alloy_primitives::Address> {
        match &self.server_identities {
            ServerIdentities::Pks(pks) => pks
                .iter()
                .map(|(i, pk)| (*i, alloy_signer::utils::public_key_to_address(pk.pk())))
                .collect(),
            ServerIdentities::Addrs(inner) => inner.clone(),
        }
    }

    pub fn get_client_address(&self) -> alloy_primitives::Address {
        self.client_address
    }
}

/// Wait for a server to be ready for requests. I.e. wait until it enters the SERVING state.
/// Note that this method may panic if the server does not become ready within a certain time frame.
#[cfg(feature = "non-wasm")]
pub async fn await_server_ready(service_name: &str, port: u16) {
    let mut wrapped_client = get_health_client(port).await;
    let mut client_tries = 1;
    while wrapped_client.is_err() {
        if client_tries >= MAX_TRIES {
            panic!("Failed to start health client on server {service_name} on port {port}");
        }
        wrapped_client = get_health_client(port).await;
        client_tries += 1;
    }
    // We can safely unwrap here since we know the wrapped client does not contain an error
    let mut client = wrapped_client.unwrap();
    let mut status = get_status(&mut client, service_name).await;
    let mut service_tries = 1;
    while status.is_err()
        || status
            .clone()
            .is_ok_and(|status| status == ServingStatus::NotServing as i32)
    {
        if service_tries >= MAX_TRIES {
            panic!(
                "Failed to get health status on {service_name} on port {port}. Status: {status:?}"
            );
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        status = get_status(&mut client, service_name).await;
        service_tries += 1;
    }
}

#[cfg(feature = "non-wasm")]
async fn get_health_client(port: u16) -> anyhow::Result<HealthClient<Channel>> {
    let server_address = &format!("{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{port}");
    let channel_builder = Channel::from_shared(server_address.to_string())?;
    let channel = channel_builder.connect().await?;
    Ok(HealthClient::new(channel))
}

#[cfg(feature = "non-wasm")]
async fn get_status(
    health_client: &mut HealthClient<Channel>,
    service_name: &str,
) -> Result<i32, tonic::Status> {
    let request = tonic::Request::new(HealthCheckRequest {
        service: service_name.to_string(),
    });
    let response = health_client.check(request).await?;
    Ok(response.into_inner().status)
}

#[cfg(test)]
pub(crate) mod tests {
    mod centralized;
    mod common;
    mod threshold;
}
