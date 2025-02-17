/// Core Client library
///
/// This library implements most functionnalities to interact with a KMS ASC.
/// This library also includes an associated CLI.
use aes_prng::AesRng;
use alloy_primitives::PrimitiveSignature;
use alloy_sol_types::Eip712Domain;
use anyhow::anyhow;
use bytes::Bytes;
use clap::Parser;
use conf_trace::conf::Settings;
use core::str;
use events::kms::FheType;
use kms_common::DecryptionMode;
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, FheParameter,
    KeyGenPreprocStatusEnum, KeyGenRequest, KeyGenResult, RequestId, TypedCiphertext,
    TypedPlaintext,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType, SIGNING_KEY_ID};
use kms_lib::client::{assemble_metadata_alloy, Client, ParsedReencryptionRequest};
use kms_lib::consts::DEFAULT_PARAM;
use kms_lib::engine::base::{compute_external_pubdata_message_hash, compute_pt_message_hash};
use kms_lib::util::key_setup::ensure_client_keys_exist;
use kms_lib::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, compute_compressed_cipher_from_stored_key,
    compute_proven_ct_from_stored_key_and_serialize, load_crs_from_storage, load_pk_from_storage,
    load_server_key_from_storage, TestingPlaintext,
};
use kms_lib::vault::storage::{file::FileStorage, StorageType};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Once;
use strum_macros::{Display, EnumString};
use tfhe::named::Named;
use tfhe::Versionize;
use tokio::task::JoinSet;
use tonic::transport::Channel;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::MakeWriterExt;

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
                tokio::time::sleep(tokio::time::Duration::from_millis($interval)).await;
            }
        };
        result
    }};
    ($f:expr) => {
        retry!($f, 5, 100)
    };
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct CoreClientConfig {
    /// S3 endpoint from which to fetch keys
    /// NOTE: We should probably move away from that and use the key-url
    pub s3_endpoint: Option<String>,
    /// Key folder where to store the keys
    pub object_folder: Vec<String>,
    pub decryption_mode: Option<DecryptionMode>,
    pub num_majority: usize,
    pub num_reconstruct: usize,
    pub core_addresses: Vec<String>,
}

impl<'de> Deserialize<'de> for CoreClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Clone, Default, Debug)]
        pub struct CoreClientConfigBuffer {
            pub s3_endpoint: Option<String>,
            pub object_folder: Vec<String>,
            pub decryption_mode: Option<DecryptionMode>,
            pub num_majority: usize,
            pub num_reconstruct: usize,
            pub core_addresses: Vec<String>,
        }

        let temp = CoreClientConfigBuffer::deserialize(deserializer)?;

        Ok(CoreClientConfig {
            s3_endpoint: temp.s3_endpoint,
            object_folder: temp.object_folder,
            decryption_mode: temp.decryption_mode,
            num_majority: temp.num_majority,
            num_reconstruct: temp.num_reconstruct,
            core_addresses: temp.core_addresses,
        })
    }
}

pub struct CiphertextConfig {
    pub clear_value: Vec<u8>,
    pub data_type: FheType,
    pub compressed: Option<bool>,
}

// Define the custom Uint4 type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U4(u8);

impl U4 {
    pub fn new(value: u8) -> Result<Self, &'static str> {
        if value <= 0x0F {
            Ok(U4(value))
        } else {
            Err("Value exceeds 4 bits")
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

// CLI arguments
#[derive(Debug, Parser)]
pub struct NoParameters {}

/// Parse a string as hex string. The string can optionally start with "0x". Odd-length strings will be padded with a leading zero.
pub fn parse_hex(arg: &str) -> anyhow::Result<Vec<u8>> {
    // Remove "0x" or "0X" prefix if present
    let arg = arg.strip_prefix("0x").unwrap_or(arg);
    let hex_str = arg.strip_prefix("0X").unwrap_or(arg);

    // Handle odd-length hex strings by padding with leading zero
    let hex_str = if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    Ok(hex::decode(hex_str)?)
}

#[derive(Debug, Parser)]
pub struct CipherParameters {
    /// Value that we want to encrypt and request a decryption/re-encryption.
    /// The value will be converted from a little endian hex string to a `Vec<u8>`.
    #[clap(long, short = 'e')]
    pub to_encrypt: String,
    /// Data type of `to_encrypt`.
    /// Expected one of ebool, euint4, ..., euint2048
    #[clap(long, short = 'd')]
    pub data_type: FheType,
    /// Boolean to activate ciphertext compression or not.
    #[clap(long, short = 'p', default_value_t = false)]
    pub compressed: bool,
    /// CRS identifier to use
    #[clap(long, short = 'c')]
    pub crs_id: String,
    /// Key identifier to use for decryption/re-encryption purposes
    #[clap(long, short = 'k')]
    pub key_id: String,
}

#[derive(Debug, Parser)]
pub struct KeyGenParameters {
    #[clap(long, short = 'i')]
    pub preproc_id: String,
}

#[derive(Debug, Parser)]
pub struct CrsParameters {
    #[clap(long, short = 'm')]
    pub max_num_bits: u32,
}

#[derive(Debug, Parser)]
pub enum CCCommand {
    PreprocKeyGen(NoParameters),
    KeyGen(KeyGenParameters),
    InsecureKeyGen(NoParameters),
    Decrypt(CipherParameters),
    ReEncrypt(CipherParameters),
    CrsGen(CrsParameters),
    InsecureCrsGen(CrsParameters),
    DoNothing(NoParameters),
}

#[derive(Debug, Parser)]
pub struct CmdConfig {
    #[clap(long, short = 'f')]
    pub file_conf: Option<String>,
    #[clap(subcommand)]
    pub command: CCCommand,
    // TODO: expose a log-level instead
    #[clap(long, short = 'l')]
    pub logs: bool,
    #[clap(long, default_value = "200")]
    pub max_iter: usize,
    #[clap(long, short = 'a', default_value_t = false)]
    pub expect_all_responses: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString, Display)]
pub enum KmsMode {
    #[strum(serialize = "centralized")]
    #[serde(rename = "centralized")]
    Centralized,
    #[strum(serialize = "threshold")]
    #[serde(rename = "threshold")]
    Threshold,
}

/// a dummy Eip-712 domain for testing
fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
    )
}

/// a dummy ACL address for testing
fn dummy_acl_address() -> alloy_primitives::Address {
    alloy_primitives::address!("EEdA6bf26964aF9D7Eed9e03e53415D37aa960EE")
}

#[allow(clippy::too_many_arguments)]
pub async fn encrypt_and_prove(
    to_encrypt: Vec<u8>,
    data_type: FheType,
    domain: &Eip712Domain,
    contract_address: &alloy_primitives::Address,
    acl_address: &alloy_primitives::Address,
    client_address: &alloy_primitives::Address,
    crs_id: &str,
    key_id: &str,
    keys_folder: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
    let metadata = assemble_metadata_alloy(
        contract_address,
        client_address,
        acl_address,
        &domain.chain_id.unwrap(),
    );

    tracing::info!(
        "attempting to create proven ct using materials from {:?}",
        keys_folder
    );

    let msgs = vec![TestingPlaintext::from(TypedPlaintext {
        bytes: to_encrypt,
        fhe_type: data_type as i32,
    })];

    Ok(compute_proven_ct_from_stored_key_and_serialize(
        Some(keys_folder),
        msgs,
        key_id,
        crs_id,
        &metadata,
    )
    .await)
}

pub async fn encrypt(
    to_encrypt: Vec<u8>,
    fhe_type: FheType,
    key_id: &str,
    keys_folder: &Path,
    compressed: Option<bool>,
) -> Result<(Vec<u8>, TypedPlaintext), Box<dyn std::error::Error + 'static>> {
    if to_encrypt.len() != fhe_type.bits().div_ceil(8) {
        tracing::warn!("Byte length of value to encrypt ({}) does not match FHE type ({}) and will be padded/truncated.", to_encrypt.len(), fhe_type);
    }

    let ptxt = TypedPlaintext {
        bytes: to_encrypt,
        fhe_type: fhe_type as i32,
    };

    let typed_to_encrypt = TestingPlaintext::from(ptxt.clone());

    tracing::info!(
        "Encrypting plaintext: {:?}, {:?}, {:?}",
        ptxt,
        fhe_type,
        typed_to_encrypt
    );

    tracing::debug!(
        "attempting to create ct using materials from {:?}",
        keys_folder
    );

    let cipher: Vec<u8>;
    if compressed.unwrap_or(false) {
        (cipher, _) =
            compute_compressed_cipher_from_stored_key(Some(keys_folder), typed_to_encrypt, key_id)
                .await;
    } else {
        (cipher, _) =
            compute_cipher_from_stored_key(Some(keys_folder), typed_to_encrypt, key_id).await;
    }

    Ok((cipher, ptxt))
}

pub async fn store_cipher(
    cipher: &Vec<u8>,
    kv_store_address: &String,
) -> Result<String, anyhow::Error> {
    let response = reqwest::Client::new()
        .post(format!("{}/store", kv_store_address))
        .body(hex::encode(cipher))
        .send()
        .await;

    match response {
        Ok(result) => {
            if result.status() != 200 {
                return Err(anyhow!(
                    "Failed to store ciphertext {}",
                    result.text().await?
                ));
            }
            let handle = result.text().await?;
            Ok(handle)
        }
        Err(error) => Err(anyhow!("Failed to store ciphertext: {}", error)),
    }
}

fn join_vars(args: &[&str]) -> String {
    args.iter()
        .filter(|&s| !s.is_empty())
        .cloned()
        .collect::<Vec<&str>>()
        .join("/")
}

// TODO: handle auth
// TODO: add option to either use local  key or remote key
pub async fn fetch_object(endpoint: &str, folder: &str, object_id: &str) -> anyhow::Result<Bytes> {
    let object_key = object_id.to_string();
    // Construct the URL
    let url = join_vars(&[endpoint, folder, object_key.as_str()]);

    // If URL we fetch it
    if url.starts_with("http") {
        // Make the request
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await?;

        if response.status().is_success() {
            let bytes = response.bytes().await?;
            tracing::info!("Successfully downloaded {} bytes", bytes.len());
            // Here you can process the bytes as needed
            Ok(bytes)
        } else {
            let response_status = response.status();
            let response_content = response.text().await?;
            tracing::error!("Error: {}", response_status);
            tracing::error!("Response: {}", response_content);
            Err(anyhow::anyhow!(format!(
                "Couldn't fetch key from endpoint\nStatus: {}\nResponse: {}",
                response_status, response_content
            ),))
        }
    } else {
        let key_path = Path::new(endpoint).join(folder).join(object_id);
        match tokio::fs::read(&key_path).await {
            Ok(content) => Ok(Bytes::from(content)),
            Err(error) => Err(anyhow::anyhow!(format!(
                "Couldn't fetch key from file {:?} from error: {:?}",
                key_path, error
            ),)),
        }
    }
}

pub fn write_bytes_to_file(folder_path: &Path, filename: &str, data: &[u8]) -> anyhow::Result<()> {
    std::fs::create_dir_all(folder_path)?;
    let path = std::path::absolute(folder_path.join(filename))?;
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

static INIT_LOG: Once = Once::new();

pub fn init_testing() {
    INIT_LOG.call_once(setup_logging);
}

pub fn setup_logging() {
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "core-client.log");
    let file_and_stdout = file_appender.and(std::io::stdout);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(file_and_stdout)
        .with_ansi(false)
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
}

/// This fetches material which is global
/// i.e. everything related to CRS and FHE public materials
async fn fetch_global_pub_object_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    object_id: &str,
    object_name: &str,
    object_folder: &str,
) -> anyhow::Result<()> {
    // Fetch pub-key from storage and dump it for later use
    let folder = destination_prefix.join("PUB").join(object_name);
    let content = fetch_object(
        s3_endpoint,
        &format!("{}/{}", object_folder, object_name),
        object_id,
    )
    .await?;
    write_bytes_to_file(&folder, object_id, content.as_ref())?;
    Ok(())
}

/// This fetches material which is local
/// i.e. everything related to parties verification keys
async fn fetch_local_key_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    object_id: &str,
    object_name: &str,
    object_folder: &[String],
) -> anyhow::Result<()> {
    // Fetch pub-key from storage and dump it for later use
    if object_folder.len() == 1 {
        fetch_global_pub_object_and_write_to_file(
            destination_prefix,
            s3_endpoint,
            object_id,
            object_name,
            object_folder.first().unwrap(),
        )
        .await
    } else {
        for (party_idx, folder_name) in object_folder.iter().enumerate() {
            let folder = destination_prefix
                .join(format!("PUB-p{}", party_idx + 1))
                .join(object_name);
            let content = fetch_object(
                s3_endpoint,
                &format!("{}/{}", folder_name, object_name),
                object_id,
            )
            .await?;
            let _ = write_bytes_to_file(&folder, object_id, content.as_ref());
        }
        Ok(())
    }
}

/// This fetches the kms ethereum address from local storage
async fn fetch_kms_addresses(
    sim_conf: &CoreClientConfig,
    is_centralized: bool,
) -> Result<Vec<alloy_primitives::Address>, Box<dyn std::error::Error + 'static>> {
    // TODO: handle local file
    let key_id = &SIGNING_KEY_ID.to_string();

    let mut addr_bytes = Vec::new();
    if is_centralized {
        let content = fetch_object(
            &sim_conf
                .s3_endpoint
                .clone()
                .expect("s3 endpoint should be provided"),
            &format!(
                "{}/{}",
                sim_conf.object_folder.first().unwrap(),
                "VerfAddress"
            ),
            key_id,
        )
        .await?;
        addr_bytes.push(content);
    } else {
        for folder_name in sim_conf.object_folder.iter() {
            let content = fetch_object(
                &sim_conf
                    .s3_endpoint
                    .clone()
                    .expect("s3 endpoint should be provided"),
                &format!("{}/{}", folder_name, "VerfAddress"),
                key_id,
            )
            .await?;
            addr_bytes.push(content);
        }
    }

    // turn bytes read into Address type
    let kms_addrs: Vec<_> = addr_bytes
        .iter()
        .map(|x| {
            alloy_primitives::Address::parse_checksummed(
                str::from_utf8(x).unwrap_or_else(|_| {
                    panic!("cannot convert address bytes into UTF-8 string: {:?}", x)
                }),
                None,
            )
            .unwrap_or_else(|_| panic!("invalid ethereum address: {:?}", x))
        })
        .collect();

    Ok(kms_addrs)
}

/// check that the external signature on the CRS or pubkey is valid, i.e. was made by one of the supplied addresses
fn check_ext_pubdata_signature<D: Serialize + Versionize + Named>(
    data: &D,
    external_sig: &[u8],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // Deserialize the Signature. It reverses the call to `signature.as_bytes()` that we use for serialization.
    let sig = PrimitiveSignature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

    tracing::debug!("ext. signature bytes: {:x?}", external_sig);
    tracing::debug!("ext. signature: {:?}", sig);
    tracing::debug!("EIP-712 domain: {:?}", domain);

    let hash = compute_external_pubdata_message_hash(data, domain)?;

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("reconstructed address: {}", addr);

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!(
            "External crs/pubkey signature verification failed!"
        ))
    }
}

/// check that the external signature on the decryption result(s) is valid, i.e. was made by one of the supplied addresses
fn check_ext_pt_signature(
    external_sig: &[u8],
    plaintexts: &Vec<TypedPlaintext>,
    decrypt_req: &DecryptionRequest,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // this reverses the call to `signature.as_bytes()` that we use for serialization
    let sig = PrimitiveSignature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

    let domain_msg = decrypt_req.domain.as_ref().unwrap();
    let domain = protobuf_to_alloy_domain(domain_msg)?;

    let acl_address =
        alloy_primitives::Address::parse_checksummed(decrypt_req.acl_address(), None)?;

    // unpack the HexVectorList
    let external_handles: Vec<_> = decrypt_req
        .ciphertexts
        .iter()
        .map(|ct| ct.external_handle.clone())
        .collect();

    tracing::debug!("ext. signature bytes: {:x?}", external_sig);
    tracing::debug!("ext. signature: {:?}", sig);
    tracing::debug!("EIP-712 domain: {:?}", domain_msg);
    tracing::debug!("ACL addres: {:?}", acl_address);
    tracing::debug!("PTs: {:?}", plaintexts);
    tracing::debug!("ext. handles: {:?}", external_handles);

    let hash = compute_pt_message_hash(external_handles, plaintexts, domain, acl_address);

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("reconstructed address: {}", addr);

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!("External PT signature verification failed!"))
    }
}

fn check_external_decryption_signature(
    responses: &[DecryptionResponse], // one response per party
    expected_answer: TypedPlaintext,
    request: &DecryptionRequest,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for response in responses.iter() {
        let payload = response.payload.as_ref().unwrap();
        check_ext_pt_signature(
            payload.external_signature(),
            &payload.plaintexts,
            request,
            kms_addrs,
        )?;

        for (idx, pt) in payload.plaintexts.iter().enumerate() {
            tracing::info!(
                "Decrypt Result #{idx}: Plaintext: {} ({:?}).",
                hex::encode(pt.bytes.as_slice()),
                pt.fhe_type()
            );
            results.push(pt.clone());
        }
    }

    let tp_expected = TestingPlaintext::from(expected_answer);
    for result in results {
        assert_eq!(tp_expected, TestingPlaintext::from(result));
    }

    tracing::info!("Decryption response successfully processed.");
    Ok(())
}

async fn fetch_all_public_data(
    key_id: &str,
    crs_id: &str,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    fetch_verf_keys(cc_conf, destination_prefix).await?;
    fetch_key(key_id, cc_conf, destination_prefix).await?;
    fetch_crs(crs_id, cc_conf, destination_prefix).await?;

    Ok(())
}

/// retrieve public verification keys and Ethereum addresses of the MPC servers
async fn fetch_verf_keys(
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    tracing::info!("Fetching verification keys");

    // Fetch objects associated with Signature keys
    for object_name in ["VerfAddress", "VerfKey"] {
        fetch_local_key_and_write_to_file(
            destination_prefix,
            cc_conf
                .s3_endpoint
                .clone()
                .expect("S3 endpoint should be provided")
                .as_str(),
            &SIGNING_KEY_ID.to_string(),
            object_name,
            &cc_conf.object_folder,
        )
        .await?;
    }
    Ok(())
}

/// Fetch all remote objects associated with TFHE keys and store locally for the core client
async fn fetch_key(
    key_id: &str,
    sim_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    tracing::info!("Fetching public key and server key with id {key_id}");
    for object_name in ["PublicKey", "PublicKeyMetadata", "ServerKey"] {
        fetch_global_pub_object_and_write_to_file(
            destination_prefix,
            sim_conf
                .s3_endpoint
                .clone()
                .expect("S3 endpoint should be provided")
                .as_str(),
            key_id,
            object_name,
            sim_conf.object_folder.first().unwrap(),
        )
        .await?;
    }
    Ok(())
}

/// Fetch the remote CRS and store locally for the core client
async fn fetch_crs(
    crs_id: &str,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    tracing::info!("Fetching CRS with id {crs_id}");
    fetch_global_pub_object_and_write_to_file(
        destination_prefix,
        cc_conf
            .s3_endpoint
            .clone()
            .expect("S3 endpoint should be provided")
            .as_str(),
        crs_id,
        "CRS",
        cc_conf.object_folder.first().unwrap(),
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn do_keygen(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    kms_addrs: &[alloy_primitives::Address],
    param: FheParameter,
    preproc_id: Option<RequestId>,
    insecure: bool,
    destination_prefix: &Path,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let dkg_req = internal_client.key_gen_request(
        &req_id,
        preproc_id,
        Some(param),
        None,
        None,
        Some(dummy_domain()),
    )?;

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = dkg_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            if insecure {
                cur_client
                    .insecure_key_gen(tonic::Request::new(req_cloned))
                    .await
            } else {
                cur_client.key_gen(tonic::Request::new(req_cloned)).await
            }
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties);

    // get all responses
    let mut resp_tasks = JoinSet::new();
    for ce in core_endpoints.iter_mut() {
        let mut cur_client = ce.clone();
        let req_id_clone = dkg_req.request_id.as_ref().unwrap().clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut response = if insecure {
                cur_client
                    .get_insecure_key_gen_result(tonic::Request::new(req_id_clone.clone()))
                    .await
            } else {
                cur_client
                    .get_key_gen_result(tonic::Request::new(req_id_clone.clone()))
                    .await
            };

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if ctr >= max_iter {
                    panic!(
                        "timeout while waiting for keygen after {} retries (insecure {insecure})",
                        max_iter
                    );
                }
                ctr += 1;
                response = if insecure {
                    cur_client
                        .get_insecure_key_gen_result(tonic::Request::new(req_id_clone.clone()))
                        .await
                } else {
                    cur_client
                        .get_key_gen_result(tonic::Request::new(req_id_clone.clone()))
                        .await
                };

                tracing::info!(
                    "Got response for insecure keygen: {:?} (insecure {insecure})",
                    response
                );
            }
            (req_id_clone, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        resp_response_vec.push(resp.unwrap().1);
    }

    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    fetch_and_check_keygen(
        num_expected_responses,
        cc_conf,
        kms_addrs,
        destination_prefix,
        dkg_req,
        resp_response_vec,
    )
    .await?;

    Ok(req_id)
}

#[allow(clippy::too_many_arguments)]
async fn do_crsgen(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    kms_addrs: &[alloy_primitives::Address],
    max_num_bits: Option<u32>,
    param: FheParameter,
    insecure: bool,
    destination_prefix: &Path,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let crs_req = internal_client.crs_gen_request(
        &req_id,
        max_num_bits,
        Some(param),
        Some(dummy_domain()),
    )?;

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = crs_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            if insecure {
                cur_client
                    .insecure_crs_gen(tonic::Request::new(req_cloned))
                    .await
            } else {
                cur_client.crs_gen(tonic::Request::new(req_cloned)).await
            }
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); //TODO

    // get all responses
    let mut resp_tasks = JoinSet::new();
    for ce in core_endpoints.iter_mut() {
        let mut cur_client = ce.clone();
        let req_id_clone = crs_req.request_id.as_ref().unwrap().clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut response = if insecure {
                cur_client
                    .get_insecure_crs_gen_result(tonic::Request::new(req_id_clone.clone()))
                    .await
            } else {
                cur_client
                    .get_crs_gen_result(tonic::Request::new(req_id_clone.clone()))
                    .await
            };

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                // do at most max_iter retries
                if ctr >= max_iter {
                    panic!("timeout while waiting for crsgen after {max_iter} retries (insecure {insecure})");
                }
                ctr += 1;
                response = if insecure {
                    cur_client
                        .get_insecure_crs_gen_result(tonic::Request::new(req_id_clone.clone()))
                        .await
                } else {
                    cur_client
                        .get_crs_gen_result(tonic::Request::new(req_id_clone.clone()))
                        .await
                };

                println!("Got response for crsgen: {:?} (insecure {insecure})", response);
            }
            (req_id_clone, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        resp_response_vec.push(resp.unwrap().1);
    }
    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    fetch_and_check_crsgen(
        num_expected_responses,
        cc_conf,
        kms_addrs,
        destination_prefix,
        crs_req,
        resp_response_vec,
    )
    .await?;

    Ok(req_id)
}

#[allow(clippy::too_many_arguments)]
async fn do_preproc(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    param: FheParameter,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let pp_req = internal_client.preproc_request(&req_id, Some(param), None)?; //TODO keyset config

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = pp_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); //TODO

    // Wait for preprocessing to be done
    for _i in 0..max_iter {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        // get all responses
        let mut resp_tasks = JoinSet::new();
        for ce in core_endpoints.iter_mut() {
            let mut cur_client = ce.clone();
            let req_id_clone = pp_req.request_id.as_ref().unwrap().clone();

            resp_tasks.spawn(async move {
                // Sleep to give the server some time to complete decryption
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                let response = cur_client
                    .get_preproc_status(tonic::Request::new(req_id_clone.clone()))
                    .await;

                (req_id_clone, response.unwrap().into_inner())
            });
        }
        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            resp_response_vec.push(resp.unwrap().1);
        }

        // Panic if we see an error
        if resp_response_vec.iter().any(|x| {
            KeyGenPreprocStatusEnum::try_from(x.result).unwrap()
                != KeyGenPreprocStatusEnum::InProgress
                && KeyGenPreprocStatusEnum::try_from(x.result).unwrap()
                    != KeyGenPreprocStatusEnum::Finished
        }) {
            panic!("Preprocessing failed with error: {:?}", resp_response_vec);
        }
        // Stop the loop if there is no longer a party that is still preprocessing
        if !resp_response_vec.iter().any(|x| {
            KeyGenPreprocStatusEnum::try_from(x.result).unwrap()
                == KeyGenPreprocStatusEnum::InProgress
        }) {
            // All parties are finished so we check the result
            resp_response_vec.iter().for_each(|x| {
                assert_eq!(
                    KeyGenPreprocStatusEnum::try_from(x.result).unwrap(),
                    KeyGenPreprocStatusEnum::Finished
                );
            });
            return Ok(req_id);
        }
    }

    Err(anyhow!("Preprocessing failed"))
}

pub async fn execute_cmd(
    cmd_config: &CmdConfig,
    destination_prefix: &Path,
) -> Result<(Option<RequestId>, String), Box<dyn std::error::Error + 'static>> {
    let path_to_config = cmd_config.file_conf.clone().unwrap();
    let command = &cmd_config.command;
    let max_iter = cmd_config.max_iter;
    let expect_all_responses = cmd_config.expect_all_responses;

    tracing::info!("Path to config: {:?}", &path_to_config);
    tracing::info!("starting command: {:?}", command);
    let cc_conf: CoreClientConfig = Settings::builder()
        .path(&path_to_config)
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()?;

    tracing::info!("Core Client Config: {:?}", cc_conf);

    let mut rng = AesRng::from_entropy();

    let num_parties = cc_conf.core_addresses.len();
    // Check if the KMS is centralized (ie, there is only one party)
    let is_centralized = num_parties == 1;

    ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;

    fetch_verf_keys(&cc_conf, destination_prefix).await?;

    let mut pub_storage: Vec<FileStorage> = Vec::with_capacity(num_parties);
    let client_storage: FileStorage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
    let mut internal_client: Client;
    let mut core_endpoints = Vec::with_capacity(num_parties);

    if num_parties == 1 {
        // central cores

        let address = cc_conf
            .core_addresses
            .first()
            .expect("No core address provided")
            .clone();

        tracing::info!("Centralized CClient - connecting to: {}", address);

        // make sure address starts with http://
        let url = if address.starts_with("http://") {
            address
        } else {
            "http://".to_string() + &address
        };

        let core_endpoint = retry!(
            CoreServiceEndpointClient::connect(url.to_owned()).await,
            5,
            100
        )?;
        core_endpoints.push(core_endpoint);

        pub_storage
            .push(FileStorage::new(Some(destination_prefix), StorageType::PUB, None).unwrap());
        internal_client = Client::new_client(client_storage, pub_storage, &DEFAULT_PARAM, None)
            .await
            .unwrap();
        tracing::info!("Centralized Client setup done.");
    } else {
        // threshold cores
        let addresses = cc_conf.core_addresses.clone();

        tracing::info!("Threshold Client - connecting to: {:?}", addresses);

        for (i, address) in addresses.iter().enumerate() {
            // make sure address starts with http://
            let url = if address.starts_with("http://") {
                address.clone()
            } else {
                "http://".to_string() + address
            };

            tracing::info!("Connecting to {:?}", url);

            let core_endpoint = retry!(
                CoreServiceEndpointClient::connect(url.to_owned()).await,
                5,
                100
            )?;
            core_endpoints.push(core_endpoint);

            pub_storage.push(
                FileStorage::new(Some(destination_prefix), StorageType::PUB, Some(i + 1)).unwrap(),
            );
        }

        internal_client = Client::new_client(client_storage, pub_storage, &DEFAULT_PARAM, None)
            .await
            .unwrap();

        tracing::info!("Threshold Client setup done.");
    }

    // if it's a de- or reencryption, fetch the key and crs
    match command {
        CCCommand::Decrypt(cipher_params) | CCCommand::ReEncrypt(cipher_params) => {
            tracing::info!("Fetching Verification keys, Public Key and CRS. ({command:?})");

            fetch_all_public_data(
                cipher_params.key_id.as_str(),
                cipher_params.crs_id.as_str(),
                &cc_conf,
                destination_prefix,
            )
            .await?;
        }
        _ => {
            tracing::info!("No need to fetch key and CRS. ({command:?})");
        }
    }

    // read FHE_PARAMETER
    let param = match env::var("FHE_PARAMETER") {
        Ok(val) => match val.to_lowercase().as_str() {
            "test" => FheParameter::Test,
            "default" => FheParameter::Default,
            _ => FheParameter::Test,
        },
        Err(_) => FheParameter::Test,
    };

    tracing::info!(
        "Parties: {}. (Centralized: {}). FHE Parameters: {}",
        num_parties,
        is_centralized,
        param.as_str_name()
    );

    let kms_addrs = fetch_kms_addresses(&cc_conf, is_centralized).await?;

    let req_id = RequestId::new_random(&mut rng);

    // Execute the command
    let res = match command {
        CCCommand::Decrypt(cipher_params) => {
            let to_encrypt = parse_hex(cipher_params.to_encrypt.as_str())?;
            let data_type = cipher_params.data_type;
            let key_id = &cipher_params.key_id;
            let keys_folder = destination_prefix;
            let compressed = Some(cipher_params.compressed);

            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };

            let (cipher, ptxt) =
                encrypt(to_encrypt, data_type, key_id, keys_folder, compressed).await?;

            // this is currently a batch of size 1
            let ct = vec![TypedCiphertext {
                ciphertext: cipher,
                fhe_type: data_type as i32,
                external_handle: vec![23_u8; 32],
            }];

            // DECRYPTION REQUEST
            let dec_req = internal_client.decryption_request(
                ct,
                &dummy_domain(),
                &req_id,
                &dummy_acl_address(),
                &RequestId {
                    request_id: cipher_params.key_id.clone(),
                },
            )?;

            // make parallel requests by calling [decrypt] in a thread
            let mut req_tasks = JoinSet::new();

            for ce in core_endpoints.iter_mut() {
                let req_cloned = dec_req.clone();
                let mut cur_client = ce.clone();
                req_tasks.spawn(async move {
                    cur_client.decrypt(tonic::Request::new(req_cloned)).await
                });
            }

            let mut req_response_vec = Vec::new();
            while let Some(inner) = req_tasks.join_next().await {
                req_response_vec.push(inner.unwrap().unwrap().into_inner());
            }

            assert!(req_response_vec.len() >= num_expected_responses); // TODO stop after expected num responses

            // get all responses
            let mut resp_tasks = JoinSet::new();
            for ce in core_endpoints.iter_mut() {
                let mut cur_client = ce.clone();
                let req_id_clone = dec_req.request_id.as_ref().unwrap().clone();

                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete decryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                    let mut response = cur_client
                        .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                    let mut ctr = 0_usize;
                    while response.is_err()
                        && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                    {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        // do at most max_iter retries (stop after max. 50 secs)
                        if ctr >= max_iter {
                            panic!("timeout while waiting for decryption after {max_iter} retries");
                        }
                        ctr += 1;
                        response = cur_client
                            .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }
                    (req_id_clone, response.unwrap().into_inner())
                });
            }

            let mut resp_response_vec = Vec::new();
            while let Some(resp) = resp_tasks.join_next().await {
                resp_response_vec.push(resp.unwrap().1);
            }

            // check the internal signatures
            internal_client.process_decryption_resp(
                Some(dec_req.clone()),
                &resp_response_vec,
                num_expected_responses as u32,
            )?;

            // check the external signatures
            check_external_decryption_signature(&resp_response_vec, ptxt, &dec_req, &kms_addrs)
                .unwrap();

            let res = format!("{:?}", resp_response_vec);
            (Some(req_id), res)
        }
        CCCommand::ReEncrypt(cipher_params) => {
            let to_encrypt = parse_hex(cipher_params.to_encrypt.as_str())?;
            let data_type = cipher_params.data_type;
            let key_id = &cipher_params.key_id;
            let keys_folder = destination_prefix;
            let compressed = Some(cipher_params.compressed);

            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_reconstruct
            };

            let (cipher, ptxt) =
                encrypt(to_encrypt, data_type, key_id, keys_folder, compressed).await?;

            internal_client.convert_to_addresses();
            let typed_ciphertexts = vec![TypedCiphertext {
                fhe_type: data_type as i32,
                ciphertext: cipher,
                external_handle: vec![1, 2, 3],
            }];

            // REENCRYPTION REQUEST
            let reenc_req_tuple = internal_client.reencryption_request(
                &dummy_domain(),
                typed_ciphertexts,
                &req_id,
                &RequestId {
                    request_id: cipher_params.key_id.clone(),
                },
            )?;

            let (reenc_req, enc_pk, enc_sk) = reenc_req_tuple;

            // make parallel requests by calling reencrypt in a thread
            let mut req_tasks = JoinSet::new();

            for ce in core_endpoints.iter_mut() {
                let req_cloned = reenc_req.clone();
                let mut cur_client = ce.clone();
                req_tasks.spawn(async move {
                    cur_client.reencrypt(tonic::Request::new(req_cloned)).await
                });
            }

            let mut req_response_vec = Vec::new();
            while let Some(inner) = req_tasks.join_next().await {
                req_response_vec.push(inner.unwrap().unwrap().into_inner());
            }

            assert!(req_response_vec.len() >= num_expected_responses);

            // get all responses
            let mut resp_tasks = JoinSet::new();
            for ce in core_endpoints.iter_mut() {
                let mut cur_client = ce.clone();
                let req_id_clone = reenc_req.request_id.as_ref().unwrap().clone();

                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete decryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                    let mut response = cur_client
                        .get_reencrypt_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                    let mut ctr = 0_usize;
                    while response.is_err()
                        && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                    {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        // do at most max_iter retries (stop after max. 50 secs)
                        if ctr >= max_iter {
                            panic!("timeout while waiting for decryption after {max_iter} retries");
                        }
                        ctr += 1;
                        response = cur_client
                            .get_reencrypt_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }
                    (req_id_clone, response.unwrap().into_inner())
                });
            }

            let mut resp_response_vec = Vec::new();
            while let Some(resp) = resp_tasks.join_next().await {
                resp_response_vec.push(resp.unwrap().1);
            }

            let client_request = ParsedReencryptionRequest::try_from(&reenc_req).unwrap();
            let eip712_domain =
                protobuf_to_alloy_domain(reenc_req.domain.as_ref().unwrap()).unwrap();
            match internal_client.process_reencryption_resp(
                &client_request,
                &eip712_domain,
                &resp_response_vec,
                &enc_pk,
                &enc_sk,
            ) {
                Ok(plaintexts) => {
                    let plaintext = plaintexts[0].clone();
                    assert_eq!(
                        TestingPlaintext::from(plaintext.clone()),
                        TestingPlaintext::from(ptxt.clone())
                    );
                    tracing::info!(
                        "Reencryption response is ok: {:?} / {:?}",
                        ptxt,
                        TestingPlaintext::from(plaintext),
                    );
                }
                Err(e) => tracing::warn!("Reencryption response is NOT valid! Reason: {}", e),
            };

            let res = format!("Reencrypted Plaintext {:?}", TestingPlaintext::from(ptxt));
            (Some(req_id), res)
        }
        CCCommand::KeyGen(KeyGenParameters { preproc_id }) => {
            tracing::info!("key generation with parameter {}.", param.as_str_name());
            let req_id = do_keygen(
                &mut internal_client,
                &mut core_endpoints,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                param,
                Some(RequestId {
                    request_id: preproc_id.clone(),
                }),
                false,
                destination_prefix,
            )
            .await?;

            (Some(req_id), "keygen done".to_string())
        }
        CCCommand::InsecureKeyGen(NoParameters {}) => {
            tracing::info!(
                "Insecure key generation with parameter {}.",
                param.as_str_name()
            );
            let req_id = do_keygen(
                &mut internal_client,
                &mut core_endpoints,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                param,
                None,
                true,
                destination_prefix,
            )
            .await?;

            (Some(req_id), "insecure keygen done".to_string())
        }
        CCCommand::CrsGen(CrsParameters { max_num_bits }) => {
            tracing::info!(
                "Insecure CRS generation with parameter {}.",
                param.as_str_name()
            );

            let req_id = do_crsgen(
                &mut internal_client,
                &mut core_endpoints,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                Some(*max_num_bits),
                param,
                false,
                destination_prefix,
            )
            .await?;
            (Some(req_id), "insecure crsgen done".to_string())
        }
        CCCommand::InsecureCrsGen(CrsParameters { max_num_bits }) => {
            tracing::info!("CRS generation with parameter {}.", param.as_str_name());

            let req_id = do_crsgen(
                &mut internal_client,
                &mut core_endpoints,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                Some(*max_num_bits),
                param,
                true,
                destination_prefix,
            )
            .await?;
            (Some(req_id), "crsgen done".to_string())
        }
        CCCommand::PreprocKeyGen(NoParameters {}) => {
            tracing::info!("Preprocessing with parameter {}.", param.as_str_name());

            let req_id = do_preproc(
                &mut internal_client,
                &mut core_endpoints,
                &mut rng,
                cmd_config,
                num_parties,
                param,
            )
            .await?;
            (Some(req_id), "preproc done".to_string())
        }
        CCCommand::DoNothing(NoParameters {}) => {
            tracing::info!("Nothing to do.");
            (None, "".to_string())
        }
    };

    tracing::info!("Core Client terminated successfully.");
    Ok(res)
}

async fn fetch_and_check_keygen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    keygen_request: KeyGenRequest,
    responses: Vec<KeyGenResult>,
) -> anyhow::Result<()> {
    assert!(
        num_expected_responses <= responses.len(),
        "Expected at least {} responses, but got {}",
        num_expected_responses,
        responses.len()
    );

    let req_id = keygen_request.request_id.unwrap().to_string();

    // Download the generated keys. We do this just once, to save time, assuming that all generated keys are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all keys and compare them.
    fetch_key(&req_id, cc_conf, destination_prefix).await?;
    let pk = load_pk_from_storage(Some(destination_prefix), &req_id).await;
    let sk = load_server_key_from_storage(Some(destination_prefix), &req_id).await;

    for response in responses {
        let resp_req_id = &response.request_id.unwrap().to_string();
        tracing::info!("Received KeyGenResult with request ID {}", resp_req_id); //TODO print key digests and signatures?

        assert_eq!(
            &req_id, resp_req_id,
            "Request ID of response does not match the transaction"
        );

        let domain = if let Some(domain) = &keygen_request.domain {
            protobuf_to_alloy_domain(domain)?
        } else {
            return Err(anyhow!("No domain provided in keygen request"));
        };

        let extpksig = if let Some(spdh) = response
            .key_results
            .get(&PubDataType::PublicKey.to_string())
        {
            &spdh.external_signature
        } else {
            return Err(anyhow!("No external pubkey signature in response"));
        };
        check_ext_pubdata_signature(&pk, extpksig, &domain, kms_addrs)?;

        let extsksig = if let Some(spdh) = response
            .key_results
            .get(&PubDataType::ServerKey.to_string())
        {
            &spdh.external_signature
        } else {
            return Err(anyhow!("No external pubkey signature in response"));
        };
        check_ext_pubdata_signature(&sk, extsksig, &domain, kms_addrs)?;

        tracing::info!("EIP712 verification of Public Key and Server Key successful.");
    }
    Ok(())
}

async fn fetch_and_check_crsgen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    crsgen_request: CrsGenRequest,
    responses: Vec<CrsGenResult>,
) -> anyhow::Result<()> {
    assert!(
        num_expected_responses <= responses.len(),
        "Expected at least {} responses, but got {}",
        num_expected_responses,
        responses.len()
    );

    let req_id = crsgen_request.request_id.unwrap().to_string();

    // Download the generated keys. We do this just once, to save time, assuming that all generated keys are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all keys and compare them.
    fetch_crs(&req_id, cc_conf, destination_prefix).await?;
    let crs = load_crs_from_storage(Some(destination_prefix), &req_id).await;

    for response in responses {
        let resp_req_id = &response.request_id.unwrap().to_string();
        tracing::info!("Received CrsGenResult with request ID {}", resp_req_id); //TODO print key digests and signatures?

        assert_eq!(
            &req_id, resp_req_id,
            "Request ID of response does not match the transaction"
        );

        let domain = if let Some(domain) = &crsgen_request.domain {
            protobuf_to_alloy_domain(domain)?
        } else {
            return Err(anyhow!("No domain provided in crsgen request"));
        };

        let extpksig = if let Some(spdh) = response.crs_results {
            spdh.external_signature
        } else {
            return Err(anyhow!("No external CRS signature in response"));
        };
        check_ext_pubdata_signature(&crs, &extpksig, &domain, kms_addrs)?;

        tracing::info!("EIP712 verification of CRS successful.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::k256::ecdsa::SigningKey;
    use kms_grpc::rpc_types::PrivDataType;
    use kms_lib::{
        consts::{TEST_CENTRAL_CRS_ID, TEST_PARAM},
        cryptography::internal_crypto_types::PrivateSigKey,
        engine::base::compute_external_pubdata_signature,
        util::key_setup::{ensure_central_crs_exists, ensure_central_server_signing_keys_exist},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };
    use tfhe::zk::CompactPkeCrs;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("00").unwrap(), vec![0u8]);
        assert_eq!(parse_hex("0x00").unwrap(), vec![0u8]);
        assert_eq!(parse_hex("ff").unwrap(), vec![255u8]);
        assert_eq!(parse_hex("0xff").unwrap(), vec![255u8]);
        assert_eq!(parse_hex("0001").unwrap(), vec![0u8, 1u8]);
        assert_eq!(parse_hex("0x1234").unwrap(), vec![18u8, 52u8]);
        assert_eq!(parse_hex("1").unwrap(), vec![1u8]);
        assert_eq!(parse_hex("0x1").unwrap(), vec![1u8]);
    }

    #[test]
    fn test_invalid_hex() {
        assert!(parse_hex("zz").is_err());
        assert!(parse_hex("0xzz").is_err());
        assert!(parse_hex("0x1234g").is_err());
        assert!(parse_hex("0x12345g").is_err());
        assert!(parse_hex("Ox01").is_err()); // leading O instead of 0
    }

    #[tokio::test]
    async fn test_eip712_sigs() {
        let mut pub_storage = RamStorage::new(StorageType::PUB);
        let mut priv_storage = RamStorage::new(StorageType::PRIV);

        // make sure signing keys exist
        ensure_central_server_signing_keys_exist(
            &mut pub_storage,
            &mut priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;

        // compute a small CRS for testing
        ensure_central_crs_exists(
            &mut pub_storage,
            &mut priv_storage,
            TEST_PARAM,
            &TEST_CENTRAL_CRS_ID,
            true,
        )
        .await;
        let crs: CompactPkeCrs = read_versioned_at_request_id(
            &pub_storage,
            &RequestId {
                request_id: TEST_CENTRAL_CRS_ID.to_string(),
            },
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();

        // read generated private signature key, derive public verifcation key and address from it
        let sk: PrivateSigKey = read_versioned_at_request_id(
            &priv_storage,
            &RequestId {
                request_id: SIGNING_KEY_ID.to_string(),
            },
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        let pk = SigningKey::verifying_key(sk.sk());
        let addr = alloy_signer::utils::public_key_to_address(pk);

        // set up a dummy EIP 712 domain
        let domain = alloy_sol_types::eip712_domain!(
            name: "dummy-test",
            version: "1",
            chain_id: 0,
            verifying_contract: alloy_primitives::Address::ZERO,
            // No salt
        );

        // sign with EIP712
        let sig = compute_external_pubdata_signature(&sk, &crs, &domain).unwrap();

        // check that the signature verifies and unwraps without error
        check_ext_pubdata_signature(&crs, &sig, &domain, &[addr]).unwrap();

        // check that verification fails for a wrong address
        let wrong_address = alloy_primitives::address!("0EdA6bf26964aF942Eed9e03e53442D37aa960EE");
        assert!(
            check_ext_pubdata_signature(&crs, &sig, &domain, &[wrong_address])
                .unwrap_err()
                .to_string()
                .contains("External crs/pubkey signature verification failed!")
        );

        // check that verification fails for signature that is too short
        let short_sig = [0_u8; 37];
        assert!(
            check_ext_pubdata_signature(&crs, &short_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("Expected external signature of length 65 Bytes, but got 37")
        );

        // check that verification fails for a byte string that is not a signature
        let malformed_sig = [23_u8; 65];
        assert!(
            check_ext_pubdata_signature(&crs, &malformed_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("signature error")
        );

        // check that verification fails for a signature that does not match the message
        let wrong_sig = hex::decode("cf92fe4c0b7c72fd8571c9a6680f2cd7481ebed7a3c8c7c7a6e6eaf27f5654f36100c146e609e39950953602ed73a3c10c1672729295ed8b33009b375813e5801b").unwrap();
        assert!(
            check_ext_pubdata_signature(&crs, &wrong_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("External crs/pubkey signature verification failed!")
        );
    }
}
