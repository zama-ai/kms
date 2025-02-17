use aes_prng::AesRng;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use core::str;
use kms_common::DecryptionMode;
use kms_grpc::kms::v1::{InitRequest, RequestId, TypedCiphertext};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, SIGNING_KEY_ID};
use kms_lib::client::{Client, ParsedReencryptionRequest};
use kms_lib::consts::DEFAULT_THRESHOLD;
use kms_lib::util::key_setup::ensure_client_keys_exist;
use kms_lib::{
    conf::init_kms_core_telemetry,
    consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM},
    util::key_setup::test_tools::compute_compressed_cipher_from_stored_key,
    vault::storage::{file::FileStorage, StorageType},
};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::fs;
use tokio::task::JoinSet;
use tonic::transport::Channel;

const CLIENT_RETRY_COUNTER: usize = 100;

#[derive(Parser)]
#[clap(name = "KMS Example Client")]
struct KmsArgs {
    #[clap(subcommand)]
    mode: ExecutionMode,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct CoreClientConfig {
    /// S3 endpoint from which to fetch keys
    /// NOTE: We should probably move away from that and use the key-url
    pub s3_endpoint: Option<String>,
    /// Key folder where to store the keys
    pub object_folder: Vec<String>,
    /// The decryption mode used for reencryption reconstruction in threshold mode
    pub decryption_mode: Option<DecryptionMode>,
}

#[derive(Subcommand, Clone)]
enum ExecutionMode {
    Threshold {
        #[clap(
            short,
            default_value = "localhost:50100,localhost:50200,localhost:50300,localhost:50400",
            value_parser, num_args = 1.., value_delimiter = ',',
            help = "the addresses of the threshold KMS cores"
        )]
        addresses: Vec<String>,

        #[clap(short, help = "initialize PRSS")]
        init: bool,
    },
    Centralized {
        #[clap(
            short,
            default_value = "localhost:50051",
            help = "the address of the centralized KMS core"
        )]
        address: String,
    },
}

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

/// retrieve public verification keys and Ethereum addresses of the MPC servers
async fn fetch_verf_keys(
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
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

/// fetches all public material (verification keys, CRS, public and server keys) from the remote storage
async fn _fetch_all_public_material(
    key_id: &str,
    crs_id: &str,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    fetch_verf_keys(cc_conf, destination_prefix).await?;
    fetch_key(key_id, cc_conf, destination_prefix).await?;
    _fetch_crs(crs_id, cc_conf, destination_prefix).await?;

    Ok(())
}

/// Fetch all remote objects associated with TFHE keys (public and server key) and store locally for the simulator
async fn fetch_key(
    request_id: &str,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    tracing::info!("Fetching public key and server key stored under requst id {request_id}");
    for object_name in ["PublicKey", "PublicKeyMetadata", "ServerKey"] {
        fetch_global_pub_object_and_write_to_file(
            destination_prefix,
            cc_conf
                .s3_endpoint
                .clone()
                .expect("S3 endpoint should be provided")
                .as_str(),
            request_id,
            object_name,
            cc_conf.object_folder.first().unwrap(),
        )
        .await?;
    }
    Ok(())
}

/// Fetch the remote CRS and store locally for the simulator
async fn _fetch_crs(
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
    let _ = write_bytes_to_file(&folder, object_id, content.as_ref());
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

/// This fetches the kms ethereum address from S3
async fn _fetch_kms_addresses(
    cc_conf: &CoreClientConfig,
    is_centralized: bool,
) -> Result<Vec<alloy_primitives::Address>, Box<dyn std::error::Error + 'static>> {
    // TODO: handle local file
    let key_id = &SIGNING_KEY_ID.to_string();

    let mut addr_bytes = Vec::new();
    if is_centralized {
        let content = fetch_object(
            &cc_conf
                .s3_endpoint
                .clone()
                .expect("s3 endpoint should be provided"),
            &format!(
                "{}/{}",
                cc_conf.object_folder.first().unwrap(),
                "VerfAddress"
            ),
            key_id,
        )
        .await?;
        addr_bytes.push(content);
    } else {
        for folder_name in cc_conf.object_folder.iter() {
            let content = fetch_object(
                &cc_conf
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
        match fs::read(&key_path).await {
            Ok(content) => Ok(Bytes::from(content)),
            Err(error) => Err(anyhow::anyhow!(format!(
                "Couldn't fetch key from file {:?} from error: {:?}",
                key_path, error
            ),)),
        }
    }
}

pub fn write_bytes_to_file(folder_path: &Path, filename: &str, data: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(folder_path)?;
    let path = std::path::absolute(folder_path.join(filename))?;
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
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
    alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045")
}

async fn central_requests(address: String) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();

    tracing::info!("Centralized Client - connecting to: {}", address);

    // make sure address starts with http://
    let url = if address.starts_with("http://") {
        address
    } else {
        "http://".to_string() + &address
    };

    let mut kms_client = retry!(
        CoreServiceEndpointClient::connect(url.to_owned()).await,
        5,
        100
    )?;
    let pub_storage = vec![FileStorage::new(None, StorageType::PUB, None).unwrap()];
    let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
    let mut internal_client = Client::new_client(client_storage, pub_storage, &DEFAULT_PARAM, None)
        .await
        .unwrap();
    let msg = rng.gen::<u32>();
    let (ct, fhe_type) = compute_compressed_cipher_from_stored_key(
        None,
        msg.into(),
        &DEFAULT_CENTRAL_KEY_ID.to_string(),
    )
    .await;

    // this is currently a batch of size 1
    let ct = vec![TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type.into(),
        external_handle: vec![99_u8; 32],
    }];

    // DECRYPTION REQUEST
    let random_req_id = RequestId::from(rng.gen::<u128>());
    let req = internal_client.decryption_request(
        ct.clone(),
        &dummy_domain(),
        &random_req_id,
        &dummy_acl_address(),
        &DEFAULT_CENTRAL_KEY_ID,
    )?;
    let response = kms_client.decrypt(tonic::Request::new(req.clone())).await?;
    tracing::debug!("DECRYPT RESPONSE={:?}", response);
    // Wait for the servers to complete the decryption
    let mut response = kms_client
        .get_decrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete decryption
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        response = kms_client
            .get_decrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
            .await;
    }
    tracing::debug!("GET DECRYPT RESPONSE={:?}", response);
    let responses = vec![response?.into_inner()];
    match internal_client.process_decryption_resp(Some(req), &responses, 1) {
        Ok(plaintext) => {
            tracing::info!(
                "Decryption response is ok: {:?} of type {:?}",
                plaintext[0].as_u32(),
                plaintext[0].fhe_type()
            );
            assert_eq!(plaintext[0].as_u32(), msg);
        }
        Err(e) => tracing::warn!("Decryption response is NOT valid! Reason: {}", e),
    };

    // REENCRYPTION REQUEST
    let (req, enc_pk, enc_sk) = internal_client.reencryption_request(
        &dummy_domain(),
        ct,
        &random_req_id,
        &DEFAULT_CENTRAL_KEY_ID,
    )?;
    let response = kms_client
        .reencrypt(tonic::Request::new(req.clone()))
        .await?;
    tracing::debug!("REENCRYPT RESPONSE={:?}", response);
    // Wait for the servers to complete the reencryption
    let mut response = kms_client
        .get_reencrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete reencryption
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        response = kms_client
            .get_reencrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
            .await;
    }
    tracing::debug!("GET REENCRYPT RESPONSE={:?}", response);
    let responses = vec![response?.into_inner()];

    let eip712_domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap()).unwrap();
    let client_request = ParsedReencryptionRequest::try_from(&req).unwrap();
    internal_client.convert_to_addresses();
    match internal_client.process_reencryption_resp(
        &client_request,
        &eip712_domain,
        &responses,
        &enc_pk,
        &enc_sk,
    ) {
        Ok(plaintexts) => {
            let plaintext = &plaintexts[0];
            tracing::info!(
                "Reencryption response is ok: {:?} of type {:?}",
                plaintext.as_u32(),
                plaintext.fhe_type()
            );
            assert_eq!(plaintext.as_u32(), msg);
        }
        Err(e) => tracing::warn!("Reencryption response is NOT valid! Reason: {}", e),
    };

    Ok(())
}

async fn do_insecure_keygen(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::from(rng.gen::<u128>());

    let dkg_req = internal_client.key_gen_request(&req_id, None, None, None, None, None)?;

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = dkg_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .insecure_key_gen(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), 4);

    // get all responses
    let mut resp_tasks = JoinSet::new();
    for ce in core_endpoints.iter_mut() {
        let mut cur_client = ce.clone();
        let req_id_clone = dkg_req.request_id.as_ref().unwrap().clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut response = cur_client
                .get_insecure_key_gen_result(tonic::Request::new(req_id_clone.clone()))
                .await;

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                // do at most 100 retries (stop after max. 50 secs)
                if ctr >= CLIENT_RETRY_COUNTER {
                    panic!(
                        "timeout while waiting for insecure keygen after {CLIENT_RETRY_COUNTER} retries"
                    );
                }
                ctr += 1;
                response = cur_client
                    .get_insecure_key_gen_result(tonic::Request::new(req_id_clone.clone()))
                    .await;

                println!("Got response for insecure keygen: {:?}", response);
            }
            (req_id_clone, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        resp_response_vec.push(resp.unwrap().1);
    }

    // let resp = resp_response_vec[0].clone();
    let destination_prefix: &Path = Path::new("tests/data/keys");

    // Download the generated keys. We do this just once, to save time, assuming that all generated keys are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all keys and compare them.
    fetch_key(&req_id.to_string(), cc_conf, destination_prefix).await?;
    // let pk = load_pk_from_storage(Some(destination_prefix), &req_id.to_string()).await;
    // let sk = load_server_key_from_storage(Some(destination_prefix), &req_id.to_string()).await;

    Ok(req_id)
}

async fn do_threshold_decryption(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    key_id: &RequestId,
) -> anyhow::Result<()> {
    let num_parties = core_endpoints.len();
    let msg: u8 = rng.gen();

    let destination_prefix = Path::new("tests/data/keys");

    let (ct, fhe_type) = compute_compressed_cipher_from_stored_key(
        Some(destination_prefix),
        msg.into(),
        &key_id.to_string(),
    )
    .await;

    let random_req_id = RequestId::from(rng.gen::<u128>());

    // this is currently a batch of size 1
    let ct = vec![TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type.into(),
        external_handle: vec![88_u8; 32],
    }];

    // DECRYPTION REQUEST
    let dec_req = internal_client.decryption_request(
        ct,
        &dummy_domain(),
        &random_req_id,
        &dummy_acl_address(),
        key_id,
    )?;

    // make parallel requests by calling [decrypt] in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = dec_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move { cur_client.decrypt(tonic::Request::new(req_cloned)).await });
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
                // do at most 100 retries (stop after max. 50 secs)
                if ctr >= CLIENT_RETRY_COUNTER {
                    panic!(
                        "timeout while waiting for decryption after {CLIENT_RETRY_COUNTER} retries"
                    );
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

    match internal_client.process_decryption_resp(
        Some(dec_req),
        &resp_response_vec,
        (DEFAULT_THRESHOLD + 1) as u32,
    ) {
        Ok(plaintexts) => {
            tracing::info!(
                "Decryption response is ok: {:?} of type {:?}",
                plaintexts[0].as_u8(),
                plaintexts[0].fhe_type()
            );
            assert_eq!(plaintexts[0].as_u8(), msg);
        }
        Err(e) => tracing::warn!("Decryption response is NOT valid! Error: {}", e),
    };

    Ok(())
}

async fn do_threshold_reencryption(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    key_id: &RequestId,
) -> anyhow::Result<()> {
    let num_parties = core_endpoints.len();
    let msg: u8 = rng.gen();
    let destination_prefix = Path::new("tests/data/keys");

    let (ct, fhe_type) = compute_compressed_cipher_from_stored_key(
        Some(destination_prefix),
        msg.into(),
        &key_id.to_string(),
    )
    .await;
    let typed_ciphertexts = vec![TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type.into(),
        external_handle: vec![123],
    }];

    let random_req_id = RequestId::from(rng.gen::<u128>());

    internal_client.convert_to_addresses();

    // REENCRYPTION REQUEST
    let domain = dummy_domain();
    let reenc_req_tuple =
        internal_client.reencryption_request(&domain, typed_ciphertexts, &random_req_id, key_id)?;
    let (reenc_req, enc_pk, enc_sk) = reenc_req_tuple;

    // make parallel requests by calling [decrypt] in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = reenc_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move { cur_client.reencrypt(tonic::Request::new(req_cloned)).await });
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
                // do at most 100 retries (stop after max. 50 secs)
                if ctr >= CLIENT_RETRY_COUNTER {
                    panic!(
                        "timeout while waiting for decryption after {CLIENT_RETRY_COUNTER} retries"
                    );
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
    let eip712_domain = protobuf_to_alloy_domain(reenc_req.domain.as_ref().unwrap()).unwrap();
    match internal_client.process_reencryption_resp(
        &client_request,
        &eip712_domain,
        &resp_response_vec,
        &enc_pk,
        &enc_sk,
    ) {
        Ok(plaintexts) => {
            let plaintext = &plaintexts[0];
            tracing::info!(
                "Reencryption response is ok: {:?} of type {:?}",
                plaintext.as_u8(),
                plaintext.fhe_type()
            );
            assert_eq!(plaintext.as_u8(), msg);
        }
        Err(e) => tracing::warn!("Reencryption response is NOT valid! Reason: {}", e),
    };

    Ok(())
}

async fn threshold_requests(
    addresses: Vec<String>,
    init: bool,
    cc_conf: &CoreClientConfig,
) -> anyhow::Result<()> {
    let mut rng = AesRng::from_entropy();

    let destination_path = Path::new("tests/data/keys");
    fetch_verf_keys(cc_conf, destination_path).await?;

    tracing::info!("Threshold Client - connecting to: {:?}", addresses);
    let num_parties = addresses.len();
    let mut pub_storage = Vec::with_capacity(num_parties);
    let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
    let mut core_endpoints = Vec::with_capacity(num_parties);

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

        pub_storage
            .push(FileStorage::new(Some(destination_path), StorageType::PUB, Some(i + 1)).unwrap());
    }

    let mut internal_client = Client::new_client(client_storage, pub_storage, &DEFAULT_PARAM, None)
        .await
        .unwrap();

    // initialize PRSS if flag is set
    if init {
        let mut handles = JoinSet::new();

        for ce in core_endpoints.iter_mut() {
            let mut ce = ce.clone();

            handles.spawn(tokio::spawn(async move {
                let init_request = InitRequest {
                    config: Some(kms_grpc::kms::v1::Config {}),
                };
                let _ = ce.init(init_request).await.unwrap();
            }));
        }

        while handles.join_next().await.is_some() {}
    }

    let req_id =
        do_insecure_keygen(&mut internal_client, &mut core_endpoints, &mut rng, cc_conf).await?;

    println!("Request ID Keygen: {:?}", req_id);

    do_threshold_decryption(&mut internal_client, &mut core_endpoints, &mut rng, &req_id).await?;
    do_threshold_reencryption(&mut internal_client, &mut core_endpoints, &mut rng, &req_id).await?;
    Ok(())
}

/// This client serves test purposes.
#[cfg(feature = "non-wasm")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = KmsArgs::parse();

    use conf_trace::conf::Settings;

    init_kms_core_telemetry()?;

    let path_to_config = Path::new("config/client_local_threshold.toml");
    tracing::info!("Path to config: {:?}", path_to_config);

    let cc_conf: CoreClientConfig = Settings::builder()
        .path(path_to_config.to_str().unwrap())
        .env_prefix("KMS_CLIENT")
        .build()
        .init_conf()?;

    tracing::info!("Client config: {:?}", cc_conf);

    ensure_client_keys_exist(None, &kms_grpc::rpc_types::SIGNING_KEY_ID, true).await;

    match args.mode {
        ExecutionMode::Centralized { address } => {
            central_requests(address).await?;
        }
        ExecutionMode::Threshold { addresses, init } => {
            threshold_requests(addresses, init, &cc_conf).await?;
        }
    };

    Ok(())
}
