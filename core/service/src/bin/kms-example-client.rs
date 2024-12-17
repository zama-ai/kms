use aes_prng::AesRng;
use clap::{Parser, Subcommand};
use kms_lib::client::{Client, ParsedReencryptionRequest};
use kms_lib::consts::DEFAULT_THRESHOLD;
use kms_lib::kms::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_lib::kms::{RequestId, TypedCiphertext};
use kms_lib::rpc::rpc_types::protobuf_to_alloy_domain;
use kms_lib::util::key_setup::ensure_client_keys_exist;
use kms_lib::{
    conf::init_kms_core_telemetry,
    consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM, DEFAULT_THRESHOLD_KEY_ID_4P},
    kms::InitRequest,
    storage::{file::FileStorage, StorageType},
    util::key_setup::test_tools::compute_compressed_cipher_from_stored_key,
};
use rand::{Rng, SeedableRng};
use tokio::task::JoinSet;
use tonic::transport::Channel;

const CLIENT_RETRY_COUNTER: usize = 100;

#[derive(Parser)]
#[clap(name = "KMS Example Client")]
struct KmsArgs {
    #[clap(subcommand)]
    mode: ExecutionMode,
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
    let mut internal_client = Client::new_client(client_storage, pub_storage, &DEFAULT_PARAM)
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
        external_handle: Some(vec![99_u8; 32]),
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
        ct[0].ciphertext.clone(),
        &dummy_domain(),
        fhe_type,
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
        Ok(plaintext) => {
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

async fn do_threshold_decryption(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
) -> anyhow::Result<()> {
    let num_parties = core_endpoints.len();
    let msg: u8 = rng.gen();
    let (ct, fhe_type) = compute_compressed_cipher_from_stored_key(
        None,
        msg.into(),
        &DEFAULT_THRESHOLD_KEY_ID_4P.to_string(),
    )
    .await;

    let random_req_id = RequestId::from(rng.gen::<u128>());

    // this is currently a batch of size 1
    let ct = vec![TypedCiphertext {
        ciphertext: ct,
        fhe_type: fhe_type.into(),
        external_handle: Some(vec![88_u8; 32]),
    }];

    // DECRYPTION REQUEST
    let dec_req = internal_client.decryption_request(
        ct,
        &dummy_domain(),
        &random_req_id,
        &dummy_acl_address(),
        &DEFAULT_THRESHOLD_KEY_ID_4P,
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
) -> anyhow::Result<()> {
    let num_parties = core_endpoints.len();
    let msg: u8 = rng.gen();
    let (ct, fhe_type) = compute_compressed_cipher_from_stored_key(
        None,
        msg.into(),
        &DEFAULT_THRESHOLD_KEY_ID_4P.to_string(),
    )
    .await;

    let random_req_id = RequestId::from(rng.gen::<u128>());

    internal_client.convert_to_addresses();

    // REENCRYPTION REQUEST
    let domain = dummy_domain();
    let reenc_req_tuple = internal_client.reencryption_request(
        ct.clone(),
        &domain,
        fhe_type,
        &random_req_id,
        &DEFAULT_THRESHOLD_KEY_ID_4P,
    )?;
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
        Ok(plaintext) => {
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

async fn threshold_requests(addresses: Vec<String>, init: bool) -> anyhow::Result<()> {
    let mut rng = AesRng::from_entropy();

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

        pub_storage.push(FileStorage::new(None, StorageType::PUB, Some(i + 1)).unwrap());
    }

    let mut internal_client = Client::new_client(client_storage, pub_storage, &DEFAULT_PARAM)
        .await
        .unwrap();

    // initialize PRSS if flag is set
    if init {
        let mut handles = JoinSet::new();

        for ce in core_endpoints.iter_mut() {
            let mut ce = ce.clone();

            handles.spawn(tokio::spawn(async move {
                let init_request = InitRequest {
                    config: Some(kms_lib::kms::Config {}),
                };
                let _ = ce.init(init_request).await.unwrap();
            }));
        }

        while handles.join_next().await.is_some() {}
    }

    do_threshold_decryption(&mut internal_client, &mut core_endpoints, &mut rng).await?;
    do_threshold_reencryption(&mut internal_client, &mut core_endpoints, &mut rng).await
}

/// This client serves test purposes.
#[cfg(feature = "non-wasm")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use kms_lib::consts::SIGNING_KEY_ID;

    init_kms_core_telemetry()?;

    ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;

    let args = KmsArgs::parse();
    match args.mode {
        ExecutionMode::Centralized { address } => {
            central_requests(address).await?;
        }
        ExecutionMode::Threshold { addresses, init } => {
            threshold_requests(addresses, init).await?;
        }
    };

    Ok(())
}
