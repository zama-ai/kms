use clap::{Parser, Subcommand};
use kms_lib::client::Client;
use kms_lib::consts::THRESHOLD;
use kms_lib::kms::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_lib::kms::RequestId;
use kms_lib::util::key_setup::ensure_client_keys_exist;
use kms_lib::{
    conf::init_trace,
    consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM_PATH, DEFAULT_THRESHOLD_KEY_ID},
    kms::InitRequest,
    storage::{FileStorage, StorageType},
    util::key_setup::test_tools::compute_cipher_from_storage,
};
use rand::Rng;
use tokio::task::JoinSet;

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
                tokio::time::sleep(std::time::Duration::from_millis($interval)).await;
            }
        };
        result
    }};
    ($f:expr) => {
        retry!($f, 5, 100)
    };
}

// TODO correctly implement domain parsing in CLI when
// it's more clear what fields are needed
fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "dummy",
        version: "1",
        chain_id: 1,
        verifying_contract: alloy_primitives::Address::ZERO,
    )
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
    let pub_storage = vec![FileStorage::new_centralized(None, StorageType::PUB).unwrap()];
    let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
    let mut internal_client = Client::new_client(client_storage, pub_storage, DEFAULT_PARAM_PATH)
        .await
        .unwrap();
    let msg = rng.gen::<u32>();
    let (ct, fhe_type) =
        compute_cipher_from_storage(None, msg.into(), &DEFAULT_CENTRAL_KEY_ID.to_string()).await;

    // DECRYPTION REQUEST
    let random_req_id = RequestId::from(rng.gen::<u128>());
    let req = internal_client.decryption_request(
        ct.clone(),
        fhe_type,
        &random_req_id,
        &DEFAULT_CENTRAL_KEY_ID,
    )?;
    let response = kms_client.decrypt(tonic::Request::new(req.clone())).await?;
    tracing::debug!("DECRYPT RESPONSE={:?}", response);
    // Wait for the servers to complete the decryption
    let mut response = kms_client
        .get_decrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete reencryption
        std::thread::sleep(std::time::Duration::from_millis(100));
        response = kms_client
            .get_decrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
            .await;
    }
    tracing::debug!("GET DECRYPT RESPONSE={:?}", response);
    let responses = vec![response?.into_inner()];
    match internal_client.process_decryption_resp(Some(req), &responses, 1) {
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
    let (req, enc_pk, enc_sk) = internal_client.reencryption_request(
        ct,
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
        std::thread::sleep(std::time::Duration::from_millis(100));
        response = kms_client
            .get_reencrypt_result(tonic::Request::new(req.request_id.clone().unwrap()))
            .await;
    }
    tracing::debug!("GET REENCRYPT RESPONSE={:?}", response);
    let responses = vec![response?.into_inner()];
    match internal_client.process_reencryption_resp(Some(req), &responses, &enc_pk, &enc_sk) {
        Ok(plaintext) => {
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

async fn threshold_requests(addresses: Vec<String>, init: bool) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();

    tracing::info!("Threshold  Client - connecting to: {:?}", addresses);
    let num_parties = addresses.len();
    let mut pub_storage = Vec::with_capacity(num_parties);
    let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
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

        pub_storage.push(FileStorage::new_threshold(None, StorageType::PUB, i + 1).unwrap());
    }

    let mut internal_client = Client::new_client(client_storage, pub_storage, DEFAULT_PARAM_PATH)
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

    let msg: u8 = rng.gen();
    let (ct, fhe_type) =
        compute_cipher_from_storage(None, msg.into(), &DEFAULT_THRESHOLD_KEY_ID.to_string()).await;

    let random_req_id = RequestId::from(rng.gen::<u128>());

    // DECRYPTION REQUEST
    let dec_req = internal_client.decryption_request(
        ct.clone(),
        fhe_type,
        &random_req_id,
        &DEFAULT_THRESHOLD_KEY_ID,
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
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            let mut response = cur_client
                .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
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
        (THRESHOLD + 1) as u32,
    ) {
        Ok(Some(plaintext)) => {
            tracing::info!(
                "Decryption response is ok: {:?} of type {:?}",
                plaintext.as_u32(),
                plaintext.fhe_type()
            )
        }
        _ => tracing::warn!("Decryption response is NOT valid"),
    };

    Ok(())
}
/// This client serves test purposes.
#[cfg(feature = "non-wasm")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_trace()?;

    ensure_client_keys_exist(None, true).await;

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
