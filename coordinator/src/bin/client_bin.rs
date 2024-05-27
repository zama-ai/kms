use kms_lib::client::Client;
use kms_lib::consts::DEFAULT_CENTRAL_KEY_ID;
use kms_lib::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
use kms_lib::kms::{AggregatedDecryptionResponse, AggregatedReencryptionResponse};
use std::collections::HashMap;
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

/// This client serves test purposes.
/// Assuming a connection to a centralized server
/// URL format is without protocol e.g.: 0.0.0.0:50051
#[cfg(feature = "non-wasm")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use kms_lib::{
        consts::{DEFAULT_DEC_ID, DEFAULT_PARAM_PATH, TEST_MSG},
        storage::{FileStorage, StorageType},
        util::key_setup::compute_cipher_from_storage,
    };

    // TODO ensure the keys exist
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::WARN))
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("Missing required argument: server URL. Please provide the server URL as the second argument.".into());
    }
    let url = &args[1];

    let mut kms_client = retry!(
        CoordinatorEndpointClient::connect(url.to_owned()).await,
        5,
        100
    )?;
    let pub_storage = vec![FileStorage::new_central(StorageType::PUB)];
    let client_storage = FileStorage::new_central(StorageType::CLIENT);
    let mut internal_client =
        Client::new_client(client_storage, pub_storage, DEFAULT_PARAM_PATH, 1, 1)
            .await
            .unwrap();
    let (ct, fhe_type) =
        compute_cipher_from_storage(TEST_MSG, &DEFAULT_CENTRAL_KEY_ID.to_string()).await;

    // DECRYPTION REQUEST
    let req = internal_client.decryption_request(
        ct.clone(),
        fhe_type,
        &DEFAULT_DEC_ID,
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
    let responses = AggregatedDecryptionResponse {
        responses: vec![response?.into_inner()],
    };
    match internal_client.process_decryption_resp(Some(req), &responses) {
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
        &DEFAULT_DEC_ID,
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
    let responses = AggregatedReencryptionResponse {
        responses: HashMap::from([(1, response?.into_inner())]),
    };
    match internal_client.process_reencryption_resp(Some(req), &responses, &enc_pk, &enc_sk) {
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
