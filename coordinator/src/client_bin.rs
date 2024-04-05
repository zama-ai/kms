use kms_lib::kms::kms_endpoint_client::KmsEndpointClient;
use kms_lib::kms::{AggregatedDecryptionResponse, AggregatedReencryptionResponse, FheType};
use kms_lib::setup_rpc::CentralizedTestingKeys;
use kms_lib::{
    client::Client,
    consts::{DEFAULT_CENTRAL_CT_PATH, DEFAULT_CENTRAL_KEYS_PATH},
    file_handling::read_element,
};
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
/// URL format is without protocol e.g.: 0.0.0.0:50051
#[cfg(feature = "non-wasm")]
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
        Some(central_keys.client_sk),
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
    let (req, enc_pk, enc_sk) =
        internal_client.reencyption_request(ct, &dummy_domain(), fhe_type, None)?;
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
