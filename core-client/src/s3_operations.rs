use std::collections::HashMap;
use std::{collections::HashSet, path::Path};

use crate::{CoreClientConfig, CoreConf};
use bytes::Bytes;
#[cfg(feature = "testing")]
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::rpc_types::PubDataType;
#[cfg(feature = "testing")]
use kms_lib::cryptography::signatures::PrivateSigKey;
use kms_lib::vault::storage::s3::{build_anonymous_s3_client, find_region_from_s3_url, S3Storage};
use kms_lib::vault::storage::{StorageReader, StorageType};
use kms_lib::{consts::SAFE_SER_SIZE_LIMIT, cryptography::signatures::PublicSigKey};
use tfhe::safe_serialization::safe_serialize;

/// Fetch all remote elements and store them locally for the core client
/// Return the server IDs of all servers that were successfully contacted
/// or an error if no server could be contacted
/// element_id: the id of the element to fetch (key id or crs id)
/// element_types: the types of elements to fetch (e.g. public key, server key, CRS)
/// sim_conf: the core client configuration
/// destination_prefix: the local folder to store the fetched elements
/// download_all: whether to download from all cores or just the first one
/// returns: the party IDs of the cores that were successfully contacted, unsorted
pub async fn fetch_public_elements(
    element_id: &str,
    element_types: &[PubDataType],
    sim_conf: &CoreClientConfig,
    destination_prefix: &Path,
    download_all: bool,
) -> anyhow::Result<Vec<CoreConf>> {
    // set of core ids, to track which cores we successfully contacted
    let mut successful_core_ids: HashSet<CoreConf> = HashSet::new();

    // go over list of cores to retrieve the public elements from
    'cores: for cur_core in &sim_conf.cores {
        let mut all_elements = true;
        // try to fetch all elements from this core
        'elements: for element_name in element_types {
            tracing::info!(
                "Fetching {element_name:?} with id {element_id} from {}/{}",
                cur_core.s3_endpoint.as_str(),
                &cur_core.object_folder,
            );

            if fetch_global_pub_element_and_write_to_file(
                destination_prefix,
                cur_core.s3_endpoint.as_str(),
                element_id,
                &element_name.to_string(),
                &cur_core.object_folder,
            )
            .await
            .is_err()
            {
                tracing::warn!(
                    "Could not fetch element {element_name} with id {element_id} from core at endpoint {}. At least one core is required to proceed.",
                    cur_core.s3_endpoint
                );
                all_elements = false;
                break 'elements;
            }
        }
        // if we were able to retrieve all elements, add the core id to the set of successful nodes
        if all_elements {
            successful_core_ids.insert(cur_core.clone());
            // if we only want to download from one core, break here
            if !download_all {
                break 'cores;
            }
        }
    }

    if successful_core_ids.is_empty() {
        Err(anyhow::anyhow!(
            "Could not fetch all of [{element_types:?}] with id {element_id} from any core. At least one core is required to proceed."
        ))
    } else {
        Ok(successful_core_ids.into_iter().collect())
    }
}

/// This tries to fetch the KMS public verification keys and store them in the local file system
/// Return the server IDs of all servers that were successfully contacted
/// or an error if no server could be contacted
/// sim_conf: the core client configuration
/// destination_prefix: the local folder to store the fetched elements
/// download_all: whether to download from all cores or just the first one
/// returns: the party IDs of the cores that were successfully contacted, unsorted
pub(crate) async fn fetch_and_store_kms_verification_keys(
    sim_conf: &CoreClientConfig,
    destination_prefix: &Path,
    download_all: bool,
) -> anyhow::Result<Vec<CoreConf>> {
    // set of core ids, to track which cores we successfully contacted
    let mut successful_core_ids: HashSet<CoreConf> = HashSet::new();
    for cur_core in &sim_conf.cores {
        let mut all_elements = true;
        let verf_folder = destination_prefix
            .join(&cur_core.object_folder)
            .join(&PubDataType::VerfKey.to_string());
        let addr_folder = destination_prefix
            .join(&cur_core.object_folder)
            .join(&PubDataType::VerfAddress.to_string());
        let region = find_region_from_s3_url(&cur_core.s3_endpoint)?;
        let s3_client = build_anonymous_s3_client(&cur_core.s3_endpoint, region).await?;
        let s3_storage = S3Storage::new(
            s3_client,
            cur_core.object_folder.clone(),
            StorageType::PUB,
            None,
        )?;
        let key_ids = match s3_storage
            .all_data_ids(&PubDataType::VerfKey.to_string())
            .await
        {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(
                    "Could not fetch verification key IDs from core at endpoint {} with error {e}.",
                    cur_core.s3_endpoint
                );
                continue;
            }
        };
        for cur_key_id in key_ids {
            let cur_key: PublicSigKey = match s3_storage
                .read_data(&cur_key_id, &PubDataType::VerfKey.to_string())
                .await
            {
                Ok(cur_key) => cur_key,
                Err(e) => {
                    tracing::warn!("Could not fetch verification key with id {cur_key_id} from core at endpoint {} with error {e}.", cur_core.s3_endpoint);
                    all_elements = false;
                    continue;
                }
            };

            let mut cur_key_bytes: Vec<_> = Vec::new();
            safe_serialize(&cur_key, &mut cur_key_bytes, SAFE_SER_SIZE_LIMIT)?;
            write_bytes_to_file(&verf_folder, &cur_key_id.as_str(), cur_key_bytes.as_ref()).await?;
            let addr_string = cur_key.address().to_string();
            let addr_bytes = addr_string.as_bytes();
            write_bytes_to_file(&addr_folder, &cur_key_id.as_str(), addr_bytes).await?;
        }
        // if we were able to retrieve all elements, add the core id to the set of successful nodes
        if all_elements {
            successful_core_ids.insert(cur_core.clone());
            // if we only want to download from one core, break here
            if !download_all {
                break;
            }
        }
    }
    if successful_core_ids.is_empty() {
        Err(anyhow::anyhow!(
            "Could not fetch elements from any core. At least one core is required to proceed."
        ))
    } else {
        Ok(successful_core_ids.into_iter().collect())
    }
}

/// This tries to fetch the KMS public verification keys from S3 for all the cores.
pub(crate) async fn fetch_kms_verification_keys(
    sim_conf: &CoreClientConfig,
) -> anyhow::Result<HashMap<usize, PublicSigKey>> {
    let mut keys_map = HashMap::with_capacity(sim_conf.cores.len());
    for cur_core in &sim_conf.cores {
        let region = find_region_from_s3_url(&cur_core.s3_endpoint)?;
        let s3_client = build_anonymous_s3_client(&cur_core.s3_endpoint, region).await?;
        let s3_storage = S3Storage::new(
            s3_client,
            cur_core.object_folder.clone(),
            StorageType::PUB,
            None,
        )?;
        let key_ids = s3_storage
            .all_data_ids(&PubDataType::VerfKey.to_string())
            .await?;
        // Use the single verification key (take the first one found)
        for cur_key_id in key_ids {
            let cur_key: PublicSigKey = s3_storage
                .read_data(&cur_key_id, &PubDataType::VerfKey.to_string())
                .await?;
            keys_map.insert(cur_core.party_id, cur_key);
            break; // single key per server
        }
    }

    Ok(keys_map)
}

/// This fetches the KMS private signing keys from S3 for all the cores.
#[cfg(feature = "testing")]
pub(crate) async fn fetch_kms_signing_keys(
    sim_conf: &CoreClientConfig,
) -> anyhow::Result<HashMap<usize, PrivateSigKey>> {
    let mut keys_map = HashMap::with_capacity(sim_conf.cores.len());
    for cur_core in &sim_conf.cores {
        let region = find_region_from_s3_url(&cur_core.s3_endpoint)?;
        let s3_client = build_anonymous_s3_client(&cur_core.s3_endpoint, region).await?;
        let s3_storage = S3Storage::new(
            s3_client,
            cur_core.object_folder.clone(),
            StorageType::PRIV,
            None,
        )?;
        let key_ids = s3_storage
            .all_data_ids(&PrivDataType::SigningKey.to_string())
            .await?;
        // Use the single signing key (take the first one found)
        for cur_key_id in key_ids {
            let cur_key: PrivateSigKey = s3_storage
                .read_data(&cur_key_id, &PrivDataType::SigningKey.to_string())
                .await?;
            keys_map.insert(cur_core.party_id, cur_key);
            break; // single key per server
        }
    }
    Ok(keys_map)
}

/// This fetches material which is global
/// i.e. everything related to CRS and FHE public materials
async fn fetch_global_pub_element_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    element_id: &str,
    element_name: &str,
    element_folder: &str,
) -> anyhow::Result<()> {
    // Fetch pub-key from storage and dump it for later use
    let folder = destination_prefix.join(element_folder).join(element_name);
    let content = generic_fetch_element(
        s3_endpoint,
        &format!("{element_folder}/{element_name}"),
        element_id,
    )
    .await?;
    tracing::info!("writing element to folder {:?}", folder);
    write_bytes_to_file(&folder, element_id, content.as_ref()).await
}

fn join_vars(args: &[&str]) -> String {
    args.iter()
        .filter(|&s| !s.is_empty())
        .copied()
        .collect::<Vec<&str>>()
        .join("/")
}

// TODO: handle auth
// TODO: add option to either use local key or remote key
async fn generic_fetch_element(
    endpoint: &str,
    folder: &str,
    element_id: &str,
) -> anyhow::Result<Bytes> {
    let element_key = element_id.to_string();
    // Construct the URL
    let url = join_vars(&[endpoint, folder, element_key.as_str()]);
    tracing::debug!("Fetching element: {url}");

    // If URL we fetch it
    if url.starts_with("http") {
        // Make the request
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await?;

        if response.status().is_success() {
            let bytes = response.bytes().await?;
            tracing::info!(
                "Successfully downloaded {} bytes for element {element_id} from endpoint {endpoint}/{folder}",
                bytes.len()
            );
            // Here you can process the bytes as needed
            Ok(bytes)
        } else {
            let response_status = response.status();
            let response_content = response.text().await?;
            tracing::error!("Fetch element error: {}", response_status);
            tracing::error!("Response: {}", response_content);
            Err(anyhow::anyhow!(format!(
                "Couldn't fetch element {element_id} from endpoint {endpoint}/{folder}\nStatus: {}\nResponse: {}",
                response_status, response_content
            ),))
        }
    } else {
        // read from local file system
        // Strip file:// prefix if present
        let local_path = if let Some(stripped) = endpoint.strip_prefix("file://") {
            stripped
        } else {
            endpoint
        };
        let key_path = Path::new(local_path).join(folder).join(element_id);
        let byte_res = tokio::fs::read(&key_path).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to read bytes from file at {:?} with error: {e}",
                &key_path
            )
        })?;
        let res = Bytes::from(byte_res);
        tracing::info!(
            "Successfully read {} bytes for element {element_id} from local path {local_path}/{folder}",
            res.len()
        );
        Ok(res)
    }
}

async fn write_bytes_to_file(
    folder_path: &Path,
    filename: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let path = folder_path.join(filename);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?;
    }
    tokio::fs::write(&path, data).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to write bytes to file at {:?} with error: {e}",
            &path
        )
    })?;
    Ok(())
}
