use std::collections::HashMap;
use std::{collections::HashSet, path::Path};

use bytes::Bytes;
use kms_grpc::rpc_types::PubDataType;
#[cfg(feature = "testing")]
use kms_lib::cryptography::signatures::PrivateSigKey;
use kms_lib::{
    consts::{SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID},
    cryptography::signatures::PublicSigKey,
};

use crate::{CoreClientConfig, CoreConf};

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
                tracing::warn!("Could not fetch element {element_name} with id {element_id} from core at endpoint {}. At least one core is required to proceed.", cur_core.s3_endpoint);
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

/// This fetches the KMS public verification keys from S3 for all the cores.
pub(crate) async fn fetch_kms_verification_keys(
    sim_conf: &CoreClientConfig,
) -> anyhow::Result<HashMap<usize, PublicSigKey>> {
    let key_id = &SIGNING_KEY_ID.to_string();
    let mut keys_map = HashMap::with_capacity(sim_conf.cores.len());

    for cur_core in &sim_conf.cores {
        let content = generic_fetch_element(
            &cur_core.s3_endpoint.clone(),
            &format!(
                "{}/{}",
                cur_core.object_folder,
                &PubDataType::VerfKey.to_string()
            ),
            key_id,
        )
        .await?;

        let vk = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&content),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        keys_map.insert(cur_core.party_id, vk);
    }

    Ok(keys_map)
}

/// This fetches the KMS private signing keys from S3 for all the cores.
#[cfg(feature = "testing")]
pub(crate) async fn fetch_kms_signing_keys(
    sim_conf: &CoreClientConfig,
) -> anyhow::Result<HashMap<usize, PrivateSigKey>> {
    let key_id = &SIGNING_KEY_ID.to_string();
    let mut keys_map = HashMap::with_capacity(sim_conf.cores.len());

    for cur_core in &sim_conf.cores {
        use kms_grpc::rpc_types::PrivDataType;

        let content = generic_fetch_element(
            &cur_core.s3_endpoint.clone(),
            &format!(
                "{}/{}",
                cur_core
                    .private_object_folder
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!(
                        "Private object folder not set for core {}",
                        cur_core.party_id
                    ))?,
                &PrivDataType::SigningKey.to_string()
            ),
            key_id,
        )
        .await?;

        let signing_key: PrivateSigKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&content),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        keys_map.insert(cur_core.party_id, signing_key);
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
            tracing::info!("Successfully downloaded {} bytes for element {element_id} from endpoint {endpoint}/{folder}", bytes.len());
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
        let key_path = Path::new(endpoint).join(folder).join(element_id);
        let byte_res = tokio::fs::read(&key_path).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to read bytes from file at {:?} with error: {e}",
                &key_path
            )
        })?;
        let res = Bytes::from(byte_res);
        tracing::info!("Successfully read {} bytes for element {element_id} from local path {endpoint}/{folder}", res.len());
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
