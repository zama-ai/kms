//! Helpers that drive epoch requests and compare the four parties' public and private files.

use crate::client::client_wasm::Client;
use crate::client::tests::common::{PollConfig, retrying_poll};
use crate::consts::{
    DEFAULT_MPC_CONTEXT, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
};
use crate::vault::storage::{
    StorageType, file::FileStorage, store_versioned_at_request_and_epoch_id,
    store_versioned_at_request_id, test_support::EntryDigest, test_support::digest_entry,
    tests::TestType,
};
use kms_grpc::identifiers::{ContextId, EpochId};
use kms_grpc::kms::v1::{DestroyMpcEpochRequest, EpochResultResponse};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio::task::JoinSet;
use tonic::{Code, Response, Status, transport::Channel};
use walkdir::WalkDir;

pub(super) const PARTY_COUNT: usize = 4;

/// A digest for every file, keyed by its path below the material directory.
pub(super) type FileState = BTreeMap<PathBuf, EntryDigest>;

/// Fingerprints all files in the four `PUB-p*` and `PRIV-p*` directories.
pub(super) fn threshold_storage_state(material_path: &Path) -> FileState {
    let prefixes = PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[..PARTY_COUNT]
        .iter()
        .chain(&PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[..PARTY_COUNT]);
    let mut state = FileState::new();

    for prefix in prefixes {
        let prefix = prefix.as_deref().expect("threshold storage prefix is set");
        let storage_root = material_path.join(prefix);
        for entry in WalkDir::new(&storage_root) {
            let entry = entry.unwrap();
            if !entry.file_type().is_file() {
                continue;
            }
            let bytes = std::fs::read(entry.path()).unwrap();
            let relative_path = entry
                .path()
                .strip_prefix(material_path)
                .unwrap()
                .to_path_buf();
            state.insert(relative_path, digest_entry(&bytes));
        }
    }

    state
}

/// Stores small values at the public-key and target-epoch `FheKeyInfo` paths under one key ID.
pub(super) async fn seed_fhe_storage_layout(material_path: &Path, target_epoch: EpochId) {
    let key_id = crate::engine::base::derive_request_id("storage_smoke_fhe_key").unwrap();
    let public_type = PubDataType::PublicKey.to_string();
    let private_type = PrivDataType::FheKeyInfo.to_string();

    for prefix in &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[..PARTY_COUNT] {
        let mut storage =
            FileStorage::new(Some(material_path), StorageType::PUB, prefix.as_deref()).unwrap();
        store_versioned_at_request_id(&mut storage, &key_id, &TestType { i: 1 }, &public_type)
            .await
            .unwrap();
    }
    for prefix in &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[..PARTY_COUNT] {
        let mut storage =
            FileStorage::new(Some(material_path), StorageType::PRIV, prefix.as_deref()).unwrap();
        store_versioned_at_request_and_epoch_id(
            &mut storage,
            &key_id,
            &target_epoch,
            &TestType { i: 2 },
            &private_type,
        )
        .await
        .unwrap();
    }
}

/// Creates a PRSS-only epoch on all four parties and waits for each result.
pub(super) async fn create_prss_epoch(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    context_id: ContextId,
    epoch_id: EpochId,
) {
    let request = internal_client
        .new_epoch_request(&context_id, &epoch_id, None, None)
        .unwrap();
    let mut create_tasks = JoinSet::new();
    for (party_id, client) in clients {
        let party_id = *party_id;
        let mut client = client.clone();
        let request = request.clone();
        create_tasks.spawn(async move { (party_id, client.new_mpc_epoch(request).await) });
    }
    for (party_id, result) in create_tasks.join_all().await {
        result
            .unwrap_or_else(|error| panic!("party {party_id} failed to create the epoch: {error}"));
    }

    let request_id = kms_grpc::RequestId::from(epoch_id);
    let mut result_tasks = JoinSet::new();
    for (party_id, client) in clients {
        let party_id = *party_id;
        let client = client.clone();
        result_tasks.spawn(async move {
            let result: Result<Response<EpochResultResponse>, Status> = retrying_poll(
                client,
                request_id.into(),
                "epoch creation",
                PollConfig::default(),
                |client, request| Box::pin(async move { client.get_epoch_result(request).await }),
            )
            .await;
            (party_id, result)
        });
    }
    for (party_id, result) in result_tasks.join_all().await {
        result.unwrap_or_else(|error| panic!("party {party_id} did not create the epoch: {error}"));
    }
}

async fn destroy_epoch(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    epoch_id: EpochId,
) -> Vec<(u32, Result<Response<kms_grpc::kms::v1::Empty>, Status>)> {
    let mut tasks = JoinSet::new();
    for (party_id, client) in clients {
        let party_id = *party_id;
        let mut client = client.clone();
        tasks.spawn(async move {
            let result = client
                .destroy_mpc_epoch(DestroyMpcEpochRequest {
                    epoch_id: Some(epoch_id.into()),
                })
                .await;
            (party_id, result)
        });
    }
    tasks.join_all().await
}

/// Requires all four parties to delete `epoch_id`.
///
/// Panics on failure.
pub(super) async fn assert_destroy_success(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    epoch_id: EpochId,
) {
    for (party_id, result) in destroy_epoch(clients, epoch_id).await {
        result.unwrap_or_else(|error| {
            panic!("party {party_id} failed to destroy the epoch: {error}")
        });
    }
}

/// Requires all four parties to reject deletion with `expected_code`.
///
/// Panics on failure.
pub(super) async fn assert_destroy_error(
    clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    epoch_id: EpochId,
    expected_code: Code,
) {
    for (party_id, result) in destroy_epoch(clients, epoch_id).await {
        let error = match result {
            Ok(_) => panic!("party {party_id} unexpectedly destroyed the epoch"),
            Err(error) => error,
        };
        assert_eq!(error.code(), expected_code, "party {party_id}: {error}");
    }
}

/// Requires deletion to remove only the target epoch's private files from all four parties.
///
/// Panics on failure.
pub(super) fn assert_epoch_delete_delta(before: &FileState, after: &FileState, epoch_id: EpochId) {
    let removed: Vec<_> = before
        .keys()
        .filter(|path| !after.contains_key(*path))
        .collect();
    assert!(!removed.is_empty(), "the epoch deletion removed no files");

    let epoch_component = epoch_id.to_string();
    assert!(
        removed.iter().all(|path| {
            path.components()
                .any(|component| component.as_os_str() == epoch_component.as_str())
        }),
        "the epoch deletion removed unrelated files: {removed:#?}"
    );
    assert!(
        removed.iter().all(|path| {
            PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[..PARTY_COUNT]
                .iter()
                .filter_map(|prefix| prefix.as_deref())
                .any(|prefix| path.starts_with(prefix))
        }),
        "the epoch deletion removed public files: {removed:#?}"
    );
    for prefix in &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[..PARTY_COUNT] {
        let prefix = prefix.as_deref().expect("threshold storage prefix is set");
        assert!(
            removed.iter().any(|path| path.starts_with(prefix)),
            "party storage {prefix} kept every file for the deleted epoch"
        );
    }
    assert!(
        after.keys().all(|path| before.contains_key(path)),
        "the epoch deletion added files"
    );
    assert!(
        after.keys().all(|path| {
            !path
                .components()
                .any(|component| component.as_os_str() == epoch_component.as_str())
        }),
        "the epoch deletion left files for {epoch_id}"
    );
    for (path, fingerprint) in after {
        assert_eq!(
            before.get(path),
            Some(fingerprint),
            "the epoch deletion changed {}",
            path.display()
        );
    }
}

/// Requires restart to preserve every path and every file except the rewritten default context.
///
/// Panics on failure.
pub(super) fn assert_restart_state(before: &FileState, after: &FileState) {
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "restarting the parties added or removed files"
    );

    let context_directory = PrivDataType::ContextInfo.to_string();
    let default_context = DEFAULT_MPC_CONTEXT.to_string();
    for (path, fingerprint) in after {
        // The test servers receive new random ports at restart. Startup rewrites the default
        // context with those endpoints, but no other stored material should change.
        let components: Vec<_> = path.components().map(|part| part.as_os_str()).collect();
        if components.len() == 3
            && components[1] == context_directory.as_str()
            && components[2] == default_context.as_str()
        {
            continue;
        }
        assert_eq!(
            before.get(path),
            Some(fingerprint),
            "restarting the parties changed {}",
            path.display()
        );
    }
}
