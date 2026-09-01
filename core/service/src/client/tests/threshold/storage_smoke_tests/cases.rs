//! Four-party file-storage checks for epoch deletion and restart.

use super::support::{
    PARTY_COUNT, assert_destroy_error, assert_destroy_success, assert_epoch_delete_delta,
    assert_restart_state, create_prss_epoch, seed_fhe_storage_layout, threshold_storage_state,
};
use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, TEST_PARAM};
use crate::engine::base::derive_request_id;
use crate::testing::prelude::{TestMaterialSpec, ThresholdTestEnv};
use kms_grpc::identifiers::EpochId;
use tonic::Code;

/// Destroying the only epoch changes no files. Destroying a second epoch removes only its private
/// files, and the remaining state loads after all four parties restart.
#[tokio::test(flavor = "multi_thread")]
async fn epoch_destruction_changes_only_the_target_epoch_on_disk() {
    let env = ThresholdTestEnv::builder()
        .with_test_name("epoch_destruction_changes_only_the_target_epoch_on_disk")
        .with_party_count(PARTY_COUNT)
        .with_threshold(1)
        .with_material_spec(TestMaterialSpec::threshold_signing_only(PARTY_COUNT))
        .with_prss()
        .build()
        .await
        .unwrap();
    let internal_client = env.create_internal_client(&TEST_PARAM, None).await.unwrap();
    let material_path = env.material_dir.path().to_path_buf();

    let before_rejected_delete = threshold_storage_state(&material_path);
    assert_destroy_error(&env.clients, *DEFAULT_EPOCH_ID, Code::FailedPrecondition).await;
    assert_eq!(
        threshold_storage_state(&material_path),
        before_rejected_delete,
        "destroying the only epoch changed files"
    );

    let second_epoch: EpochId = derive_request_id("storage_smoke_second_epoch")
        .unwrap()
        .into();
    create_prss_epoch(
        &env.clients,
        &internal_client,
        *DEFAULT_MPC_CONTEXT,
        second_epoch,
    )
    .await;
    seed_fhe_storage_layout(&material_path, second_epoch).await;

    let before_successful_delete = threshold_storage_state(&material_path);
    assert_destroy_success(&env.clients, second_epoch).await;
    let after_successful_delete = threshold_storage_state(&material_path);
    assert_epoch_delete_delta(
        &before_successful_delete,
        &after_successful_delete,
        second_epoch,
    );

    let material_dir = env.material_dir;
    for (_, server) in env.servers {
        server.assert_shutdown().await;
    }
    drop(env.clients);

    let (restarted_servers, restarted_clients) = ThresholdTestEnv::builder()
        .with_party_count(PARTY_COUNT)
        .with_threshold(1)
        .with_prss()
        .from_path(&material_path)
        .await
        .unwrap();
    let after_restart = threshold_storage_state(&material_path);
    assert_restart_state(&after_successful_delete, &after_restart);
    assert_destroy_error(&restarted_clients, second_epoch, Code::NotFound).await;
    // This response proves startup loaded the remaining epoch from disk. Without it, deletion
    // would return `NotFound` instead of rejecting removal of the last epoch.
    assert_destroy_error(
        &restarted_clients,
        *DEFAULT_EPOCH_ID,
        Code::FailedPrecondition,
    )
    .await;

    for (_, server) in restarted_servers {
        server.assert_shutdown().await;
    }
    drop(material_dir);
}
