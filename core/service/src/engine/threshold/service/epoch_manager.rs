use std::{marker::PhantomData, sync::Arc};

use kms_grpc::{
    identifiers::EpochId,
    kms::v1::{DestroyMpcEpochRequest, Empty, EpochResultResponse, NewMpcEpochRequest, RequestId},
    rpc_types::PrivDataType,
};
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::small_execution::prss::{PRSSInit, PRSSSetup},
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

use crate::{
    engine::{
        base::KeyGenMetadata, threshold::service::session::SessionMaker, traits::EpochManager,
    },
    util::{meta_store::MetaStore, rate_limiter::RateLimiter},
    vault::storage::{
        crypto_material::ThresholdCryptoMaterialStorage, delete_at_request_and_epoch_id,
        delete_at_request_id, Storage, StorageExt,
    },
};

// The Epoch Manager takes over the role of the Initiator and Resharer
// For now the struct is thus a union of the RealInitiator and RealResharer structs
pub struct RealThresholdEpochManager<
    PrivS: StorageExt + Send + Sync + 'static,
    PubS: Storage + Send + Sync + 'static,
    Init: PRSSInit<ResiduePolyF4Z64> + PRSSInit<ResiduePolyF4Z128>,
> {
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub(crate) session_maker: SessionMaker,
    pub health_reporter: HealthReporter,
    pub base_kms: crate::engine::base::BaseKmsStruct,
    pub reshare_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub(crate) _init: PhantomData<Init>,
}

/// Destroys an epoch by deleting all shares stored under it and removing
/// the epoch from the session maker.
///
/// The `priv_data_type` parameter specifies the type of private data to delete
/// (e.g., `FheKeyInfo` for threshold KMS).
pub(crate) async fn destroy_epoch<PrivS: StorageExt + Send + Sync + 'static>(
    epoch_id: &EpochId,
    priv_data_type: PrivDataType,
    priv_storage: &tokio::sync::Mutex<PrivS>,
    session_maker: &SessionMaker,
) -> Result<Response<Empty>, Status> {
    tracing::info!("Destroying MPC epoch: {}", epoch_id);

    // Check if the epoch exists in session_maker
    if !session_maker.epoch_exists(epoch_id).await {
        return Err(Status::not_found(format!(
            "Epoch {} not found in session maker",
            epoch_id
        )));
    }

    // Delete shares and PRSS data from storage within a scoped block
    {
        let mut priv_storage_guard = priv_storage.lock().await;

        // Delete all data of the specified type stored under this epoch
        let data_type_str = priv_data_type.to_string();
        let data_ids = priv_storage_guard
            .all_data_ids_at_epoch(epoch_id, &data_type_str)
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "Failed to get data IDs for epoch {}: {}",
                    epoch_id, e
                ))
            })?;

        for data_id in data_ids {
            tracing::debug!(
                "Deleting {} for key_id {} at epoch {}",
                priv_data_type,
                data_id,
                epoch_id
            );
            delete_at_request_and_epoch_id(
                &mut (*priv_storage_guard),
                &data_id,
                epoch_id,
                &data_type_str,
            )
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "Failed to delete {} for key_id {} at epoch {}: {}",
                    priv_data_type, data_id, epoch_id, e
                ))
            })?;
        }

        // Delete the PRSS setup data for this epoch
        // PRSS setup is stored at the epoch_id converted to RequestId
        let epoch_as_request_id: kms_grpc::RequestId = (*epoch_id).into();
        delete_at_request_id(
            &mut (*priv_storage_guard),
            &epoch_as_request_id,
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await
        .map_err(|e| {
            Status::internal(format!(
                "Failed to delete PRSS setup for epoch {}: {}",
                epoch_id, e
            ))
        })?;
    }

    // Remove the epoch from session_maker
    session_maker.remove_epoch(epoch_id).await;

    tracing::info!("Successfully destroyed MPC epoch: {}", epoch_id);
    Ok(Response::new(Empty {}))
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > EpochManager for RealThresholdEpochManager<PrivS, PubS, Init>
{
    async fn new_mpc_epoch(
        &self,
        _request: Request<NewMpcEpochRequest>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn destroy_mpc_epoch(
        &self,
        request: Request<DestroyMpcEpochRequest>,
    ) -> Result<Response<Empty>, Status> {
        let epoch_id: EpochId = request
            .into_inner()
            .epoch_id
            .ok_or_else(|| Status::invalid_argument("Missing epoch_id"))?
            .try_into()
            .map_err(|e| Status::invalid_argument(format!("Invalid epoch_id: {e}")))?;

        destroy_epoch(
            &epoch_id,
            PrivDataType::FheKeyInfo,
            &self.crypto_storage.get_private_storage(),
            &self.session_maker,
        )
        .await
    }

    async fn get_epoch_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<EpochResultResponse>, Status> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::threshold::service::session::PRSSSetupCombined;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::store_versioned_at_request_id;
    use crate::vault::storage::tests::TestType;
    use crate::vault::storage::{StorageReader, StorageReaderExt};
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_destroy_epoch_success() {
        use threshold_fhe::execution::small_execution::prss::PRSSSetup;

        let mut rng = AesRng::seed_from_u64(42);
        let epoch_id = EpochId::new_random(&mut rng);

        // Create dummy PRSS setups so the epoch gets added to the session maker
        let prss_z128 = PRSSSetup::new_testing_prss(vec![], vec![]);
        let prss_z64 = PRSSSetup::new_testing_prss(vec![], vec![]);

        // Create a session maker with the epoch
        let session_maker = SessionMaker::four_party_dummy_session(
            Some(prss_z128),
            Some(prss_z64),
            &epoch_id,
            AesRng::seed_from_u64(1),
        );

        // Create storage and add test data
        let priv_storage = tokio::sync::Mutex::new(RamStorage::new());

        // Store some FheKeyInfo data under this epoch
        let key_id_1 = kms_grpc::RequestId::new_random(&mut rng);
        let key_id_2 = kms_grpc::RequestId::new_random(&mut rng);
        let data1 = TestType { i: 100 };
        let data2 = TestType { i: 200 };

        {
            let mut storage_guard = priv_storage.lock().await;
            storage_guard
                .store_data_at_epoch(
                    &data1,
                    &key_id_1,
                    &epoch_id,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await
                .unwrap();
            storage_guard
                .store_data_at_epoch(
                    &data2,
                    &key_id_2,
                    &epoch_id,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await
                .unwrap();

            // Store PRSS setup data at the epoch_id
            let prss = PRSSSetupCombined {
                prss_setup_z128:
                    threshold_fhe::execution::small_execution::prss::PRSSSetup::new_testing_prss(
                        vec![],
                        vec![],
                    ),
                prss_setup_z64:
                    threshold_fhe::execution::small_execution::prss::PRSSSetup::new_testing_prss(
                        vec![],
                        vec![],
                    ),
                num_parties: 4,
                threshold: 1,
            };
            let epoch_as_request_id: kms_grpc::RequestId = epoch_id.into();
            store_versioned_at_request_id(
                &mut (*storage_guard),
                &epoch_as_request_id,
                &prss,
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap();
        }

        // Verify data exists before destroy
        {
            let storage_guard = priv_storage.lock().await;
            assert!(storage_guard
                .data_exists_at_epoch(&key_id_1, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
                .await
                .unwrap());
            assert!(storage_guard
                .data_exists_at_epoch(&key_id_2, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
                .await
                .unwrap());
            let epoch_as_request_id: kms_grpc::RequestId = epoch_id.into();
            assert!(storage_guard
                .data_exists(
                    &epoch_as_request_id,
                    &PrivDataType::PrssSetupCombined.to_string()
                )
                .await
                .unwrap());
        }
        assert!(session_maker.epoch_exists(&epoch_id).await);

        // Call destroy_epoch
        let result = destroy_epoch(
            &epoch_id,
            PrivDataType::FheKeyInfo,
            &priv_storage,
            &session_maker,
        )
        .await;
        assert!(result.is_ok());

        // Verify data is deleted
        {
            let storage_guard = priv_storage.lock().await;
            assert!(!storage_guard
                .data_exists_at_epoch(&key_id_1, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
                .await
                .unwrap());
            assert!(!storage_guard
                .data_exists_at_epoch(&key_id_2, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
                .await
                .unwrap());
            let epoch_as_request_id: kms_grpc::RequestId = epoch_id.into();
            assert!(!storage_guard
                .data_exists(
                    &epoch_as_request_id,
                    &PrivDataType::PrssSetupCombined.to_string()
                )
                .await
                .unwrap());
        }

        // Verify epoch is removed from session_maker
        assert!(!session_maker.epoch_exists(&epoch_id).await);
    }

    #[tokio::test]
    async fn test_destroy_epoch_not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_id = EpochId::new_random(&mut rng);
        let other_epoch_id = EpochId::new_random(&mut rng);

        // Create a session maker with a different epoch
        let session_maker = SessionMaker::four_party_dummy_session(
            None,
            None,
            &other_epoch_id,
            AesRng::seed_from_u64(1),
        );

        let priv_storage = tokio::sync::Mutex::new(RamStorage::new());

        // Try to destroy an epoch that doesn't exist
        let result = destroy_epoch(
            &epoch_id,
            PrivDataType::FheKeyInfo,
            &priv_storage,
            &session_maker,
        )
        .await;

        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
    }
}
