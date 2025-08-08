// === Standard Library ===
use std::{marker::PhantomData, sync::Arc};

// === External Crates ===
use kms_grpc::{
    kms::v1::{self, Empty},
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::PrivDataType,
    RequestId,
};
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::session::ParameterHandles,
        small_execution::prss::{PRSSInit, PRSSSetup},
    },
    networking::NetworkMode,
};
use tokio::sync::{Mutex, RwLock};
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    engine::{
        base::derive_request_id, threshold::traits::Initiator, validation::validate_request_id,
    },
    tonic_some_or_err,
    vault::storage::{read_versioned_at_request_id, store_versioned_at_request_id, Storage},
};

// === Current Module Imports ===
use super::{session::SessionPreparer, RealThresholdKms};

pub struct RealInitiator<
    PrivS: Storage + Send + Sync + 'static,
    Init: PRSSInit<ResiduePolyF4Z64> + PRSSInit<ResiduePolyF4Z128>,
> {
    // TODO eventually add mode to allow for nlarge as well.
    pub prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    pub prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
    pub private_storage: Arc<Mutex<PrivS>>,
    pub session_preparer: SessionPreparer,
    pub health_reporter: HealthReporter,
    pub(crate) _init: PhantomData<Init>,
}

impl<
        PrivS: Storage + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > RealInitiator<PrivS, Init>
{
    pub async fn init_prss_from_disk(&self, req_id: &RequestId) -> anyhow::Result<()> {
        let prss_setup_z128_from_file = {
            let guarded_private_storage = self.private_storage.lock().await;
            let parameters = self
                .session_preparer
                .get_session_parameters(req_id.derive_session_id()?)?;
            read_versioned_at_request_id(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z128_ID_{}_{}_{}",
                    req_id,
                    parameters.num_parties(),
                    parameters.threshold()
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z128 from file with error: {e}");
            })
        };

        // check if a PRSS setup already exists in storage.
        match prss_setup_z128_from_file {
            Ok(prss_setup) => {
                let mut guarded_prss_setup = self.prss_setup_z128.write().await;
                *guarded_prss_setup = Some(prss_setup);
                tracing::info!("Initializing threshold KMS server with PRSS Setup Z128 from disk",)
            }
            Err(e) => return Err(e),
        }

        let prss_setup_z64_from_file = {
            let guarded_private_storage = self.private_storage.lock().await;
            let parameters = self
                .session_preparer
                .get_session_parameters(req_id.derive_session_id()?)?;
            read_versioned_at_request_id(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z64_ID_{}_{}_{}",
                    req_id,
                    parameters.num_parties(),
                    parameters.threshold()
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z64 from file with error: {e}");
            })
        };

        // check if a PRSS setup already exists in storage.
        match prss_setup_z64_from_file {
            Ok(prss_setup) => {
                let mut guarded_prss_setup = self.prss_setup_z64.write().await;
                *guarded_prss_setup = Some(prss_setup);
                tracing::info!("Initializing threshold KMS server with PRSS Setup Z64 from disk",)
            }
            Err(e) => return Err(e),
        }

        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS>>>()
                .await;
        }
        Ok(())
    }

    pub async fn init_prss(&self, req_id: &RequestId) -> anyhow::Result<()> {
        if self.prss_setup_z128.read().await.is_some() || self.prss_setup_z64.read().await.is_some()
        {
            return Err(anyhow_error_and_log("PRSS state already exists"));
        }

        let own_identity = self.session_preparer.own_identity()?;
        let session_id = req_id.derive_session_id()?;
        //PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = self
            .session_preparer
            .make_base_session(session_id, NetworkMode::Sync)
            .await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        tracing::info!(
            "Session has {} parties with threshold {}",
            base_session.parameters.num_parties(),
            base_session.parameters.threshold()
        );
        tracing::info!(
            "Role assignments: {:?}",
            base_session.parameters.role_assignments()
        );

        // It seems we cannot do something like
        // `Init::default().init(&mut base_session).await?;`
        // as the type inference gets confused even when using the correct return type.
        let prss_setup_obj_z128: PRSSSetup<ResiduePolyF4Z128> =
            <Init as PRSSInit<ResiduePolyF4Z128>>::init(&Init::default(), &mut base_session)
                .await?;
        let prss_setup_obj_z64: PRSSSetup<ResiduePolyF4Z64> =
            <Init as PRSSInit<ResiduePolyF4Z64>>::init(&Init::default(), &mut base_session).await?;

        let mut guarded_prss_setup = self.prss_setup_z128.write().await;
        *guarded_prss_setup = Some(prss_setup_obj_z128.clone());

        let mut guarded_prss_setup = self.prss_setup_z64.write().await;
        *guarded_prss_setup = Some(prss_setup_obj_z64.clone());

        // serialize and write PRSS Setup to disk into private storage
        let private_storage = Arc::clone(&self.private_storage);
        let mut priv_storage = private_storage.lock().await;
        store_versioned_at_request_id(
            &mut (*priv_storage),
            &derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{}_{}",
                req_id,
                base_session.parameters.num_parties(),
                base_session.parameters.threshold(),
            ))?,
            &prss_setup_obj_z128,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await?;

        store_versioned_at_request_id(
            &mut (*priv_storage),
            &derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{}_{}",
                req_id,
                base_session.parameters.num_parties(),
                base_session.parameters.threshold(),
            ))?,
            &prss_setup_obj_z64,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await?;
        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS>>>()
                .await;
        }
        tracing::info!("PRSS completed successfully for identity {}.", own_identity);
        Ok(())
    }
}

#[tonic::async_trait]
impl<
        PrivS: Storage + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > Initiator for RealInitiator<PrivS, Init>
{
    async fn init(&self, request: Request<v1::InitRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (initiator)".to_string(),
        )?
        .into();
        validate_request_id(&request_id)?;

        self.init_prss(&request_id).await.map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("PRSS initialization failed with error {e}"),
            )
        })?;
        Ok(Response::new(Empty {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        client::test_tools::{self},
        consts::PRSS_INIT_REQ_ID,
        util::key_setup::test_tools::purge,
        vault::storage::{file::FileStorage, ram, StorageType},
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::InitRequest;
    use rand::SeedableRng;
    use threshold_fhe::{
        execution::runtime::party::Role,
        malicious_execution::small_execution::malicious_prss::{
            FailingPrss, MaliciousPrssDropPRSSSetup,
        },
    };

    impl<
            Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
                + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>,
        > RealInitiator<ram::RamStorage, Init>
    {
        fn init_test(session_preparer: SessionPreparer) -> Self {
            Self {
                prss_setup_z128: Arc::new(RwLock::new(None)),
                prss_setup_z64: Arc::new(RwLock::new(None)),
                private_storage: Arc::new(Mutex::new(ram::RamStorage::new())),
                session_preparer,
                health_reporter: HealthReporter::new(),
                _init: PhantomData,
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    #[tracing_test::traced_test]
    async fn prss_disk_test() {
        // We're starting two sets of servers in this test, both sets of servers will load all the keys
        // but it seems that the when shutting down the first set of servers, the keys are not immediately removed from memory
        // and this leads to OOM. So we reduce the amount of parties to 4 for this test.
        const PRSS_AMOUNT_PARTIES: usize = 4;
        const PRSS_THRESHOLD: usize = 1;

        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        let mut vaults = Vec::new();
        let mut vaults2 = Vec::new();
        // TODO use clone instead
        for i in 1..=PRSS_AMOUNT_PARTIES {
            let cur_pub =
                FileStorage::new(None, StorageType::PUB, Some(Role::indexed_from_one(i))).unwrap();
            pub_storage.push(cur_pub);
            let cur_priv =
                FileStorage::new(None, StorageType::PRIV, Some(Role::indexed_from_one(i))).unwrap();

            // make sure the store does not contain any PRSS info (currently stored under ID 1)
            let req_id = derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{PRSS_INIT_REQ_ID}_{PRSS_AMOUNT_PARTIES}_{PRSS_THRESHOLD}"
            ))
            .unwrap();
            purge(None, None, None, &req_id, PRSS_AMOUNT_PARTIES).await;

            let req_id = derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{PRSS_INIT_REQ_ID}_{PRSS_AMOUNT_PARTIES}_{PRSS_THRESHOLD}"
            ))
            .unwrap();
            purge(None, None, None, &req_id, PRSS_AMOUNT_PARTIES).await;

            priv_storage.push(cur_priv);
            vaults.push(None);
            vaults2.push(None);
        }

        // create parties and run PrssSetup
        let server_handles = test_tools::setup_threshold_no_client(
            PRSS_THRESHOLD as u8,
            pub_storage.clone(),
            priv_storage.clone(),
            vaults,
            true,
            None,
            None,
        )
        .await;
        assert_eq!(server_handles.len(), PRSS_AMOUNT_PARTIES);

        // shut parties down
        for server_handle in server_handles.into_values() {
            server_handle.assert_shutdown().await;
        }

        // check that PRSS setups were created (and not read from disk)
        assert!(!logs_contain(
            "Initializing threshold KMS server with PRSS Setup Z128 from disk"
        ));
        assert!(!logs_contain(
            "Initializing threshold KMS server with PRSS Setup Z64 from disk"
        ));
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // create parties again without running PrssSetup this time (it should now be read from disk)
        let server_handles = test_tools::setup_threshold_no_client(
            PRSS_THRESHOLD as u8,
            pub_storage,
            priv_storage,
            vaults2,
            false,
            None,
            None,
        )
        .await;
        assert_eq!(server_handles.len(), PRSS_AMOUNT_PARTIES);

        // check that PRSS setups were not created, but instead read from disk now
        assert!(logs_contain(
            "Initializing threshold KMS server with PRSS Setup Z128 from disk"
        ));
        assert!(logs_contain(
            "Initializing threshold KMS server with PRSS Setup Z64 from disk"
        ));
    }

    #[tokio::test]
    async fn sunshine() {
        let session_preparer = SessionPreparer::new_test_session(false);
        let initiator = RealInitiator::<ram::RamStorage, MaliciousPrssDropPRSSSetup>::init_test(
            session_preparer,
        );

        let mut rng = AesRng::seed_from_u64(42);
        let req_id = RequestId::new_random(&mut rng);
        initiator
            .init(tonic::Request::new(InitRequest {
                request_id: Some(req_id.into()),
            }))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn invalid_argument() {
        let session_preparer = SessionPreparer::new_test_session(false);
        let initiator = RealInitiator::<ram::RamStorage, MaliciousPrssDropPRSSSetup>::init_test(
            session_preparer,
        );

        let bad_req_id = kms_grpc::kms::v1::RequestId {
            request_id: "bad req id".to_string(),
        };
        assert_eq!(
            initiator
                .init(tonic::Request::new(InitRequest {
                    request_id: Some(bad_req_id)
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn aborted() {
        let session_preparer = SessionPreparer::new_test_session(false);
        let initiator = RealInitiator::<ram::RamStorage, MaliciousPrssDropPRSSSetup>::init_test(
            session_preparer,
        );

        assert_eq!(
            initiator
                .init(tonic::Request::new(InitRequest {
                    // this is set to none
                    request_id: None
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );
    }

    #[tokio::test]
    async fn internal() {
        let session_preparer = SessionPreparer::new_test_session(false);
        let initiator = RealInitiator::<ram::RamStorage, FailingPrss>::init_test(session_preparer);

        let mut rng = AesRng::seed_from_u64(42);
        let req_id = RequestId::new_random(&mut rng);
        assert_eq!(
            initiator
                .init(tonic::Request::new(InitRequest {
                    request_id: Some(req_id.into())
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
    }
}
