// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

// === External Crates ===
use kms_grpc::{
    identifiers::EpochId,
    kms::v1::{self, Empty},
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::PrivDataType,
    ContextId, RequestId,
};
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::prss::{PRSSInit, PRSSSetup},
    },
    networking::NetworkMode,
};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

// === Internal Crate ===
use crate::{
    consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT},
    engine::{
        base::derive_request_id,
        threshold::{
            service::session::{PRSSSetupCombined, SessionMaker},
            traits::Initiator,
        },
        validation::{
            parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
        },
    },
    vault::storage::{
        delete_at_request_id, read_all_data_versioned, read_versioned_at_request_id,
        store_versioned_at_request_id, StorageExt,
    },
};

// === Current Module Imports ===
use super::RealThresholdKms;

pub struct RealInitiator<
    PrivS: StorageExt + Send + Sync + 'static,
    Init: PRSSInit<ResiduePolyF4Z64> + PRSSInit<ResiduePolyF4Z128>,
> {
    // TODO eventually add mode to allow for nlarge as well.
    pub private_storage: Arc<Mutex<PrivS>>,
    pub(crate) session_maker: SessionMaker,
    pub health_reporter: HealthReporter,
    pub(crate) _init: PhantomData<Init>,
    pub base_kms: crate::engine::base::BaseKmsStruct,
}

impl<
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > RealInitiator<PrivS, Init>
{
    /// This will load all PRSS setups from storage into session maker.
    ///
    /// It should be called after [init_legacy_prss_from_storage] so that
    /// if there is a new PRSS under the same epoch ID as a legacy one,
    /// then the legacy one is overwritten.
    pub async fn init_all_prss_from_storage(&self) -> anyhow::Result<()> {
        let guarded_private_storage = self.private_storage.lock().await;
        let all_prss: HashMap<RequestId, PRSSSetupCombined> = read_all_data_versioned(
            &(*guarded_private_storage),
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;
        for (epoch_id, prss) in all_prss {
            self.session_maker.add_epoch(epoch_id.into(), prss).await;
            tracing::info!(
                "Loaded PRSS Setup from storage for request ID {}.",
                epoch_id
            );
        }
        Ok(())
    }

    /// This assumes the default context exists.
    /// It will overwrite the PRSS in session maker if it already exists,
    /// so make sure this is called before the normal (non-legacy) initialization.
    #[expect(deprecated)]
    pub async fn init_legacy_prss_from_storage(&self) -> anyhow::Result<()> {
        // TODO(zama-ai/kms-internal#2530) set the correct context ID here.
        let epoch_id = *DEFAULT_EPOCH_ID;
        let context_id = *DEFAULT_MPC_CONTEXT;
        let threshold = self.session_maker.threshold(&context_id).await?;
        let num_parties = self.session_maker.num_parties(&context_id).await?;

        let prss_from_storage = {
            let guarded_private_storage = self.private_storage.lock().await;
            let prss_128 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z128>>(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z128_ID_{}_{}_{}",
                    epoch_id, num_parties, threshold,
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z128 from file with error: {e}");
            });
            let prss_64 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z64>>(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z64_ID_{}_{}_{}",
                    epoch_id, num_parties, threshold,
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z64 from file with error: {e}");
            });

            (prss_128, prss_64)
        };

        match prss_from_storage {
            (Ok(prss_128), Ok(prss_64)) => {
                self.session_maker
                    .add_epoch(
                        epoch_id,
                        PRSSSetupCombined {
                            prss_setup_z128: prss_128,
                            prss_setup_z64: prss_64,
                            num_parties: num_parties as u8,
                            threshold,
                        },
                    )
                    .await;
            }
            (Err(e), Ok(_)) => return Err(e),
            (Ok(_), Err(e)) => return Err(e),
            (Err(_e), Err(e)) => return Err(e),
        }

        tracing::info!(
            "Loaded PRSS Setup from storage for request ID {}.",
            epoch_id
        );
        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS>>>()
                .await;
        }
        Ok(())
    }

    // NOTE: this function will overwrite the existing PRSS state
    pub async fn init_prss(
        &self,
        context_id: &ContextId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()> {
        // TODO(zama-ai/kms-internal/issues/2721),
        // we never try to store the PRSS in meta_store, so the ID is not guaranteed to be unique

        let own_identity = self
            .session_maker
            .my_identity(context_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("own identity not found in context {}", context_id))?;

        let session_id = epoch_id.derive_session_id()?;

        // PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = self
            .session_maker
            .make_base_session(session_id, *context_id, NetworkMode::Sync)
            .await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        tracing::info!(
            "Session has {} parties with threshold {}",
            base_session.parameters.num_parties(),
            base_session.parameters.threshold()
        );
        tracing::info!("Role assignments: {:?}", base_session.parameters.roles());

        // It seems we cannot do something like
        // `Init::default().init(&mut base_session).await?;`
        // as the type inference gets confused even when using the correct return type.
        let prss_setup_obj_z128: PRSSSetup<ResiduePolyF4Z128> =
            PRSSInit::<ResiduePolyF4Z128>::init(&Init::default(), &mut base_session).await?;
        let prss_setup_obj_z64: PRSSSetup<ResiduePolyF4Z64> =
            PRSSInit::<ResiduePolyF4Z64>::init(&Init::default(), &mut base_session).await?;

        let prss = PRSSSetupCombined {
            prss_setup_z128: prss_setup_obj_z128,
            prss_setup_z64: prss_setup_obj_z64,
            num_parties: base_session.parameters.num_parties() as u8,
            threshold: base_session.parameters.threshold(),
        };

        // serialize and write PRSS Setup to storage into private storage
        let private_storage = Arc::clone(&self.private_storage);
        let mut priv_storage = private_storage.lock().await;

        // if PRSS already exists, overwrite it
        if priv_storage
            .data_exists(
                &(*epoch_id).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?
        {
            tracing::warn!(
                "PRSS Setup epoch ID {} already exists, overwriting.",
                epoch_id
            );
            delete_at_request_id(
                &mut (*priv_storage),
                &(*epoch_id).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?;
        }

        store_versioned_at_request_id(
            &mut (*priv_storage),
            &(*epoch_id).into(),
            &prss,
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;

        self.session_maker.add_epoch(*epoch_id, prss).await;

        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS>>>()
                .await;
        }
        tracing::info!(
            "PRSS on epoch ID {} completed successfully for identity {}.",
            epoch_id,
            own_identity
        );
        Ok(())
    }
}

#[tonic::async_trait]
impl<
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > Initiator for RealInitiator<PrivS, Init>
{
    async fn init(&self, request: Request<v1::InitRequest>) -> Result<Response<Empty>, Status> {
        // TODO set the correct context ID here as it should be contained in the InitRequest.
        // since the connector is not giving us a context yet, we read it from file
        // eventually this piece of code will move to the context endpoint and this
        // endpoint will be removed.

        // TODO(zama-ai/kms-internal#2530)
        // the only way to set the role assignment is through the configuration
        // so we do not attempt to modify `session_preparer_manager` or `networking_manager`
        // until we have a context endpoint that can modify these two fields.
        // In addition, we need to persist context on storage otherwise they'll be lost on restart
        // See zama-ai/kms-internal/#2741

        let inner = request.into_inner();
        // the request ID of the init request is the epoch ID for PRSS and shares
        let epoch_id: EpochId =
            parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::Init)?.into();

        let context_id: ContextId = match inner.context_id {
            Some(ctx_id) => parse_proto_request_id(&ctx_id, RequestIdParsingErr::Init)?.into(),
            None => *DEFAULT_MPC_CONTEXT,
        };

        if self.session_maker.epoch_exists(&epoch_id).await {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                "PRSS state already exists".to_string(),
            ));
        }

        // NOTE: here we're using session_maker to check if the context exists since it's quick
        // and happens all in memory.
        // But it's also ok to use context_manager.mpc_context_exists to check,
        // but this function requires communication with the storage backend.
        if !self.session_maker.context_exists(&context_id).await {
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("MPC context ID {context_id} does not exist"),
            ));
        }

        self.init_prss(&context_id, &epoch_id).await.map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("PRSS initialization failed with error: {e}"),
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
        consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL},
        cryptography::signatures::gen_sig_keys,
        engine::base::BaseKmsStruct,
        util::key_setup::test_tools::purge,
        vault::storage::{file::FileStorage, ram, StorageType},
    };
    use aes_prng::AesRng;
    use kms_grpc::{kms::v1::InitRequest, rpc_types::KMSType};
    use rand::SeedableRng;
    use threshold_fhe::malicious_execution::small_execution::malicious_prss::{
        EmptyPrss, FailingPrss,
    };

    impl<
            Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
                + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>,
        > RealInitiator<ram::RamStorage, Init>
    {
        fn init_test(base_kms: BaseKmsStruct, session_maker: SessionMaker) -> Self {
            Self {
                private_storage: Arc::new(Mutex::new(ram::RamStorage::new())),
                session_maker,
                health_reporter: HealthReporter::new(),
                _init: PhantomData,
                base_kms,
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    #[tracing_test::traced_test]
    async fn prss_from_storage_test() {
        // We're starting two sets of servers in this test, both sets of servers will load all the keys
        // but it seems that the when shutting down the first set of servers, the keys are not immediately removed from memory
        // and this leads to OOM. So we reduce the amount of parties to 4 for this test.
        const PRSS_AMOUNT_PARTIES: usize = 4;
        const PRSS_THRESHOLD: usize = 1;

        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        let mut vaults = Vec::new();
        let mut vaults2 = Vec::new();
        let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[..PRSS_AMOUNT_PARTIES];
        let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[..PRSS_AMOUNT_PARTIES];

        for (priv_prefix, pub_prefix) in priv_storage_prefixes
            .iter()
            .zip(pub_storage_prefixes.iter())
        {
            let cur_pub = FileStorage::new(None, StorageType::PUB, pub_prefix.as_deref()).unwrap();
            pub_storage.push(cur_pub);
            let cur_priv =
                FileStorage::new(None, StorageType::PRIV, priv_prefix.as_deref()).unwrap();

            // make sure the store does not contain any PRSS info (currently stored under ID 1)
            let req_id = derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{PRSS_AMOUNT_PARTIES}_{PRSS_THRESHOLD}",
                *DEFAULT_EPOCH_ID
            ))
            .unwrap();
            purge(
                None,
                None,
                &req_id,
                pub_storage_prefixes,
                priv_storage_prefixes,
            )
            .await;

            let req_id = derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{PRSS_AMOUNT_PARTIES}_{PRSS_THRESHOLD}",
                *DEFAULT_EPOCH_ID
            ))
            .unwrap();
            purge(
                None,
                None,
                &req_id,
                pub_storage_prefixes,
                priv_storage_prefixes,
            )
            .await;

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

        // check that PRSS setups were created
        assert!(logs_contain(
            "Initializing threshold KMS server and generating a new PRSS Setup for"
        ));
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // create parties again without running PrssSetup this time (it should now be read from storage)
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

        // check that PRSS setups were not created, but instead read from storage now
        assert!(logs_contain("Loaded PRSS Setup from storage"));
    }

    // write prss to storage using the legacy method
    async fn write_legacy_empty_prss_to_storage(private_storage: &mut ram::RamStorage) {
        let epoch_id = *DEFAULT_EPOCH_ID;
        let num_parties = 4;
        let threshold = 1u8;

        let prss_setup_obj_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
        let prss_setup_obj_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);

        // serialize and write PRSS Setup to storage into private storage
        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z128,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z64,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn legacy_prss() {
        let mut rng = AesRng::seed_from_u64(42);

        // initially the storage should be empty
        let initiator = make_initiator::<EmptyPrss>(&mut rng).await;
        {
            let mut guarded_private_storage = initiator.private_storage.lock().await;
            write_legacy_empty_prss_to_storage(&mut guarded_private_storage).await;
        }

        initiator.init_legacy_prss_from_storage().await.unwrap();

        let default_epoch_id = *DEFAULT_EPOCH_ID;
        assert!(
            initiator
                .session_maker
                .epoch_exists(&default_epoch_id)
                .await
        );
    }

    #[tokio::test]
    async fn load_all_prss() {
        let mut rng = AesRng::seed_from_u64(42);

        // initially the storage should be empty
        let initiator = make_initiator::<EmptyPrss>(&mut rng).await;
        let epoch_ids: Vec<EpochId> = (0..3).map(|_| EpochId::new_random(&mut rng)).collect();
        for epoch_id in epoch_ids.iter() {
            let mut guarded_private_storage = initiator.private_storage.lock().await;
            let prss_setup_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
            let prss_setup_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);

            let prss = PRSSSetupCombined {
                prss_setup_z128,
                prss_setup_z64,
                num_parties: 4,
                threshold: 1,
            };

            store_versioned_at_request_id(
                &mut (*guarded_private_storage),
                &(*epoch_id).into(),
                &prss,
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap();
        }

        assert_eq!(0, initiator.session_maker.epoch_count().await);
        initiator.init_all_prss_from_storage().await.unwrap();
        assert_eq!(epoch_ids.len(), initiator.session_maker.epoch_count().await);

        for epoch_id in epoch_ids {
            assert!(initiator.session_maker.epoch_exists(&epoch_id).await);
        }
    }

    async fn make_initiator<
        I: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>,
    >(
        rng: &mut AesRng,
    ) -> RealInitiator<ram::RamStorage, I> {
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk).unwrap();
        let epoch_id = *DEFAULT_EPOCH_ID;
        let session_maker =
            SessionMaker::four_party_dummy_session(None, None, &epoch_id, base_kms.new_rng().await);

        RealInitiator::<ram::RamStorage, I>::init_test(base_kms, session_maker)
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let initiator = make_initiator::<EmptyPrss>(&mut rng).await;
        let epoch_id = EpochId::new_random(&mut rng);
        initiator
            .init(tonic::Request::new(InitRequest {
                request_id: Some(epoch_id.into()),
                context_id: None,
            }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(42);
        let initiator = make_initiator::<EmptyPrss>(&mut rng).await;

        {
            // bad request ID
            let bad_req_id = kms_grpc::kms::v1::RequestId {
                request_id: "bad req id".to_string(),
            };
            assert_eq!(
                initiator
                    .init(tonic::Request::new(InitRequest {
                        request_id: Some(bad_req_id),
                        context_id: None,
                    }))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // missing request ID
            assert_eq!(
                initiator
                    .init(tonic::Request::new(InitRequest {
                        request_id: None,
                        context_id: None,
                    }))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let initiator = make_initiator::<EmptyPrss>(&mut rng).await;

        let epoch_id = EpochId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng); // should not exist
        let err = initiator
            .init(tonic::Request::new(InitRequest {
                request_id: Some(epoch_id.into()),
                context_id: Some(context_id.into()),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(42);
        let initiator = make_initiator::<EmptyPrss>(&mut rng).await;

        let epoch_id = EpochId::new_random(&mut rng);
        initiator
            .init(tonic::Request::new(InitRequest {
                request_id: Some(epoch_id.into()),
                context_id: None,
            }))
            .await
            .unwrap();

        // try the same again and we should see an AlreadyExists error
        assert_eq!(
            initiator
                .init(tonic::Request::new(InitRequest {
                    request_id: Some(epoch_id.into()),
                    context_id: None,
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn internal() {
        let mut rng = AesRng::seed_from_u64(42);
        let initiator = make_initiator::<FailingPrss>(&mut rng).await;

        let epoch_id = EpochId::new_random(&mut rng);
        assert_eq!(
            initiator
                .init(tonic::Request::new(InitRequest {
                    request_id: Some(epoch_id.into()),
                    context_id: None,
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
    }
}
