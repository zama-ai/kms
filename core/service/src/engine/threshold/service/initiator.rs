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
        runtime::{party::Role, session::ParameterHandles},
        small_execution::prss::{PRSSInit, PRSSSetup},
    },
    networking::NetworkMode,
};
use tokio::sync::{Mutex, RwLock};
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

// === Internal Crate ===
use crate::{
    conf::threshold::ThresholdPartyConf,
    consts::DEFAULT_MPC_CONTEXT_BYTES,
    engine::{
        base::derive_request_id,
        threshold::{service::session::SessionPreparer, traits::Initiator},
        validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    },
    tonic_some_or_err,
    vault::storage::{read_versioned_at_request_id, store_versioned_at_request_id, Storage},
};

// === Current Module Imports ===
use super::{session::SessionPreparerManager, RealThresholdKms};

pub struct RealInitiator<
    PrivS: Storage + Send + Sync + 'static,
    Init: PRSSInit<ResiduePolyF4Z64> + PRSSInit<ResiduePolyF4Z128>,
> {
    // TODO eventually add mode to allow for nlarge as well.
    pub prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    pub prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
    pub private_storage: Arc<Mutex<PrivS>>,
    pub session_preparer_manager: SessionPreparerManager,
    pub health_reporter: HealthReporter,
    pub(crate) _init: PhantomData<Init>,
    // This is needed as a workaround to initialize the session preparer
    pub threshold_config: ThresholdPartyConf,
    pub base_kms: crate::engine::base::BaseKmsStruct,
}

impl<
        PrivS: Storage + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > RealInitiator<PrivS, Init>
{
    // Note that `req_id` is not the context ID. It is the request ID for the PRSS setup.
    pub async fn init_prss_from_disk(&self, req_id: &RequestId) -> anyhow::Result<()> {
        // TODO set the correct context ID here.
        let session_preparer = self
            .session_preparer_manager
            .get(&RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES))
            .await?;

        let prss_setup_z128_from_file = {
            let guarded_private_storage = self.private_storage.lock().await;
            let parameters = session_preparer
                .get_session_parameters(req_id.derive_session_id()?)
                .await?;
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
            let parameters = session_preparer
                .get_session_parameters(req_id.derive_session_id()?)
                .await?;
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

    // NOTE: this function will overwrite the existing PRSS state
    pub async fn init_prss(&self, req_id: &RequestId) -> anyhow::Result<()> {
        // TODO set the correct context ID here.
        let session_preparer = self
            .session_preparer_manager
            .get(&RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES))
            .await?;

        // TODO(zama-ai/kms-internal/issues/2721),
        // we never try to store the PRSS in meta_store, so the ID is not guaranteed to be unique

        let own_identity = session_preparer.own_identity().await?;
        let session_id = req_id.derive_session_id()?;

        // PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = session_preparer
            .make_base_session(session_id, NetworkMode::Sync)
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
        // TODO set the correct context ID here as it should be contained in the InitRequest.
        // since the connector is not giving us a context yet, we read it from file
        // eventually this piece of code will move to the context endpoint and this
        // endpoint will be removed.

        let networking_manager = self.session_preparer_manager.get_networking_manager().await;
        let role_assignment = self.session_preparer_manager.get_role_assignment().await;

        let peers = tonic_some_or_err(self.threshold_config.peers.clone(), "Peer list not set in the configuration file, setting it through the context is unsupported yet".to_string())?;

        // Careful not to hold the write lock longer than needed
        role_assignment.write().await.extend(
            peers
                .into_iter()
                .map(|peer_config| peer_config.into_role_identity()),
        );

        let session_preparer = SessionPreparer::new(
            self.base_kms.new_instance().await,
            self.threshold_config.threshold,
            Role::indexed_from_one(self.threshold_config.my_id),
            role_assignment.clone(),
            networking_manager.clone(),
            Arc::clone(&self.prss_setup_z128),
            Arc::clone(&self.prss_setup_z64),
        );
        self.session_preparer_manager
            .insert(
                RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES),
                session_preparer,
            )
            .await;

        let inner = request.into_inner();
        let request_id =
            parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::Init)?;

        if self.prss_setup_z128.read().await.is_some() || self.prss_setup_z64.read().await.is_some()
        {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                "PRSS state already exists".to_string(),
            ));
        }

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
        conf::threshold::PeerConf,
        consts::PRSS_INIT_REQ_ID,
        cryptography::internal_crypto_types::gen_sig_keys,
        engine::base::BaseKmsStruct,
        util::key_setup::test_tools::purge,
        vault::storage::{file::FileStorage, ram, StorageType},
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::InitRequest;
    use rand::SeedableRng;
    use threshold_fhe::{
        execution::{endpoints::decryption::DecryptionMode, runtime::party::Role},
        malicious_execution::small_execution::malicious_prss::{EmptyPrss, FailingPrss},
    };

    impl<
            Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
                + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>,
        > RealInitiator<ram::RamStorage, Init>
    {
        fn init_test(
            base_kms: BaseKmsStruct,
            session_preparer_manager: SessionPreparerManager,
        ) -> Self {
            Self {
                prss_setup_z128: Arc::new(RwLock::new(None)),
                prss_setup_z64: Arc::new(RwLock::new(None)),
                private_storage: Arc::new(Mutex::new(ram::RamStorage::new())),
                session_preparer_manager,
                health_reporter: HealthReporter::new(),
                _init: PhantomData,
                threshold_config: ThresholdPartyConf {
                    listen_address: "localhost".to_string(),
                    listen_port: 5001,
                    tls: None,
                    threshold: 1,
                    my_id: 1,
                    dec_capacity: 0,
                    min_dec_cache: 0,
                    preproc_redis: None,
                    num_sessions_preproc: None,
                    peers: Some(vec![PeerConf {
                        party_id: 1,
                        address: "dummy".to_string(),
                        port: 1,
                        tls_cert: None,
                    }]),
                    core_to_core_net: None,
                    decryption_mode: DecryptionMode::NoiseFloodSmall,
                },
                base_kms,
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
        let (_pk, sk) = gen_sig_keys(&mut rand::rngs::OsRng);
        let base_kms = BaseKmsStruct::new(sk).unwrap();
        let session_preparer_manager = SessionPreparerManager::new_test_session();
        let session_preparer = SessionPreparer::new_test_session(
            base_kms.new_instance().await,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
        );
        session_preparer_manager
            .insert(
                RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES),
                session_preparer,
            )
            .await;
        let initiator = RealInitiator::<ram::RamStorage, EmptyPrss>::init_test(
            base_kms,
            session_preparer_manager,
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
        let (_pk, sk) = gen_sig_keys(&mut rand::rngs::OsRng);
        let base_kms = BaseKmsStruct::new(sk).unwrap();
        let session_preparer_manager = SessionPreparerManager::new_test_session();
        let session_preparer = SessionPreparer::new_test_session(
            base_kms.new_instance().await,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
        );
        session_preparer_manager
            .insert(
                RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES),
                session_preparer,
            )
            .await;
        let initiator = RealInitiator::<ram::RamStorage, EmptyPrss>::init_test(
            base_kms,
            session_preparer_manager,
        );

        {
            // bad request ID
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
        {
            // missing request ID
            assert_eq!(
                initiator
                    .init(tonic::Request::new(InitRequest { request_id: None }))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let (_pk, sk) = gen_sig_keys(&mut rand::rngs::OsRng);
        let base_kms = BaseKmsStruct::new(sk).unwrap();
        let session_preparer_manager = SessionPreparerManager::new_test_session();
        let session_preparer = SessionPreparer::new_test_session(
            base_kms.new_instance().await,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
        );
        session_preparer_manager
            .insert(
                RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES),
                session_preparer,
            )
            .await;

        let initiator = RealInitiator::<ram::RamStorage, EmptyPrss>::init_test(
            base_kms,
            session_preparer_manager,
        );

        let mut rng = AesRng::seed_from_u64(42);
        let req_id = RequestId::new_random(&mut rng);
        initiator
            .init(tonic::Request::new(InitRequest {
                request_id: Some(req_id.into()),
            }))
            .await
            .unwrap();

        // try the same again and we should see an AlreadyExists error
        assert_eq!(
            initiator
                .init(tonic::Request::new(InitRequest {
                    request_id: Some(req_id.into()),
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn internal() {
        let (_pk, sk) = gen_sig_keys(&mut rand::rngs::OsRng);
        let base_kms = BaseKmsStruct::new(sk).unwrap();
        let session_preparer_manager = SessionPreparerManager::new_test_session();
        let session_preparer = SessionPreparer::new_test_session(
            base_kms.new_instance().await,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
        );
        session_preparer_manager
            .insert(
                RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES),
                session_preparer,
            )
            .await;
        let initiator = RealInitiator::<ram::RamStorage, FailingPrss>::init_test(
            base_kms,
            session_preparer_manager,
        );

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
