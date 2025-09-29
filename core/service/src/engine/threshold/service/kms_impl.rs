// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

// === External Crates ===
use kms_grpc::{
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::{KMSType, PrivDataType, PubDataType, SignedPubDataHandleInternal},
    RequestId,
};
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::prelude::LweKeyswitchKey, integer::compression_keys::DecompressionKey,
    named::Named, Versionize,
};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring},
    execution::{
        endpoints::keygen::SecureOnlineDistributedKeyGen128,
        online::preprocessing::{
            create_memory_factory, create_redis_factory,
            orchestration::producer_traits::SecureSmallProducerFactory, DKGPreprocessing,
        },
        runtime::party::{Role, RoleAssignment},
        small_execution::prss::RobustSecurePrssInit,
        tfhe_internals::{parameters::DKGParams, private_keysets::PrivateKeySet},
        zk::ceremony::SecureCeremony,
    },
    networking::grpc::{GrpcNetworkingManager, GrpcServer, TlsExtensionGetter},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tokio_rustls::rustls::{client::ClientConfig, server::ServerConfig};
use tokio_util::task::TaskTracker;
use tonic::transport::{server::TcpIncoming, Server};
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_tls::rustls::TlsIncoming;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    backup::{custodian::InternalCustodianContext, operator::RecoveryValidationMaterial},
    conf::threshold::ThresholdPartyConf,
    consts::DEFAULT_MPC_CONTEXT,
    consts::{MINIMUM_SESSIONS_PREPROC, PRSS_INIT_REQ_ID},
    cryptography::{attestation::SecurityModuleProxy, internal_crypto_types::PrivateSigKey},
    engine::{
        backup_operator::RealBackupOperator,
        base::{BaseKmsStruct, CrsGenMetadata, KeyGenMetadata},
        context_manager::RealContextManager,
        prepare_shutdown_signals,
        threshold::{
            service::public_decryptor::SecureNoiseFloodDecryptor,
            service::session::{SessionPreparer, SessionPreparerManager},
            service::user_decryptor::SecureNoiseFloodPartialDecryptor,
            threshold_kms::ThresholdKms,
        },
    },
    grpc::metastore_status_service::MetaStoreStatusServiceImpl,
    util::{
        meta_store::MetaStore,
        rate_limiter::{RateLimiter, RateLimiterConfig},
    },
    vault::{
        storage::{
            crypto_material::ThresholdCryptoMaterialStorage, read_all_data_versioned,
            read_pk_at_request_id, Storage,
        },
        Vault,
    },
};

// === Current Module Imports ===
use super::{
    crs_generator::RealCrsGenerator, initiator::RealInitiator, key_generator::RealKeyGenerator,
    preprocessor::RealPreprocessor, public_decryptor::RealPublicDecryptor,
    user_decryptor::RealUserDecryptor,
};

// === Insecure Feature-Specific Imports ===
#[cfg(feature = "insecure")]
use super::{crs_generator::RealInsecureCrsGenerator, key_generator::RealInsecureKeyGenerator};

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum ThresholdFheKeysVersioned {
    V0(ThresholdFheKeysV0),
    V1(ThresholdFheKeys),
}

/// These are the internal key materials (public and private)
/// that's needed for decryption, user decryption and verifying a proven input.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(ThresholdFheKeysVersioned)]
pub struct ThresholdFheKeys {
    pub private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    pub integer_server_key: Arc<tfhe::integer::ServerKey>,
    pub sns_key: Option<Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>>,
    pub decompression_key: Option<Arc<DecompressionKey>>,
    pub meta_data: KeyGenMetadata,
}

/// These are the internal key materials (public and private)
/// that's needed for decryption, user decryption and verifying a proven input.
#[derive(Clone, Serialize, Deserialize, Version)]
pub struct ThresholdFheKeysV0 {
    pub private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    pub integer_server_key: Arc<tfhe::integer::ServerKey>,
    pub sns_key: Option<Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>>,
    pub decompression_key: Option<Arc<DecompressionKey>>,
    pub pk_meta_data: HashMap<PubDataType, SignedPubDataHandleInternal>,
}

impl Upgrade<ThresholdFheKeys> for ThresholdFheKeysV0 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<ThresholdFheKeys, Self::Error> {
        Ok(ThresholdFheKeys {
            private_keys: Arc::clone(&self.private_keys),
            integer_server_key: Arc::clone(&self.integer_server_key),
            sns_key: self.sns_key.map(|sns_key| Arc::clone(&sns_key)),
            decompression_key: self
                .decompression_key
                .map(|decompression_key| Arc::clone(&decompression_key)),
            meta_data: KeyGenMetadata::LegacyV0(self.pk_meta_data),
        })
    }
}

impl ThresholdFheKeys {
    pub fn get_key_switching_key(&self) -> anyhow::Result<&LweKeyswitchKey<Vec<u64>>> {
        match &self.integer_server_key.as_ref().as_ref().atomic_pattern {
            tfhe::shortint::atomic_pattern::AtomicPatternServerKey::Standard(
                standard_atomic_pattern_server_key,
            ) => Ok(&standard_atomic_pattern_server_key.key_switching_key),
            tfhe::shortint::atomic_pattern::AtomicPatternServerKey::KeySwitch32(_) => {
                anyhow::bail!("No support for KeySwitch32 server key")
            }
            tfhe::shortint::atomic_pattern::AtomicPatternServerKey::Dynamic(_) => {
                anyhow::bail!("No support for dynamic atomic pattern server key")
            }
        }
    }
}

impl Named for ThresholdFheKeys {
    const NAME: &'static str = "ThresholdFheKeys";
}

impl std::fmt::Debug for ThresholdFheKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdFheKeys")
            .field("private_keys", &"ommitted")
            .field("server_key", &"ommitted")
            .field("decompression_key", &"ommitted")
            .field("pk_meta_data", &self.meta_data)
            .field("ksk", &"ommitted")
            .finish()
    }
}

#[derive(Clone)]
pub struct BucketMetaStore {
    pub(crate) preprocessing_id: RequestId,
    pub(crate) external_signature: Vec<u8>,
    pub(crate) preprocessing_store: Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>,
    pub(crate) dkg_param: DKGParams,
}

#[cfg(not(feature = "insecure"))]
pub type RealThresholdKms<PubS, PrivS> = ThresholdKms<
    RealInitiator<PrivS, RobustSecurePrssInit>,
    RealUserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
    RealPublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
    RealKeyGenerator<
        PubS,
        PrivS,
        SecureOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    >,
    RealPreprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
    RealCrsGenerator<PubS, PrivS, SecureCeremony>,
    RealContextManager<PubS, PrivS>,
    RealBackupOperator<PubS, PrivS>,
>;

#[cfg(feature = "insecure")]
pub type RealThresholdKms<PubS, PrivS> = ThresholdKms<
    RealInitiator<PrivS, RobustSecurePrssInit>,
    RealUserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
    RealPublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
    RealKeyGenerator<
        PubS,
        PrivS,
        SecureOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    >,
    RealInsecureKeyGenerator<
        PubS,
        PrivS,
        SecureOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    >,
    RealPreprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
    RealCrsGenerator<PubS, PrivS, SecureCeremony>,
    RealInsecureCrsGenerator<PubS, PrivS, SecureCeremony>, // doesn't matter which ceremony we use here
    RealContextManager<PubS, PrivS>,
    RealBackupOperator<PubS, PrivS>,
>;

#[allow(clippy::too_many_arguments)]
pub async fn new_real_threshold_kms<PubS, PrivS, F>(
    config: ThresholdPartyConf,
    public_storage: PubS,
    private_storage: PrivS,
    backup_storage: Option<Vault>,
    security_module: Option<SecurityModuleProxy>,
    mpc_listener: TcpListener,
    sk: PrivateSigKey,
    tls_config: Option<(ServerConfig, ClientConfig)>,
    peer_tcp_proxy: bool,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    shutdown_signal: F,
) -> anyhow::Result<(
    RealThresholdKms<PubS, PrivS>,
    HealthServer<impl Health>,
    MetaStoreStatusServiceImpl,
)>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // load keys from storage
    let key_info_versioned: HashMap<RequestId, ThresholdFheKeys> =
        read_all_data_versioned(&private_storage, &PrivDataType::FheKeyInfo.to_string()).await?;
    let mut public_key_info = HashMap::new();
    let mut pk_map = HashMap::new();
    let validation_material: HashMap<RequestId, RecoveryValidationMaterial> =
        read_all_data_versioned(&public_storage, &PubDataType::Commitments.to_string()).await?;
    let custodian_context: HashMap<RequestId, InternalCustodianContext> = validation_material
        .into_iter()
        .map(|(r, com)| (r, com.custodian_context().to_owned()))
        .collect();
    for (id, info) in key_info_versioned.clone().into_iter() {
        public_key_info.insert(id, info.meta_data.clone());

        let pk = read_pk_at_request_id(&public_storage, &id).await?;
        pk_map.insert(id, pk);
    }

    // load crs_info (roughly hashes of CRS) from storage
    let crs_info: HashMap<RequestId, CrsGenMetadata> =
        read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;

    let networking_manager = Arc::new(RwLock::new(GrpcNetworkingManager::new(
        tls_config
            .as_ref()
            .map(|(_, client_config)| client_config.clone()),
        config.core_to_core_net,
        peer_tcp_proxy,
    )?));

    // the initial MPC node might not accept any peers because initially there's no context
    let mpc_socket_addr = mpc_listener.local_addr()?;

    let (threshold_health_reporter, threshold_health_service) =
        tonic_health::server::health_reporter();

    let networking_server = networking_manager
        .write()
        .await
        .new_server(TlsExtensionGetter::SslConnectInfo);
    let router = Server::builder()
        .http2_adaptive_window(Some(true))
        .add_service(networking_server)
        .add_service(threshold_health_service);

    tracing::info!(
        "Starting core-to-core server for party {} on address {:?}.",
        config.my_id,
        mpc_socket_addr
    );

    let manager_clone = Arc::clone(&networking_manager);
    let abort_handle = tokio::spawn(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(prepare_shutdown_signals(shutdown_signal, tx));
        let graceful_shutdown_signal = async {
            // Set the server to be serving when we boot
            threshold_health_reporter.set_serving::<GrpcServer>().await;
            // await is the same as recv on a oneshot channel
            _ = rx.await;
            manager_clone.write().await.sending_service.shutdown();
            // Observe that the following is the shut down of the core (which communicates with the other cores)
            // That is, not the threshold KMS server itself which picks up requests from the blockchain.
            tracing::info!(
                "Starting graceful shutdown of core/threshold {}",
                mpc_socket_addr
            );
            threshold_health_reporter
                .set_not_serving::<GrpcServer>()
                .await;
        };

        // this looks somewhat hairy but there doesn't seem to be an easier way
        // to use arbitrary rustls configs until tonic::transport becomes a
        // separate crate from tonic (whose maintainers don't want to make its
        // API dependent on rustls)
        let tcp_incoming = TcpIncoming::from(mpc_listener);
        match tls_config {
            Some((server_config, _)) => {
                router
                    .serve_with_incoming_shutdown(
                        TlsIncoming::new(tcp_incoming, server_config.into()),
                        graceful_shutdown_signal,
                    )
                    .await
            }
            None => {
                router
                    .serve_with_incoming_shutdown(tcp_incoming, graceful_shutdown_signal)
                    .await
            }
        }
        .map_err(|e| {
            anyhow_error_and_log(format!(
                "Failed to launch ddec server on {mpc_socket_addr} with error: {e:?}"
            ))
        })?;
        tracing::info!(
            "core/threshold on {} shutdown completed successfully",
            mpc_socket_addr
        );
        Ok(())
    });

    // If no RedisConf is provided, we just use in-memory storage for the
    // preprocessing. Note: This is only allowed for testing.
    let preproc_factory = match &config.preproc_redis {
        None => {
            if cfg!(feature = "insecure") || cfg!(feature = "testing") {
                create_memory_factory()
            } else {
                panic!("Redis configuration must be provided")
            }
        }
        Some(ref conf) => create_redis_factory(format!("PARTY_{}", config.my_id), conf),
    };
    let num_sessions_preproc = config
        .num_sessions_preproc
        .map_or(MINIMUM_SESSIONS_PREPROC, |x| {
            std::cmp::max(x, MINIMUM_SESSIONS_PREPROC)
        });
    let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk)?;

    let prss_setup_z128 = Arc::new(RwLock::new(None));
    let prss_setup_z64 = Arc::new(RwLock::new(None));
    let preproc_buckets = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let preproc_factory = Arc::new(Mutex::new(preproc_factory));
    let crs_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(crs_info)));
    let dkg_pubinfo_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info)));
    let pub_dec_meta_store = Arc::new(RwLock::new(MetaStore::new(
        config.dec_capacity,
        config.min_dec_cache,
    )));
    let user_decrypt_meta_store = Arc::new(RwLock::new(MetaStore::new(
        config.dec_capacity,
        config.min_dec_cache,
    )));
    let custodian_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(custodian_context)));
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        public_storage,
        private_storage,
        backup_storage,
        pk_map,
        key_info_versioned,
    );

    // Note that the manager is empty, it needs to be filled with session preparers
    // For testing this needs to be done manually.
    let session_preparer_manager = SessionPreparerManager::empty(config.my_id.to_string());

    // Optionally add a testing session preparer.
    let _ = match config.peers {
        Some(ref peers) => {
            let role_assignment = RoleAssignment {
                inner: peers
                    .iter()
                    .map(|peer_config| peer_config.into_role_identity())
                    .collect(),
            };
            let session_preparer = SessionPreparer::new(
                base_kms.new_instance().await,
                config.threshold,
                Role::indexed_from_one(config.my_id),
                role_assignment.clone(),
                networking_manager.clone(),
                Arc::clone(&prss_setup_z128),
                Arc::clone(&prss_setup_z64),
            );
            session_preparer_manager
                .insert(*DEFAULT_MPC_CONTEXT, session_preparer)
                .await;
            Some(())
        }
        None => None,
    };
    let session_preparer_getter = session_preparer_manager.make_getter();

    let metastore_status_service = MetaStoreStatusServiceImpl::new(
        Some(dkg_pubinfo_meta_store.clone()),  // key_gen_store
        Some(pub_dec_meta_store.clone()),      // pub_dec_store
        Some(user_decrypt_meta_store.clone()), // user_dec_store
        Some(crs_meta_store.clone()),          // crs_store
        Some(preproc_buckets.clone()),         // preproc_store
        Some(custodian_meta_store.clone()),    // custodian_context_store
    );

    let (core_service_health_reporter, core_service_health_service) =
        tonic_health::server::health_reporter();
    let thread_core_health_reporter = core_service_health_reporter.clone();
    {
        // We are only serving after initialization
        thread_core_health_reporter
            .set_not_serving::<CoreServiceEndpointServer<RealThresholdKms<PubS, PrivS>>>()
            .await;
    }
    let initiator = RealInitiator {
        prss_setup_z128: Arc::clone(&prss_setup_z128),
        prss_setup_z64: Arc::clone(&prss_setup_z64),
        private_storage: crypto_storage.get_private_storage(),
        session_preparer_manager,
        networking_manager,
        health_reporter: thread_core_health_reporter.clone(),
        _init: PhantomData,
        threshold_config: config.clone(),
        base_kms: base_kms.new_instance().await,
    };

    // TODO eventually this PRSS ID should come from the context request
    // the PRSS should never be run in this function.
    let req_id_prss = RequestId::try_from(PRSS_INIT_REQ_ID.to_string())?; // the init epoch ID is currently fixed to PRSS_INIT_REQ_ID
    if run_prss {
        tracing::info!(
            "Initializing threshold KMS server and generating a new PRSS Setup for {}",
            config.my_id
        );
        initiator.init_prss(&req_id_prss).await?;
    } else {
        tracing::info!(
            "Trying to initializing threshold KMS server and reading PRSS from storage for {}",
            config.my_id
        );
        if let Err(e) = initiator.init_prss_from_disk(&req_id_prss).await {
            tracing::warn!(
                "Could not read PRSS Setup from storage for {}: {}. You will need to call the init end-point later before you can use the KMS server",
                config.my_id,
                e
            );
        }
    }

    let tracker = Arc::new(TaskTracker::new());
    let slow_events = Arc::new(Mutex::new(HashMap::new()));
    let rate_limiter = RateLimiter::new(rate_limiter_conf.unwrap_or_default());

    let user_decryptor = RealUserDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        user_decrypt_meta_store,
        session_preparer_getter: session_preparer_getter.clone(),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode: config.decryption_mode,
        _dec: PhantomData,
    };

    let public_decryptor = RealPublicDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        pub_dec_meta_store,
        session_preparer_getter: session_preparer_getter.clone(),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode: config.decryption_mode,
        _dec: PhantomData,
    };

    let keygenerator = RealKeyGenerator {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        preproc_buckets: Arc::clone(&preproc_buckets),
        dkg_pubinfo_meta_store,
        session_preparer_getter: session_preparer_getter.clone(),
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
        _kg: PhantomData,
    };

    #[cfg(feature = "insecure")]
    let insecure_keygenerator = RealInsecureKeyGenerator::from_real_keygen(&keygenerator).await;

    let keygen_preprocessor = RealPreprocessor {
        sig_key: Arc::clone(&base_kms.sig_key),
        preproc_buckets,
        preproc_factory,
        num_sessions_preproc,
        session_preparer_getter: session_preparer_getter.clone(),
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
        _producer_factory: PhantomData,
    };

    let crs_generator = RealCrsGenerator {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        crs_meta_store,
        session_preparer_getter,
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
        _ceremony: PhantomData,
    };

    #[cfg(feature = "insecure")]
    let insecure_crs_generator = RealInsecureCrsGenerator::from_real_crsgen(&crs_generator).await;

    let context_manager = RealContextManager {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.inner.clone(),
        custodian_meta_store,
        my_role: Role::indexed_from_one(config.my_id),
    };

    let backup_operator = RealBackupOperator::new(
        Role::indexed_from_one(config.my_id),
        base_kms.new_instance().await,
        crypto_storage.inner.clone(),
        security_module,
    );
    // Update backup vault if it exists
    // This ensures that all files in the private storage are also in the backup vault
    // Thus the vault gets automatically updated incase its location changes, or in case of a deletion
    // Note however that the data in the vault is not checked for corruption.
    backup_operator.update_backup_vault().await?;

    let kms = ThresholdKms::new(
        initiator,
        user_decryptor,
        public_decryptor,
        keygenerator,
        #[cfg(feature = "insecure")]
        insecure_keygenerator,
        keygen_preprocessor,
        crs_generator,
        #[cfg(feature = "insecure")]
        insecure_crs_generator,
        context_manager,
        backup_operator,
        Arc::new(config.clone()),
        Arc::clone(&tracker),
        thread_core_health_reporter,
        abort_handle,
    );

    Ok((kms, core_service_health_service, metastore_status_service))
}

#[cfg(test)]
mod tests {
    use threshold_fhe::execution::tfhe_internals::public_keysets::FhePubKeySet;

    use super::*;

    impl ThresholdFheKeys {
        /// Initializes a dummy private keyset with the given parameters and returns it along with a public key set.
        /// The keyset is *not* meant to be used for any computation or protocol,
        /// it's only used during testing with a mocked decryption protocol that does not actually load the keys.
        pub fn init_dummy<R: rand::Rng + rand::CryptoRng>(
            param: threshold_fhe::execution::tfhe_internals::parameters::DKGParams,
            rng: &mut R,
        ) -> (Self, FhePubKeySet) {
            let keyset =
                threshold_fhe::execution::tfhe_internals::test_feature::gen_key_set(param, rng);

            let server_key = keyset.public_keys.server_key.clone();
            let (
                integer_server_key,
                _ksk,
                _compression_key,
                decompression_key,
                sns_key,
                _sns_compression_key,
                _rerand_key,
                _tag,
            ) = keyset.public_keys.server_key.into_raw_parts();

            let pub_key_set = FhePubKeySet {
                public_key: keyset.public_keys.public_key,
                server_key,
            };

            let priv_key_set = PrivateKeySet::init_dummy(param);

            let priv_key_set = Self {
                private_keys: Arc::new(priv_key_set),
                integer_server_key: Arc::new(integer_server_key),
                sns_key: sns_key.map(Arc::new),
                decompression_key: decompression_key.map(Arc::new),
                meta_data: KeyGenMetadata::new(
                    RequestId::zeros(),
                    RequestId::zeros(),
                    HashMap::new(),
                    vec![],
                ),
            };

            (priv_key_set, pub_key_set)
        }
    }
}
