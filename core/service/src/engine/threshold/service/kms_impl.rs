// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

// === External Crates ===
use kms_grpc::{
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::{PrivDataType, PubDataType, SignedPubDataHandleInternal},
    RequestId,
};
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::prelude::LweKeyswitchKey, integer::compression_keys::DecompressionKey,
    named::Named, Versionize,
};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring},
    execution::{
        endpoints::keygen::SecureOnlineDistributedKeyGen128,
        online::preprocessing::{
            create_memory_factory, create_redis_factory,
            orchestration::producer_traits::SecureSmallProducerFactory, DKGPreprocessing,
        },
        runtime::party::Role,
        small_execution::prss::RobustSecurePrssInit,
        tfhe_internals::{private_keysets::PrivateKeySet, public_keysets::FhePubKeySet},
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
    backup::custodian::InternalCustodianContext,
    conf::threshold::ThresholdPartyConf,
    consts::DEFAULT_MPC_CONTEXT_BYTES,
    consts::{MINIMUM_SESSIONS_PREPROC, PRSS_INIT_REQ_ID},
    cryptography::{attestation::SecurityModuleProxy, internal_crypto_types::PrivateSigKey},
    engine::{
        backup_operator::RealBackupOperator,
        base::{compute_info, BaseKmsStruct, KeyGenCallValues, DSEP_PUBDATA_KEY},
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

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum ThresholdFheKeysVersioned {
    V0(ThresholdFheKeys),
}

/// These are the internal key materials (public and private)
/// that's needed for decryption, user decryption and verifying a proven input.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(ThresholdFheKeysVersioned)]
pub struct ThresholdFheKeys {
    pub private_keys: PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    pub integer_server_key: tfhe::integer::ServerKey,
    pub sns_key: Option<tfhe::integer::noise_squashing::NoiseSquashingKey>,
    pub decompression_key: Option<DecompressionKey>,
    pub pk_meta_data: KeyGenCallValues,
}

impl ThresholdFheKeys {
    pub fn get_key_switching_key(&self) -> anyhow::Result<&LweKeyswitchKey<Vec<u64>>> {
        match &self.integer_server_key.as_ref().atomic_pattern {
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
            .field("pk_meta_data", &self.pk_meta_data)
            .field("ksk", &"ommitted")
            .finish()
    }
}

pub type BucketMetaStore = Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>;

/// Compute all the info of a [FhePubKeySet] and return the result as as [KeyGenCallValues]
pub fn compute_all_info(
    sig_key: &PrivateSigKey,
    fhe_key_set: &FhePubKeySet,
    domain: &alloy_sol_types::Eip712Domain,
) -> anyhow::Result<KeyGenCallValues> {
    //Compute all the info required for storing
    let pub_key_info = compute_info(sig_key, &DSEP_PUBDATA_KEY, &fhe_key_set.public_key, domain);
    let serv_key_info = compute_info(sig_key, &DSEP_PUBDATA_KEY, &fhe_key_set.server_key, domain);

    //Make sure we did manage to compute the info
    Ok(match (pub_key_info, serv_key_info) {
        (Ok(pub_key_info), Ok(serv_key_info)) => {
            let mut info = HashMap::new();
            info.insert(PubDataType::PublicKey, pub_key_info);
            info.insert(PubDataType::ServerKey, serv_key_info);
            info
        }
        _ => {
            return Err(anyhow_error_and_log(
                "Could not compute info on some public key element",
            ));
        }
    })
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
    for (id, info) in key_info_versioned.clone().into_iter() {
        public_key_info.insert(id, info.pk_meta_data.clone());

        let pk = read_pk_at_request_id(&public_storage, &id).await?;
        pk_map.insert(id, pk);
    }

    // load crs_info (roughly hashes of CRS) from storage
    let crs_info: HashMap<RequestId, SignedPubDataHandleInternal> =
        read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;

    // The mapping from roles to network addresses is dependent on contexts set dynamically, so we put it in a mutable map
    let role_assignment = Arc::new(RwLock::new(HashMap::new()));

    let networking_manager = Arc::new(RwLock::new(GrpcNetworkingManager::new(
        Role::indexed_from_one(config.my_id),
        tls_config
            .as_ref()
            .map(|(_, client_config)| client_config.clone()),
        config.core_to_core_net,
        peer_tcp_proxy,
        role_assignment.clone(),
    )?));

    // the initial MPC node might not accept any peers because initially there's no context
    let mpc_socket_addr = mpc_listener.local_addr()?;

    let (threshold_health_reporter, threshold_health_service) =
        tonic_health::server::health_reporter();

    let manager_clone = Arc::clone(&networking_manager);
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

    let custodian_context: HashMap<RequestId, InternalCustodianContext> =
        read_all_data_versioned(&private_storage, &PrivDataType::CustodianInfo.to_string()).await?;

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
        Some(conf) => create_redis_factory(format!("PARTY_{}", config.my_id), conf),
    };
    let num_sessions_preproc = config
        .num_sessions_preproc
        .map_or(MINIMUM_SESSIONS_PREPROC, |x| {
            std::cmp::max(x, MINIMUM_SESSIONS_PREPROC)
        });
    let base_kms = BaseKmsStruct::new(sk)?;

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
    let session_preparer_manager = SessionPreparerManager::empty(
        config.my_id.to_string(),
        networking_manager.clone(),
        role_assignment.clone(),
    );

    // Optionally add a testing session preparer.
    let _ = match config.peers {
        Some(ref peers) => {
            let mut role_assignment_write = role_assignment.write().await;
            role_assignment_write.extend(
                peers
                    .iter()
                    .map(|peer_config| peer_config.into_role_identity()),
            );
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
                .insert(
                    RequestId::from_bytes(DEFAULT_MPC_CONTEXT_BYTES),
                    session_preparer,
                )
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
        prss_setup: prss_setup_z128,
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
        crypto_storage: crypto_storage.clone(),
        custodian_meta_store,
        my_role: Role::indexed_from_one(config.my_id),
        tracker: Arc::clone(&tracker),
    };

    let backup_operator = RealBackupOperator {
        crypto_storage: crypto_storage.clone(),
        security_module,
    };
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
        Arc::clone(&tracker),
        thread_core_health_reporter,
        abort_handle,
    );

    Ok((kms, core_service_health_service, metastore_status_service))
}

#[cfg(test)]
mod tests {
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
                _tag,
            ) = keyset.public_keys.server_key.into_raw_parts();

            let pub_key_set = FhePubKeySet {
                public_key: keyset.public_keys.public_key,
                server_key,
            };

            let priv_key_set = PrivateKeySet::init_dummy(param);

            let priv_key_set = Self {
                private_keys: priv_key_set,
                integer_server_key,
                sns_key,
                decompression_key,
                pk_meta_data: HashMap::new(),
            };

            (priv_key_set, pub_key_set)
        }
    }
}
