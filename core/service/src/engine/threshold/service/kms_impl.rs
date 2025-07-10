// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use kms_grpc::{
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::{PrivDataType, PubDataType, SignedPubDataHandleInternal},
    RequestId,
};
use serde::{Deserialize, Serialize};
use tfhe::{integer::compression_keys::DecompressionKey, named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring},
    execution::{
        endpoints::keygen::{FhePubKeySet, PrivateKeySet},
        online::preprocessing::{create_memory_factory, create_redis_factory, DKGPreprocessing},
        runtime::party::{Role, RoleAssignment},
    },
    networking::{
        grpc::{GrpcNetworkingManager, GrpcServer},
        tls::{
            build_ca_certs_map, AttestedClientVerifier, BasicTLSConfig, SendingServiceTLSConfig,
        },
        Networking, NetworkingStrategy,
    },
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ServerConfig,
};
use tokio_util::task::TaskTracker;
use tonic::transport::{server::TcpIncoming, Server};
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_tls::rustls::TlsIncoming;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    conf::threshold::{PeerConf, ThresholdPartyConf, TlsCert},
    consts::{MINIMUM_SESSIONS_PREPROC, PRSS_INIT_REQ_ID},
    cryptography::internal_crypto_types::PrivateSigKey,
    engine::{
        base::{compute_info, BaseKmsStruct, KeyGenCallValues, DSEP_PUBDATA_KEY},
        prepare_shutdown_signals,
        threshold::threshold_kms::ThresholdKms,
    },
    grpc::metastore_status_service::MetaStoreStatusServiceImpl,
    tonic_some_or_err,
    util::{
        meta_store::MetaStore,
        rate_limiter::{RateLimiter, RateLimiterConfig},
    },
    vault::storage::{
        crypto_material::ThresholdCryptoMaterialStorage, read_all_data_versioned,
        read_pk_at_request_id, Storage,
    },
};

// === Current Module Imports ===
use super::{
    context_manager::RealContextManager, crs_generator::RealCrsGenerator, initiator::RealInitiator,
    key_generator::RealKeyGenerator, preprocessor::RealPreprocessor,
    public_decryptor::RealPublicDecryptor, session::SessionPreparer,
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
    domain: Option<&alloy_sol_types::Eip712Domain>,
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
pub type RealThresholdKms<PubS, PrivS, BackS> = ThresholdKms<
    RealInitiator<PrivS>,
    RealUserDecryptor<PubS, PrivS, BackS>,
    RealPublicDecryptor<PubS, PrivS, BackS>,
    RealKeyGenerator<PubS, PrivS, BackS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS, BackS>,
    RealContextManager<PubS, PrivS, BackS>,
>;

#[cfg(feature = "insecure")]
pub type RealThresholdKms<PubS, PrivS, BackS> = ThresholdKms<
    RealInitiator<PrivS>,
    RealUserDecryptor<PubS, PrivS, BackS>,
    RealPublicDecryptor<PubS, PrivS, BackS>,
    RealKeyGenerator<PubS, PrivS, BackS>,
    RealInsecureKeyGenerator<PubS, PrivS, BackS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS, BackS>,
    RealInsecureCrsGenerator<PubS, PrivS, BackS>,
    RealContextManager<PubS, PrivS, BackS>,
>;

#[allow(clippy::too_many_arguments)]
pub async fn new_real_threshold_kms<PubS, PrivS, BackS, F>(
    config: ThresholdPartyConf,
    public_storage: PubS,
    private_storage: PrivS,
    backup_storage: Option<BackS>,
    mpc_listener: TcpListener,
    sk: PrivateSigKey,
    tls_identity: Option<BasicTLSConfig>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    shutdown_signal: F,
) -> anyhow::Result<(
    RealThresholdKms<PubS, PrivS, BackS>,
    HealthServer<impl Health>,
    MetaStoreStatusServiceImpl,
)>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
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

    // set up the MPC service
    let role_assignments: RoleAssignment = config
        .peers
        .clone()
        .into_iter()
        .map(|peer_config| peer_config.into_role_identity())
        .collect();

    let own_identity = tonic_some_or_err(
        role_assignments.get(&Role::indexed_from_one(config.my_id)),
        "Could not find my own identity".to_string(),
    )?;
    let mpc_socket_addr = mpc_listener.local_addr()?;

    // We put the party CA certificates into a hashmap keyed by party addresses
    // to be able to limit trust anchors to only one CA certificate both on
    // client and server.
    let tls_certs = extract_tls_certs(tls_identity, &config.peers).await?;

    // We have to construct a rustls config ourselves instead of using the
    // wrapper from tonic::transport because we need to provide our own
    // certificate verifier that can also validate bundled attestation
    // documents.
    let tls_config = match tls_certs.clone() {
        Some(SendingServiceTLSConfig {
            cert,
            key,
            ca_certs,
            trusted_releases,
            pcr8_expected,
        }) => {
            let cert_chain =
                vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()];
            let key_der = PrivateKeyDer::try_from(key.contents.as_slice())
                .map_err(|e| anyhow_error_and_log(e.to_string()))?
                .clone_key();
            let client_verifier =
                AttestedClientVerifier::new(ca_certs, trusted_releases.clone(), pcr8_expected)?;

            match trusted_releases {
                Some(_) => tracing::info!("Creating server with TLS and AWS Nitro attestation"),
                None => {
                    tracing::info!("Creating server with TLS and without AWS Nitro attestation")
                }
            }
            Some(
                ServerConfig::builder()
                    .with_client_cert_verifier(Arc::new(client_verifier))
                    .with_single_cert(cert_chain, key_der)?,
            )
        }
        None => {
            tracing::warn!("Creating server without TLS");
            None
        }
    };

    let (threshold_health_reporter, threshold_health_service) =
        tonic_health::server::health_reporter();
    // This will setup client TLS if tls_certs is set to Some(...)
    let networking_manager = Arc::new(RwLock::new(GrpcNetworkingManager::new(
        own_identity.to_owned(),
        tls_certs,
        config.core_to_core_net,
    )?));
    let manager_clone = Arc::clone(&networking_manager);
    let networking_server = networking_manager.write().await.new_server();
    // we won't be setting TLS configuration through tonic::transport knobs here
    // since it doesn't permit setting rustls configuration directly, and we
    // need to supply a custom certificate verifier to enable AWS Nitro
    // attestation in TLS
    let router = Server::builder()
        .http2_adaptive_window(Some(true))
        .add_service(networking_server)
        .add_service(threshold_health_service);

    tracing::info!(
        "Starting core-to-core server for identity {} on address {:?}.",
        own_identity,
        mpc_socket_addr
    );

    let nm_networking_strategy = networking_manager.clone();
    let networking_strategy: Arc<RwLock<NetworkingStrategy>> = Arc::new(RwLock::new(Box::new(
        move |session_id, roles, network_mode| {
            let nm = nm_networking_strategy.clone();
            Box::pin(async move {
                let manager = nm.read().await;
                let impl_networking = manager.make_session(session_id, roles, network_mode);
                Ok(impl_networking as Arc<dyn Networking + Send + Sync>)
            })
        },
    )));

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
            Some(tls_config) => {
                router
                    .serve_with_incoming_shutdown(
                        TlsIncoming::new(tcp_incoming, tls_config.into()),
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
    let preproc_factory = match config.preproc_redis {
        None => {
            if cfg!(feature = "insecure") || cfg!(feature = "testing") {
                create_memory_factory()
            } else {
                panic!("Redis configuration must be provided")
            }
        }
        Some(conf) => create_redis_factory(format!("PARTY_{}", config.my_id), &conf),
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
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        public_storage,
        private_storage,
        backup_storage,
        pk_map,
        key_info_versioned,
    );

    let session_preparer = SessionPreparer {
        base_kms: base_kms.new_instance().await,
        threshold: config.threshold,
        my_id: config.my_id,
        role_assignments: role_assignments.clone(),
        networking_strategy,
        prss_setup_z128: Arc::clone(&prss_setup_z128),
        prss_setup_z64: Arc::clone(&prss_setup_z64),
        networking_manager: Arc::clone(&networking_manager),
    };

    let metastore_status_service = MetaStoreStatusServiceImpl::new(
        Some(dkg_pubinfo_meta_store.clone()),  // key_gen_store
        Some(pub_dec_meta_store.clone()),      // pub_dec_store
        Some(user_decrypt_meta_store.clone()), // user_dec_store
        Some(crs_meta_store.clone()),          // crs_store
        Some(preproc_buckets.clone()),         // preproc_store
    );

    let (core_service_health_reporter, core_service_health_service) =
        tonic_health::server::health_reporter();
    let thread_core_health_reporter = Arc::new(RwLock::new(core_service_health_reporter));
    {
        // We are only serving after initialization
        thread_core_health_reporter
            .write()
            .await
            .set_not_serving::<CoreServiceEndpointServer<RealThresholdKms<PubS, PrivS, BackS>>>()
            .await;
    }
    let initiator = RealInitiator {
        prss_setup_z128: Arc::clone(&prss_setup_z128),
        prss_setup_z64: Arc::clone(&prss_setup_z64),
        private_storage: crypto_storage.get_private_storage(),
        session_preparer: session_preparer.new_instance().await,
        health_reporter: thread_core_health_reporter.clone(),
    };
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
        session_preparer: Arc::new(session_preparer.new_instance().await),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode: config.decryption_mode,
    };

    let public_decryptor = RealPublicDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        pub_dec_meta_store,
        session_preparer: Arc::new(session_preparer.new_instance().await),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode: config.decryption_mode,
    };

    let keygenerator = RealKeyGenerator {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        preproc_buckets: Arc::clone(&preproc_buckets),
        dkg_pubinfo_meta_store,
        session_preparer: session_preparer.new_instance().await,
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
    };

    #[cfg(feature = "insecure")]
    let insecure_keygenerator = RealInsecureKeyGenerator::from_real_keygen(&keygenerator).await;

    let keygen_preprocessor = RealPreprocessor {
        prss_setup: prss_setup_z128,
        preproc_buckets,
        preproc_factory,
        num_sessions_preproc,
        session_preparer: session_preparer.new_instance().await,
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
    };

    let crs_generator = RealCrsGenerator {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        crs_meta_store,
        session_preparer,
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
    };

    #[cfg(feature = "insecure")]
    let insecure_crs_generator = RealInsecureCrsGenerator::from_real_crsgen(&crs_generator).await;

    let context_manager = RealContextManager {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
    };

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
        Arc::clone(&tracker),
        Arc::clone(&thread_core_health_reporter),
        abort_handle,
    );

    Ok((kms, core_service_health_service, metastore_status_service))
}

/// Helper function to extract the TLS certificates from the peer configurations and TLS configuration.
/// It returns a `SendingServiceTLSConfig` which consists of a tuple of the server certificate, private key, and a map of CA certificates
async fn extract_tls_certs(
    tls_identity: Option<BasicTLSConfig>,
    peer_configs: &[PeerConf],
) -> anyhow::Result<Option<SendingServiceTLSConfig>> {
    if let Some(BasicTLSConfig {
        cert,
        key,
        trusted_releases,
        pcr8_expected,
    }) = tls_identity
    {
        let mut cert_strings = Vec::new();
        for peer in peer_configs {
            match peer.tls_cert.as_ref() {
                Some(TlsCert::Path(path)) => cert_strings.push(
                    tokio::fs::read_to_string(path)
                        .await
                        .map_err(|e| anyhow::anyhow!("Could not read CA certificates: {e}")),
                ),
                Some(TlsCert::Pem(bytes)) => cert_strings.push(Ok(bytes.to_string())),
                None => {}
            };
        }
        let ca_certs = build_ca_certs_map(cert_strings.into_iter())?;
        tracing::info!("Using TLS trust anchors: {:?}", ca_certs.keys());
        Ok(Some(SendingServiceTLSConfig {
            cert,
            key,
            ca_certs,
            trusted_releases,
            pcr8_expected,
        }))
    } else {
        Ok(None)
    }
}
