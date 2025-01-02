use crate::conf::threshold::{PeerConf, ThresholdParty};
use crate::consts::{INFLIGHT_REQUEST_WAITING_TIME, MINIMUM_SESSIONS_PREPROC, PRSS_EPOCH_ID};
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicEncKey};
use crate::cryptography::proven_ct_verifier::{
    get_verify_proven_ct_result, non_blocking_verify_proven_ct,
};
use crate::cryptography::signcryption::signcrypt;
use crate::engine::base::compute_info;
use crate::engine::base::BaseKmsStruct;
use crate::engine::base::{
    compute_external_pt_signature, deserialize_to_low_level, retrieve_parameters,
};
use crate::engine::base::{convert_key_response, DecCallValues, KeyGenCallValues, ReencCallValues};
use crate::engine::centralized::central_kms::async_generate_crs;
use crate::engine::threshold::generic::GenericKms;
use crate::engine::threshold::traits::{
    CrsGenerator, Decryptor, Initiator, KeyGenPreprocessor, KeyGenerator, ProvenCtVerifier,
    Reencryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use crate::engine::validation::{
    validate_decrypt_req, validate_reencrypt_req, validate_request_id,
};
use crate::engine::{prepare_shutdown_signals, traits::BaseKms};
use crate::util::meta_store::{handle_res_mapping, MetaStore};
use crate::util::rate_limiter::{RateLimiter, RateLimiterConfig};
use crate::vault::storage::{
    crypto_material::ThresholdCryptoMaterialStorage, read_all_data_versioned,
    read_pk_at_request_id, read_versioned_at_request_id, store_versioned_at_request_id, Storage,
};
use crate::{anyhow_error_and_log, get_exactly_one, tonic_handle_potential_err, tonic_some_or_err};
use aes_prng::AesRng;
use ahash::RandomState;
use anyhow::anyhow;
use conf_trace::metrics;
use conf_trace::metrics_names::{
    ERR_DECRYPTION_FAILED, ERR_RATE_LIMIT_EXCEEDED, HASH_CIPHERTEXT_SEEDS, OP_DECRYPT,
    OP_REENCRYPT, TAG_CIPHERTEXT_ID, TAG_PARTY_ID, TAG_REQUEST_ID,
};
use distributed_decryption::algebra::galois_rings::common::pack_residue_poly;
use distributed_decryption::algebra::galois_rings::degree_8::ResiduePolyF8Z128;
use distributed_decryption::conf::party::CertificatePaths;
use distributed_decryption::execution::endpoints::decryption::{
    decrypt_using_noiseflooding, partial_decrypt_using_noiseflooding, Small,
};
use distributed_decryption::execution::endpoints::keygen::{
    distributed_keygen_z128, PrivateKeySet,
};
use distributed_decryption::execution::large_execution::vss::RealVss;
use distributed_decryption::execution::online::preprocessing::orchestrator::PreprocessingOrchestrator;
use distributed_decryption::execution::online::preprocessing::{
    create_memory_factory, create_redis_factory, DKGPreprocessing, PreprocessorFactory,
};
use distributed_decryption::execution::runtime::party::{Identity, Role, RoleAssignment};
use distributed_decryption::execution::runtime::session::{
    BaseSessionStruct, DecryptionMode, ParameterHandles, SessionParameters, SmallSession,
    ToBaseSession,
};
use distributed_decryption::execution::small_execution::prss::PRSSSetup;
use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
use distributed_decryption::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use distributed_decryption::execution::tfhe_internals::test_feature::{
    initialize_key_material, transfer_crs,
};
use distributed_decryption::execution::zk::ceremony::{
    compute_witness_dim, Ceremony, RealCeremony,
};
use distributed_decryption::networking::grpc::{
    CoreToCoreNetworkConfig, GrpcNetworkingManager, GrpcServer,
};
use distributed_decryption::networking::NetworkMode;
use distributed_decryption::networking::NetworkingStrategy;
use distributed_decryption::session_id::SessionId;
use distributed_decryption::{algebra::base_ring::Z64, execution::endpoints::keygen::FhePubKeySet};
use itertools::Itertools;
use k256::ecdsa::SigningKey;
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, FheType, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus,
    KeyGenPreprocStatusEnum, KeyGenRequest, KeyGenResult, ReencryptionRequest,
    ReencryptionResponse, ReencryptionResponsePayload, RequestId, TypedPlaintext,
    VerifyProvenCtRequest, VerifyProvenCtResponse, VerifyProvenCtResponsePayload,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::{
    protobuf_to_alloy_domain_option, PrivDataType, PubDataType, SigncryptionPayload,
    SignedPubDataHandleInternal,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::named::Named;
use tfhe::zk::CompactPkePublicParams;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tonic::transport::{Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;
use tracing::Instrument;

const DECRYPTION_MODE: DecryptionMode = DecryptionMode::PRSSDecrypt;

/// Initialize a threshold KMS server using the DDec initialization protocol.
/// This MUST be done before the server is started.
///
/// # Arguments
///
/// * `config` - Threshold configuration.
///
/// * `public_storage` - Abstract public storage.
///
/// * `private_storage` - Abstract private storage for storing sensitive information.
///
/// * `run_prss` - If this is true, we execute a PRSS setup regardless of whether it already exists in the storage.
///   Otherwise, the setup must be done out of band by calling the init
///   GRPC endpoint, or using the kms-init binary.
#[allow(clippy::too_many_arguments)]
pub async fn threshold_server_init<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
>(
    config: ThresholdParty,
    public_storage: PubS,
    private_storage: PrivS,
    backup_storage: Option<BackS>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    health_reporter: Arc<RwLock<HealthReporter>>,
    shutdown_signal: F,
) -> anyhow::Result<RealThresholdKms<PubS, PrivS, BackS>> {
    let cert_paths = config.get_tls_cert_paths();

    //If no RedisConf is provided, we just use in-memory storage for the preprocessing buckets.
    //NOTE: This should probably only be allowed for testing
    let factory = match config.preproc_redis {
        None => create_memory_factory(),
        Some(conf) => create_redis_factory(format!("PARTY_{}", config.my_id), &conf),
    };
    let num_sessions_preproc = if let Some(x) = config.num_sessions_preproc {
        if x < MINIMUM_SESSIONS_PREPROC {
            MINIMUM_SESSIONS_PREPROC
        } else {
            x
        }
    } else {
        MINIMUM_SESSIONS_PREPROC
    };

    let kms = new_real_threshold_kms(
        config.threshold,
        config.dec_capacity,
        config.min_dec_cache,
        &config.listen_address,
        config.listen_port,
        config.my_id,
        factory,
        num_sessions_preproc,
        config.peers,
        public_storage,
        private_storage,
        backup_storage,
        cert_paths,
        config.core_to_core_net,
        run_prss,
        rate_limiter_conf,
        health_reporter,
        shutdown_signal,
    )
    .await?;

    tracing::info!(
        "Initialization done! Starting threshold KMS server for party {} ...",
        config.my_id
    );
    Ok(kms)
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum ThresholdFheKeysVersioned {
    V0(ThresholdFheKeys),
}

/// These are the internal key materials (public and private)
/// that's needed for decryption, reencryption and verifying a proven input.
#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(ThresholdFheKeysVersioned)]
pub struct ThresholdFheKeys {
    pub private_keys: PrivateKeySet,
    pub sns_key: SwitchAndSquashKey,
    pub decompression_key: Option<DecompressionKey>,
    pub pk_meta_data: KeyGenCallValues,
}

impl Named for ThresholdFheKeys {
    const NAME: &'static str = "ThresholdFheKeys";
}

type BucketMetaStore = Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF8Z128>>>>;

/// Compute all the info of a [FhePubKeySet] and return the result as as [KeyGenCallValues]
pub fn compute_all_info(
    sig_key: &PrivateSigKey,
    fhe_key_set: &FhePubKeySet,
    domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<KeyGenCallValues> {
    //Compute all the info required for storing
    let pub_key_info = compute_info(sig_key, &fhe_key_set.public_key, domain);
    let serv_key_info = compute_info(sig_key, &fhe_key_set.server_key, domain);

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
pub type RealThresholdKms<PubS, PrivS, BackS> = GenericKms<
    RealInitiator<PrivS>,
    RealReencryptor<PubS, PrivS, BackS>,
    RealDecryptor<PubS, PrivS, BackS>,
    RealKeyGenerator<PubS, PrivS, BackS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS, BackS>,
    RealProvenCtVerifier<PubS, PrivS, BackS>,
>;

#[cfg(feature = "insecure")]
pub type RealThresholdKms<PubS, PrivS, BackS> = GenericKms<
    RealInitiator<PrivS>,
    RealReencryptor<PubS, PrivS, BackS>,
    RealDecryptor<PubS, PrivS, BackS>,
    RealKeyGenerator<PubS, PrivS, BackS>,
    RealInsecureKeyGenerator<PubS, PrivS, BackS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS, BackS>,
    RealInsecureCrsGenerator<PubS, PrivS, BackS>,
    RealProvenCtVerifier<PubS, PrivS, BackS>,
>;

#[derive(Debug)]
struct FileNotFoundError {
    message: String,
}

impl std::error::Error for FileNotFoundError {}

impl std::fmt::Display for FileNotFoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[allow(clippy::too_many_arguments)]
async fn new_real_threshold_kms<PubS, PrivS, BackS, F>(
    threshold: u8,
    dec_capacity: usize,
    min_dec_cache: usize,
    listen_address: &str,
    listen_port: u16,
    my_id: usize,
    preproc_factory: Box<dyn PreprocessorFactory>,
    num_sessions_preproc: u16,
    peer_configs: Vec<PeerConf>,
    public_storage: PubS,
    private_storage: PrivS,
    backup_storage: Option<BackS>,
    cert_paths: Option<CertificatePaths>,
    core_to_core_net_conf: Option<CoreToCoreNetworkConfig>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    core_service_health_reporter: Arc<RwLock<HealthReporter>>,
    shutdown_signal: F,
) -> anyhow::Result<RealThresholdKms<PubS, PrivS, BackS>>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tracing::info!(
        "Starting threshold KMS Server. Party ID {my_id}, listening on {listen_address}:{listen_port} ...",
    );

    let sks: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(&private_storage, &PrivDataType::SigningKey.to_string()).await?;
    let sk = get_exactly_one(sks).inspect_err(|e| {
        tracing::error!("signing key hashmap is not exactly 1, {}", e);
    })?;

    // compute corresponding public key and derive address from private sig key
    let pk = SigningKey::verifying_key(sk.sk());
    tracing::info!(
        "Public ethereum address is {}",
        alloy_signer::utils::public_key_to_address(pk)
    );

    // load keys from storage
    let key_info_versioned: HashMap<RequestId, ThresholdFheKeys> =
        read_all_data_versioned(&private_storage, &PrivDataType::FheKeyInfo.to_string()).await?;
    let mut public_key_info = HashMap::new();
    let mut pk_map = HashMap::new();
    for (id, info) in key_info_versioned.clone().into_iter() {
        public_key_info.insert(id.clone(), info.pk_meta_data.clone());

        let pk = read_pk_at_request_id(&public_storage, &id).await?;
        pk_map.insert(id, pk);
    }

    // load crs_info (roughly hashes of CRS) from storage
    let crs_info: HashMap<RequestId, SignedPubDataHandleInternal> =
        read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;

    // load crs from storage
    let crs_map: HashMap<RequestId, CompactPkePublicParams> =
        read_all_data_versioned(&public_storage, &PubDataType::CRS.to_string()).await?;

    let role_assignments: RoleAssignment = peer_configs
        .into_iter()
        .map(|peer_config| peer_config.into_role_identity())
        .collect();

    let own_identity = tonic_some_or_err(
        role_assignments.get(&Role::indexed_by_one(my_id)),
        "Could not find my own identity".to_string(),
    )?;

    let mut server = match &cert_paths {
        Some(cert_bundle) => {
            tracing::info!(
                "Creating server with TLS enabled with certificate: {:?}.",
                cert_bundle.cert
            );

            let certificate = cert_bundle
                .get_certificate()
                .map_err(|e| FileNotFoundError {
                    message: format!("Failed to open file '{}': {}", cert_bundle.cert, e),
                })?;
            tracing::info!("Certificate key loaded");
            let san_strings = distributed_decryption::networking::grpc::extract_san_from_certs(
                &[certificate],
                true,
            )
            .map_err(|e| anyhow!(e))?;
            tracing::info!("San strings loaded");
            let host = own_identity
                .0
                .split(':')
                .next()
                .ok_or_else(|| anyhow!("hostname not found in own_identity"))?
                .to_string();
            if !san_strings.contains(&host) {
                return Err(anyhow_error_and_log(format!(
                    "cannot find hostname {} in SAN {:?}",
                    host, san_strings
                )));
            }

            // now setup the TLS server
            let identity = cert_bundle.get_identity()?;
            tracing::info!("Identity loaded");
            tracing::info!("ca list: {:?}", cert_bundle.calist);
            let ca_cert = cert_bundle.get_flattened_ca_list()?;
            tracing::info!("CA list loaded");
            let tls_config = ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(ca_cert);
            tracing::info!("TLS config setup");
            Server::builder().tls_config(tls_config)?
        }
        _ => {
            tracing::warn!("Creating server without TLS support.");
            Server::builder()
        }
    };

    // This will setup TLS if cert_paths is set to Some(...)
    let (mut threshold_health_reporter, threshold_health_service) =
        tonic_health::server::health_reporter();
    let networking_manager =
        GrpcNetworkingManager::new(own_identity.to_owned(), cert_paths, core_to_core_net_conf);
    let networking_server = networking_manager.new_server();
    let router = server
        .add_service(networking_server)
        .add_service(threshold_health_service);
    let socket_addr = format!("{}:{}", listen_address, listen_port)
        .to_socket_addrs()?
        .next()
        .expect("Failed to parse socket address for internal core network");

    tracing::info!(
        "Starting core-to-core server for identity {} on address {}.",
        own_identity,
        socket_addr
    );
    // Ensure the port is available before starting
    if !crate::util::random_free_port::is_free(socket_addr.port(), &socket_addr.ip()).await {
        return Err(anyhow::anyhow!(
            "socket address {socket_addr} is not free for core/threshold"
        ));
    }
    let abort_handle = tokio::spawn(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(prepare_shutdown_signals(shutdown_signal, tx));

        match router
            .serve_with_shutdown(socket_addr, async {
                // Set the server to be serving when we boot
                threshold_health_reporter.set_serving::<GrpcServer>().await;
                // await is the same as recv on a oneshot channel
                _ = rx.await;
                tracing::info!(
                    "Starting graceful shutdown of core/threshold {}",
                    socket_addr
                );
                threshold_health_reporter
                    .set_not_serving::<GrpcServer>()
                    .await;

                // Allow time for in-flight requests to complete
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    INFLIGHT_REQUEST_WAITING_TIME,
                ))
                .await;
            })
            .await
        {
            Ok(handle) => {
                tracing::info!(
                    "core/threshold on {} shutdown completed successfully",
                    socket_addr
                );
                Ok(handle)
            }
            Err(e) => {
                let msg = format!(
                    "Failed to launch ddec server on {} with error: {:?}",
                    socket_addr, e
                );
                Err(anyhow_error_and_log(msg))
            }
        }
    });

    let networking_strategy: Arc<RwLock<NetworkingStrategy>> = Arc::new(RwLock::new(Box::new(
        move |session_id, roles, network_mode| {
            networking_manager.make_session(session_id, roles, network_mode)
        },
    )));
    let base_kms = BaseKmsStruct::new(sk)?;

    let prss_setup = Arc::new(RwLock::new(None));
    let preproc_buckets = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let preproc_factory = Arc::new(Mutex::new(preproc_factory));
    let crs_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(crs_info)));
    let dkg_pubinfo_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info)));
    let dec_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let reenc_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let ct_verifier_payload_meta_store =
        Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        public_storage,
        private_storage,
        backup_storage,
        pk_map,
        crs_map,
        key_info_versioned,
    );

    let session_preparer = SessionPreparer {
        base_kms: base_kms.new_instance().await,
        threshold,
        my_id,
        role_assignments: role_assignments.clone(),
        networking_strategy,
        prss_setup: prss_setup.clone(),
    };

    {
        // We are only serving after initialization
        core_service_health_reporter
            .write()
            .await
            .set_not_serving::<CoreServiceEndpointServer<RealThresholdKms<PubS, PrivS, BackS>>>()
            .await;
    }
    let initiator = RealInitiator {
        prss_setup: Arc::clone(&prss_setup),
        private_storage: crypto_storage.get_private_storage(),
        session_preparer: session_preparer.new_instance().await,
        health_reporter: core_service_health_reporter.clone(),
    };
    if run_prss {
        tracing::info!(
            "Initializing threshold KMS server and generating a new PRSS Setup for {}",
            my_id
        );
        initiator.init_prss().await?;
    } else {
        tracing::info!(
            "Trying to initializing threshold KMS server and reading PRSS from storage for {}",
            my_id
        );
        if let Err(e) = initiator.init_prss_from_disk().await {
            tracing::warn!(
                "Could not read PRSS Setup from storage for {}: {}. You will need to call the init end-point later before you can use the KMS server",
                my_id,
                e
            );
        }
    }

    let tracker = Arc::new(TaskTracker::new());
    let slow_events = Arc::new(Mutex::new(HashMap::new()));
    let rate_limiter = RateLimiter::new(rate_limiter_conf.unwrap_or_default());

    let reencryptor = RealReencryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        reenc_meta_store,
        session_preparer: session_preparer.new_instance().await,
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
    };

    let decryptor = RealDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        dec_meta_store,
        session_preparer: session_preparer.new_instance().await,
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
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
        prss_setup,
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

    let proven_ct_verifier = RealProvenCtVerifier {
        crypto_storage: crypto_storage.clone(),
        base_kms,
        ct_verifier_payload_meta_store,
        rate_limiter: rate_limiter.clone(),
    };

    let kms = GenericKms::new(
        initiator,
        reencryptor,
        decryptor,
        keygenerator,
        #[cfg(feature = "insecure")]
        insecure_keygenerator,
        keygen_preprocessor,
        crs_generator,
        #[cfg(feature = "insecure")]
        insecure_crs_generator,
        proven_ct_verifier,
        Arc::clone(&tracker),
        Arc::clone(&slow_events),
        abort_handle.abort_handle(),
    );

    Ok(kms)
}

/// This is a shared type between all the modules,
/// it's responsible for creating sessions and holds
/// information on the network setting.
struct SessionPreparer {
    base_kms: BaseKmsStruct,
    threshold: u8,
    my_id: usize,
    role_assignments: RoleAssignment,
    networking_strategy: Arc<RwLock<NetworkingStrategy>>,
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF8Z128>>>>,
}

impl SessionPreparer {
    fn own_identity(&self) -> anyhow::Result<Identity> {
        let id = tonic_some_or_err(
            self.role_assignments.get(&Role::indexed_by_one(self.my_id)),
            "Could not find my own identity in role assignments".to_string(),
        )?;
        Ok(id.to_owned())
    }

    async fn get_networking(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> distributed_decryption::execution::runtime::session::NetworkingImpl {
        let strat = self.networking_strategy.read().await;
        (strat)(session_id, self.role_assignments.clone(), network_mode)
    }

    async fn make_base_session(
        &self,
        session_id: SessionId,
        network_mode: NetworkMode,
    ) -> anyhow::Result<BaseSessionStruct<AesRng, SessionParameters>> {
        let networking = self.get_networking(session_id, network_mode).await;
        let own_identity = self.own_identity()?;

        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            own_identity,
            self.role_assignments.clone(),
        )?;
        let base_session =
            BaseSessionStruct::new(parameters, networking, self.base_kms.new_rng().await)?;
        Ok(base_session)
    }

    async fn prepare_ddec_data_from_requestid(
        &self,
        request_id: &RequestId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF8Z128>> {
        self.prepare_ddec_data_from_sessionid(SessionId(request_id.clone().try_into()?))
            .await
    }

    async fn prepare_ddec_data_from_sessionid(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF8Z128>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
            .await?;
        let prss_setup = tonic_some_or_err(
            self.prss_setup.read().await.clone(),
            "No PRSS setup exists".to_string(),
        )?;
        let prss_state = prss_setup.new_prss_session_state(session_id);

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    /// Retuns a copy of the `SessionPreparer` with a fresh randomness generator so it is safe to use.
    async fn new_instance(&self) -> Self {
        Self {
            base_kms: self.base_kms.new_instance().await,
            threshold: self.threshold,
            my_id: self.my_id,
            role_assignments: self.role_assignments.clone(),
            networking_strategy: self.networking_strategy.clone(),
            prss_setup: self.prss_setup.clone(),
        }
    }
}

pub struct RealInitiator<PrivS: Storage + Send + Sync + 'static> {
    // TODO eventually add mode to allow for nlarge as well.
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF8Z128>>>>,
    private_storage: Arc<Mutex<PrivS>>,
    session_preparer: SessionPreparer,
    health_reporter: Arc<RwLock<HealthReporter>>,
}

impl<PrivS: Storage + Send + Sync + 'static> RealInitiator<PrivS> {
    async fn init_prss_from_disk(&self) -> anyhow::Result<()> {
        // TODO pass epoch ID fom config? (once we have epochs)
        let epoch_id = PRSS_EPOCH_ID;
        let prss_setup_from_file = {
            let guarded_private_storage = self.private_storage.lock().await;
            let base_session = self
                .session_preparer
                .make_base_session(SessionId(epoch_id), NetworkMode::Sync)
                .await?;
            read_versioned_at_request_id(
                &(*guarded_private_storage),
                &RequestId::derive(&format!(
                    "PRSSSetup_ID_{epoch_id}_{}_{}",
                    base_session.parameters.num_parties(),
                    base_session.parameters.threshold()
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS from file with error: {e}");
            })
        };

        // check if a PRSS setup already exists in storage.
        match prss_setup_from_file {
            Ok(prss_setup) => {
                let mut guarded_prss_setup = self.prss_setup.write().await;
                *guarded_prss_setup = Some(prss_setup);
                tracing::info!("Initializing threshold KMS server with PRSS Setup from disk",)
            }
            Err(e) => return Err(e),
        }
        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .write()
                .await
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS, PrivS>>>()
                .await;
        }
        Ok(())
    }

    async fn init_prss(&self) -> anyhow::Result<()> {
        if self.prss_setup.read().await.is_some() {
            return Err(anyhow_error_and_log("PRSS state already exists"));
        }

        let own_identity = self.session_preparer.own_identity()?;
        // Assume we only have one epoch and start with session 1
        let epoch_id = PRSS_EPOCH_ID;
        let session_id = SessionId(epoch_id);
        //PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = self
            .session_preparer
            .make_base_session(session_id, NetworkMode::Sync)
            .await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        let prss_setup_obj: PRSSSetup<ResiduePolyF8Z128> =
            PRSSSetup::robust_init(&mut base_session, &RealVss::default()).await?;

        let mut guarded_prss_setup = self.prss_setup.write().await;
        *guarded_prss_setup = Some(prss_setup_obj.clone());

        // serialize and write PRSS Setup to disk into private storage
        let private_storage = Arc::clone(&self.private_storage);
        let mut priv_storage = private_storage.lock().await;
        store_versioned_at_request_id(
            &mut (*priv_storage),
            &RequestId::derive(&format!(
                "PRSSSetup_ID_{epoch_id}_{}_{}",
                base_session.parameters.num_parties(),
                base_session.parameters.threshold(),
            ))?,
            &prss_setup_obj,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await?;
        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .write()
                .await
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS, PrivS>>>()
                .await;
        }
        tracing::info!("PRSS completed successfully for identity {}.", own_identity);
        Ok(())
    }
}

#[tonic::async_trait]
impl<PrivS: Storage + Send + Sync + 'static> Initiator for RealInitiator<PrivS> {
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        // NOTE: request is not needed because our config is empty at the moment
        self.init_prss().await.map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("PRSS initialization failed with error {}", e),
            )
        })?;
        Ok(Response::new(Empty {}))
    }
}
pub struct RealReencryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    reenc_meta_store: Arc<RwLock<MetaStore<ReencCallValues>>>,
    session_preparer: SessionPreparer,
    tracker: Arc<TaskTracker>,
    rate_limiter: RateLimiter,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealReencryptor<PubS, PrivS, BackS>
{
    /// Helper method for reencryptin which carries out the actual threshold decryption using noise
    /// flooding.
    ///
    /// This function does not perform reencryption in a background thread.
    #[allow(clippy::too_many_arguments)]
    async fn inner_reencrypt(
        session: &mut SmallSession<ResiduePolyF8Z128>,
        protocol: &mut Small,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheType,
        link: Vec<u8>,
        client_enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
    ) -> anyhow::Result<Vec<u8>> {
        let keys = fhe_keys;
        let low_level_ct = deserialize_to_low_level(&fhe_type, ct, &keys.decompression_key)?;
        let partial_signcryption = match partial_decrypt_using_noiseflooding(
            session,
            protocol,
            &keys.sns_key,
            low_level_ct,
            &keys.private_keys,
            DECRYPTION_MODE,
        )
        .await
        {
            Ok((partial_dec_map, time)) => {
                let partial_signcryption = match partial_dec_map
                    .get(&session.session_id().to_string())
                {
                    Some(partial_dec) => {
                        let partial_dec = pack_residue_poly(partial_dec);
                        let partial_dec_serialized = bincode::serialize(&partial_dec)?;
                        let signcryption_msg = SigncryptionPayload {
                            plaintext: TypedPlaintext::from_bytes(partial_dec_serialized, fhe_type),
                            link,
                        };
                        let enc_res = signcrypt(
                            rng,
                            &bincode::serialize(&signcryption_msg)?,
                            client_enc_key,
                            client_address,
                            &sig_key,
                        )?;
                        bincode::serialize(&enc_res)?
                    }
                    None => {
                        return Err(anyhow!(
                            "Reencryption with session ID {} could not be retrived",
                            session.session_id().to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Reencryption completed for type {}. Inner thread took {:?} ms",
                    fhe_type.as_str_name(),
                    time.as_millis()
                );
                partial_signcryption
            }
            Err(e) => return Err(anyhow!("Failed reencryption with noiseflooding: {e}")),
        };
        Ok(partial_signcryption)
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > Reencryptor for RealReencryptor<PubS, PrivS, BackS>
{
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        // Start timing and counting before any operations
        let timer = metrics::METRICS
            .time_operation(OP_REENCRYPT)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_REENCRYPT)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        let permit = self.rate_limiter.start_reenc().await.map_err(|e| {
            let _ = metrics::METRICS.increment_error_counter(OP_REENCRYPT, ERR_RATE_LIMIT_EXCEEDED);
            Status::resource_exhausted(e.to_string())
        })?;

        let inner = request.into_inner();
        tracing::info!(
            "Party {:?} received a new reencryption request with request_id {:?}",
            self.session_preparer.own_identity(),
            inner.request_id
        );
        let (ciphertext, fhe_type, link, client_enc_key, client_address, key_id, req_id) =
            tonic_handle_potential_err(
                validate_reencrypt_req(&inner).await,
                format!("Invalid reencryption request {:?}", inner),
            )?;

        // Add ciphertext ID tag after validation and start timing
        let _timer = if let Ok(timer) = timer {
            // Calculate hash for the ciphertextt
            let (seed1, seed2, seed3, seed4) = HASH_CIPHERTEXT_SEEDS;
            let mut hasher = RandomState::with_seeds(seed1, seed2, seed3, seed4).build_hasher();
            hasher.write(&ciphertext);
            let ciphertext_id = format!("{:06x}", hasher.finish() & 0xFFFFFF); // mask to use only 6 last hex chars

            timer
                .tag(TAG_REQUEST_ID, req_id.to_string())
                .and_then(|b| b.tag(TAG_CIPHERTEXT_ID, ciphertext_id))
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to add tags: {}", e))
        } else {
            timer.map(|b| b.start())
        }
        .ok();

        let mut session = tonic_handle_potential_err(
            self.session_preparer
                .prepare_ddec_data_from_requestid(&req_id)
                .await,
            "Could not prepare ddec data".to_string(),
        )?;
        let mut protocol = Small::new(session.clone());
        let meta_store = Arc::clone(&self.reenc_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let mut rng = self.base_kms.new_rng().await;
        let sig_key = Arc::clone(&self.base_kms.sig_key);

        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        {
            let mut guarded_meta_store = self.reenc_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert reencryption request".to_string(),
            )?;
        }

        tonic_handle_potential_err(
            crypto_storage.refresh_threshold_fhe_keys(&key_id).await,
            "Cannot find threshold keys".to_string(),
        )?;

        // the result of the computation is tracked the crs_meta_store
        self.tracker.spawn(
            async move {
                // explicitly move the rate limiter context
                let _permit = permit;
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await;
                let tmp = match fhe_keys_rlock {
                    Ok(k) => {
                        Self::inner_reencrypt(
                            &mut session,
                            &mut protocol,
                            &mut rng,
                            &ciphertext,
                            fhe_type,
                            link.clone(),
                            &client_enc_key,
                            &client_address,
                            sig_key,
                            k,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                let mut guarded_meta_store = meta_store.write().await;
                match tmp {
                    Ok(partial_dec) => {
                        // We cannot do much if updating the storage fails at this point...
                        let _ =
                            guarded_meta_store.update(&req_id, Ok((fhe_type, link, partial_dec)));
                    }
                    Result::Err(e) => {
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store
                            .update(&req_id, Err(format!("Failed decryption: {e}")));
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let request_id = request.into_inner();
        if !request_id.is_valid() {
            tracing::warn!(
                "The value {} is not a valid request ID!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("The value {} is not a valid request ID!", request_id),
            ));
        }

        // Retrieve the ReencMetaStore object
        let status = {
            let guarded_meta_store = self.reenc_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (fhe_type, link, signcrypted_ciphertext) =
            handle_res_mapping(status, &request_id, "Reencryption").await?;
        let server_verf_key = self.base_kms.get_serialized_verf_key();
        let payload = ReencryptionResponsePayload {
            signcrypted_ciphertext,
            fhe_type: fhe_type.into(),
            digest: link,
            verification_key: server_verf_key,
            party_id: self.session_preparer.my_id as u32,
            degree: self.session_preparer.threshold as u32,
        };

        let sig_payload_vec = tonic_handle_potential_err(
            bincode::serialize(&payload),
            format!("Could not convert payload to bytes {:?}", payload),
        )?;

        let sig = tonic_handle_potential_err(
            self.base_kms.sign(&sig_payload_vec),
            format!("Could not sign payload {:?}", payload),
        )?;
        Ok(Response::new(ReencryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(payload),
        }))
    }
}

pub struct RealDecryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    dec_meta_store: Arc<RwLock<MetaStore<DecCallValues>>>,
    session_preparer: SessionPreparer,
    tracker: Arc<TaskTracker>,
    rate_limiter: RateLimiter,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealDecryptor<PubS, PrivS, BackS>
{
    /// Helper method for decryption which carries out the actual threshold decryption using noise
    /// flooding.
    async fn inner_decrypt<T>(
        session: &mut SmallSession<ResiduePolyF8Z128>,
        protocol: &mut Small,
        ct: &[u8],
        fhe_type: FheType,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    {
        tracing::info!("{:?} started inner_decrypt", session.own_identity());
        let keys = fhe_keys;
        let low_level_ct = deserialize_to_low_level(&fhe_type, ct, &keys.decompression_key)?;
        let raw_decryption = match decrypt_using_noiseflooding(
            session,
            protocol,
            &keys.sns_key,
            low_level_ct,
            &keys.private_keys,
            DECRYPTION_MODE,
            session.own_identity(),
        )
        .await
        {
            Ok((partial_dec, time)) => {
                let raw_decryption = match partial_dec.get(&session.session_id().to_string()) {
                    Some(raw_decryption) => *raw_decryption,
                    None => {
                        return Err(anyhow!(
                            "Decryption with session ID {} could not be retrived",
                            session.session_id().to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Decryption completed on {:?}. Inner thread took {:?} ms",
                    session.own_identity(),
                    time.as_millis()
                );
                raw_decryption
            }
            Err(e) => return Err(anyhow!("Failed decryption with noiseflooding: {e}")),
        };
        Ok(raw_decryption)
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > Decryptor for RealDecryptor<PubS, PrivS, BackS>
{
    #[tracing::instrument(skip(self, request), fields(
        party_id = ?self.session_preparer.my_id,
        operation = "decrypt"
    ))]
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        // Start timing and counting before any operations
        let timer = metrics::METRICS
            .time_operation(OP_DECRYPT)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_DECRYPT)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        let permit = self
            .rate_limiter
            .start_dec()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let inner = request.into_inner();
        tracing::info!(
            request_id = ?inner.request_id,
            "Received new decryption request"
        );

        let (ciphertexts, req_digest, key_id, req_id, eip712_domain, acl_address) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    request_id = ?inner.request_id,
                    "Failed to validate decrypt request"
                );
                let _ = metrics::METRICS.increment_error_counter(OP_DECRYPT, ERR_DECRYPTION_FAILED);
                e
            })?;

        // Add ciphertext ID tag after validation and start timing
        let _timer = if let Ok(timer) = timer {
            timer
                .tag(TAG_REQUEST_ID, req_id.to_string())
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to add tag request id: {}", e))
        } else {
            timer.map(|b| b.start())
        }
        .ok();

        tracing::debug!(
            request_id = ?req_id,
            key_id = ?key_id,
            ciphertexts_count = ciphertexts.len(),
            "Starting decryption process"
        );
        // the session id that is used between the threshold engines to identify the decryption session, derived from the request id
        let internal_sid = tonic_handle_potential_err(
            u128::try_from(req_id.clone()),
            format!("Invalid request id {:?}", inner),
        )?;

        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        {
            let mut guarded_meta_store = self.dec_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert decryption into meta store".to_string(),
            )?;
        }

        tonic_handle_potential_err(
            self.crypto_storage
                .refresh_threshold_fhe_keys(&key_id)
                .await,
            "Cannot find threshold keys".to_string(),
        )?;

        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();

        let mut dec_tasks = Vec::new();

        // iterate over ciphertexts in this batch and decrypt each in their own session (so that it happens in parallel)
        for (idx, ct) in ciphertexts.into_iter().enumerate() {
            let internal_sid = SessionId::from(internal_sid + idx as u128);
            let key_id = key_id.clone();

            let mut session = tonic_handle_potential_err(
                self.session_preparer
                    .prepare_ddec_data_from_sessionid(internal_sid)
                    .await,
                "Could not prepare ddec data for reencryption".to_string(),
            )?;

            let mut protocol = Small::new(session.clone());
            let crypto_storage = self.crypto_storage.clone();

            // we do not need to hold the handle,
            // the result of the computation is tracked by the dec_meta_store
            let decrypt_future = || async move {
                let fhe_type = if let Ok(f) = FheType::try_from(ct.fhe_type) {
                    f
                } else {
                    return Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed due to wrong fhe type: {}",
                        ct.fhe_type
                    )));
                };

                let ciphertext = &ct.ciphertext;
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await?;

                let res_plaintext = match fhe_type {
                    FheType::Euint2048 => Self::inner_decrypt::<tfhe::integer::bigint::U2048>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(TypedPlaintext::from_u2048),
                    FheType::Euint1024 => Self::inner_decrypt::<tfhe::integer::bigint::U1024>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(TypedPlaintext::from_u1024),
                    FheType::Euint512 => Self::inner_decrypt::<tfhe::integer::bigint::U512>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(TypedPlaintext::from_u512),
                    FheType::Euint256 => Self::inner_decrypt::<tfhe::integer::U256>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(TypedPlaintext::from_u256),
                    FheType::Euint160 => Self::inner_decrypt::<tfhe::integer::U256>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(TypedPlaintext::from_u160),
                    FheType::Euint128 => Self::inner_decrypt::<u128>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(|x| TypedPlaintext::new(x, fhe_type)),
                    FheType::Ebool
                    | FheType::Euint4
                    | FheType::Euint8
                    | FheType::Euint16
                    | FheType::Euint32
                    | FheType::Euint64 => Self::inner_decrypt::<u64>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(|x| TypedPlaintext::new(x as u128, fhe_type)),
                };
                match res_plaintext {
                    Ok(plaintext) => Ok((idx, plaintext)),
                    Result::Err(e) => Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed:{}",
                        e
                    ))),
                }
            };
            dec_tasks.push(
                self.tracker
                    .spawn(decrypt_future().instrument(tracing::Span::current())),
            );
        }

        // collect decryption results in async mgmt task so we can return from this call without waiting for the decryption(s) to finish
        let meta_store = Arc::clone(&self.dec_meta_store);
        let sigkey = Arc::clone(&self.base_kms.sig_key);
        let dec_sig_future = |_permit| async move {
            // NOTE: _permit should be dropped at the end of this function
            let mut decs = HashMap::new();
            while let Some(resp) = dec_tasks.pop() {
                match resp.await {
                    Ok(Ok((idx, plaintext))) => {
                        decs.insert(idx, plaintext);
                    }
                    _ => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store
                            .update(&req_id, Err("Failed decryption.".to_string()));
                        // exit mgmt task early in case of error
                        return;
                    }
                }
            }

            let pts: Vec<_> = decs
                .keys()
                .sorted()
                .map(|idx| decs.get(idx).unwrap().clone()) // unwrap is fine here, since we iterate over all keys.
                .collect();

            // sign the plaintexts and handles for external verification (in the fhevm)
            let external_sig = if let (Some(domain), Some(acl_address)) =
                (eip712_domain, acl_address)
            {
                compute_external_pt_signature(&sigkey, ext_handles_bytes, &pts, domain, acl_address)
            } else {
                tracing::warn!(
                    "Skipping external signature computation due to missing domain or acl address"
                );
                vec![]
            };

            let mut guarded_meta_store = meta_store.write().await;
            let _ = guarded_meta_store.update(&req_id, Ok((req_digest.clone(), pts, external_sig)));
        };
        self.tracker
            .spawn(dec_sig_future(permit).instrument(tracing::Span::current()));

        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let status = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (req_digest, plaintexts, external_signature) =
            handle_res_mapping(status, &request_id, "Decryption").await?;

        let server_verf_key = self.base_kms.get_serialized_verf_key();
        let sig_payload = DecryptionResponsePayload {
            plaintexts,
            verification_key: server_verf_key,
            digest: req_digest,
            external_signature: Some(external_signature),
        };

        let sig_payload_vec = tonic_handle_potential_err(
            bincode::serialize(&sig_payload),
            format!("Could not convert payload to bytes {:?}", sig_payload),
        )?;

        let sig = tonic_handle_potential_err(
            self.base_kms.sign(&sig_payload_vec),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload),
        }))
    }
}

pub struct RealKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    // TODO eventually add mode to allow for nlarge as well.
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
    session_preparer: SessionPreparer,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    tracker: Arc<TaskTracker>,
    // Map of ongoing key generation tasks
    ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    rate_limiter: RateLimiter,
}

#[cfg(feature = "insecure")]
pub struct RealInsecureKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
> {
    real_key_generator: RealKeyGenerator<PubS, PrivS, BackS>,
}

#[cfg(feature = "insecure")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > RealInsecureKeyGenerator<PubS, PrivS, BackS>
{
    async fn from_real_keygen(value: &RealKeyGenerator<PubS, PrivS, BackS>) -> Self {
        Self {
            real_key_generator: RealKeyGenerator {
                base_kms: value.base_kms.new_instance().await,
                crypto_storage: value.crypto_storage.clone(),
                preproc_buckets: Arc::clone(&value.preproc_buckets),
                dkg_pubinfo_meta_store: Arc::clone(&value.dkg_pubinfo_meta_store),
                session_preparer: value.session_preparer.new_instance().await,
                tracker: Arc::clone(&value.tracker),
                ongoing: Arc::clone(&value.ongoing),
                rate_limiter: value.rate_limiter.clone(),
            },
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > InsecureKeyGenerator for RealInsecureKeyGenerator<PubS, PrivS, BackS>
{
    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        tracing::info!("starting insecure key gen in RealInsecureKeyGenerator");
        self.real_key_generator.inner_key_gen(request, true).await
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        self.real_key_generator.inner_get_result(request).await
    }
}

// This is an enum to determine whether to start the dkg
// in a secure mode. If the secure mode is selected,
// a preprocessing handle must be given.
// This is essentially the same as an Option, but it's
// more clear to label the variants as `Secure`
// and `Insecure`.
enum PreprocHandleWithMode {
    Secure(Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF8Z128>>>>),
    Insecure,
}

impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > RealKeyGenerator<PubS, PrivS, BackS>
{
    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        preproc_handle_w_mode: PreprocHandleWithMode,
        req_id: RequestId,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        // Update status
        {
            let mut guarded_meta_store = self.dkg_pubinfo_meta_store.write().await;
            guarded_meta_store.insert(&req_id)?;
        }

        // Create the base session necessary to run the DKG
        let base_session = {
            let session_id = SessionId(req_id.clone().try_into()?);
            self.session_preparer
                .make_base_session(session_id, NetworkMode::Async)
                .await?
        };

        // Clone all the Arcs to give them to the tokio thread
        let meta_store = Arc::clone(&self.dkg_pubinfo_meta_store);
        let meta_store_cancelled = Arc::clone(&self.dkg_pubinfo_meta_store);
        let sk = Arc::clone(&self.base_kms.sig_key);
        let crypto_storage = self.crypto_storage.clone();
        let crypto_storage_cancelled = self.crypto_storage.clone();
        let eip712_domain_copy = eip712_domain.cloned();

        let token = CancellationToken::new();
        {
            self.ongoing
                .lock()
                .await
                .insert(req_id.clone(), token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);
        self.tracker
            .spawn(async move {
                tokio::select! {
                    () = Self::key_gen_background(&req_id, base_session, meta_store, crypto_storage, preproc_handle_w_mode, sk, dkg_params, eip712_domain_copy, permit) => {
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&req_id);
                        tracing::info!("Key generation of request {} exiting normally.", req_id);
                    },
                    () = token.cancelled() => {
                        tracing::error!("Key generation of request {} exiting before completion because of a cancellation event.", req_id);
                        // Delete any persistant data. Since we only cancel during shutdown we can ignore cleaning up the meta store since it is only in RAM
                        let guarded_meta_store = meta_store_cancelled.write().await;
                        crypto_storage_cancelled.purge_key_material(&req_id, guarded_meta_store).await;
                        tracing::info!("Trying to clean up any already written material.")
                    },
                }
            }.instrument(tracing::Span::current()));
        Ok(())
    }

    async fn inner_key_gen(
        &self,
        request: Request<KeyGenRequest>,
        insecure: bool,
    ) -> Result<Response<Empty>, Status> {
        let permit = self
            .rate_limiter
            .start_keygen()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let req = request.into_inner();
        tracing::info!("Keygen Request ID: {:?}", req.request_id);
        let request_id = tonic_some_or_err(
            req.request_id.clone(),
            "Request ID is not set (inner key gen)".to_string(),
        )?;

        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not valid!", request_id),
            ));
        }

        //Retrieve kg params and preproc_id
        let dkg_params = tonic_handle_potential_err(
            retrieve_parameters(req.params),
            "Parameter choice is not recognized".to_string(),
        )?;

        let preproc_handle = if insecure {
            PreprocHandleWithMode::Insecure
        } else {
            let preproc_id = tonic_some_or_err(
                req.preproc_id.clone(),
                "Pre-Processing ID is not set".to_string(),
            )?;
            let preproc = {
                let mut map = self.preproc_buckets.write().await;
                map.delete(&preproc_id)
            };
            PreprocHandleWithMode::Secure(
                handle_res_mapping(preproc, &preproc_id, "Preprocessing").await?,
            )
        };

        let eip712_domain = protobuf_to_alloy_domain_option(req.domain.as_ref());

        tonic_handle_potential_err(
            self.launch_dkg(
                dkg_params,
                preproc_handle,
                request_id.clone(),
                eip712_domain.as_ref(),
                permit,
            )
            .await,
            format!("Error launching dkg for request ID {request_id}"),
        )?;

        //Always answer with Empty
        Ok(Response::new(Empty {}))
    }

    async fn inner_get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let status = {
            let guarded_meta_store = self.dkg_pubinfo_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let res = handle_res_mapping(status, &request_id, "DKG").await?;
        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id),
            key_results: convert_key_response(res),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn key_gen_background(
        req_id: &RequestId,
        mut base_session: BaseSessionStruct<AesRng, SessionParameters>,
        meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
        preproc_handle_w_mode: PreprocHandleWithMode,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        eip712_domain: Option<alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit;
        let start = Instant::now();
        let dkg_res = match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure => {
                initialize_key_material(&mut base_session, params).await
            }
            PreprocHandleWithMode::Secure(preproc_handle) => {
                let mut preproc_handle = preproc_handle.lock().await;
                distributed_keygen_z128(&mut base_session, preproc_handle.as_mut(), params).await
            }
        };

        //Make sure the dkg ended nicely
        let (mut pub_key_set, private_keys) = match dkg_res {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => {
                //If dkg errored out, update status
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(req_id, Err(e.to_string()));
                return;
            }
        };

        //Make sure we do have a SnS key
        let sns_key = match pub_key_set.sns_key.clone() {
            Some(sns_key) => sns_key,
            None => {
                //If sns key is missing, update status
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(req_id, Err("Missing SNS key".to_string()));
                return;
            }
        };

        //Compute all the info required for storing
        let info = match compute_all_info(&sk, &pub_key_set, eip712_domain.as_ref()) {
            Ok(info) => info,
            Err(_) => {
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage
                    .update(req_id, Err("Failed to compute key info".to_string()));
                return;
            }
        };

        //Retrieve decompression key if there's one
        let (raw_server_key, raw_ksk_material, raw_compression_key, raw_decompression_key, raw_tag) =
            pub_key_set.server_key.into_raw_parts();
        let decompression_key = raw_decompression_key.clone();

        pub_key_set.server_key = tfhe::ServerKey::from_raw_parts(
            raw_server_key,
            raw_ksk_material,
            raw_compression_key,
            raw_decompression_key,
            raw_tag,
        );

        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys,
            sns_key,
            decompression_key,
            pk_meta_data: info.clone(),
        };
        crypto_storage
            .write_threshold_keys_with_meta_store(
                req_id,
                threshold_fhe_keys,
                pub_key_set,
                info,
                meta_store,
            )
            .await;

        tracing::info!(
            "DKG protocol took {} ms to complete for request {req_id}",
            start.elapsed().as_millis()
        );
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > KeyGenerator for RealKeyGenerator<PubS, PrivS, BackS>
{
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        self.inner_key_gen(request, false).await
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        self.inner_get_result(request).await
    }
}

pub struct RealPreprocessor {
    // TODO eventually add mode to allow for nlarge as well.
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF8Z128>>>>,
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    preproc_factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
    num_sessions_preproc: u16,
    session_preparer: SessionPreparer,
    tracker: Arc<TaskTracker>,
    ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    rate_limiter: RateLimiter,
}

impl RealPreprocessor {
    async fn launch_dkg_preproc(
        &self,
        dkg_params: DKGParams,
        request_id: RequestId,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }
        // Derive a sequence of sessionId from request_id
        let session_id: u128 = request_id.clone().try_into()?;
        let own_identity = self.session_preparer.own_identity()?;

        let sids: Vec<_> = (session_id..session_id + self.num_sessions_preproc as u128).collect();
        let base_sessions = {
            let mut res = Vec::with_capacity(sids.len());
            for sid in sids {
                let base_session = self
                    .session_preparer
                    .make_base_session(SessionId(sid), NetworkMode::Sync)
                    .await?;
                res.push(base_session)
            }
            res
        };

        let factory = Arc::clone(&self.preproc_factory);
        let bucket_store = Arc::clone(&self.preproc_buckets);
        let bucket_store_cancellation = Arc::clone(&self.preproc_buckets);

        let prss_setup = tonic_some_or_err(
            (*self.prss_setup.read().await).clone(),
            "No PRSS setup exists".to_string(),
        )?;
        let token = CancellationToken::new();
        {
            self.ongoing
                .lock()
                .await
                .insert(request_id.clone(), token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);
        self.tracker.spawn(
            async move {
                 tokio::select! {
                    () = Self::preprocessing_background(&request_id, base_sessions, bucket_store, prss_setup, own_identity, dkg_params, factory, permit) => {
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&request_id);
                        tracing::info!("Preprocessing of request {} exiting normally.", &request_id);
                    },
                    () = token.cancelled() => {
                        tracing::error!("Preprocessing of request {} exiting before completion because of a cancellation event.", &request_id);
                        // Delete any stored data. Since we only cancel during shutdown we can ignore cleaning up the meta store since it is only in RAM
                        let mut guarded_bucket_store = bucket_store_cancellation.write().await;
                        let _ = guarded_bucket_store.delete(&request_id);
                        tracing::info!("Trying to clean up any already written material.")
                    },
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn preprocessing_background(
        req_id: &RequestId,
        base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
        bucket_store: Arc<RwLock<MetaStore<BucketMetaStore>>>,
        prss_setup: PRSSSetup<ResiduePolyF8Z128>,
        own_identity: Identity,
        params: DKGParams,
        factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit; // dropped at the end of the function
        fn create_sessions(
            base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
            prss_setup: PRSSSetup<ResiduePolyF8Z128>,
        ) -> Vec<SmallSession<ResiduePolyF8Z128>> {
            base_sessions
                .into_iter()
                .map(|base_session| {
                    let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap()
                })
                .collect_vec()
        }
        let sessions = create_sessions(base_sessions, prss_setup);
        let orchestrator = {
            let mut factory_guard = factory.lock().await;
            let factory = factory_guard.as_mut();
            PreprocessingOrchestrator::<ResiduePolyF8Z128>::new(factory, params).unwrap()
        };
        tracing::info!("Starting Preproc Orchestration on P[{:?}]", own_identity);
        let preproc_result = orchestrator
            .orchestrate_small_session_dkg_processing(sessions)
            .await;
        //write the preproc handle to the bucket store
        let handle_update = match preproc_result {
            Ok((_, preproc_handle)) => Ok(Arc::new(Mutex::new(preproc_handle))),
            Err(error) => Err(error.to_string()),
        };
        let mut guarded_meta_store = bucket_store.write().await;
        // We cannot do much if updating the storage fails at this point...
        let _ = guarded_meta_store.update(req_id, handle_update);
        tracing::info!("Preproc Finished P[{:?}]", own_identity);
    }
}

#[tonic::async_trait]
impl KeyGenPreprocessor for RealPreprocessor {
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        let permit = self
            .rate_limiter
            .start_preproc()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (key_gen_preproc)".to_string(),
        )?;

        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not valid!", request_id),
            ));
        }

        //Retrieve the DKG parameters
        let dkg_params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;

        //Ensure there's no entry in preproc buckets for that request_id
        let entry_exists = {
            let map = self.preproc_buckets.read().await;
            map.exists(&request_id)
        };

        //If the entry did not exist before, start the preproc
        if !entry_exists {
            tracing::info!("Starting preproc generation for Request ID {}", request_id);
            tonic_handle_potential_err(self.launch_dkg_preproc(dkg_params, request_id.clone(), permit).await, format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {:?}",dkg_params))?;
        } else {
            tracing::warn!(
                "Tried to generate preproc multiple times for the same Request ID {} -- skipped it!",
                request_id
            );
        }
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        let request_id = request.into_inner();
        let response = {
            let map = self.preproc_buckets.read().await;
            //TODO(#1792): For now we do not wait here as we do for other get_result
            //In any case, we may want to refactor this bit as it is the sole one
            //using a custom enum for status instead of the tonic ones
            match map.retrieve(&request_id) {
                None => {
                    tracing::warn!(
                        "Requesting status for request id that does not exist {request_id}"
                    );
                    KeyGenPreprocStatusEnum::Missing
                }
                Some(cell) => {
                    if cell.is_set() {
                        let result = cell.get().await;
                        if let Err(e) = result {
                            tracing::warn!(
                        "Error while generating keygen preproc for request id {request_id} : {e}"
                    );
                            KeyGenPreprocStatusEnum::Error
                        } else {
                            KeyGenPreprocStatusEnum::Finished
                        }
                    } else {
                        tracing::info!("Preproc for request id {request_id} is in progress.");
                        KeyGenPreprocStatusEnum::InProgress
                    }
                }
            }
        };
        Ok(Response::new(KeyGenPreprocStatus {
            result: response.into(),
        }))
    }
}

pub struct RealCrsGenerator<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    crs_meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    session_preparer: SessionPreparer,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    tracker: Arc<TaskTracker>,
    // Map of ongoing crs generation tasks
    ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    rate_limiter: RateLimiter,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealCrsGenerator<PubS, PrivS, BackS>
{
    async fn inner_crs_gen_from_request(
        &self,
        request: Request<CrsGenRequest>,
        insecure: bool,
    ) -> Result<Response<Empty>, Status> {
        let permit = self
            .rate_limiter
            .start_crsgen()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let req = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            req.request_id
        );

        let dkg_params = retrieve_parameters(req.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::NotFound,
                format!("Can not retrieve fhe parameters with error {e}"),
            )
        })?;
        let crs_params = dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let witness_dim = tonic_handle_potential_err(
            compute_witness_dim(&crs_params, req.max_num_bits.map(|x| x as usize)),
            "witness dimension computation failed".to_string(),
        )?;

        let req_id = req.request_id.ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                "missing request ID in CRS generation",
            )
        })?;

        let eip712_domain = protobuf_to_alloy_domain_option(req.domain.as_ref());

        self.inner_crs_gen(
            req_id,
            witness_dim,
            req.max_num_bits,
            dkg_params,
            eip712_domain.as_ref(),
            permit,
            insecure,
        )
        .await
        .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    #[allow(clippy::too_many_arguments)]
    async fn inner_crs_gen(
        &self,
        req_id: RequestId,
        witness_dim: usize,
        max_num_bits: Option<u32>,
        dkg_params: DKGParams,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
        insecure: bool,
    ) -> anyhow::Result<()> {
        {
            let mut guarded_meta_store = self.crs_meta_store.write().await;
            guarded_meta_store.insert(&req_id).map_err(|e| {
                anyhow_error_and_log(format!(
                    "failed to insert to meta store in inner_crs_gen with error: {e}"
                ))
            })?;
        }

        let session_id = SessionId(req_id.clone().try_into()?);
        let session = self
            .session_preparer
            .prepare_ddec_data_from_sessionid(session_id)
            .await?
            .to_base_session()?;

        let meta_store = Arc::clone(&self.crs_meta_store);
        let meta_store_cancelled = Arc::clone(&self.crs_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let crypto_storage_cancelled = self.crypto_storage.clone();
        let eip712_domain_copy = eip712_domain.cloned();

        // we need to clone the signature key because it needs to be given
        // the thread that spawns the CRS ceremony
        let sk = self.base_kms.sig_key.clone();

        // we do not need to hold the handle,
        // the result of the computation is tracked the crs_meta_store
        let rng = self.base_kms.new_rng().await.to_owned();

        let token = CancellationToken::new();
        {
            self.ongoing
                .lock()
                .await
                .insert(req_id.clone(), token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);
        self.tracker
            .spawn(async move {
                tokio::select! {
                    () = Self::crs_gen_background(&req_id, witness_dim, max_num_bits, session, rng, meta_store, crypto_storage, sk, dkg_params.to_owned(), eip712_domain_copy, permit, insecure) => {
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&req_id);
                        tracing::info!("CRS generation of request {} exiting normally.", req_id);
                    },
                    () = token.cancelled() => {
                        tracing::error!("CRS generation of request {} exiting before completion because of a cancellation event.", req_id);
                        // Delete any persistant data. Since we only cancel during shutdown we can ignore cleaning up the meta store since it is only in RAM
                        let guarded_meta_store= meta_store_cancelled.write().await;
                        crypto_storage_cancelled.purge_crs_material(&req_id, guarded_meta_store).await;
                        tracing::info!("Trying to clean up any already written material.")
                    },
                }
            }.instrument(tracing::Span::current()));
        Ok(())
    }

    async fn inner_get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
        let status = {
            let guarded_meta_store = self.crs_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let crs_data = handle_res_mapping(status, &request_id, "CRS generation").await?;
        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(crs_data.into()),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn crs_gen_background(
        req_id: &RequestId,
        witness_dim: usize,
        max_num_bits: Option<u32>,
        mut base_session: BaseSessionStruct<AesRng, SessionParameters>,
        rng: AesRng,
        meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        eip712_domain: Option<alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
        insecure: bool,
    ) {
        let _permit = permit;
        let crs_start_timer = Instant::now();
        let my_role = base_session
            .my_role()
            .map_err(|e| tracing::error!("Error getting role: {e}"))
            .expect("No role found in the session");
        let pke_params = params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let pp = if insecure {
            // We let the first party sample the seed (we are using 1-based party IDs)
            let input_party_id = 1;
            if my_role.one_based() == input_party_id {
                let crs_res =
                    async_generate_crs(&sk, rng, params, max_num_bits, eip712_domain.as_ref())
                        .await;
                let crs = match crs_res {
                    Ok((crs, _)) => crs,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(req_id, Err(e.to_string()));
                        return;
                    }
                };
                transfer_crs(&base_session, Some(crs), input_party_id).await
            } else {
                transfer_crs(&base_session, None, input_party_id).await
            }
        } else {
            // real, secure ceremony (insecure = false)
            let real_ceremony = RealCeremony::default();
            let internal_pp = real_ceremony
                .execute::<Z64, _, _>(&mut base_session, witness_dim, max_num_bits)
                .await;
            internal_pp.and_then(|internal| internal.try_into_tfhe_zk_pok_pp(&pke_params))
        };
        let res_info_pp =
            pp.and_then(|pp| compute_info(&sk, &pp, eip712_domain.as_ref()).map(|info| (pp, info)));

        let (pp_id, meta_data) = match res_info_pp {
            Ok((meta, pp_id)) => (meta, pp_id),
            Err(e) => {
                let mut guarded_meta_store = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_store.update(req_id, Err(e.to_string()));
                return;
            }
        };

        crypto_storage
            .write_crs_with_meta_store(req_id, pp_id, meta_data, meta_store)
            .await;

        let crs_stop_timer = Instant::now();
        let elapsed_time = crs_stop_timer.duration_since(crs_start_timer);
        tracing::info!(
            "CRS stored. CRS ceremony time was {:?} ms",
            (elapsed_time).as_millis()
        );
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > CrsGenerator for RealCrsGenerator<PubS, PrivS, BackS>
{
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        self.inner_crs_gen_from_request(request, false).await
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        self.inner_get_result(request).await
    }
}

#[cfg(feature = "insecure")]
pub struct RealInsecureCrsGenerator<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    real_crs_generator: RealCrsGenerator<PubS, PrivS, BackS>,
}

#[cfg(feature = "insecure")]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealInsecureCrsGenerator<PubS, PrivS, BackS>
{
    async fn from_real_crsgen(value: &RealCrsGenerator<PubS, PrivS, BackS>) -> Self {
        Self {
            real_crs_generator: RealCrsGenerator {
                base_kms: value.base_kms.new_instance().await,
                crypto_storage: value.crypto_storage.clone(),
                crs_meta_store: Arc::clone(&value.crs_meta_store),
                session_preparer: value.session_preparer.new_instance().await,
                tracker: Arc::clone(&value.tracker),
                ongoing: Arc::clone(&value.ongoing),
                rate_limiter: value.rate_limiter.clone(),
            },
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > InsecureCrsGenerator for RealInsecureCrsGenerator<PubS, PrivS, BackS>
{
    async fn insecure_crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        tracing::info!("starting insecure crs gen in RealInsecureCrsGenerator");
        self.real_crs_generator
            .inner_crs_gen_from_request(request, true)
            .await
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        self.real_crs_generator.inner_get_result(request).await
    }
}

pub struct RealProvenCtVerifier<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    ct_verifier_payload_meta_store: Arc<RwLock<MetaStore<VerifyProvenCtResponsePayload>>>,
    rate_limiter: RateLimiter,
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > ProvenCtVerifier for RealProvenCtVerifier<PubS, PrivS, BackS>
{
    async fn verify(
        &self,
        request: Request<VerifyProvenCtRequest>,
    ) -> Result<Response<Empty>, Status> {
        let permit = self
            .rate_limiter
            .start_verify_proven_ct()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let meta_store = Arc::clone(&self.ct_verifier_payload_meta_store);
        let sigkey = Arc::clone(&self.base_kms.sig_key);
        let crypto_storage = self.crypto_storage.clone();

        // Check well-formedness of the request and return an error early if there's an error
        let request_id = request
            .get_ref()
            .request_id
            .as_ref()
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "missing request ID".to_string(),
                )
            })?
            .clone();
        validate_request_id(&request_id)?;

        non_blocking_verify_proven_ct(
            (&crypto_storage).into(),
            meta_store,
            request_id.clone(),
            request.into_inner(),
            sigkey,
            permit,
        )
        .await
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("non_blocking_verify_proven_ct failed for request_id {request_id} ({e})"),
            )
        })?;

        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<VerifyProvenCtResponse>, Status> {
        let meta_store = Arc::clone(&self.ct_verifier_payload_meta_store);
        get_verify_proven_ct_result(&self.base_kms, meta_store, request).await
    }
}

#[cfg(test)]
mod tests {
    use kms_grpc::kms::v1::RequestId;

    use crate::{
        client::test_tools,
        consts::{DEFAULT_AMOUNT_PARTIES, DEFAULT_THRESHOLD, PRSS_EPOCH_ID},
        util::key_setup::test_tools::purge,
        vault::storage::file::FileStorage,
        vault::storage::StorageType,
    };

    #[tokio::test]
    #[serial_test::serial]
    #[tracing_test::traced_test]
    async fn prss_disk_test() {
        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        for i in 1..=DEFAULT_AMOUNT_PARTIES {
            let cur_pub = FileStorage::new(None, StorageType::PUB, Some(i)).unwrap();
            pub_storage.push(cur_pub);
            let cur_priv = FileStorage::new(None, StorageType::PRIV, Some(i)).unwrap();

            // make sure the store does not contain any PRSS info (currently stored under ID 1)
            let req_id = &RequestId::derive(&format!(
                "PRSSSetup_ID_{PRSS_EPOCH_ID}_{}_{}",
                DEFAULT_AMOUNT_PARTIES, DEFAULT_THRESHOLD
            ))
            .unwrap();
            purge(None, None, &req_id.to_string(), DEFAULT_AMOUNT_PARTIES).await;

            priv_storage.push(cur_priv);
        }

        // create parties and run PrssSetup
        let core_handles = test_tools::setup_threshold_no_client(
            DEFAULT_THRESHOLD as u8,
            pub_storage.clone(),
            priv_storage.clone(),
            true,
            None,
        )
        .await;
        assert_eq!(core_handles.len(), DEFAULT_AMOUNT_PARTIES);

        // shut parties down
        for h in core_handles.into_values() {
            h.assert_shutdown().await;
        }

        // check that PRSS was created (and not read from disk)
        assert!(!logs_contain(
            "Initializing threshold KMS server with PRSS Setup from disk"
        ));
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // create parties again without running PrssSetup this time (it should now be read from disk)
        let core_handles = test_tools::setup_threshold_no_client(
            DEFAULT_THRESHOLD as u8,
            pub_storage,
            priv_storage,
            false,
            None,
        )
        .await;
        assert_eq!(core_handles.len(), DEFAULT_AMOUNT_PARTIES);

        // check that PRSS was not created, but instead read from disk now
        assert!(logs_contain(
            "Initializing threshold KMS server with PRSS Setup from disk"
        ));

        for h in core_handles.into_values() {
            h.assert_shutdown().await;
        }
    }
}
