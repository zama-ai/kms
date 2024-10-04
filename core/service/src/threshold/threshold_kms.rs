use crate::conf::threshold::{PeerConf, ThresholdConfig};
use crate::consts::{MINIMUM_SESSIONS_PREPROC, PRSS_EPOCH_ID};
use crate::cryptography::central_kms::{compute_info, BaseKmsStruct};
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicEncKey};
use crate::cryptography::signcryption::signcrypt;
use crate::kms::core_service_endpoint_server::CoreServiceEndpointServer;
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, FheType, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus,
    KeyGenPreprocStatusEnum, KeyGenRequest, KeyGenResult, ReencryptionRequest,
    ReencryptionResponse, ReencryptionResponsePayload, RequestId, ZkVerifyRequest,
    ZkVerifyResponse, ZkVerifyResponsePayload,
};
use crate::rpc::central_rpc::{
    convert_key_response, get_zk_verify_result, non_blocking_zk_verify, retrieve_parameters,
    tonic_handle_potential_err, tonic_some_or_err, validate_decrypt_req, validate_reencrypt_req,
    validate_request_id,
};
use crate::rpc::rpc_types::{
    compute_external_pt_signature, BaseKms, Plaintext, PrivDataType, PubDataType,
    SigncryptionPayload, SignedPubDataHandleInternal, WrappedPublicKey, CURRENT_FORMAT_VERSION,
};
use crate::storage::{
    delete_at_request_id, delete_pk_at_request_id, read_all_data_versioned,
    read_versioned_at_request_id, store_pk_at_request_id, store_versioned_at_request_id, Storage,
};
#[cfg(feature = "insecure")]
use crate::threshold::generic::InsecureKeyGenerator;
use crate::threshold::generic::{
    CrsGenerator, Decryptor, GenericKms, Initiator, KeyGenPreprocessor, KeyGenerator, Reencryptor,
    ZkVerifier,
};
use crate::util::meta_store::{handle_res_mapping, HandlerStatus, MetaStore};
use crate::{anyhow_error_and_log, get_exactly_one};
use aes_prng::AesRng;
use anyhow::anyhow;
use conf_trace::telemetry::{accept_trace, make_span, record_trace_id};
use distributed_decryption::algebra::residue_poly::ResiduePoly128;
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
};
use distributed_decryption::execution::small_execution::prss::PRSSSetup;
use distributed_decryption::execution::tfhe_internals::parameters::{Ciphertext64, DKGParams};
use distributed_decryption::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use distributed_decryption::execution::tfhe_internals::test_feature::initialize_key_material;
use distributed_decryption::execution::zk::ceremony::{
    compute_witness_dim, Ceremony, RealCeremony,
};
use distributed_decryption::networking::grpc::{CoreToCoreNetworkConfig, GrpcNetworkingManager};
use distributed_decryption::networking::NetworkMode;
use distributed_decryption::networking::NetworkingStrategy;
use distributed_decryption::session_id::SessionId;
use distributed_decryption::{algebra::base_ring::Z64, execution::endpoints::keygen::FhePubKeySet};
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::integer::IntegerCiphertext;
use tfhe::named::Named;
use tfhe::{
    FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32,
    FheUint4, FheUint512, FheUint64, FheUint8, Versionize,
};
use tfhe_versionable::VersionsDispatch;
use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tonic::transport::{Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tower_http::trace::TraceLayer;

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
/// * `run_prss` - If this is true, a setup protocol will be executed in this funciton.
///   Otherwise, the setup must be done out of band by calling the init
///   GRPC endpoint, or using the kms-init binary.
pub async fn threshold_server_init<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    config: ThresholdConfig,
    public_storage: PubS,
    private_storage: PrivS,
    run_prss: bool,
) -> anyhow::Result<RealThresholdKms<PubS, PrivS>> {
    let cert_paths = config.get_tls_cert_paths();

    //If no RedisConf is provided, we just use in-memory storage for the preprocessing buckets.
    //NOTE: This should probably only be allowed for testing
    let factory = match config.preproc_redis_conf {
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
        &config.listen_address_core,
        config.listen_port_core,
        config.my_id,
        factory,
        num_sessions_preproc,
        config.peer_confs,
        public_storage,
        private_storage,
        cert_paths,
        config.core_to_core_net_conf,
        run_prss,
    )
    .await?;

    tracing::info!(
        "Initialization done! Starting threshold KMS server for {} ...",
        config.my_id
    );
    Ok(kms)
}

/// Starts threshold KMS server.
///
/// This function must be called after the server has been initialized.
/// The server accepts requests from clients (not the other cores).
pub async fn threshold_server_start<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    listen_address: String,
    listen_port: u16,
    timeout_secs: u64,
    grpc_max_message_size: usize,
    kms_server: RealThresholdKms<PubS, PrivS>,
) -> anyhow::Result<()> {
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PubS, PrivS>>>()
        .await;

    let socket_addr = format!("{}:{}", listen_address, listen_port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    let trace_request = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace)
        .map_request(record_trace_id);

    let server = Server::builder()
        .layer(trace_request)
        .timeout(tokio::time::Duration::from_secs(timeout_secs))
        .add_service(
            CoreServiceEndpointServer::new(kms_server)
                .max_decoding_message_size(grpc_max_message_size)
                .max_encoding_message_size(grpc_max_message_size),
        )
        .add_service(health_service)
        .serve(socket_addr);

    tracing::info!("Starting threshold KMS server on socket {socket_addr}");
    server.await?;
    Ok(())
}

// TODO should be moved to rpc_types.rs
impl FheType {
    pub fn deserialize_to_low_level(
        &self,
        serialized_high_level: &[u8],
        decompression_key: &Option<DecompressionKey>,
    ) -> anyhow::Result<Ciphertext64> {
        let radix_ct = match self {
            FheType::Ebool => {
                let hl_ct: FheBool =
                    decompression::from_bytes::<FheBool>(decompression_key, serialized_high_level)?;
                let radix_ct = hl_ct.into_raw_parts();
                BaseRadixCiphertext::from_blocks(vec![radix_ct])
            }
            FheType::Euint4 => {
                let hl_ct: FheUint4 = decompression::from_bytes::<FheUint4>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint8 => {
                let hl_ct: FheUint8 = decompression::from_bytes::<FheUint8>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint16 => {
                let hl_ct: FheUint16 = decompression::from_bytes::<FheUint16>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint32 => {
                let hl_ct: FheUint32 = decompression::from_bytes::<FheUint32>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint64 => {
                let hl_ct: FheUint64 = decompression::from_bytes::<FheUint64>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint128 => {
                let hl_ct: FheUint128 = decompression::from_bytes::<FheUint128>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint160 => {
                let hl_ct: FheUint160 = decompression::from_bytes::<FheUint160>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint256 => {
                let hl_ct: FheUint256 = decompression::from_bytes::<FheUint256>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint512 => {
                let hl_ct: FheUint512 = decompression::from_bytes::<FheUint512>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint1024 => {
                let hl_ct: FheUint1024 = decompression::from_bytes::<FheUint1024>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint2048 => {
                let hl_ct: FheUint2048 = decompression::from_bytes::<FheUint2048>(
                    decompression_key,
                    serialized_high_level,
                )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                radix_ct
            }
        };
        Ok(radix_ct)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum ThresholdFheKeysVersioned {
    V0(ThresholdFheKeys),
}

#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(ThresholdFheKeysVersioned)]
pub struct ThresholdFheKeys {
    pub private_keys: PrivateKeySet,
    pub sns_key: SwitchAndSquashKey,
    pub decompression_key: Option<DecompressionKey>,
    pub pk_meta_data: DkgMetaStore,
}

impl Named for ThresholdFheKeys {
    const NAME: &'static str = "ThresholdFheKeys";
}

// Request digest, and resultant plaintext
type DecMetaStore = (Vec<u8>, Vec<Plaintext>, Vec<u8>);
// Request digest, fhe type of encryption and resultant partial decryption
type ReencMetaStore = (Vec<u8>, FheType, Vec<u8>);
// Hashmap of `PubDataType` to the corresponding `SignedPubDataHandleInternal` information for all the different
// public keys
type DkgMetaStore = HashMap<PubDataType, SignedPubDataHandleInternal>;

type BucketMetaStore = Box<dyn DKGPreprocessing<ResiduePoly128>>;

/// Compute all the info of a [FhePubKeySet] and return the result as as [DkgMetaStore]
pub fn compute_all_info(
    sig_key: &PrivateSigKey,
    fhe_key_set: &FhePubKeySet,
) -> anyhow::Result<DkgMetaStore> {
    //Compute all the info required for storing
    let pub_key_info = compute_info(sig_key, &fhe_key_set.public_key);
    let serv_key_info = compute_info(sig_key, &fhe_key_set.server_key);

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
pub type RealThresholdKms<PubS, PrivS> = GenericKms<
    RealInitiator<PrivS>,
    RealReencryptor,
    RealDecryptor,
    RealKeyGenerator<PubS, PrivS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS>,
    RealZkVerifier<PubS>,
>;

#[cfg(feature = "insecure")]
pub type RealThresholdKms<PubS, PrivS> = GenericKms<
    RealInitiator<PrivS>,
    RealReencryptor,
    RealDecryptor,
    RealKeyGenerator<PubS, PrivS>,
    RealInsecureKeyGenerator<PubS, PrivS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS>,
    RealZkVerifier<PubS>,
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
async fn new_real_threshold_kms<PubS, PrivS>(
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
    cert_paths: Option<CertificatePaths>,
    core_to_core_net_conf: Option<CoreToCoreNetworkConfig>,
    run_prss: bool,
) -> anyhow::Result<RealThresholdKms<PubS, PrivS>>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    let sks: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(&private_storage, &PrivDataType::SigningKey.to_string()).await?;
    let sk = get_exactly_one(sks).inspect_err(|e| {
        tracing::error!("signing key hashmap is not exactly 1, {}", e);
    })?;

    let key_info_versioned: HashMap<RequestId, ThresholdFheKeys> =
        read_all_data_versioned(&private_storage, &PrivDataType::FheKeyInfo.to_string()).await?;
    let mut key_info = HashMap::new();
    let mut key_info_w_status = HashMap::new();
    for (id, info) in key_info_versioned.into_iter() {
        key_info_w_status.insert(id.clone(), HandlerStatus::Done(info.pk_meta_data.clone()));
        key_info.insert(id, info);
    }
    let cs: HashMap<RequestId, SignedPubDataHandleInternal> =
        read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;
    let mut cs_w_status: HashMap<RequestId, HandlerStatus<SignedPubDataHandleInternal>> =
        HashMap::new();
    for (id, crs) in cs {
        cs_w_status.insert(id.to_owned(), HandlerStatus::Done(crs));
    }
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
            tracing::info!("Creating server without TLS support.");
            Server::builder()
        }
    };

    // This will setup TLS if cert_paths is set to Some(...)
    let networking_manager =
        GrpcNetworkingManager::new(own_identity.to_owned(), cert_paths, core_to_core_net_conf);
    let networking_server = networking_manager.new_server();

    let router = server.add_service(networking_server);
    let socket_addr = format!("{}:{}", listen_address, listen_port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    tracing::info!(
        "Starting core-to-core server for identity {} on address {}.",
        own_identity,
        socket_addr
    );
    let ddec_handle = tokio::spawn(async move {
        match router.serve(socket_addr).await {
            Ok(handle) => Ok(handle),
            Err(e) => {
                let msg = format!("Failed to launch ddec server with error: {:?}", e);
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

    let fhe_keys = Arc::new(RwLock::new(key_info));
    let prss_setup = Arc::new(RwLock::new(None));
    let preproc_buckets = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let preproc_factory = Arc::new(Mutex::new(preproc_factory));
    let public_storage = Arc::new(Mutex::new(public_storage));
    let private_storage = Arc::new(Mutex::new(private_storage));
    let crs_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(cs_w_status)));
    let dkg_pubinfo_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(key_info_w_status)));
    let dec_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let reenc_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let zk_payload_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));

    let session_preparer = SessionPreparer {
        base_kms: base_kms.new_instance().await,
        threshold,
        my_id,
        role_assignments: role_assignments.clone(),
        networking_strategy,
        prss_setup: prss_setup.clone(),
    };

    let initiator = RealInitiator {
        prss_setup: Arc::clone(&prss_setup),
        private_storage: Arc::clone(&private_storage),
        session_preparer: session_preparer.new_instance().await,
    };
    if run_prss {
        tracing::info!(
            "Initializing threshold KMS server and generating a new PRSS Setup for {}",
            my_id
        );
        initiator.init_prss().await?;
    } else {
        tracing::info!(
            "Initializing threshold KMS server and reading PRSS from storage for {}",
            my_id
        );
        initiator.init_prss_from_disk().await?;
    }

    let reencryptor = RealReencryptor {
        fhe_keys: Arc::clone(&fhe_keys),
        base_kms: base_kms.new_instance().await,
        reenc_meta_store,
        session_preparer: session_preparer.new_instance().await,
    };

    let decryptor = RealDecryptor {
        fhe_keys: Arc::clone(&fhe_keys),
        base_kms: base_kms.new_instance().await,
        dec_meta_store,
        session_preparer: session_preparer.new_instance().await,
    };

    let keygenerator = RealKeyGenerator {
        fhe_keys,
        base_kms: base_kms.new_instance().await,
        preproc_buckets: Arc::clone(&preproc_buckets),
        public_storage: Arc::clone(&public_storage),
        private_storage: Arc::clone(&private_storage),
        dkg_pubinfo_meta_store,
        session_preparer: session_preparer.new_instance().await,
    };

    #[cfg(feature = "insecure")]
    let insecureerator = RealInsecureKeyGenerator::from_real_keygen(&keygenerator).await;

    let preprocessor = RealPreprocessor {
        prss_setup,
        preproc_buckets,
        preproc_factory,
        num_sessions_preproc,
        session_preparer: session_preparer.new_instance().await,
    };

    let crsgenerator = RealCrsGenerator {
        base_kms: base_kms.new_instance().await,
        public_storage: Arc::clone(&public_storage),
        private_storage,
        crs_meta_store,
        session_preparer,
    };

    let zkverifier = RealZkVerifier {
        base_kms,
        zk_payload_meta_store,
        public_storage,
    };

    let kms = GenericKms::new(
        initiator,
        reencryptor,
        decryptor,
        keygenerator,
        #[cfg(feature = "insecure")]
        insecureerator,
        preprocessor,
        crsgenerator,
        zkverifier,
        ddec_handle.abort_handle(),
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
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePoly128>>>>,
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
    ) -> anyhow::Result<SmallSession<ResiduePoly128>> {
        self.prepare_ddec_data_from_sessionid(SessionId(request_id.clone().try_into()?))
            .await
    }

    async fn prepare_ddec_data_from_sessionid(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePoly128>> {
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

    /// Returns a copy of the `SessionPreparer` with a fresh randomness generator so it is safe to use.
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
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePoly128>>>>,
    private_storage: Arc<Mutex<PrivS>>,
    session_preparer: SessionPreparer,
}

impl<PrivS: Storage + Send + Sync + 'static> RealInitiator<PrivS> {
    async fn init_prss_from_disk(&self) -> anyhow::Result<()> {
        // TODO pass epoch ID fom config? (once we have epochs)
        let epoch_id = PRSS_EPOCH_ID;

        let prss_setup_from_file = {
            let guarded_private_storage = self.private_storage.lock().await;
            read_versioned_at_request_id(
                &(*guarded_private_storage),
                &RequestId::from(epoch_id),
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS from file with error: {e}");
            })
            .ok()
        };

        // check if a PRSS setup already exists in storage.
        match prss_setup_from_file {
            Some(prss_setup) => {
                let mut guarded_prss_setup = self.prss_setup.write().await;
                *guarded_prss_setup = Some(prss_setup);
                tracing::info!("Initializing threshold KMS server with PRSS Setup from disk",)
            }
            None => tracing::info!(
                "Initializing threshold KMS server without PRSS Setup, \
                        remember to call the init GRPC endpoint",
            ),
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
        let prss_setup_obj: PRSSSetup<ResiduePoly128> =
            PRSSSetup::robust_init(&mut base_session, &RealVss::default()).await?;

        let mut guarded_prss_setup = self.prss_setup.write().await;
        *guarded_prss_setup = Some(prss_setup_obj.clone());

        // serialize and write PRSS Setup to disk into private storage
        let private_storage = Arc::clone(&self.private_storage);
        let mut priv_storage = private_storage.lock().await;
        store_versioned_at_request_id(
            &mut (*priv_storage),
            &RequestId::from(epoch_id),
            &prss_setup_obj,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await?;

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
pub struct RealReencryptor {
    fhe_keys: Arc<RwLock<HashMap<RequestId, ThresholdFheKeys>>>,
    base_kms: BaseKmsStruct,
    reenc_meta_store: Arc<RwLock<MetaStore<ReencMetaStore>>>,
    session_preparer: SessionPreparer,
}

impl RealReencryptor {
    /// Helper method for reencryptin which carries out the actual threshold decryption using noise
    /// flooding.
    #[allow(clippy::too_many_arguments)]
    async fn inner_reencrypt(
        session: &mut SmallSession<ResiduePoly128>,
        protocol: &mut Small,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheType,
        link: Vec<u8>,
        key_handle: &RequestId,
        client_enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: RwLockReadGuard<'_, HashMap<RequestId, ThresholdFheKeys>>,
    ) -> anyhow::Result<Vec<u8>> {
        let keys = match fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => return Err(anyhow!("Could not deserialize meta store")),
        };
        let low_level_ct = fhe_type.deserialize_to_low_level(ct, &keys.decompression_key)?;
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
                let partial_signcryption =
                    match partial_dec_map.get(&session.session_id().to_string()) {
                        Some(partial_dec) => {
                            let partial_dec_serialized = bincode::serialize(&partial_dec)?;
                            let signcryption_msg = SigncryptionPayload {
                                plaintext: Plaintext::from_bytes(partial_dec_serialized, fhe_type),
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
                    "Reencryption completed. Inner thread took {:?} ms",
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
impl Reencryptor for RealReencryptor {
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
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

        let mut session = tonic_handle_potential_err(
            self.session_preparer
                .prepare_ddec_data_from_requestid(&req_id)
                .await,
            "Could not prepare ddec data".to_string(),
        )?;
        let mut protocol = Small::new(session.clone());
        let meta_store = Arc::clone(&self.reenc_meta_store);
        let fhe_keys = Arc::clone(&self.fhe_keys);
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

        // we do not need to hold the handle,
        // the result of the computation is tracked the crs_meta_store
        let _handle = tokio::spawn(async move {
            let fhe_keys_rlock = fhe_keys.read().await;
            let tmp = Self::inner_reencrypt(
                &mut session,
                &mut protocol,
                &mut rng,
                &ciphertext,
                fhe_type,
                link.clone(),
                &key_id,
                &client_enc_key,
                &client_address,
                sig_key,
                fhe_keys_rlock,
            )
            .await;
            let mut guarded_meta_store = meta_store.write().await;
            match tmp {
                Ok(partial_dec) => {
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store
                        .update(&req_id, HandlerStatus::Done((link, fhe_type, partial_dec)));
                }
                Result::Err(e) => {
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store.update(
                        &req_id,
                        HandlerStatus::Error(format!("Failed decryption: {e}")),
                    );
                }
            }
        });
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
        let (link, fhe_type, signcrypted_ciphertext) = {
            let guarded_meta_store = self.reenc_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Reencryption",
            )?
        };
        let server_verf_key = self.base_kms.get_serialized_verf_key();
        let payload = ReencryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
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

pub struct RealDecryptor {
    fhe_keys: Arc<RwLock<HashMap<RequestId, ThresholdFheKeys>>>,
    base_kms: BaseKmsStruct,
    dec_meta_store: Arc<RwLock<MetaStore<DecMetaStore>>>,
    session_preparer: SessionPreparer,
}

impl RealDecryptor {
    /// Helper method for decryption which carries out the actual threshold decryption using noise
    /// flooding.
    async fn inner_decrypt<T>(
        session: &mut SmallSession<ResiduePoly128>,
        protocol: &mut Small,
        ct: &[u8],
        fhe_type: FheType,
        key_handle: &RequestId,
        fhe_keys: RwLockReadGuard<'_, HashMap<RequestId, ThresholdFheKeys>>,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    {
        tracing::info!("{:?} started inner_decrypt", session.own_identity());
        let keys = match fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => {
                return Err(anyhow_error_and_log(format!(
                    "Key handle {key_handle} does not exist"
                )))
            }
        };
        let low_level_ct = fhe_type.deserialize_to_low_level(ct, &keys.decompression_key)?;
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
impl Decryptor for RealDecryptor {
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        tracing::info!(
            "Party {:?} received a new decryption request with request_id {:?}",
            self.session_preparer.own_identity(),
            inner.request_id
        );
        let (ciphertexts, req_digest, key_id, req_id, eip712_domain, acl_address) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )?;

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

        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();

        let mut dec_tasks = JoinSet::new();

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
            let fhe_keys = Arc::clone(&self.fhe_keys);

            // we do not need to hold the handle,
            // the result of the computation is tracked by the dec_meta_store
            dec_tasks.spawn(async move {
                let fhe_type = if let Ok(f) = FheType::try_from(ct.fhe_type) {
                    f
                } else {
                    return Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed due to wrong fhe type: {}",
                        ct.fhe_type
                    )));
                };

                let ciphertext = &ct.ciphertext;

                let fhe_keys_rlock = fhe_keys.read().await;
                let res_plaintext = match fhe_type {
                    FheType::Euint512 => {
                        todo!("Implement decryption for Euint512")
                    }
                    FheType::Euint1024 => {
                        todo!("Implement decryption for Euint1024")
                    }
                    FheType::Euint2048 => Self::inner_decrypt::<tfhe::integer::bigint::U2048>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        &key_id,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(Plaintext::from_u2048),
                    FheType::Euint256 => Self::inner_decrypt::<tfhe::integer::U256>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        &key_id,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(Plaintext::from_u256),
                    FheType::Euint160 => Self::inner_decrypt::<tfhe::integer::U256>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        &key_id,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(Plaintext::from_u160),
                    FheType::Euint128 => Self::inner_decrypt::<u128>(
                        &mut session,
                        &mut protocol,
                        ciphertext,
                        fhe_type,
                        &key_id,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(|x| Plaintext::new(x, fhe_type)),
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
                        &key_id,
                        fhe_keys_rlock,
                    )
                    .await
                    .map(|x| Plaintext::new(x as u128, fhe_type)),
                };
                match res_plaintext {
                    Ok(plaintext) => Ok((idx, plaintext)),
                    Result::Err(e) => Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed:{}",
                        e
                    ))),
                }
            });
        }

        // collect decryption results in async mgmt task so we can return from this call without waiting for the decryption(s) to finish
        let meta_store = Arc::clone(&self.dec_meta_store);
        let sigkey = Arc::clone(&self.base_kms.sig_key);
        let _handle = tokio::spawn(async move {
            let mut decs = HashMap::new();
            while let Some(resp) = dec_tasks.join_next().await {
                match resp {
                    Ok(Ok((idx, plaintext))) => {
                        decs.insert(idx, plaintext);
                    }
                    _ => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Error("Failed decryption.".to_string()),
                        );
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
                vec![]
            };

            let mut guarded_meta_store = meta_store.write().await;
            let _ = guarded_meta_store.update(
                &req_id,
                HandlerStatus::Done((req_digest.clone(), pts, external_sig)),
            );
        });

        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
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
        let (req_digest, plaintexts, external_signature) = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Decryption",
            )?
        };

        let pt_payload = tonic_handle_potential_err(
            plaintexts
                .iter()
                .map(bincode::serialize)
                .collect::<Result<Vec<Vec<u8>>, _>>(),
            "Error serializing plaintexts in get_result()".to_string(),
        )?;

        let server_verf_key = self.base_kms.get_serialized_verf_key();
        let sig_payload = DecryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            plaintexts: pt_payload,
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
> {
    // NOTE: To avoid deadlocks the fhe_keys SHOULD NOT be written to while holding a meta storage
    // mutex!
    fhe_keys: Arc<RwLock<HashMap<RequestId, ThresholdFheKeys>>>,
    base_kms: BaseKmsStruct,
    // TODO eventually add mode to allow for nlarge as well.
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    // NOTE: To avoid deadlocks the public_storage MUST ALWAYS be accessed BEFORE the private_storage when both are needed concurrently
    public_storage: Arc<Mutex<PubS>>,
    private_storage: Arc<Mutex<PrivS>>,
    dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<DkgMetaStore>>>,
    session_preparer: SessionPreparer,
}

#[cfg(feature = "insecure")]
pub struct RealInsecureKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    real_key_generator: RealKeyGenerator<PubS, PrivS>,
}

#[cfg(feature = "insecure")]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    RealInsecureKeyGenerator<PubS, PrivS>
{
    async fn from_real_keygen(value: &RealKeyGenerator<PubS, PrivS>) -> Self {
        Self {
            real_key_generator: RealKeyGenerator {
                fhe_keys: Arc::clone(&value.fhe_keys),
                base_kms: value.base_kms.new_instance().await,
                preproc_buckets: Arc::clone(&value.preproc_buckets),
                public_storage: Arc::clone(&value.public_storage),
                private_storage: Arc::clone(&value.private_storage),
                dkg_pubinfo_meta_store: Arc::clone(&value.dkg_pubinfo_meta_store),
                session_preparer: value.session_preparer.new_instance().await,
            },
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    InsecureKeyGenerator for RealInsecureKeyGenerator<PubS, PrivS>
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
    Secure(Box<dyn DKGPreprocessing<ResiduePoly128>>),
    Insecure,
}

impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    RealKeyGenerator<PubS, PrivS>
{
    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        preproc_handle_w_mode: PreprocHandleWithMode,
        req_id: RequestId,
    ) -> anyhow::Result<()> {
        // Update status
        {
            let mut guarded_meta_store = self.dkg_pubinfo_meta_store.write().await;
            guarded_meta_store.insert(&req_id)?;
        }

        // Create the base session necessary to run the DKG
        let mut base_session = {
            let session_id = SessionId(req_id.clone().try_into()?);
            self.session_preparer
                .make_base_session(session_id, NetworkMode::Async)
                .await?
        };

        // Clone all the Arcs to give them to the tokio thread
        let meta_store = Arc::clone(&self.dkg_pubinfo_meta_store);
        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let sig_key = Arc::clone(&self.base_kms.sig_key);
        let fhe_keys = Arc::clone(&self.fhe_keys);

        let _handle = tokio::spawn(async move {
            let dkg_res = match preproc_handle_w_mode {
                PreprocHandleWithMode::Insecure => {
                    initialize_key_material(&mut base_session, dkg_params).await
                }
                PreprocHandleWithMode::Secure(mut preproc_handle) => {
                    distributed_keygen_z128(&mut base_session, preproc_handle.as_mut(), dkg_params)
                        .await
                }
            };

            //Make sure the dkg ended nicely
            let (mut pub_key_set, private_keys) = match dkg_res {
                Ok((pk, sk)) => (pk, sk),
                Err(e) => {
                    //If dkg errored out, update status
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ =
                        guarded_meta_storage.update(&req_id, HandlerStatus::Error(e.to_string()));
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
                    let _ = guarded_meta_storage
                        .update(&req_id, HandlerStatus::Error("Missing SNS key".to_string()));
                    return;
                }
            };

            //Compute all the info required for storing
            let info = match compute_all_info(&sig_key, &pub_key_set) {
                Ok(info) => info,
                Err(_) => {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage.update(
                        &req_id,
                        HandlerStatus::Error("Failed to compute key info".to_string()),
                    );
                    return;
                }
            };

            //Retrieve decompression key if there's one
            let (
                raw_server_key,
                raw_ksk_material,
                raw_compression_key,
                raw_decompression_key,
                raw_tag,
            ) = pub_key_set.server_key.into_raw_parts();
            let decompression_key = raw_decompression_key.clone();

            pub_key_set.server_key = tfhe::ServerKey::from_raw_parts(
                raw_server_key,
                raw_ksk_material,
                raw_compression_key,
                raw_decompression_key,
                raw_tag,
            );

            //Take lock on all the storage at once, so we either update everything or nothing
            let mut pub_storage = public_storage.lock().await;
            let mut priv_storage = private_storage.lock().await;

            let unversioned_keys = ThresholdFheKeys {
                private_keys,
                sns_key,
                decompression_key,
                pk_meta_data: info.clone(),
            };
            //Try to store the new data
            if store_versioned_at_request_id(
                &mut (*priv_storage),
                &req_id,
                &unversioned_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .is_ok()
            // Only store the public keys if no other server has already stored them
                && store_pk_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    WrappedPublicKey::Compact(&pub_key_set.public_key),
                )
                .await
                .is_ok()
                && store_versioned_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &pub_key_set.server_key,
                    &PubDataType::ServerKey.to_string(),
                )
                .await
                .is_ok()
                && store_versioned_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &unversioned_keys.sns_key,
                    &PubDataType::SnsKey.to_string(),
                )
                .await
                .is_ok()
            {
                {
                    let mut guarded_fhe_keys = fhe_keys.write().await;
                    guarded_fhe_keys.insert(req_id.clone(), unversioned_keys);
                }
                //If everything succeeded, update state and store private key
                {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage.update(&req_id, HandlerStatus::Done(info));
                }
                tracing::info!("Finished DKG for Request Id {req_id}.");
            } else {
                tracing::error!("Could not store all the key data from request ID {req_id}. Deleting any dangling data.");
                // Try to delete stored data to avoid anything dangling
                // Ignore any failure to delete something since it might be because the data did not get created
                // In any case, we can't do much.
                let _ = delete_pk_at_request_id(&mut (*pub_storage), &req_id).await;
                let _ = delete_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &PubDataType::ServerKey.to_string(),
                )
                .await;
                let _ = delete_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &PubDataType::SnsKey.to_string(),
                )
                .await;
                let _ = delete_at_request_id(
                    &mut (*priv_storage),
                    &req_id,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await;
                //If writing to public store failed, update status
                {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage.update(
                        &req_id,
                        HandlerStatus::Error(
                            "Failed to write the public key to public store".to_string(),
                        ),
                    );
                }
            }
        });
        Ok(())
    }

    async fn inner_key_gen(
        &self,
        request: Request<KeyGenRequest>,
        insecure: bool,
    ) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        tracing::info!("Request ID: {:?}", inner.request_id);
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (inner key gen)".to_string(),
        )?;
        tracing::info!("Request ID after tonic: {:?}", request_id);

        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not valid!", request_id),
            ));
        }

        let storage = Arc::clone(&self.public_storage);
        {
            let storage = storage.lock().await;
            // TODO I don't think we need to do this check since the key will only be stored if it
            // is already persisted in dkg_pubinfo_meta_store
            if tonic_handle_potential_err(
                storage
                    .data_exists(&tonic_handle_potential_err(
                        storage.compute_url(
                            &request_id.to_string(),
                            &PubDataType::PublicKey.to_string(),
                        ),
                        "Could not compute url for public key".to_string(),
                    )?)
                    .await,
                "Could not validate if the public key exist".to_string(),
            )? || tonic_handle_potential_err(
                storage
                    .data_exists(&tonic_handle_potential_err(
                        storage.compute_url(
                            &request_id.to_string(),
                            &PubDataType::ServerKey.to_string(),
                        ),
                        "Could not compute url for server key".to_string(),
                    )?)
                    .await,
                "Could not validate if the server key exist".to_string(),
            )? || tonic_handle_potential_err(
                storage
                    .data_exists(&tonic_handle_potential_err(
                        storage
                            .compute_url(&request_id.to_string(), &PubDataType::SnsKey.to_string()),
                        "Could not compute url for SnS key".to_string(),
                    )?)
                    .await,
                "Could not validate if the SnS key exist".to_string(),
            )? {
                tracing::warn!(
                    "Keys with request ID {} already exist!",
                    request_id.to_string()
                );
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("Keys with request ID {} already exist!", request_id),
                ));
            }
        }

        //Retrieve kg params and preproc_id
        let dkg_params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;

        let preproc_handle = if insecure {
            PreprocHandleWithMode::Insecure
        } else {
            let preproc_id = tonic_some_or_err(
                inner.preproc_id.clone(),
                "Pre-Processing ID is not set".to_string(),
            )?;
            let mut map = self.preproc_buckets.write().await;
            let preproc = map.delete(&preproc_id);
            PreprocHandleWithMode::Secure(handle_res_mapping(
                preproc,
                &preproc_id,
                "Preprocessing",
            )?)
        };

        tonic_handle_potential_err(
            self.launch_dkg(dkg_params, preproc_handle, request_id.clone())
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
        let guarded_meta_store = self.dkg_pubinfo_meta_store.read().await;
        let res = handle_res_mapping(
            guarded_meta_store.retrieve(&request_id).cloned(),
            &request_id,
            "DKG",
        )?;
        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id),
            key_results: convert_key_response(res),
        }))
    }
}

#[tonic::async_trait]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static> KeyGenerator
    for RealKeyGenerator<PubS, PrivS>
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
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePoly128>>>>,
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    preproc_factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
    num_sessions_preproc: u16,
    session_preparer: SessionPreparer,
}

impl RealPreprocessor {
    async fn launch_dkg_preproc(
        &self,
        dkg_params: DKGParams,
        request_id: RequestId,
    ) -> anyhow::Result<()> {
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }

        fn create_sessions(
            base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
            prss_setup: PRSSSetup<ResiduePoly128>,
        ) -> Vec<SmallSession<ResiduePoly128>> {
            base_sessions
                .into_iter()
                .map(|base_session| {
                    let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap()
                })
                .collect_vec()
        }
        //Derive a sequence of sessionId from request_id
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

        let prss_setup = tonic_some_or_err(
            (*self.prss_setup.read().await).clone(),
            "No PRSS setup exists".to_string(),
        )?;
        //NOTE: For now we just discard the handle, we can check status with get_preproc_status
        // endpoint
        let _handle = tokio::spawn(async move {
            let sessions = create_sessions(base_sessions, prss_setup);
            let orchestrator = {
                let mut factory_guard = factory.lock().await;
                let factory = factory_guard.as_mut();
                PreprocessingOrchestrator::<ResiduePoly128>::new(factory, dkg_params).unwrap()
            };
            tracing::info!("Starting Preproc Orchestration on P[{:?}]", own_identity);
            let preproc_result = orchestrator
                .orchestrate_small_session_dkg_processing(sessions)
                .await;
            //write the preproc handle to the bucket store
            let handle_update = match preproc_result {
                Ok((_, preproc_handle)) => HandlerStatus::Done(preproc_handle),
                Err(error) => HandlerStatus::Error(error.to_string()),
            };
            let mut guarded_meta_store = bucket_store.write().await;
            // We cannot do much if updating the storage fails at this point...
            let _ = guarded_meta_store.update(&request_id, handle_update);
            tracing::info!("Preproc Finished P[{:?}]", own_identity);
        });

        Ok(())
    }
}

#[tonic::async_trait]
impl KeyGenPreprocessor for RealPreprocessor {
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
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
            tonic_handle_potential_err(self.launch_dkg_preproc(dkg_params, request_id.clone()).await, format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {:?}",dkg_params))?;
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
            match map.retrieve(&request_id) {
                None => {
                    tracing::warn!(
                        "Requesting status for request id that does not exist {request_id}"
                    );
                    KeyGenPreprocStatusEnum::Missing
                }
                Some(HandlerStatus::Error(e)) => {
                    tracing::warn!(
                        "Error while generating keygen preproc for request id {request_id} : {e}"
                    );
                    KeyGenPreprocStatusEnum::Error
                }
                Some(HandlerStatus::Started) => {
                    tracing::info!("Preproc for request id {request_id} is in progress.");
                    KeyGenPreprocStatusEnum::InProgress
                }
                Some(HandlerStatus::Done(_)) => {
                    tracing::info!("Preproc for request id {request_id} is finished.");
                    KeyGenPreprocStatusEnum::Finished
                }
            }
        };
        Ok(Response::new(KeyGenPreprocStatus {
            result: response.into(),
        }))
    }
}

pub struct RealCrsGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    base_kms: BaseKmsStruct,
    public_storage: Arc<Mutex<PubS>>,
    private_storage: Arc<Mutex<PrivS>>,
    crs_meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    session_preparer: SessionPreparer,
}

impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    RealCrsGenerator<PubS, PrivS>
{
    async fn inner_crs_gen(
        &self,
        req_id: &RequestId,
        witness_dim: usize,
        max_num_bits: Option<u32>,
        dkg_params: &DKGParams,
    ) -> anyhow::Result<()> {
        {
            let mut guarded_meta_store = self.crs_meta_store.write().await;
            guarded_meta_store.insert(req_id).map_err(|e| {
                anyhow_error_and_log(format!(
                    "failed to insert to meta store in inner_crs_gen with error: {e}"
                ))
            })?;
        }

        let session_id = SessionId(req_id.clone().try_into()?);
        let mut session = self
            .session_preparer
            .prepare_ddec_data_from_sessionid(session_id)
            .await?;
        let meta_store = Arc::clone(&self.crs_meta_store);
        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let owned_req_id = req_id.to_owned();

        // we need to clone the signature key because it needs to be given
        // the thread that spawns the CRS ceremony
        let sig_key = self.base_kms.sig_key.clone();

        // we do not need to hold the handle,
        // the result of the computation is tracked the crs_meta_store

        let pke_params = dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let _handle = tokio::spawn(async move {
            let crs_start_timer = Instant::now();
            let real_ceremony = RealCeremony::default();
            let internal_pp = real_ceremony
                .execute::<Z64, _, _>(&mut session, witness_dim, max_num_bits)
                .await;
            let pp = internal_pp.and_then(|internal| internal.try_into_tfhe_zk_pok_pp(&pke_params));
            let res_info_pp = pp.and_then(|pp| compute_info(&sig_key, &pp).map(|info| (info, pp)));
            let f = || async {
                // we take these two locks at the same time in case there are races
                // on return, the two locks should be dropped in the correct order also
                let mut pub_storage = public_storage.lock().await;
                let mut priv_storage = private_storage.lock().await;

                let (meta_data, pp_id) = match res_info_pp {
                    Ok((meta, pp_id)) => (meta, pp_id),
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store
                            .update(&owned_req_id, HandlerStatus::Error(e.to_string()));
                        return;
                    }
                };

                if store_versioned_at_request_id(
                    &mut (*priv_storage),
                    &owned_req_id,
                    &meta_data,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await
                .is_ok()
                // Only store the CRS if no other server has already stored it
                    && store_versioned_at_request_id(
                        &mut (*pub_storage),
                        &owned_req_id,
                        &pp_id,
                        &PubDataType::CRS.to_string(),
                    )
                    .await
                    .is_ok()
                {
                    let mut guarded_meta_store = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ =
                        guarded_meta_store.update(&owned_req_id, HandlerStatus::Done(meta_data));
                } else {
                    tracing::error!("Could not store all the CRS data from request ID {owned_req_id}. Deleting any dangling data.");
                    // Try to delete stored data to avoid anything dangling
                    // Ignore any failure to delete something since it might be because the data did not get created
                    // In any case, we can't do much.
                    let _ = delete_at_request_id(
                        &mut (*pub_storage),
                        &owned_req_id,
                        &PubDataType::CRS.to_string(),
                    )
                    .await;
                    let _ = delete_at_request_id(
                        &mut (*priv_storage),
                        &owned_req_id,
                        &PrivDataType::CrsInfo.to_string(),
                    )
                    .await;
                    {
                        let mut guarded_meta_store = meta_store.write().await;
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(
                            &owned_req_id,
                            HandlerStatus::Error(format!(
                                "failed to store data to public storage for ID {}",
                                owned_req_id
                            )),
                        );
                    }
                }
            };
            let _ = f().await;

            let crs_stop_timer = Instant::now();
            let elapsed_time = crs_stop_timer.duration_since(crs_start_timer);
            tracing::info!(
                "CRS stored. CRS ceremony time was {:?} ms",
                (elapsed_time).as_millis()
            );
        });
        Ok(())
    }
}

#[tonic::async_trait]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static> CrsGenerator
    for RealCrsGenerator<PubS, PrivS>
{
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        let req_inner = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            req_inner.request_id
        );

        let dkg_params =
            crate::rpc::central_rpc::retrieve_parameters(req_inner.params).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Can not retrieve fhe parameters with error {e}"),
                )
            })?;
        let crs_params = dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let witness_dim = tonic_handle_potential_err(
            compute_witness_dim(&crs_params, req_inner.max_num_bits.map(|x| x as usize)),
            "witness dimension computation failed".to_string(),
        )?;

        let req_id = req_inner.request_id.ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                "missing request ID in CRS generation",
            )
        })?;

        self.inner_crs_gen(&req_id, witness_dim, req_inner.max_num_bits, &dkg_params)
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
        let guarded_meta_store = self.crs_meta_store.read().await;
        let crs_data = handle_res_mapping(
            guarded_meta_store.retrieve(&request_id).cloned(),
            &request_id,
            "CRS generation",
        )?;
        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(crs_data.into()),
        }))
    }
}

pub struct RealZkVerifier<PubS: Storage + Sync + Send + 'static> {
    base_kms: BaseKmsStruct,
    zk_payload_meta_store: Arc<RwLock<MetaStore<ZkVerifyResponsePayload>>>,
    public_storage: Arc<Mutex<PubS>>,
}

#[tonic::async_trait]
impl<PubS: Storage + Sync + Send + 'static> ZkVerifier for RealZkVerifier<PubS> {
    async fn verify(&self, request: Request<ZkVerifyRequest>) -> Result<Response<Empty>, Status> {
        let meta_store = Arc::clone(&self.zk_payload_meta_store);
        let sigkey = Arc::clone(&self.base_kms.sig_key);

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

        let public_storage = Arc::clone(&self.public_storage);

        non_blocking_zk_verify(
            meta_store,
            public_storage,
            request_id.clone(),
            request.into_inner(),
            sigkey,
        )
        .await
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("non_blocking_zk_verify failed for request_id {request_id} ({e})"),
            )
        })?;

        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ZkVerifyResponse>, Status> {
        let meta_store = Arc::clone(&self.zk_payload_meta_store);
        get_zk_verify_result(&self.base_kms, meta_store, request).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_tools,
        consts::{AMOUNT_PARTIES, PRSS_EPOCH_ID, THRESHOLD},
        storage::{FileStorage, StorageType},
        threshold::threshold_kms::RequestId,
        util::key_setup::test_tools::purge,
    };

    #[tokio::test]
    #[serial_test::serial]
    #[tracing_test::traced_test]
    async fn prss_disk_test() {
        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        for i in 1..=AMOUNT_PARTIES {
            let cur_pub = FileStorage::new_threshold(None, StorageType::PUB, i).unwrap();
            pub_storage.push(cur_pub);
            let cur_priv = FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap();

            // make sure the store does not contain any PRSS info (currently stored under ID 1)
            let req_id = RequestId::from(PRSS_EPOCH_ID);
            purge(None, None, &req_id.to_string()).await;

            priv_storage.push(cur_priv);
        }

        // create parties and run PrssSetup
        let core_handles = test_tools::setup_threshold_no_client(
            THRESHOLD as u8,
            pub_storage.clone(),
            priv_storage.clone(),
            true,
        )
        .await;
        assert_eq!(core_handles.len(), AMOUNT_PARTIES);

        // shut parties down
        for h in core_handles.values() {
            h.abort();
        }
        for (_, handle) in core_handles {
            assert!(handle.await.unwrap_err().is_cancelled());
        }

        // check that PRSS was created (and not read from disk)
        assert!(!logs_contain(
            "Initializing threshold KMS server with PRSS Setup from disk"
        ));

        // create parties again without running PrssSetup this time (it should now be read from disk)
        let core_handles = test_tools::setup_threshold_no_client(
            THRESHOLD as u8,
            pub_storage,
            priv_storage,
            false,
        )
        .await;
        assert_eq!(core_handles.len(), AMOUNT_PARTIES);

        // check that PRSS was not created, but instead read from disk now
        assert!(logs_contain(
            "Initializing threshold KMS server with PRSS Setup from disk"
        ));

        for h in core_handles.values() {
            h.abort();
        }
        for (_, handle) in core_handles {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }
}
