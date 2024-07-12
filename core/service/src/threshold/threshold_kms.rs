use super::generic::{
    CrsGenerator, Decryptor, GenericKms, Initiator, KeyGenPreprocessor, KeyGenerator, Reencryptor,
};
use crate::conf::threshold::{PeerConf, ThresholdConfigNoStorage};
use crate::consts::{MINIMUM_SESSIONS_PREPROC, PRSS_EPOCH_ID, SEC_PAR};
use crate::cryptography::central_kms::{compute_info, BaseKmsStruct};
use crate::cryptography::der_types::{PrivateSigKey, PublicEncKey, PublicSigKey};
use crate::cryptography::signcryption::signcrypt;
use crate::kms::core_service_endpoint_server::CoreServiceEndpointServer;
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, FheType, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus,
    KeyGenPreprocStatusEnum, KeyGenRequest, KeyGenResult, ParamChoice, ReencryptionRequest,
    ReencryptionResponse, RequestId, SignedPubDataHandle,
};
use crate::rpc::central_rpc::{
    convert_key_response, retrieve_parameters_sync, tonic_handle_potential_err, tonic_some_or_err,
    validate_decrypt_req, validate_reencrypt_req, validate_request_id,
};
use crate::rpc::rpc_types::PrivDataType;
use crate::rpc::rpc_types::{
    BaseKms, Plaintext, PubDataType, SigncryptionPayload, CURRENT_FORMAT_VERSION,
};
use crate::storage::{
    delete_at_request_id, read_all_data, read_at_request_id, store_at_request_id, Storage,
};
use crate::util::meta_store::{handle_res_mapping, HandlerStatus, MetaStore};
use crate::{anyhow_error_and_log, some_or_err};
use aes_prng::AesRng;
use anyhow::anyhow;
use bincode::serialize;
use conf_trace::telemetry::{accept_trace, make_span, record_trace_id};
use distributed_decryption::algebra::residue_poly::ResiduePoly128;
use distributed_decryption::choreography::NetworkingStrategy;
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
use distributed_decryption::execution::tfhe_internals::parameters::{
    Ciphertext64, DKGParams, DKGParamsRegular, DKGParamsSnS,
};
use distributed_decryption::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use distributed_decryption::execution::zk::ceremony::{
    compute_witness_dim, Ceremony, RealCeremony,
};
use distributed_decryption::networking::grpc::{CoreToCoreNetworkConfig, GrpcNetworkingManager};
use distributed_decryption::session_id::SessionId;
use distributed_decryption::{algebra::base_ring::Z64, execution::endpoints::keygen::FhePubKeySet};
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::IntegerCiphertext;
use tfhe::{
    FheBool, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32, FheUint4,
    FheUint64, FheUint8,
};
use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
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
/// Otherwise, the setup must be done out of band by calling the init
/// GRPC endpoint, or using the kms-init binary.
pub async fn threshold_server_init<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    config: ThresholdConfigNoStorage,
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
        config.param_file_map,
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

    let socket: std::net::SocketAddr = format!("{}:{}", listen_address, listen_port).parse()?;
    tracing::info!("Starting threshold KMS server on socket {socket}");
    let trace_request = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace)
        .map_request(record_trace_id);

    Server::builder()
        .layer(trace_request)
        .timeout(tokio::time::Duration::from_secs(timeout_secs))
        .add_service(
            CoreServiceEndpointServer::new(kms_server)
                .max_decoding_message_size(grpc_max_message_size)
                .max_encoding_message_size(grpc_max_message_size),
        )
        .add_service(health_service)
        .serve(socket)
        .await?;
    Ok(())
}

// TODO should be moved to rpc_types.rs
impl FheType {
    pub fn deserialize_to_low_level(
        &self,
        serialized_high_level: &[u8],
    ) -> anyhow::Result<Ciphertext64> {
        let radix_ct = match self {
            FheType::Ebool => {
                let hl_ct: FheBool = bincode::deserialize(serialized_high_level)?;
                let radix_ct = hl_ct.into_raw_parts();
                BaseRadixCiphertext::from_blocks(vec![radix_ct])
            }
            FheType::Euint4 => {
                let hl_ct: FheUint4 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint8 => {
                let hl_ct: FheUint8 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint16 => {
                let hl_ct: FheUint16 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint32 => {
                let hl_ct: FheUint32 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint64 => {
                let hl_ct: FheUint64 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint128 => {
                let hl_ct: FheUint128 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint160 => {
                let hl_ct: FheUint160 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint256 => {
                let hl_ct: FheUint256 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint512 => {
                todo!("Implement deserialization for Euint512")
            }
            FheType::Euint1024 => {
                todo!("Implement deserialization for Euint1024")
            }
            FheType::Euint2048 => {
                let hl_ct: FheUint2048 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
        };
        Ok(radix_ct)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdFheKeys {
    pub private_keys: PrivateKeySet,
    pub sns_key: SwitchAndSquashKey,
    pub pk_meta_data: DkgMetaStore,
}

#[derive(Serialize, Deserialize)]
pub struct ThresholdKmsKeys {
    pub fhe_keys: HashMap<RequestId, ThresholdFheKeys>,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

// Servers needed, request digest, and resultant plaintext
type DecMetaStore = (u32, Vec<u8>, Plaintext);
// Servers needed, request digest, fhe type of encryption and resultant partial decryption
type ReencMetaStore = (u32, Vec<u8>, FheType, Vec<u8>);
// Hashmap of `PubDataType` to the corresponding `SignedPubDataHandle` information for all the different
// public keys
type DkgMetaStore = HashMap<PubDataType, SignedPubDataHandle>;
// digest (the 160-bit hex-encoded value, computed using compute_info/handle) and the signature on
// the handle
type CrsMetaStore = (String, Vec<u8>);
type BucketMetaStore = Box<dyn DKGPreprocessing<ResiduePoly128>>;

/// Compute all the info of a [FhePubKeySet] and return the result as as [DkgMetaStore]
pub(crate) fn compute_all_info(
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

pub type RealThresholdKms<PubS, PrivS> = GenericKms<
    RealInitiator<PrivS>,
    RealReencryptor,
    RealDecryptor,
    RealKeyGenerator<PubS, PrivS>,
    RealPreprocessor,
    RealCrsGenerator<PubS, PrivS>,
>;

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
    param_file_map: HashMap<String, String>,
    cert_paths: Option<CertificatePaths>,
    core_to_core_net_conf: Option<CoreToCoreNetworkConfig>,
    run_prss: bool,
) -> anyhow::Result<RealThresholdKms<PubS, PrivS>>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    let sks: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&private_storage, &PrivDataType::SigningKey.to_string()).await?;
    let sk: PrivateSigKey = some_or_err(
        sks.values().collect_vec().first(),
        "There is no private signing key stored".to_string(),
    )?
    .to_owned()
    .to_owned();
    let key_info: HashMap<RequestId, ThresholdFheKeys> =
        read_all_data(&private_storage, &PrivDataType::FheKeyInfo.to_string()).await?;
    let key_info_w_status = key_info
        .iter()
        .map(|(id, info)| {
            (
                id.to_owned(),
                HandlerStatus::Done(info.pk_meta_data.to_owned()),
            )
        })
        .collect();
    let cs: HashMap<RequestId, CrsMetaStore> =
        read_all_data(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;
    let cs_w_status: HashMap<RequestId, HandlerStatus<CrsMetaStore>> = cs
        .iter()
        .map(|(id, crs)| (id.to_owned(), HandlerStatus::Done(crs.to_owned())))
        .collect();

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
            tracing::info!("Creating server with TLS enabled.");

            // check that own_identity matches to what's in our certificate
            let certificate = cert_bundle.get_certificate()?;
            let san_strings = distributed_decryption::networking::grpc::extract_san_from_certs(
                &[certificate],
                true,
            )
            .map_err(|e| anyhow!(e))?;
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
            let ca_cert = cert_bundle.get_flattened_ca_list()?;
            let tls_config = ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(ca_cert);
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
    let addr: SocketAddr = format!("{listen_address}:{listen_port}").parse()?;

    tracing::info!(
        "Starting core-to-core server for identity {} on address {}.",
        own_identity,
        addr
    );
    let ddec_handle = tokio::spawn(async move {
        match router.serve(addr).await {
            Ok(handle) => Ok(handle),
            Err(e) => {
                let msg = format!("Failed to launch ddec server with error: {:?}", e);
                Err(anyhow_error_and_log(msg))
            }
        }
    });

    let param_file_map = Arc::new(RwLock::new(HashMap::from_iter(
        param_file_map
            .into_iter()
            .filter_map(|(k, v)| ParamChoice::from_str_name(&k).map(|x| (x, v))),
    )));

    let networking_strategy: Arc<RwLock<NetworkingStrategy>> =
        Arc::new(RwLock::new(Box::new(move |session_id, roles| {
            networking_manager.make_session(session_id, roles)
        })));
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

    let session_preparer = SessionPreparer {
        base_kms: base_kms.clone(),
        threshold,
        my_id,
        role_assignments: role_assignments.clone(),
        networking_strategy,
        prss_setup: prss_setup.clone(),
    };

    let initiator = RealInitiator {
        prss_setup: Arc::clone(&prss_setup),
        private_storage: Arc::clone(&private_storage),
        session_preparer: session_preparer.clone(),
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
        base_kms: base_kms.clone(),
        reenc_meta_store,
        session_preparer: session_preparer.clone(),
    };

    let decryptor = RealDecryptor {
        fhe_keys: Arc::clone(&fhe_keys),
        base_kms: base_kms.clone(),
        dec_meta_store,
        session_preparer: session_preparer.clone(),
    };

    let keygenerator = RealKeyGenerator {
        fhe_keys,
        base_kms: base_kms.clone(),
        preproc_buckets: Arc::clone(&preproc_buckets),
        public_storage: Arc::clone(&public_storage),
        private_storage: Arc::clone(&private_storage),
        dkg_pubinfo_meta_store,
        param_file_map: Arc::clone(&param_file_map),
        session_preparer: session_preparer.clone(),
    };

    let preprocessor = RealPreprocessor {
        prss_setup,
        preproc_buckets,
        preproc_factory,
        num_sessions_preproc,
        param_file_map: param_file_map.clone(),
        session_preparer: session_preparer.clone(),
    };

    let crsgenerator = RealCrsGenerator {
        base_kms,
        public_storage,
        private_storage,
        crs_meta_store,
        param_file_map,
        session_preparer,
    };

    let kms = GenericKms::new(
        initiator,
        reencryptor,
        decryptor,
        keygenerator,
        preprocessor,
        crsgenerator,
        ddec_handle.abort_handle(),
    );

    Ok(kms)
}

/// This is a shared type between all the modules,
/// it's responsible for creating sessions and holds
/// information on the network setting.
#[derive(Clone)]
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
    ) -> distributed_decryption::execution::runtime::session::NetworkingImpl {
        let strat = self.networking_strategy.read().await;
        (strat)(session_id, self.role_assignments.clone())
    }

    async fn make_base_session(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<BaseSessionStruct<AesRng, SessionParameters>> {
        let networking = self.get_networking(session_id).await;
        let own_identity = self.own_identity()?;

        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            own_identity,
            self.role_assignments.clone(),
        )?;
        let base_session =
            BaseSessionStruct::new(parameters, networking, self.base_kms.new_rng().await?)?;
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
        let base_session = self.make_base_session(session_id).await?;
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
            read_at_request_id::<PrivS, PRSSSetup<ResiduePoly128>>(
                &guarded_private_storage,
                &RequestId::from(epoch_id),
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .map_err(|e| {
                tracing::warn!("failed to read PRSS from file with error: {e}");
                e
            })
            .ok()
        };

        // check if a PRSS setup already exists in storage.
        match prss_setup_from_file {
            Some(prss_setup) => {
                let mut guarded_prss_setup = self.prss_setup.write().await;
                *guarded_prss_setup = Some(prss_setup.clone());
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
        let mut base_session = self.session_preparer.make_base_session(session_id).await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        let prss_setup_obj: PRSSSetup<ResiduePoly128> =
            PRSSSetup::robust_init(&mut base_session, &RealVss::default()).await?;

        let mut guarded_prss_setup = self.prss_setup.write().await;
        *guarded_prss_setup = Some(prss_setup_obj.clone());

        // serialize and write PRSS Setup to disk into private storage
        let private_storage = Arc::clone(&self.private_storage);
        let mut priv_storage = private_storage.lock().await;
        store_at_request_id(
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
        client_verf_key: &PublicSigKey,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: RwLockReadGuard<'_, HashMap<RequestId, ThresholdFheKeys>>,
    ) -> anyhow::Result<Vec<u8>> {
        let low_level_ct = fhe_type.deserialize_to_low_level(ct)?;
        let keys = match fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => return Err(anyhow!("Could not deserialize meta store")),
        };
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
                            let partial_dec_serialized = serialize(&partial_dec)?;
                            let signcryption_msg = SigncryptionPayload {
                                plaintext: Plaintext::from_bytes(partial_dec_serialized, fhe_type),
                                link,
                            };
                            let enc_res = signcrypt(
                                rng,
                                &bincode::serialize(&signcryption_msg)?,
                                client_enc_key,
                                client_verf_key,
                                &sig_key,
                            )?;
                            serialize(&enc_res)?
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
        let (
            ciphertext,
            fhe_type,
            link,
            client_enc_key,
            client_verf_key,
            servers_needed,
            key_id,
            req_id,
        ) = tonic_handle_potential_err(
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
        let mut rng = tonic_handle_potential_err(
            self.base_kms.new_rng().await,
            "Could not get a new RNG".to_string(),
        )?;
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
                &client_verf_key,
                sig_key,
                fhe_keys_rlock,
            )
            .await;
            let mut guarded_meta_store = meta_store.write().await;
            match tmp {
                Ok(partial_dec) => {
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store.update(
                        &req_id,
                        HandlerStatus::Done((servers_needed, link, fhe_type, partial_dec)),
                    );
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
        let (servers_needed, link, fhe_type, signcrypted_ciphertext) = {
            let guarded_meta_store = self.reenc_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Reencryption",
            )?
        };
        let server_verf_key = self.base_kms.get_serialized_verf_key();
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            signcrypted_ciphertext,
            fhe_type: fhe_type.into(),
            digest: link,
            verification_key: server_verf_key,
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
        let low_level_ct = fhe_type.deserialize_to_low_level(ct)?;
        let keys = match fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => {
                return Err(anyhow_error_and_log(format!(
                    "Key handle {key_handle} does not exist"
                )))
            }
        };
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
        let (ciphertext, fhe_type, req_digest, servers_needed, key_id, req_id) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )?;

        let mut session = tonic_handle_potential_err(
            self.session_preparer
                .prepare_ddec_data_from_requestid(&req_id)
                .await,
            "Could not prepare ddec data for reencryption".to_string(),
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

        let mut protocol = Small::new(session.clone());
        let meta_store = Arc::clone(&self.dec_meta_store);
        let fhe_keys = Arc::clone(&self.fhe_keys);

        // we do not need to hold the handle,
        // the result of the computation is tracked by the dec_meta_store
        let _handle = tokio::spawn(async move {
            let fhe_keys_rlock = fhe_keys.read().await;
            let tmp = match fhe_type {
                FheType::Euint512 => {
                    todo!("Implement decryption for Euint512")
                }
                FheType::Euint1024 => {
                    todo!("Implement decryption for Euint1024")
                }
                FheType::Euint2048 => Self::inner_decrypt::<tfhe::integer::bigint::U2048>(
                    &mut session,
                    &mut protocol,
                    &ciphertext,
                    fhe_type,
                    &key_id,
                    fhe_keys_rlock,
                )
                .await
                .map(Plaintext::from_u2048),
                FheType::Euint256 => Self::inner_decrypt::<tfhe::integer::U256>(
                    &mut session,
                    &mut protocol,
                    &ciphertext,
                    fhe_type,
                    &key_id,
                    fhe_keys_rlock,
                )
                .await
                .map(Plaintext::from_u256),
                FheType::Euint160 => Self::inner_decrypt::<tfhe::integer::U256>(
                    &mut session,
                    &mut protocol,
                    &ciphertext,
                    fhe_type,
                    &key_id,
                    fhe_keys_rlock,
                )
                .await
                .map(Plaintext::from_u160),
                FheType::Euint128 => Self::inner_decrypt::<u128>(
                    &mut session,
                    &mut protocol,
                    &ciphertext,
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
                    &ciphertext,
                    fhe_type,
                    &key_id,
                    fhe_keys_rlock,
                )
                .await
                .map(|x| Plaintext::new(x as u128, fhe_type)),
            };
            let mut guarded_meta_store = meta_store.write().await;
            match tmp {
                Ok(plaintext) => {
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store.update(
                        &req_id,
                        HandlerStatus::Done((
                            servers_needed,
                            req_digest.clone(),
                            plaintext.clone(),
                        )),
                    );
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
        let (servers_needed, req_digest, plaintext) = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Decryption",
            )?
        };
        let decrypted_bytes = tonic_handle_potential_err(
            serialize(&plaintext),
            format!(
                "Could not convert plaintext to bytes in request with ID {:?}",
                request_id
            ),
        )?;
        let server_verf_key = self.base_kms.get_serialized_verf_key();
        let sig_payload = DecryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            plaintext: decrypted_bytes,
            verification_key: server_verf_key,
            digest: req_digest,
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
    // Map storing the identity of parameters and the parameter file paths
    param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>,
    session_preparer: SessionPreparer,
}

impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    RealKeyGenerator<PubS, PrivS>
{
    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        mut preproc_handle: Box<dyn DKGPreprocessing<ResiduePoly128>>,
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
            self.session_preparer.make_base_session(session_id).await?
        };

        // Clone all the Arcs to give them to the tokio thread
        let meta_store = Arc::clone(&self.dkg_pubinfo_meta_store);
        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let sig_key = Arc::clone(&self.base_kms.sig_key);
        let fhe_keys = Arc::clone(&self.fhe_keys);

        //Start the async dkg job
        // TODO the following code could be simplified with a helper method similar to inner_decrypt
        let _handle = tokio::spawn(async move {
            //Actually do the dkg
            let dkg_res =
                distributed_keygen_z128(&mut base_session, preproc_handle.as_mut(), dkg_params)
                    .await;

            //Make sure the dkg ended nicely
            let (pub_key_set, private_keys) = match dkg_res {
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

            //Take lock on all the storage at once, so we either update everything or nothing
            let mut pub_storage = public_storage.lock().await;
            let mut priv_storage = private_storage.lock().await;

            let private_key_data = ThresholdFheKeys {
                private_keys,
                sns_key,
                pk_meta_data: info.clone(),
            };
            //Try to store the new data
            if store_at_request_id(
                &mut (*priv_storage),
                &req_id,
                &private_key_data,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .is_ok()
            // Only store the public keys if no other server has already stored them
                && store_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &pub_key_set.public_key,
                    &PubDataType::PublicKey.to_string(),
                ).await
                .is_ok()
                && store_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &pub_key_set.server_key,
                    &PubDataType::ServerKey.to_string(),
                )
                .await
                .is_ok()
                && store_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &private_key_data.sns_key,
                    &PubDataType::SnsKey.to_string(),
                )
                .await
                .is_ok()
            {
                {
                    let mut guarded_fhe_keys = fhe_keys.write().await;
                    guarded_fhe_keys.insert(req_id.clone(), private_key_data);
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
                let _ = delete_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &PubDataType::PublicKey.to_string(),
                )
                .await;
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
}

#[tonic::async_trait]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static> KeyGenerator
    for RealKeyGenerator<PubS, PrivS>
{
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set".to_string(),
        )?;
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
        let params = tonic_handle_potential_err(
            retrieve_parameters_sync(inner.params, self.param_file_map.clone()).await,
            "Parameter choice is not recognized".to_string(),
        )?;
        let dkg_params = DKGParams::WithSnS(DKGParamsSnS {
            regular_params: DKGParamsRegular {
                sec: SEC_PAR,
                ciphertext_parameters: params.ciphertext_parameters,
                flag: true,
            },
            sns_params: params.sns_parameters,
        });

        let preproc_id = tonic_some_or_err(
            inner.preproc_id.clone(),
            "Request ID is not set".to_string(),
        )?;

        //separate scope to get mutex on preproc storage
        let preproc_entry = {
            let mut map = self.preproc_buckets.write().await;
            let preproc = map.delete(&preproc_id);
            handle_res_mapping(preproc, &preproc_id, "Preprocessing")?
        };
        tonic_handle_potential_err(
            self.launch_dkg(dkg_params, preproc_entry, request_id.clone())
                .await,
            format!("Error launching dkg for request ID {request_id}"),
        )?;

        //Always answer with Empty
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
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

pub struct RealPreprocessor {
    // TODO eventually add mode to allow for nlarge as well.
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePoly128>>>>,
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    preproc_factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
    num_sessions_preproc: u16,
    param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>,
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
                    .make_base_session(SessionId(sid))
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
            "Request ID is not set".to_string(),
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
        let params = tonic_handle_potential_err(
            retrieve_parameters_sync(inner.params, self.param_file_map.clone()).await,
            "Parameter choice is not recognized".to_string(),
        )?;

        let dkg_params = DKGParams::WithSnS(DKGParamsSnS {
            regular_params: DKGParamsRegular {
                sec: SEC_PAR,
                ciphertext_parameters: params.ciphertext_parameters,
                flag: true,
            },
            sns_params: params.sns_parameters,
        });

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
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set".to_string(),
        )?;
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
    crs_meta_store: Arc<RwLock<MetaStore<CrsMetaStore>>>,
    param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>,
    session_preparer: SessionPreparer,
}

impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    RealCrsGenerator<PubS, PrivS>
{
    async fn inner_crs_gen(&self, req_id: &RequestId, witness_dim: usize) -> anyhow::Result<()> {
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
        let _handle = tokio::spawn(async move {
            let crs_start_timer = Instant::now();
            let real_ceremony = RealCeremony::default();
            let res_pp = real_ceremony
                .execute::<Z64, _, _>(&mut session, witness_dim)
                .await;
            let res_info_pp =
                res_pp.and_then(|pp| compute_info(&sig_key, &pp).map(|info| (info, pp)));
            let f = || async {
                // we take these two locks at the same time in case there are races
                // on return, the two locks should be dropped in the correct order also
                let mut pub_storage = public_storage.lock().await;
                let mut priv_storage = private_storage.lock().await;

                let (info, pp) = match res_info_pp {
                    Ok(info_pp) => info_pp,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store
                            .update(&owned_req_id, HandlerStatus::Error(e.to_string()));
                        return;
                    }
                };

                let crs_meta_data = (info.key_handle, info.signature);
                if store_at_request_id(
                    &mut (*priv_storage),
                    &owned_req_id,
                    &crs_meta_data,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await
                .is_ok()
                // Only store the CRS if no other server has already stored it
                    && store_at_request_id(
                        &mut (*pub_storage),
                        &owned_req_id,
                        &pp,
                        &PubDataType::CRS.to_string(),
                    )
                    .await
                    .is_ok()
                {
                    let mut guarded_meta_store = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store
                        .update(&owned_req_id, HandlerStatus::Done(crs_meta_data));
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

        let fhe_params = crate::rpc::central_rpc::retrieve_parameters_sync(
            req_inner.params,
            self.param_file_map.clone(),
        )
        .await
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::NotFound,
                format!("Can not retrieve fhe parameters with error {e}"),
            )
        })?
        .ciphertext_parameters;
        let witness_dim = tonic_handle_potential_err(
            compute_witness_dim(&fhe_params),
            "witness dimension computation failed".to_string(),
        )?;

        let req_id = req_inner.request_id.ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                "missing request ID in CRS generation",
            )
        })?;
        self.inner_crs_gen(&req_id, witness_dim)
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
        let (digest, signature) = handle_res_mapping(
            guarded_meta_store.retrieve(&request_id).cloned(),
            &request_id,
            "CRS generation",
        )?;
        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(SignedPubDataHandle {
                key_handle: digest,
                signature,
            }),
        }))
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
            purge(None, Some(cur_priv.root_dir()), &req_id.to_string()).await;

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

        // check that PRSS was created (and not read form disk)
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

        // check that PRSS was not created, but instead read form disk now
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
