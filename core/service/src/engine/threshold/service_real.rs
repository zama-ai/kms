use crate::conf::threshold::{PeerConf, ThresholdPartyConf, TlsCert};
use crate::consts::{MINIMUM_SESSIONS_PREPROC, PRSS_INIT_REQ_ID};
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicEncKey};
use crate::cryptography::signcryption::signcrypt_with_link;
use crate::engine::base::{
    compute_external_pt_signature, deserialize_to_low_level, retrieve_parameters,
};
use crate::engine::base::{compute_external_reenc_signature, BaseKmsStruct};
use crate::engine::base::{compute_info, preproc_proto_to_keyset_config};
use crate::engine::base::{convert_key_response, DecCallValues, KeyGenCallValues, ReencCallValues};
use crate::engine::threshold::generic::GenericKms;
use crate::engine::threshold::traits::{
    CrsGenerator, Decryptor, Initiator, KeyGenPreprocessor, KeyGenerator, Reencryptor,
};
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
use anyhow::anyhow;
use conf_trace::metrics;
use conf_trace::metrics_names::{
    ERR_DECRYPTION_FAILED, ERR_RATE_LIMIT_EXCEEDED, OP_CRS_GEN, OP_DECOMPRESSION_KEYGEN,
    OP_DECRYPT_INNER, OP_DECRYPT_REQUEST, OP_INSECURE_CRS_GEN, OP_INSECURE_DECOMPRESSION_KEYGEN,
    OP_INSECURE_KEYGEN, OP_KEYGEN, OP_KEYGEN_PREPROC, OP_REENCRYPT_INNER, OP_REENCRYPT_REQUEST,
    TAG_DECRYPTION_KIND, TAG_KEY_ID, TAG_PARTY_ID, TAG_TFHE_TYPE,
};
use itertools::Itertools;
use k256::ecdsa::SigningKey;
use kms_grpc::kms::v1::{
    CiphertextFormat, CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse,
    DecryptionResponsePayload, Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocResult,
    KeyGenRequest, KeyGenResult, KeySetAddedInfo, ReencryptionRequest, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId, TypedCiphertext, TypedPlaintext,
    TypedSigncryptedCiphertext,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::{
    protobuf_to_alloy_domain_option, PrivDataType, PubDataType, SigncryptionPayload,
    SignedPubDataHandleInternal,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::Arc;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::named::Named;
use tfhe::{FheTypes, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::algebra::base_ring::Z128;
use threshold_fhe::algebra::galois_rings::common::pack_residue_poly;
use threshold_fhe::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
use threshold_fhe::algebra::structure_traits::Ring;
use threshold_fhe::execution::endpoints::decryption::{
    decrypt_using_bitdec, decrypt_using_noiseflooding, partial_decrypt_using_bitdec,
    partial_decrypt_using_noiseflooding, DecryptionMode, Small,
};
use threshold_fhe::execution::endpoints::keygen::{
    distributed_decompression_keygen_z128, distributed_keygen_from_optional_compression_sk_z128,
    distributed_keygen_z128, CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum,
    PrivateKeySet,
};
use threshold_fhe::execution::keyset_config as ddec_keyset_config;
use threshold_fhe::execution::large_execution::vss::RealVss;
use threshold_fhe::execution::online::preprocessing::orchestration::dkg_orchestrator::PreprocessingOrchestrator;
use threshold_fhe::execution::online::preprocessing::{
    create_memory_factory, create_redis_factory, DKGPreprocessing, PreprocessorFactory,
};
use threshold_fhe::execution::runtime::party::{Identity, Role, RoleAssignment};
use threshold_fhe::execution::runtime::session::{
    BaseSessionStruct, ParameterHandles, SessionParameters, SmallSession, ToBaseSession,
};
use threshold_fhe::execution::small_execution::prss::PRSSSetup;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::zk::ceremony::{compute_witness_dim, Ceremony, RealCeremony};
use threshold_fhe::networking::grpc::{CoreToCoreNetworkConfig, GrpcNetworkingManager, GrpcServer};
use threshold_fhe::networking::{
    tls::{extract_subject_from_cert, AttestedClientVerifier, BasicTLSConfig, TlsAcceptorStream},
    NetworkMode, Networking, NetworkingStrategy,
};
use threshold_fhe::session_id::{SessionId, SESSION_ID_BYTES};
use threshold_fhe::{algebra::base_ring::Z64, execution::endpoints::keygen::FhePubKeySet};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock};
use tokio::time::Instant;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ServerConfig, WebPkiClientVerifier},
    RootCertStore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_health::server::HealthReporter;
use tracing::Instrument;
use x509_parser::pem::parse_x509_pem;

const DSEP_SESSION_DECRYPTION: &[u8; 18] = b"SESSION_DECRYPTION";
const DSEP_SESSION_REENCRYPTION: &[u8; 20] = b"SESSION_REENCRYPTION";
const DSEP_SESSION_PREPROCESSING: &[u8; 21] = b"SESSION_PREPROCESSING";

fn derive_session_id_from_ctr(
    ctr: u64,
    domain_separator: &[u8],
    req_id: &RequestId,
) -> anyhow::Result<SessionId> {
    if !req_id.is_valid() {
        anyhow::bail!("invalid request ID: {}", req_id.request_id);
    }
    let req_id_buf = hex::decode(&req_id.request_id)?;

    // H(domain_separator || req_id (256 bits) || counter (64 bits))
    let mut hasher = Sha3_256::new();
    hasher.update(domain_separator);
    hasher.update(req_id_buf);
    hasher.update(ctr.to_le_bytes());
    let digest = hasher.finalize();

    let mut sid_buf = [0u8; SESSION_ID_BYTES];
    sid_buf.copy_from_slice(&digest[0..SESSION_ID_BYTES]);

    Ok(SessionId(u128::from_le_bytes(sid_buf)))
}

cfg_if::cfg_if! {
    if #[cfg(feature = "insecure")] {
        use crate::engine::centralized::central_kms::async_generate_crs;
        use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
        use threshold_fhe::algebra::galois_rings::common::{ResiduePoly};
        use threshold_fhe::execution::sharing::open::robust_opens_to;
        use threshold_fhe::execution::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
        use threshold_fhe::execution::tfhe_internals::glwe_key::GlweSecretKeyShare;
        use threshold_fhe::execution::tfhe_internals::test_feature::{
            initialize_key_material, to_hl_client_key, transfer_crs, transfer_decompression_key,
            INPUT_PARTY_ID,
        };
        use tfhe::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
    }
}

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
    config: ThresholdPartyConf,
    tcp_listener: TcpListener,
    public_storage: PubS,
    private_storage: PrivS,
    backup_storage: Option<BackS>,
    tls_identity: Option<BasicTLSConfig>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    shutdown_signal: F,
) -> anyhow::Result<(
    RealThresholdKms<PubS, PrivS, BackS>,
    HealthServer<impl Health>,
)> {
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

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let kms = new_real_threshold_kms(
        config.threshold,
        config.dec_capacity,
        config.min_dec_cache,
        tcp_listener,
        config.my_id,
        factory,
        num_sessions_preproc,
        config.peers,
        public_storage,
        private_storage,
        backup_storage,
        tls_identity,
        config.core_to_core_net,
        config.decryption_mode,
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
    Ok((kms, health_service))
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum ThresholdFheKeysVersioned {
    V0(ThresholdFheKeys),
}

/// These are the internal key materials (public and private)
/// that's needed for decryption, reencryption and verifying a proven input.
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

type BucketMetaStore = Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>;

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
>;

#[allow(clippy::too_many_arguments)]
async fn new_real_threshold_kms<PubS, PrivS, BackS, F>(
    threshold: u8,
    dec_capacity: usize,
    min_dec_cache: usize,
    tcp_listener: TcpListener,
    my_id: usize,
    preproc_factory: Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    num_sessions_preproc: u16,
    peer_configs: Vec<PeerConf>,
    public_storage: PubS,
    private_storage: PrivS,
    backup_storage: Option<BackS>,
    tls_identity: Option<BasicTLSConfig>,
    core_to_core_net_conf: Option<CoreToCoreNetworkConfig>,
    decryption_mode: DecryptionMode,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    core_service_health_reporter: HealthReporter,
    shutdown_signal: F,
) -> anyhow::Result<RealThresholdKms<PubS, PrivS, BackS>>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let local_addr = tcp_listener.local_addr()?;
    tracing::info!(
        "Starting threshold KMS Server. Party ID {my_id}, listening for MPC communication on {:?}...",local_addr
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

    let role_assignments: RoleAssignment = peer_configs
        .clone()
        .into_iter()
        .map(|peer_config| peer_config.into_role_identity())
        .collect();

    let own_identity = tonic_some_or_err(
        role_assignments.get(&Role::indexed_by_one(my_id)),
        "Could not find my own identity".to_string(),
    )?;

    let tls_certs = tls_identity
        .map(|(cert, key, trusted_releases)| {
            peer_configs
                .iter()
                .flat_map(|peer| {
                    peer.tls_cert.as_ref().map(|tls_cert| match tls_cert {
                        TlsCert::Path(path) => std::fs::read_to_string(path),
                        TlsCert::Pem(bytes) => Ok(bytes.to_string()),
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("{e}"))
                .and_then(|ca_certs| {
                    ca_certs
                        .iter()
                        .map(|c| {
                            parse_x509_pem(c.as_ref())
                                .map(|(_, pem)| pem)
                                .map_err(|e| anyhow::anyhow!("{e}"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .map(|ca_certs| (cert, key, ca_certs, trusted_releases))
        })
        .transpose()?;

    // We have to construct a rustls config ourselves instead of using the
    // wrapper from tonic::transport because we need to provide our own
    // certificate verifier that can also validate bundled attestation
    // documents.
    let tls_config = match tls_certs.clone() {
        Some((cert, key, ca_certs, trusted_releases)) => {
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(
                ca_certs
                    .iter()
                    .map(|pem| CertificateDer::from_slice(pem.contents.as_slice())),
            );
            let cert_chain =
                vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()];
            let key_der = PrivateKeyDer::try_from(key.contents.as_slice())
                .map_err(|e| anyhow_error_and_log(e.to_string()))?
                .clone_key();

            let safe_client_cert_verifier =
                WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
            let client_verifier = match trusted_releases {
                Some(trusted_releases) => {
                    tracing::info!("Creating server with TLS and AWS Nitro attestation");
                    Arc::new(AttestedClientVerifier::new(
                        safe_client_cert_verifier,
                        trusted_releases.clone(),
                    ))
                }
                None => {
                    tracing::info!("Creating server with TLS and without AWS Nitro attestation");
                    safe_client_cert_verifier
                }
            };
            Some(
                ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(cert_chain, key_der)?,
            )
        }
        None => {
            tracing::warn!("Creating server without TLS");
            None
        }
    };

    // we'll use this hashmap in SendingService to configure client TLS with
    // only one CA certificate in the root store per server
    let tls_certs = tls_certs
        .map(|(cert, key, ca_certs, trusted_releases)| {
            ca_certs
                .iter()
                .map(|cert_pem| {
                    cert_pem
                        .clone()
                        .parse_x509()
                        .map_err(|e| anyhow::anyhow!("{e}"))
                        .and_then(|ref cert| {
                            extract_subject_from_cert(cert).map(|s| (s, cert_pem.clone()))
                        })
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()
                .map(|ca_certs| {
                    tracing::info!("Using TLS trust anchors: {:?}", ca_certs.keys());
                    (cert, key, ca_certs, trusted_releases)
                })
        })
        .transpose()?;

    let (threshold_health_reporter, threshold_health_service) =
        tonic_health::server::health_reporter();
    // This will setup client TLS if tls_certs is set to Some(...)
    let networking_manager = Arc::new(RwLock::new(GrpcNetworkingManager::new(
        own_identity.to_owned(),
        tls_certs,
        core_to_core_net_conf,
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
        local_addr
    );

    let networking_strategy: Arc<RwLock<NetworkingStrategy>> = Arc::new(RwLock::new(Box::new(
        move |session_id, roles, network_mode| {
            let nm = networking_manager.clone();
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
                local_addr
            );
            threshold_health_reporter
                .set_not_serving::<GrpcServer>()
                .await;
        };

        // this looks somewhat hairy but there doesn't seem to be an easier way
        // to use arbitrary rustls configs until tonic::transport becomes a
        // separate crate from tonic (whose maintainers don't want to make its
        // API dependent on rustls)
        match tls_config {
            Some(tls_config) => {
                router
                    .serve_with_incoming_shutdown(
                        TlsAcceptorStream::new(tcp_listener, tls_config),
                        graceful_shutdown_signal,
                    )
                    .await
            }
            None => {
                router
                    .serve_with_incoming_shutdown(
                        tokio_stream::wrappers::TcpListenerStream::new(tcp_listener),
                        graceful_shutdown_signal,
                    )
                    .await
            }
        }
        .map_err(|e| {
            anyhow_error_and_log(format!(
                "Failed to launch ddec server on {} with error: {:?}",
                local_addr, e
            ))
        })?;
        tracing::info!(
            "core/threshold on {} shutdown completed successfully",
            local_addr
        );
        Ok(())
    });
    let base_kms = BaseKmsStruct::new(sk)?;

    let prss_setup_z128 = Arc::new(RwLock::new(None));
    let prss_setup_z64 = Arc::new(RwLock::new(None));
    let preproc_buckets = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let preproc_factory = Arc::new(Mutex::new(preproc_factory));
    let crs_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(crs_info)));
    let dkg_pubinfo_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info)));
    let dec_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let reenc_meta_store = Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache)));
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        public_storage,
        private_storage,
        backup_storage,
        pk_map,
        key_info_versioned,
    );

    let session_preparer = SessionPreparer {
        base_kms: base_kms.new_instance().await,
        threshold,
        my_id,
        role_assignments: role_assignments.clone(),
        networking_strategy,
        prss_setup_z128: Arc::clone(&prss_setup_z128),
        prss_setup_z64: Arc::clone(&prss_setup_z64),
    };

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
            my_id
        );

        initiator.init_prss(&req_id_prss).await?;
    } else {
        tracing::info!(
            "Trying to initializing threshold KMS server and reading PRSS from storage for {}",
            my_id
        );
        if let Err(e) = initiator.init_prss_from_disk(&req_id_prss).await {
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
        session_preparer: Arc::new(session_preparer.new_instance().await),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode,
    };

    let decryptor = RealDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        dec_meta_store,
        session_preparer: Arc::new(session_preparer.new_instance().await),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode,
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
        Arc::clone(&tracker),
        Arc::clone(&thread_core_health_reporter),
        abort_handle,
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
    prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>, // TODO make generic?
    prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,   // TODO make generic?
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
    ) -> anyhow::Result<threshold_fhe::execution::runtime::session::NetworkingImpl> {
        let strat = self.networking_strategy.read().await;
        let networking = (strat)(session_id, self.role_assignments.clone(), network_mode).await?;
        Ok(networking)
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
            BaseSessionStruct::new(parameters, networking?, self.base_kms.new_rng().await)?;
        Ok(base_session)
    }

    async fn prepare_ddec_data_from_sessionid_z128(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z128>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
            .await?;
        let prss_setup = tonic_some_or_err(
            self.prss_setup_z128.read().await.clone(),
            "No PRSS setup Z128 exists".to_string(),
        )?;
        let prss_state = prss_setup.new_prss_session_state(session_id);

        let session = SmallSession {
            base_session,
            prss_state,
        };
        Ok(session)
    }

    async fn prepare_ddec_data_from_sessionid_z64(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePolyF4Z64>> {
        //DDec for small session is only online, so requires only Async network
        let base_session = self
            .make_base_session(session_id, NetworkMode::Async)
            .await?;
        let prss_setup = tonic_some_or_err(
            self.prss_setup_z64.read().await.clone(),
            "No PRSS setup Z64 exists".to_string(),
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
            prss_setup_z128: self.prss_setup_z128.clone(),
            prss_setup_z64: self.prss_setup_z64.clone(),
        }
    }
}

pub struct RealInitiator<PrivS: Storage + Send + Sync + 'static> {
    // TODO eventually add mode to allow for nlarge as well.
    prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    prss_setup_z64: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z64>>>>,
    private_storage: Arc<Mutex<PrivS>>,
    session_preparer: SessionPreparer,
    health_reporter: Arc<RwLock<HealthReporter>>,
}

impl<PrivS: Storage + Send + Sync + 'static> RealInitiator<PrivS> {
    async fn init_prss_from_disk(&self, req_id: &RequestId) -> anyhow::Result<()> {
        let prss_setup_z128_from_file = {
            let guarded_private_storage = self.private_storage.lock().await;
            let base_session = self
                .session_preparer
                .make_base_session(SessionId(req_id.clone().try_into()?), NetworkMode::Sync)
                .await?;
            read_versioned_at_request_id(
                &(*guarded_private_storage),
                &RequestId::derive(&format!(
                    "PRSSSetup_Z128_ID_{}_{}_{}",
                    req_id,
                    base_session.parameters.num_parties(),
                    base_session.parameters.threshold()
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
            let base_session = self
                .session_preparer
                .make_base_session(SessionId(req_id.clone().try_into()?), NetworkMode::Sync)
                .await?;
            read_versioned_at_request_id(
                &(*guarded_private_storage),
                &RequestId::derive(&format!(
                    "PRSSSetup_Z64_ID_{}_{}_{}",
                    req_id,
                    base_session.parameters.num_parties(),
                    base_session.parameters.threshold()
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
                .write()
                .await
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS, PrivS>>>()
                .await;
        }
        Ok(())
    }

    async fn init_prss(&self, req_id: &RequestId) -> anyhow::Result<()> {
        if self.prss_setup_z128.read().await.is_some() || self.prss_setup_z64.read().await.is_some()
        {
            return Err(anyhow_error_and_log("PRSS state already exists"));
        }

        let own_identity = self.session_preparer.own_identity()?;
        let session_id = SessionId(req_id.clone().try_into()?);
        //PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = self
            .session_preparer
            .make_base_session(session_id, NetworkMode::Sync)
            .await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        let prss_setup_obj_z128: PRSSSetup<ResiduePolyF4Z128> =
            PRSSSetup::robust_init(&mut base_session, &RealVss::default()).await?;

        let prss_setup_obj_z64: PRSSSetup<ResiduePolyF4Z64> =
            PRSSSetup::robust_init(&mut base_session, &RealVss::default()).await?;

        let mut guarded_prss_setup = self.prss_setup_z128.write().await;
        *guarded_prss_setup = Some(prss_setup_obj_z128.clone());

        let mut guarded_prss_setup = self.prss_setup_z64.write().await;
        *guarded_prss_setup = Some(prss_setup_obj_z64.clone());

        // serialize and write PRSS Setup to disk into private storage
        let private_storage = Arc::clone(&self.private_storage);
        let mut priv_storage = private_storage.lock().await;
        store_versioned_at_request_id(
            &mut (*priv_storage),
            &RequestId::derive(&format!(
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
            &RequestId::derive(&format!(
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
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();

        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (inner key gen)".to_string(),
        )?;

        self.init_prss(&request_id).await.map_err(|e| {
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
    session_preparer: Arc<SessionPreparer>,
    tracker: Arc<TaskTracker>,
    rate_limiter: RateLimiter,
    decryption_mode: DecryptionMode,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealReencryptor<PubS, PrivS, BackS>
{
    /// Helper method for reencryptin which carries out the actual threshold decryption using noise
    /// flooding or bit-decomposition.
    ///
    /// This function does not perform reencryption in a background thread.
    /// The return type should be [ReencCallValues] except the final item in the tuple
    #[allow(clippy::too_many_arguments)]
    async fn inner_reencrypt(
        req_id: &RequestId,
        session_prep: Arc<SessionPreparer>,
        rng: &mut (impl CryptoRng + RngCore),
        typed_ciphertexts: &[TypedCiphertext],
        link: Vec<u8>,
        client_enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
        server_verf_key: Vec<u8>,
        dec_mode: DecryptionMode,
        domain: &alloy_sol_types::Eip712Domain,
        metric_tags: Vec<(&'static str, String)>,
    ) -> anyhow::Result<(ReencryptionResponsePayload, Vec<u8>)> {
        let keys = fhe_keys;

        let mut all_signcrypted_cts = vec![];

        // TODO: Each iteration of this loop should probably happen
        // inside its own tokio task
        for (ctr, typed_ciphertext) in typed_ciphertexts.iter().enumerate() {
            // Create and start a the timer, it'll be dropped and thus
            // exported at the end of the iteration
            let mut inner_timer = metrics::METRICS
                .time_operation(OP_REENCRYPT_INNER)
                .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
                .and_then(|b| {
                    b.tags(metric_tags.clone()).map_err(|e| {
                        tracing::warn!("Failed to a tag in party_id, key_id or request_id : {}", e)
                    })
                })
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
                .ok();
            let fhe_type = typed_ciphertext.fhe_type()?;
            let fhe_type_str = typed_ciphertext.fhe_type_string();
            inner_timer
                .as_mut()
                .map(|b| b.tag(TAG_TFHE_TYPE, fhe_type_str));
            let ct_format = typed_ciphertext.ciphertext_format();
            let ct = &typed_ciphertext.ciphertext;
            let external_handle = typed_ciphertext.external_handle.clone();
            let session_id =
                derive_session_id_from_ctr(ctr as u64, DSEP_SESSION_REENCRYPTION, req_id)?;

            let low_level_ct =
                deserialize_to_low_level(fhe_type, ct_format, ct, &keys.decompression_key)?;

            let pdec: Result<(Vec<u8>, u32, std::time::Duration), anyhow::Error> = match dec_mode {
                DecryptionMode::NoiseFloodSmall => {
                    let mut session = tonic_handle_potential_err(
                        session_prep
                            .prepare_ddec_data_from_sessionid_z128(session_id)
                            .await,
                        "Could not prepare ddec data for noiseflood decryption".to_string(),
                    )?;
                    let mut preparation = Small::new(session.clone());

                    let pdec = partial_decrypt_using_noiseflooding(
                        &mut session,
                        &mut preparation,
                        &keys.integer_server_key,
                        keys.sns_key
                            .as_ref()
                            .ok_or(anyhow::anyhow!("missing sns key"))?,
                        low_level_ct,
                        &keys.private_keys,
                        DecryptionMode::NoiseFloodSmall,
                    )
                    .await;

                    let res = match pdec {
                        Ok((partial_dec_map, packing_factor, time)) => {
                            let pdec_serialized = match partial_dec_map.get(&session_id.to_string())
                            {
                                Some(partial_dec) => {
                                    let partial_dec = pack_residue_poly(partial_dec);
                                    bincode::serialize(&partial_dec)?
                                }
                                None => {
                                    return Err(anyhow!(
                                        "Reencryption with session ID {} could not be retrived",
                                        session_id.to_string()
                                    ))
                                }
                            };

                            (pdec_serialized, packing_factor, time)
                        }
                        Err(e) => {
                            return Err(anyhow!("Failed reencryption with noiseflooding: {e}"))
                        }
                    };
                    Ok(res)
                }
                DecryptionMode::BitDecSmall => {
                    let mut session = tonic_handle_potential_err(
                        session_prep
                            .prepare_ddec_data_from_sessionid_z64(session_id)
                            .await,
                        "Could not prepare ddec data for bitdec decryption".to_string(),
                    )?;

                    let pdec = partial_decrypt_using_bitdec(
                        &mut session,
                        &low_level_ct.try_get_small_ct()?,
                        &keys.private_keys,
                        &keys.integer_server_key.as_ref().key_switching_key,
                        DecryptionMode::BitDecSmall,
                    )
                    .await;

                    let res = match pdec {
                        Ok((partial_dec_map, time)) => {
                            let pdec_serialized = match partial_dec_map.get(&session_id.to_string())
                            {
                                Some(partial_dec) => {
                                    // let partial_dec = pack_residue_poly(partial_dec); // TODO use more compact packing for bitdec?
                                    bincode::serialize(&partial_dec)?
                                }
                                None => {
                                    return Err(anyhow!(
                                        "Reencryption with session ID {} could not be retrived",
                                        session_id.to_string()
                                    ))
                                }
                            };

                            // packing factor is always 1 with bitdec for now
                            // we may optionally pack it later
                            (pdec_serialized, 1, time)
                        }
                        Err(e) => return Err(anyhow!("Failed reencryption with bitdec: {e}")),
                    };
                    Ok(res)
                }
                mode => {
                    return Err(anyhow_error_and_log(format!(
                        "Unsupported Decryption Mode for reencrypt: {}",
                        mode
                    )));
                }
            };

            let (partial_signcryption, packing_factor) = match pdec {
                Ok((pdec_serialized, packing_factor, time)) => {
                    let signcryption_msg = SigncryptionPayload {
                        plaintext: TypedPlaintext::from_bytes(pdec_serialized, fhe_type),
                        link: link.clone(),
                    };
                    let enc_res = signcrypt_with_link(
                        rng,
                        &signcryption_msg,
                        client_enc_key,
                        client_address,
                        &sig_key,
                    )?;
                    let res = bincode::serialize(&enc_res)?;

                    tracing::info!(
                        "Reencryption completed for type {:?}. Inner thread took {:?} ms",
                        fhe_type,
                        time.as_millis()
                    );
                    (res, packing_factor)
                }
                Err(e) => return Err(anyhow!("Failed reencryption: {e}")),
            };
            all_signcrypted_cts.push(TypedSigncryptedCiphertext {
                fhe_type: fhe_type as i32,
                signcrypted_ciphertext: partial_signcryption,
                external_handle,
                packing_factor,
            });
            //Explicitly drop the timer to record it
            drop(inner_timer);
        }

        let payload = ReencryptionResponsePayload {
            signcrypted_ciphertexts: all_signcrypted_cts,
            digest: link,
            verification_key: server_verf_key,
            party_id: session_prep.my_id as u32,
            degree: session_prep.threshold as u32,
        };

        let external_signature =
            compute_external_reenc_signature(&sig_key, &payload, domain, client_enc_key)?;
        Ok((payload, external_signature))
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
        let mut timer = metrics::METRICS
            .time_operation(OP_REENCRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_REENCRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        let permit = self.rate_limiter.start_reenc().await.map_err(|e| {
            let _ = metrics::METRICS
                .increment_error_counter(OP_REENCRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED);
            Status::resource_exhausted(e.to_string())
        })?;

        let inner = request.into_inner();
        tracing::info!(
            "Party {:?} received a new reencryption request with request_id {:?}",
            self.session_preparer.own_identity(),
            inner.request_id
        );
        let (typed_ciphertexts, link, client_enc_key, client_address, key_id, req_id, domain) =
            tonic_handle_potential_err(
                validate_reencrypt_req(&inner),
                format!("Failed to validate reencryption request: {:?}", inner),
            )?;

        if let Some(b) = timer.as_mut() {
            //We log but we don't want to return early because timer failed
            let _ = b
                .tags([(TAG_KEY_ID, key_id.request_id.clone())])
                .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
        }

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
            format!("Cannot find threshold keys with key ID {key_id}"),
        )?;

        let prep = Arc::clone(&self.session_preparer);
        let dec_mode = self.decryption_mode;

        let metric_tags = vec![
            (TAG_PARTY_ID, prep.my_id.to_string()),
            (TAG_KEY_ID, key_id.request_id.clone()),
            (TAG_DECRYPTION_KIND, dec_mode.as_str_name().to_string()),
        ];

        let server_verf_key = self.base_kms.get_serialized_verf_key();

        // the result of the computation is tracked the tracker
        self.tracker.spawn(
            async move {
                // Capture the timer, it is stopped when it's dropped
                let _timer = timer;
                // explicitly move the rate limiter context
                let _permit = permit;
                // Note that we'll hold a read lock for some time
                // but this should be ok since write locks
                // happen rarely as keygen is a rare event.
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await;
                let tmp = match fhe_keys_rlock {
                    Ok(k) => {
                        Self::inner_reencrypt(
                            &req_id,
                            prep,
                            &mut rng,
                            &typed_ciphertexts,
                            link.clone(),
                            &client_enc_key,
                            &client_address,
                            sig_key,
                            k,
                            server_verf_key,
                            dec_mode,
                            &domain,
                            metric_tags,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                let mut guarded_meta_store = meta_store.write().await;
                match tmp {
                    Ok((payload, sig)) => {
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(&req_id, Ok((payload, sig)));
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
        let (payload, external_signature) =
            handle_res_mapping(status, &request_id, "Reencryption").await?;

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
            external_signature,
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
    session_preparer: Arc<SessionPreparer>,
    tracker: Arc<TaskTracker>,
    rate_limiter: RateLimiter,
    decryption_mode: DecryptionMode,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealDecryptor<PubS, PrivS, BackS>
{
    /// Helper method for decryption which carries out the actual threshold decryption using noise
    /// flooding or bit-decomposition
    async fn inner_decrypt<T>(
        session_id: SessionId,
        session_prep: Arc<SessionPreparer>,
        ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
        dec_mode: DecryptionMode,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    {
        tracing::info!(
            "{:?} started inner_decrypt with mode {:?}",
            session_prep.own_identity(),
            dec_mode
        );

        let keys = fhe_keys;
        let low_level_ct =
            deserialize_to_low_level(fhe_type, ct_format, ct, &keys.decompression_key)?;

        let dec = match dec_mode {
            DecryptionMode::NoiseFloodSmall => {
                let mut session = tonic_handle_potential_err(
                    session_prep
                        .prepare_ddec_data_from_sessionid_z128(session_id)
                        .await,
                    "Could not prepare ddec data for noiseflood decryption".to_string(),
                )?;
                let mut preparation = Small::new(session.clone());

                decrypt_using_noiseflooding(
                    &mut session,
                    &mut preparation,
                    &keys.integer_server_key,
                    keys.sns_key
                        .as_ref()
                        .ok_or(anyhow::anyhow!("missing sns key"))?,
                    low_level_ct,
                    &keys.private_keys,
                    dec_mode,
                    session_prep.own_identity()?,
                )
                .await
            }
            DecryptionMode::BitDecSmall => {
                let mut session = tonic_handle_potential_err(
                    session_prep
                        .prepare_ddec_data_from_sessionid_z64(session_id)
                        .await,
                    "Could not prepare ddec data for bitdec decryption".to_string(),
                )?;

                decrypt_using_bitdec(
                    &mut session,
                    &low_level_ct.try_get_small_ct()?,
                    &keys.private_keys,
                    &keys.integer_server_key.as_ref().key_switching_key,
                    dec_mode,
                    session_prep.own_identity()?,
                )
                .await
            }
            mode => {
                return Err(anyhow_error_and_log(format!(
                    "Unsupported Decryption Mode: {}",
                    mode
                )));
            }
        };

        let raw_decryption = match dec {
            Ok((partial_dec, time)) => {
                let raw_decryption = match partial_dec.get(&session_id.to_string()) {
                    Some(raw_decryption) => *raw_decryption,
                    None => {
                        return Err(anyhow!(
                            "Decryption with session ID {} could not be retrived",
                            session_id.to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Decryption completed on {:?}. Inner thread took {:?} ms",
                    session_prep.own_identity(),
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
        let mut timer = metrics::METRICS
            .time_operation(OP_DECRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_DECRYPT_REQUEST)
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

        let (ciphertexts, req_digest, key_id, req_id, eip712_domain) = tonic_handle_potential_err(
            validate_decrypt_req(&inner),
            format!("Failed to validate decrypt request {:?}", inner),
        )
        .map_err(|e| {
            tracing::error!(
                error = ?e,
                request_id = ?inner.request_id,
                "Failed to validate decrypt request"
            );
            let _ =
                metrics::METRICS.increment_error_counter(OP_DECRYPT_REQUEST, ERR_DECRYPTION_FAILED);
            e
        })?;

        if let Some(b) = timer.as_mut() {
            //We log but we don't want to return early because timer failed
            let _ = b
                .tags([(TAG_KEY_ID, key_id.request_id.clone())])
                .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
        }
        tracing::debug!(
            request_id = ?req_id,
            key_id = ?key_id,
            ciphertexts_count = ciphertexts.len(),
            "Starting decryption process"
        );

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
            format!("Cannot find threshold keys with key ID {key_id}"),
        )?;

        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();

        let mut dec_tasks = Vec::new();
        let dec_mode = self.decryption_mode;

        // iterate over ciphertexts in this batch and decrypt each in their own session (so that it happens in parallel)
        for (ctr, typed_ciphertext) in ciphertexts.into_iter().enumerate() {
            let inner_timer = metrics::METRICS
                .time_operation(OP_DECRYPT_INNER)
                .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
                .and_then(|b| {
                    b.tags([
                        (TAG_PARTY_ID, self.session_preparer.my_id.to_string()),
                        (TAG_KEY_ID, key_id.request_id.clone()),
                        (TAG_DECRYPTION_KIND, dec_mode.as_str_name().to_string()),
                    ])
                    .map_err(|e| {
                        tracing::warn!("Failed to a tag in party_id, key_id or request_id : {}", e)
                    })
                })
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
                .ok();
            let internal_sid = tonic_handle_potential_err(
                derive_session_id_from_ctr(ctr as u64, DSEP_SESSION_DECRYPTION, &req_id),
                "failed to derive session ID from counter".to_string(),
            )?;
            let key_id = key_id.clone();
            let crypto_storage = self.crypto_storage.clone();
            let prep = Arc::clone(&self.session_preparer);

            // we do not need to hold the handle,
            // the result of the computation is tracked by the dec_meta_store
            let decrypt_future = || async move {
                let fhe_type_string = typed_ciphertext.fhe_type_string();
                let fhe_type = if let Ok(f) = typed_ciphertext.fhe_type() {
                    f
                } else {
                    return Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed due to wrong fhe type: {}",
                        typed_ciphertext.fhe_type
                    )));
                };
                // Capture the inner_timer inside the decryption tasks, such that when the task
                // exits, the timer is dropped and thus exported
                let mut inner_timer = inner_timer;
                inner_timer
                    .as_mut()
                    .map(|b| b.tag(TAG_TFHE_TYPE, fhe_type_string));

                let ciphertext = &typed_ciphertext.ciphertext;
                let ct_format = typed_ciphertext.ciphertext_format();
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await?;

                let res_plaintext = match fhe_type {
                    FheTypes::Uint2048 => Self::inner_decrypt::<tfhe::integer::bigint::U2048>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u2048),
                    FheTypes::Uint1024 => Self::inner_decrypt::<tfhe::integer::bigint::U1024>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u1024),
                    FheTypes::Uint512 => Self::inner_decrypt::<tfhe::integer::bigint::U512>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u512),
                    FheTypes::Uint256 => Self::inner_decrypt::<tfhe::integer::U256>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u256),
                    FheTypes::Uint160 => Self::inner_decrypt::<tfhe::integer::U256>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u160),
                    FheTypes::Uint128 => Self::inner_decrypt::<u128>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(|x| TypedPlaintext::new(x, fhe_type)),
                    FheTypes::Bool
                    | FheTypes::Uint4
                    | FheTypes::Uint8
                    | FheTypes::Uint16
                    | FheTypes::Uint32
                    | FheTypes::Uint64 => Self::inner_decrypt::<u64>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(|x| TypedPlaintext::new(x as u128, fhe_type)),
                    unsupported_fhe_type => {
                        anyhow::bail!("Unsupported fhe type {:?}", unsupported_fhe_type);
                    }
                };
                match res_plaintext {
                    Ok(plaintext) => Ok((ctr, plaintext)),
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
            // Move the timer to the management task's context, so as to drop
            // it when decryptions are available
            let _timer = timer;
            // NOTE: _permit should be dropped at the end of this function
            let mut decs = HashMap::new();
            while let Some(resp) = dec_tasks.pop() {
                match resp.await {
                    Ok(Ok((idx, plaintext))) => {
                        decs.insert(idx, plaintext);
                    }
                    Ok(Err(e)) => {
                        let msg = format!("Failed decryption with err: {:?}", e);
                        tracing::error!(msg);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(&req_id, Err(msg));
                        // exit mgmt task early in case of error
                        return;
                    }
                    Err(e) => {
                        let msg = format!("Failed decryption with JoinError: {:?}", e);
                        tracing::error!(msg);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(&req_id, Err(msg));
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

            // sign the plaintexts and handles for external verification (in fhevm)
            let external_sig = if let Some(domain) = eip712_domain {
                compute_external_pt_signature(&sigkey, ext_handles_bytes, &pts, domain)
            } else {
                tracing::warn!("Skipping external signature computation due to missing domain");
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
    Secure(Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>),
    Insecure,
}

impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > RealKeyGenerator<PubS, PrivS, BackS>
{
    #[allow(clippy::too_many_arguments)]
    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        keyset_added_info: KeySetAddedInfo,
        preproc_handle_w_mode: PreprocHandleWithMode,
        req_id: RequestId,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        //Retrieve the right metric tag
        let op_tag = match (&preproc_handle_w_mode, keyset_config) {
            (PreprocHandleWithMode::Secure(_), ddec_keyset_config::KeySetConfig::Standard(_)) => {
                OP_KEYGEN
            }
            (
                PreprocHandleWithMode::Secure(_),
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_DECOMPRESSION_KEYGEN,
            (PreprocHandleWithMode::Insecure, ddec_keyset_config::KeySetConfig::Standard(_)) => {
                OP_INSECURE_KEYGEN
            }
            (
                PreprocHandleWithMode::Insecure,
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_INSECURE_DECOMPRESSION_KEYGEN,
        };

        let _request_counter = metrics::METRICS
            .increment_request_counter(op_tag)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(op_tag)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });
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

        // we need to clone the req ID because async closures are not stable
        let req_id_clone = req_id.clone();
        let keygen_background = async move {
            match keyset_config {
                ddec_keyset_config::KeySetConfig::Standard(inner_config) => {
                    Self::key_gen_background(
                        &req_id_clone,
                        base_session,
                        meta_store,
                        crypto_storage,
                        preproc_handle_w_mode,
                        sk,
                        dkg_params,
                        inner_config,
                        keyset_added_info,
                        eip712_domain_copy,
                        permit,
                    )
                    .await
                }
                ddec_keyset_config::KeySetConfig::DecompressionOnly => {
                    Self::decompression_key_gen_background(
                        &req_id_clone,
                        base_session,
                        meta_store,
                        crypto_storage,
                        preproc_handle_w_mode,
                        sk,
                        dkg_params,
                        keyset_added_info,
                        eip712_domain_copy,
                        permit,
                    )
                    .await
                }
            }
        };
        self.tracker
            .spawn(async move {
                //Start the metric timer, it will end on drop
                let _timer = timer.map(|b| b.start());
                tokio::select! {
                    () = keygen_background => {
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

        let inner = request.into_inner();
        tracing::info!(
            "Keygen Request ID: {:?}, insecure={}",
            inner.request_id,
            insecure
        );
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
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

        // Retrieve kg params and preproc_id
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
            let preproc = {
                let mut map = self.preproc_buckets.write().await;
                map.delete(&preproc_id)
            };
            PreprocHandleWithMode::Secure(
                handle_res_mapping(preproc, &preproc_id, "Preprocessing").await?,
            )
        };

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref());

        let keyset_config = tonic_handle_potential_err(
            preproc_proto_to_keyset_config(&inner.keyset_config),
            "Failed to parse KeySetConfig".to_string(),
        )?;

        let keyset_added_info = inner.keyset_added_info.unwrap_or(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
        });

        tonic_handle_potential_err(
            self.launch_dkg(
                dkg_params,
                keyset_config,
                keyset_added_info,
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

    async fn decompression_key_gen_closure<P>(
        base_session: &mut BaseSessionStruct<AesRng, SessionParameters>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        preprocessing: &mut P,
    ) -> anyhow::Result<DecompressionKey>
    where
        P: DKGPreprocessing<threshold_fhe::algebra::galois_rings::common::ResiduePoly<Z128, 4>>
            + Send
            + ?Sized,
    {
        let from_key_id =
            keyset_added_info
                .from_keyset_id_decompression_only
                .ok_or(anyhow::anyhow!(
                "missing from key ID for the keyset that contains the compression secret key share"
            ))?;
        let to_key_id =
            keyset_added_info
                .to_keyset_id_decompression_only
                .ok_or(anyhow::anyhow!(
                    "missing to key ID for the keyset that contains the glwe secret key share"
                ))?;

        let private_compression_share = {
            let threshold_keys = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&from_key_id)
                .await?;
            let compression_sk_share = threshold_keys
                .private_keys
                .glwe_secret_key_share_compression
                .clone()
                .ok_or(anyhow::anyhow!("missing compression secret key share"))?;
            match compression_sk_share {
                CompressionPrivateKeySharesEnum::Z64(_share) => {
                    anyhow::bail!("z64 share is not supported")
                }
                CompressionPrivateKeySharesEnum::Z128(share) => share,
            }
        };
        let private_glwe_compute_share = {
            let threshold_keys = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&to_key_id)
                .await?;
            match threshold_keys.private_keys.glwe_secret_key_share.clone() {
                GlweSecretKeyShareEnum::Z64(_share) => {
                    anyhow::bail!("expected glwe secret shares to be in z128")
                }
                GlweSecretKeyShareEnum::Z128(share) => share,
            }
        };
        let shortint_decompression_key = distributed_decompression_keygen_z128(
            base_session,
            preprocessing,
            params,
            &private_glwe_compute_share,
            &private_compression_share,
        )
        .await?;
        Ok(DecompressionKey::from_raw_parts(shortint_decompression_key))
    }

    #[cfg(feature = "insecure")]
    async fn get_glwe_and_compression_key_shares(
        keyset_added_info: KeySetAddedInfo,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    ) -> anyhow::Result<(
        GlweSecretKeyShare<Z128, 4>,
        CompressionPrivateKeyShares<Z128, 4>,
    )> {
        let compression_req_id =
            keyset_added_info
                .from_keyset_id_decompression_only
                .ok_or(anyhow::anyhow!(
                "missing from key ID for the keyset that contains the compression secret key share"
            ))?;
        let glwe_req_id =
            keyset_added_info
                .to_keyset_id_decompression_only
                .ok_or(anyhow::anyhow!(
                    "missing to key ID for the keyset that contains the glwe secret key share"
                ))?;

        crypto_storage
            .refresh_threshold_fhe_keys(&glwe_req_id)
            .await?;
        let glwe_shares = {
            let guard = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&glwe_req_id)
                .await?;
            match &guard.private_keys.glwe_secret_key_share {
                GlweSecretKeyShareEnum::Z64(_) => anyhow::bail!("expected glwe shares to be z128"),
                GlweSecretKeyShareEnum::Z128(inner) => inner.clone(),
            }
        };

        crypto_storage
            .refresh_threshold_fhe_keys(&compression_req_id)
            .await?;
        let compression_shares = {
            let guard = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&compression_req_id)
                .await?;
            match &guard.private_keys.glwe_secret_key_share_compression {
                Some(compression_enum) => match compression_enum {
                    CompressionPrivateKeySharesEnum::Z64(_) => {
                        anyhow::bail!("expected compression shares to be z128")
                    }
                    CompressionPrivateKeySharesEnum::Z128(inner) => inner.clone(),
                },
                None => anyhow::bail!("expected compression shares to exist"),
            }
        };
        Ok((glwe_shares, compression_shares))
    }

    #[cfg(feature = "insecure")]
    async fn reconstruct_glwe_and_compression_key_shares(
        base_session: &BaseSessionStruct<AesRng, SessionParameters>,
        params: DKGParams,
        glwe_shares: GlweSecretKeyShare<Z128, 4>,
        compression_shares: CompressionPrivateKeyShares<Z128, 4>,
    ) -> anyhow::Result<DecompressionKey> {
        let output_party = Role::indexed_by_one(INPUT_PARTY_ID);

        // we need Vec<ResiduePoly> but we're given Vec<Share<ResiduePoly>>
        // so we need to call collect_vec()
        let opt_glwe_secret_key = robust_opens_to(
            base_session,
            &glwe_shares.data.iter().map(|x| x.value()).collect_vec(),
            base_session.parameters.threshold as usize,
            &output_party,
        )
        .await?;
        let opt_compression_secret_key = robust_opens_to(
            base_session,
            &compression_shares
                .post_packing_ks_key
                .data
                .iter()
                .map(|x| x.value())
                .collect_vec(),
            base_session.parameters.threshold as usize,
            &output_party,
        )
        .await?;

        let convert_to_bit = |input: Vec<ResiduePoly<Z128, 4>>| -> anyhow::Result<Vec<u64>> {
            let mut out = Vec::with_capacity(input.len());
            for i in input {
                let bit = i.coefs[0].0 as u64;
                if bit > 1 {
                    anyhow::bail!("reconstructed failed, expected a bit but found {}", bit)
                }
                out.push(bit);
            }
            Ok(out)
        };

        let params_handle = params.get_params_basics_handle();
        let compression_params = params_handle
            .get_compression_decompression_params()
            .ok_or(anyhow::anyhow!("missing compression parameters"))?
            .raw_compression_parameters;
        let opt_decompression_key = match (opt_glwe_secret_key, opt_compression_secret_key) {
            (Some(glwe_secret_key), Some(compression_secret_key)) => {
                let bit_glwe_secret_key = GlweSecretKeyOwned::from_container(
                    convert_to_bit(glwe_secret_key)?,
                    params_handle.polynomial_size(),
                );
                let bit_compression_secret_key =
                    tfhe::integer::compression_keys::CompressionPrivateKeys::from_raw_parts(
                        tfhe::shortint::list_compression::CompressionPrivateKeys {
                            post_packing_ks_key: GlweSecretKeyOwned::from_container(
                                convert_to_bit(compression_secret_key)?,
                                compression_params.packing_ks_polynomial_size,
                            ),
                            params: compression_params,
                        },
                    );

                let dummy_lwe_secret_key =
                    LweSecretKeyOwned::from_container(vec![0u64; params_handle.lwe_dimension().0]);

                // We need a dummy sns secret key otherwise [to_hl_client_key]
                // will fail because it will try to use this key when the parameter supports SnS
                let dummy_sns_secret_key = match params {
                    DKGParams::WithoutSnS(_) => None,
                    DKGParams::WithSnS(sns_param) => {
                        let glwe_dim = sns_param.glwe_dimension_sns();
                        let poly_size = sns_param.polynomial_size_sns();
                        Some(GlweSecretKeyOwned::from_container(
                            vec![0u128; glwe_dim.to_equivalent_lwe_dimension(poly_size).0],
                            sns_param.polynomial_size_sns(),
                        ))
                    }
                };

                let (client_key, _, _, _, _) = to_hl_client_key(
                    &params,
                    dummy_lwe_secret_key,
                    bit_glwe_secret_key,
                    None,
                    None,
                    dummy_sns_secret_key,
                )?
                .into_raw_parts();

                let (_, decompression_key) =
                    client_key.new_compression_decompression_keys(&bit_compression_secret_key);
                Some(decompression_key)
            }
            (None, None) => {
                // I'm not party 1, so I don't get to open the shares
                None
            }
            _ => {
                anyhow::bail!("failed to open the glwe and/or the compression secret key")
            }
        };

        // now party 1 sends the decompression key to everyone
        transfer_decompression_key(
            base_session,
            opt_decompression_key,
            output_party.one_based(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn decompression_key_gen_background(
        req_id: &RequestId,
        mut base_session: BaseSessionStruct<AesRng, SessionParameters>,
        meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
        preproc_handle_w_mode: PreprocHandleWithMode,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        eip712_domain: Option<alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit;
        let start = Instant::now();
        let dkg_res = match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure => {
                // sanity check to make sure we're using the insecure feature
                #[cfg(not(feature = "insecure"))]
                {
                    panic!("attempting to call insecure compression keygen when the insecure feature is not set");
                }
                #[cfg(feature = "insecure")]
                {
                    match Self::get_glwe_and_compression_key_shares(
                        keyset_added_info,
                        crypto_storage.clone(),
                    )
                    .await
                    {
                        Ok((glwe_shares, compression_shares)) => {
                            Self::reconstruct_glwe_and_compression_key_shares(
                                &base_session,
                                params,
                                glwe_shares,
                                compression_shares,
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            PreprocHandleWithMode::Secure(preproc_handle) => {
                let mut preproc_handle = preproc_handle.lock().await;
                Self::decompression_key_gen_closure(
                    &mut base_session,
                    crypto_storage.clone(),
                    params,
                    keyset_added_info,
                    preproc_handle.as_mut(),
                )
                .await
            }
        };

        // Make sure the dkg ended nicely
        let decompression_key = match dkg_res {
            Ok(k) => k,
            Err(e) => {
                // If dkg errored out, update status
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(req_id, Err(e.to_string()));
                return;
            }
        };

        // Compute all the info required for storing
        let info = match compute_info(&sk, &decompression_key, eip712_domain.as_ref()) {
            Ok(info) => HashMap::from_iter(vec![(PubDataType::DecompressionKey, info)]),
            Err(_) => {
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage
                    .update(req_id, Err("Failed to compute key info".to_string()));
                return;
            }
        };

        crypto_storage
            .write_decompression_key_with_meta_store(req_id, decompression_key, info, meta_store)
            .await;

        tracing::info!(
            "Decompression DKG protocol took {} ms to complete for request {req_id}",
            start.elapsed().as_millis()
        );
    }

    async fn key_gen_from_existing_compression_sk<P>(
        base_session: &mut BaseSessionStruct<AesRng, SessionParameters>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        preprocessing: &mut P,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<4>)>
    where
        P: DKGPreprocessing<threshold_fhe::algebra::galois_rings::common::ResiduePoly<Z128, 4>>
            + Send
            + ?Sized,
    {
        let key_id = keyset_added_info
            .compression_keyset_id
            .ok_or(anyhow::anyhow!(
                "missing key ID for the keyset that contains the compression secret key share"
            ))?;
        let existing_compression_sk = {
            let threshold_keys = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                .await?;
            let compression_sk_share = threshold_keys
                .private_keys
                .glwe_secret_key_share_compression
                .clone()
                .ok_or(anyhow::anyhow!("missing compression secret key share"))?;
            match compression_sk_share {
                CompressionPrivateKeySharesEnum::Z64(_share) => {
                    anyhow::bail!("z64 share is not supported")
                }
                CompressionPrivateKeySharesEnum::Z128(share) => share,
            }
        };
        distributed_keygen_from_optional_compression_sk_z128(
            base_session,
            preprocessing,
            params,
            Some(existing_compression_sk).as_ref(),
        )
        .await
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
        keyset_config: ddec_keyset_config::StandardKeySetConfig,
        keyset_added_info: KeySetAddedInfo,
        eip712_domain: Option<alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit;
        let start = Instant::now();
        let dkg_res = match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure => {
                // sanity check to make sure we're using the insecure feature
                #[cfg(not(feature = "insecure"))]
                {
                    panic!(
                        "attempting to call insecure keygen when the insecure feature is not set"
                    );
                }
                #[cfg(feature = "insecure")]
                {
                    match (
                        keyset_config.compression_config,
                        keyset_config.computation_key_type,
                    ) {
                        (
                            ddec_keyset_config::KeySetCompressionConfig::Generate,
                            ddec_keyset_config::ComputeKeyType::Cpu,
                        ) => initialize_key_material(&mut base_session, params).await,
                        _ => {
                            // TODO insecure keygen from existing compression key is not supported
                            let mut guarded_meta_storage = meta_store.write().await;
                            let _ = guarded_meta_storage.update(
                            req_id,
                            Err(
                                "insecure keygen from existing compression key is not supported"
                                    .to_string(),
                            ),
                        );
                            return;
                        }
                    }
                }
            }
            PreprocHandleWithMode::Secure(preproc_handle) => {
                let mut preproc_handle = preproc_handle.lock().await;
                match (
                    keyset_config.compression_config,
                    keyset_config.computation_key_type,
                ) {
                    (
                        ddec_keyset_config::KeySetCompressionConfig::Generate,
                        ddec_keyset_config::ComputeKeyType::Cpu,
                    ) => {
                        distributed_keygen_z128(&mut base_session, preproc_handle.as_mut(), params)
                            .await
                    }
                    (
                        ddec_keyset_config::KeySetCompressionConfig::UseExisting,
                        ddec_keyset_config::ComputeKeyType::Cpu,
                    ) => {
                        Self::key_gen_from_existing_compression_sk(
                            &mut base_session,
                            crypto_storage.clone(),
                            params,
                            keyset_added_info,
                            preproc_handle.as_mut(),
                        )
                        .await
                    }
                }
            }
        };

        //Make sure the dkg ended nicely
        let (pub_key_set, private_keys) = match dkg_res {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => {
                //If dkg errored out, update status
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(req_id, Err(e.to_string()));
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

        let (integer_server_key, decompression_key, sns_key) = {
            let (
                raw_server_key,
                _raw_ksk_material,
                _raw_compression_key,
                raw_decompression_key,
                raw_noise_squashing_key,
                _raw_tag,
            ) = pub_key_set.server_key.clone().into_raw_parts();
            (
                raw_server_key,
                raw_decompression_key,
                raw_noise_squashing_key,
            )
        };

        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys,
            integer_server_key,
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
    prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    preproc_factory:
        Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
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
        keyset_config: ddec_keyset_config::KeySetConfig,
        request_id: RequestId,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_KEYGEN_PREPROC)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(OP_KEYGEN_PREPROC)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }
        // Derive a sequence of sessionId from request_id
        let own_identity = self.session_preparer.own_identity()?;

        let sids = (0..self.num_sessions_preproc)
            .map(|ctr| {
                derive_session_id_from_ctr(ctr as u64, DSEP_SESSION_PREPROCESSING, &request_id)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let base_sessions = {
            let mut res = Vec::with_capacity(sids.len());
            for sid in sids {
                let base_session = self
                    .session_preparer
                    .make_base_session(sid, NetworkMode::Sync)
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
                //Start the metric timer, it will end on drop
                let _timer = timer.map(|b| b.start());
                 tokio::select! {
                    () = Self::preprocessing_background(&request_id, base_sessions, bucket_store, prss_setup, own_identity, dkg_params, keyset_config, factory, permit) => {
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
        prss_setup: PRSSSetup<ResiduePolyF4Z128>,
        own_identity: Identity,
        params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        factory: Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit; // dropped at the end of the function
        fn create_sessions(
            base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
            prss_setup: PRSSSetup<ResiduePolyF4Z128>,
        ) -> Vec<SmallSession<ResiduePolyF4Z128>> {
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
            PreprocessingOrchestrator::<ResiduePolyF4Z128>::new(factory, params, keyset_config)
                .unwrap()
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

        let keyset_config = tonic_handle_potential_err(
            preproc_proto_to_keyset_config(&inner.keyset_config),
            "Failed to process keyset config".to_string(),
        )?;

        //If the entry did not exist before, start the preproc
        if !entry_exists {
            tracing::info!("Starting preproc generation for Request ID {}", request_id);
            tonic_handle_potential_err(self.launch_dkg_preproc(dkg_params, keyset_config, request_id.clone(), permit).await, format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {:?}",dkg_params))?;
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
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.preproc_buckets.read().await;
            guarded_meta_store.retrieve(&request_id)
        };

        // if we got the result it means the preprocessing is done
        let _preproc_data = handle_res_mapping(status, &request_id, "Preprocessing").await?;

        Ok(Response::new(KeyGenPreprocResult {}))
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

        let inner = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            inner.request_id
        );

        let dkg_params = retrieve_parameters(inner.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::NotFound,
                format!("Can not retrieve fhe parameters with error {e}"),
            )
        })?;
        let crs_params = dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let witness_dim = tonic_handle_potential_err(
            compute_witness_dim(&crs_params, inner.max_num_bits.map(|x| x as usize)),
            "witness dimension computation failed".to_string(),
        )?;

        let req_id = inner.request_id.ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                "missing request ID in CRS generation",
            )
        })?;

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref());

        self.inner_crs_gen(
            req_id,
            witness_dim,
            inner.max_num_bits,
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
        //Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_CRS_GEN
        } else {
            OP_CRS_GEN
        };

        let _request_counter = metrics::METRICS
            .increment_request_counter(op_tag)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(op_tag)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });
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
            .prepare_ddec_data_from_sessionid_z128(session_id)
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
                //Start the metric timer, it will end on drop
                let _timer = timer.map(|b| b.start());
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
        tracing::info!(
            "Starting crs gen background process for req_id={req_id:?} with witness_dim={witness_dim} and max_num_bits={max_num_bits:?}"
        );
        let _permit = permit;
        let crs_start_timer = Instant::now();
        let pke_params = params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let pp = if insecure {
            // sanity check to make sure we're using the insecure feature
            #[cfg(not(feature = "insecure"))]
            {
                let _ = rng; // stop clippy from complaining
                panic!("attempting to call insecure crsgen when the insecure feature is not set");
            }
            #[cfg(feature = "insecure")]
            {
                let my_role = base_session
                    .my_role()
                    .map_err(|e| tracing::error!("Error getting role: {e}"))
                    .expect("No role found in the session");
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

        tracing::info!("CRS generation completed for req_id={req_id:?}, storing the CRS.");
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

#[cfg(test)]
mod tests {
    use crate::{
        client::test_tools::{self},
        consts::{DEFAULT_AMOUNT_PARTIES, DEFAULT_THRESHOLD, PRSS_INIT_REQ_ID},
        util::key_setup::test_tools::purge,
        vault::storage::{file::FileStorage, StorageType},
    };
    use kms_grpc::kms::v1::RequestId;

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
                "PRSSSetup_Z128_ID_{}_{}_{}",
                PRSS_INIT_REQ_ID, DEFAULT_AMOUNT_PARTIES, DEFAULT_THRESHOLD
            ))
            .unwrap();
            purge(None, None, &req_id.to_string(), DEFAULT_AMOUNT_PARTIES).await;

            let req_id = &RequestId::derive(&format!(
                "PRSSSetup_Z64_ID_{}_{}_{}",
                PRSS_INIT_REQ_ID, DEFAULT_AMOUNT_PARTIES, DEFAULT_THRESHOLD
            ))
            .unwrap();
            purge(None, None, &req_id.to_string(), DEFAULT_AMOUNT_PARTIES).await;

            priv_storage.push(cur_priv);
        }

        // create parties and run PrssSetup
        let server_handles = test_tools::setup_threshold_no_client(
            DEFAULT_THRESHOLD as u8,
            pub_storage.clone(),
            priv_storage.clone(),
            true,
            None,
            None,
        )
        .await;
        assert_eq!(server_handles.len(), DEFAULT_AMOUNT_PARTIES);

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
            DEFAULT_THRESHOLD as u8,
            pub_storage,
            priv_storage,
            false,
            None,
            None,
        )
        .await;
        assert_eq!(server_handles.len(), DEFAULT_AMOUNT_PARTIES);

        // check that PRSS setups were not created, but instead read from disk now
        assert!(logs_contain(
            "Initializing threshold KMS server with PRSS Setup Z128 from disk"
        ));
        assert!(logs_contain(
            "Initializing threshold KMS server with PRSS Setup Z64 from disk"
        ));
    }
}
