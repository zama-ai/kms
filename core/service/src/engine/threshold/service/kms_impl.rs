// === Standard Library ===
use std::{
    collections::HashMap,
    convert::Infallible,
    marker::PhantomData,
    sync::{Arc, OnceLock},
};

// === External Crates ===
use algebra::{galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring};
use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::{PrivDataType, PubDataType, SignedPubDataHandleInternal},
};
use observability::{
    conf::TelemetryConfig,
    metrics::{self},
    metrics_names::OP_BOOT,
};
use serde::{Deserialize, Serialize};
use tfhe::{
    Versionize,
    core_crypto::prelude::LweKeyswitchKey,
    integer::{ServerKey, compression_keys::DecompressionKey, noise_squashing::NoiseSquashingKey},
    named::Named,
    xof_key_set::CompressedXofKeySet,
};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};
use threshold_execution::endpoints::reshare_sk::SecureReshareSecretKeys;
use threshold_execution::{
    endpoints::keygen::SecureOnlineDistributedKeyGen128,
    online::preprocessing::{
        DKGPreprocessing, create_memory_factory, create_redis_factory,
        orchestration::producer_traits::SecureSmallProducerFactory,
    },
    small_execution::prss::RobustSecurePrssInit,
    tfhe_internals::{parameters::DKGParams, private_keysets::PrivateKeySet},
    zk::ceremony::SecureCeremony,
};
use threshold_networking::{
    grpc::{GrpcNetworkingManager, GrpcServer, TlsExtensionGetter},
    tls::AttestedVerifier,
};

use threshold_types::role::Role;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tokio_rustls::rustls::{client::ClientConfig, server::ServerConfig};
use tokio_util::task::TaskTracker;
use tonic::transport::{Server, server::TcpIncoming};
use tonic_health::{
    pb::health_server::{Health, HealthServer},
    server::HealthReporter,
};
use tonic_tls::rustls::TlsIncoming;

use crate::engine::threshold::service::epoch_manager::RealThresholdEpochManager;
// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    backup::operator::RecoveryValidationMaterial,
    conf::CoreConfig,
    consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, MINIMUM_SESSIONS_PREPROC},
    cryptography::attestation::SecurityModuleProxy,
    engine::{
        backup_operator::RealBackupOperator,
        base::{
            BaseKmsStruct, CrsGenMetadata, KeyGenMetadata, PubDecCallValues, UserDecryptCallValues,
        },
        context_manager::{ThresholdContextManager, ensure_default_threshold_context_in_storage},
        prepare_shutdown_signals,
        threshold::{
            service::{
                public_decryptor::SecureNoiseFloodDecryptor,
                session::{ImmutableSessionMaker, SessionMaker},
                user_decryptor::SecureNoiseFloodPartialDecryptor,
            },
            threshold_kms::ThresholdKms,
        },
        traits::PrivateKeyMaterialMetadata,
        utils::{sanity_check_crs_materials, sanity_check_public_materials},
    },
    grpc::metastore_status_service::MetaStoreStatusServiceImpl,
    util::{meta_store::MetaStore, rate_limiter::RateLimiter},
    vault::{
        Vault,
        storage::{
            Storage, StorageExt, crypto_material::ThresholdCryptoMaterialStorage,
            read_all_data_from_all_epochs_versioned, read_all_data_versioned,
        },
    },
};

// === Current Module Imports ===
use super::{
    crs_generator::RealCrsGenerator, key_generator::RealKeyGenerator,
    preprocessor::RealPreprocessor, public_decryptor::RealPublicDecryptor,
    user_decryptor::RealUserDecryptor,
};

// === Insecure Feature-Specific Imports ===
#[cfg(feature = "insecure")]
use super::{crs_generator::RealInsecureCrsGenerator, key_generator::RealInsecureKeyGenerator};

/// Versioned envelope for PublicKeyMaterial.
/// V0 is the fat variant (with decompressed keys), V1 is the slim variant.
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PublicKeyMaterialVersioned {
    V0(PublicKeyMaterialV0),
    V1(PublicKeyMaterial),
}

/// V0: Fat public key material — stores both compressed keyset and decompressed keys.
#[derive(Clone, Serialize, Deserialize, Version)]
pub enum PublicKeyMaterialV0 {
    Uncompressed {
        integer_server_key: Arc<tfhe::integer::ServerKey>,
        sns_key: Option<Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>>,
        decompression_key: Option<Arc<tfhe::integer::compression_keys::DecompressionKey>>,
    },
    Compressed {
        compressed_keyset: Arc<tfhe::xof_key_set::CompressedXofKeySet>,
        integer_server_key: Arc<tfhe::integer::ServerKey>,
        sns_key: Option<Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>>,
        decompression_key: Option<Arc<tfhe::integer::compression_keys::DecompressionKey>>,
    },
}

/// Enum to hold either compressed or uncompressed public key material.
/// This allows a single [`ThresholdFheKeys`] type to support both modes.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(PublicKeyMaterialVersioned)]
pub enum PublicKeyMaterial {
    Uncompressed {
        integer_server_key: Arc<ServerKey>,
        sns_key: Option<Arc<NoiseSquashingKey>>,
        decompression_key: Option<Arc<DecompressionKey>>,
    },
    Compressed {
        keyset: Arc<CompressedXofKeySet>,
    },
}

impl Upgrade<PublicKeyMaterial> for PublicKeyMaterialV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<PublicKeyMaterial, Self::Error> {
        match self {
            PublicKeyMaterialV0::Uncompressed {
                integer_server_key,
                sns_key,
                decompression_key,
            } => Ok(PublicKeyMaterial::Uncompressed {
                integer_server_key,
                sns_key,
                decompression_key,
            }),
            PublicKeyMaterialV0::Compressed {
                compressed_keyset, ..
            } => Ok(PublicKeyMaterial::Compressed {
                keyset: compressed_keyset,
            }),
        }
    }
}

impl PublicKeyMaterial {
    pub fn new(keyset: CompressedXofKeySet) -> Self {
        Self::Compressed {
            keyset: Arc::new(keyset),
        }
    }

    pub fn new_uncompressed(
        integer_server_key: Arc<ServerKey>,
        sns_key: Option<Arc<NoiseSquashingKey>>,
        decompression_key: Option<Arc<DecompressionKey>>,
    ) -> Self {
        Self::Uncompressed {
            integer_server_key,
            sns_key,
            decompression_key,
        }
    }
}

/// Uncompressed key material derived from a [`CompressedXofKeySet`].
/// All fields are Arc-wrapped, so clones are cheap.
#[derive(Clone)]
struct UncompressedKeys {
    integer_server_key: Arc<ServerKey>,
    sns_key: Option<Arc<NoiseSquashingKey>>,
    decompression_key: Option<Arc<DecompressionKey>>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum ThresholdFheKeysVersioned {
    V0(ThresholdFheKeysV0),
    V1(ThresholdFheKeysV1),
    V2(ThresholdFheKeysV2),
    V3(ThresholdFheKeys),
}

/// V3: Unified key storage supporting both compressed and uncompressed keys.
/// These are the internal key materials (public and private)
/// needed for decryption, user decryption and verifying a proven input.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(ThresholdFheKeysVersioned)]
pub struct ThresholdFheKeys {
    pub private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    pub public_material: PublicKeyMaterial,
    pub meta_data: KeyGenMetadata,

    #[versionize(skip)]
    #[serde(skip)]
    key_cache: OnceLock<UncompressedKeys>,
}

/// V2: Unified key storage supporting both compressed and uncompressed keys.
/// Note: the field type is `PublicKeyMaterial` (the latest version), not a frozen V2-era copy.
/// This is a consequence of `Versionize`: nested fields are serialized via their current dispatch
/// type, so current code reads old nested `PublicKeyMaterialVersioned::V0` values by upgrading
/// them during unversionizing, but cannot itself re-emit that old nested shape.
#[derive(Clone, Serialize, Deserialize, Version)]
pub struct ThresholdFheKeysV2 {
    pub private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    pub public_material: PublicKeyMaterial,
    pub meta_data: KeyGenMetadata,
}

impl PrivateKeyMaterialMetadata for ThresholdFheKeys {
    fn get_metadata(&self) -> &KeyGenMetadata {
        &self.meta_data
    }
}

/// V1: Original structure with separate fields for public keys.
#[derive(Clone, Serialize, Deserialize, Version)]
pub struct ThresholdFheKeysV1 {
    pub private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    pub integer_server_key: Arc<tfhe::integer::ServerKey>,
    pub sns_key: Option<Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>>,
    pub decompression_key: Option<Arc<tfhe::integer::compression_keys::DecompressionKey>>,
    pub meta_data: KeyGenMetadata,
}

/// V0: Legacy structure with pk_meta_data instead of meta_data.
#[derive(Clone, Serialize, Deserialize, Version)]
pub struct ThresholdFheKeysV0 {
    pub private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    pub integer_server_key: Arc<tfhe::integer::ServerKey>,
    pub sns_key: Option<Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>>,
    pub decompression_key: Option<Arc<tfhe::integer::compression_keys::DecompressionKey>>,
    pub pk_meta_data: HashMap<PubDataType, SignedPubDataHandleInternal>,
}

impl Upgrade<ThresholdFheKeysV1> for ThresholdFheKeysV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ThresholdFheKeysV1, Self::Error> {
        Ok(ThresholdFheKeysV1 {
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

impl Upgrade<ThresholdFheKeysV2> for ThresholdFheKeysV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ThresholdFheKeysV2, Self::Error> {
        Ok(ThresholdFheKeysV2 {
            private_keys: self.private_keys,
            public_material: PublicKeyMaterial::Uncompressed {
                integer_server_key: self.integer_server_key,
                sns_key: self.sns_key,
                decompression_key: self.decompression_key,
            },
            meta_data: self.meta_data,
        })
    }
}

impl Upgrade<ThresholdFheKeys> for ThresholdFheKeysV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ThresholdFheKeys, Self::Error> {
        Ok(ThresholdFheKeys {
            private_keys: self.private_keys,
            public_material: self.public_material,
            meta_data: self.meta_data,
            key_cache: OnceLock::new(),
        })
    }
}

impl ThresholdFheKeys {
    pub fn new(
        private_keys: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
        public_material: PublicKeyMaterial,
        meta_data: KeyGenMetadata,
    ) -> Self {
        Self {
            private_keys,
            public_material,
            meta_data,
            key_cache: OnceLock::new(),
        }
    }

    fn expand_keys(&self) -> &UncompressedKeys {
        self.key_cache.get_or_init(|| {
            match &self.public_material {
                PublicKeyMaterial::Uncompressed {
                    integer_server_key,
                    sns_key,
                    decompression_key,
                } => UncompressedKeys {
                    integer_server_key: integer_server_key.clone(),
                    sns_key: sns_key.clone(),
                    decompression_key: decompression_key.clone(),
                },
                PublicKeyMaterial::Compressed { keyset } => {
                    let cloned = (**keyset).clone(); // TODO(dp): can possibly get rid of this later once tfhe-rs #3469 lands
                    let (_pk, sk) = cloned
                        .decompress()
                        .expect("Call is infallible")
                        .into_raw_parts();
                    let (isk, _, _, decompk, snsk, _, _, _) = sk.into_raw_parts();
                    UncompressedKeys {
                        integer_server_key: Arc::new(isk),
                        sns_key: snsk.map(Arc::new),
                        decompression_key: decompk.map(Arc::new),
                    }
                }
            }
        })
    }

    /// Get the integer server key from the public material.
    /// Compressed keys are lazily decompressed. The first access is expensive.
    pub fn integer_server_key(&self) -> Arc<ServerKey> {
        self.expand_keys().integer_server_key.clone()
    }

    /// Get the SNS key from the public material.
    /// Compressed keys are lazily decompressed. The first access is expensive.
    pub fn sns_key(&self) -> Option<Arc<NoiseSquashingKey>> {
        self.expand_keys().sns_key.clone()
    }

    /// Get the decompression key from the public material.
    /// Compressed keys are lazily decompressed. The first access is expensive.
    pub fn decompression_key(&self) -> Option<Arc<DecompressionKey>> {
        self.expand_keys().decompression_key.clone()
    }

    pub fn key_switching_key(&self) -> anyhow::Result<LweKeyswitchKey<Vec<u64>>> {
        use tfhe::shortint::atomic_pattern::AtomicPatternServerKey::*;

        let integer_server_key = self.integer_server_key();
        match &integer_server_key.as_ref().as_ref().atomic_pattern {
            Standard(standard_atomic_pattern_server_key) => {
                Ok(standard_atomic_pattern_server_key.key_switching_key.clone())
            }
            KeySwitch32(_) => {
                anyhow::bail!("No support for KeySwitch32 server key")
            }
            Dynamic(_) => {
                anyhow::bail!("No support for dynamic atomic pattern server key")
            }
        }
    }

    /// Check if this ThresholdFheKeys contains compressed keys.
    pub fn is_compressed(&self) -> bool {
        matches!(self.public_material, PublicKeyMaterial::Compressed { .. })
    }
}

impl Named for ThresholdFheKeys {
    const NAME: &'static str = "ThresholdFheKeys";
}

impl std::fmt::Debug for ThresholdFheKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdFheKeys")
            .field("private_keys", &"omitted")
            .field(
                "public_material",
                &if self.is_compressed() {
                    "Compressed(omitted)"
                } else {
                    "Uncompressed(omitted)"
                },
            )
            .field("meta_data", &self.meta_data)
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
    RealThresholdEpochManager<PubS, PrivS, RobustSecurePrssInit, SecureReshareSecretKeys>,
    RealUserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
    RealPublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
    RealKeyGenerator<
        PubS,
        PrivS,
        SecureOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    >,
    RealPreprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
    RealCrsGenerator<PubS, PrivS, SecureCeremony>,
    ThresholdContextManager<PubS, PrivS>,
    RealBackupOperator<PubS, PrivS>,
>;

#[cfg(feature = "insecure")]
pub type RealThresholdKms<PubS, PrivS> = ThresholdKms<
    RealThresholdEpochManager<PubS, PrivS, RobustSecurePrssInit, SecureReshareSecretKeys>,
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
    ThresholdContextManager<PubS, PrivS>,
    RealBackupOperator<PubS, PrivS>,
>;

#[allow(clippy::too_many_arguments)]
pub async fn new_real_threshold_kms<PubS, PrivS, F>(
    config: CoreConfig,
    public_storage: PubS,
    mut private_storage: PrivS,
    backup_storage: Option<Vault>,
    security_module: Option<Arc<SecurityModuleProxy>>,
    mpc_listener: TcpListener,
    base_kms: BaseKmsStruct,
    tls_config: Option<(ServerConfig, ClientConfig, Arc<AttestedVerifier>)>,
    peer_tcp_proxy: bool,
    ensure_default_prss: bool,
    shutdown_signal: F,
) -> anyhow::Result<(
    RealThresholdKms<PubS, PrivS>,
    (HealthReporter, HealthServer<impl Health>),
    MetaStoreStatusServiceImpl,
)>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let threshold_config = config.threshold.as_ref().ok_or_else(|| {
        anyhow_error_and_log("Threshold party configuration is required for threshold KMS")
    })?;
    let rate_limiter_conf = config.rate_limiter_conf.to_owned().unwrap_or_default();
    let telemetry_conf = config
        .telemetry
        .unwrap_or_else(|| TelemetryConfig::builder().build());

    // load keys from storage
    let key_info_versioned: HashMap<(RequestId, EpochId), ThresholdFheKeys> =
        read_all_data_from_all_epochs_versioned(
            &private_storage,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;

    let mut public_key_info = HashMap::new();
    let validation_material: HashMap<RequestId, RecoveryValidationMaterial> =
        read_all_data_versioned(&public_storage, &PubDataType::RecoveryMaterial.to_string())
            .await?;

    // Validate the recovery material against the provided verification key
    for (cur_req_id, cur_rec_material) in &validation_material {
        if !cur_rec_material.validate(&base_kms.verf_key()) {
            anyhow::bail!(
                "Validation material for context {cur_req_id} failed to validate against the verification key"
            );
        }
    }

    // Build public_key_info map
    for ((id, _), info) in &key_info_versioned {
        public_key_info.insert(*id, info.meta_data.clone());
    }

    // sanity check the public materials
    let entries: Vec<_> = key_info_versioned
        .iter()
        .map(|((id, _), info)| (*id, info.meta_data.clone()))
        .collect();
    sanity_check_public_materials(&public_storage, &entries).await?;

    // load crs_info (roughly hashes of CRS) from storage
    let crs_info: HashMap<RequestId, CrsGenMetadata> = read_all_data_from_all_epochs_versioned(
        &private_storage,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await?
    .into_iter()
    .map(|((req, _epoch), v)| (req, v))
    .collect();

    sanity_check_crs_materials(&public_storage, &crs_info).await?;

    let networking_manager = Arc::new(RwLock::new(GrpcNetworkingManager::new(
        tls_config
            .as_ref()
            .map(|(_, client_config, _)| client_config.clone()),
        threshold_config.core_to_core_net,
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
        "Starting core-to-core server on address {:?} with initial party ID {:?}.",
        mpc_socket_addr,
        threshold_config.my_id,
    );

    // clone the verifier for later use
    let verifier = tls_config.as_ref().map(|(_, _, verifier)| verifier.clone());
    let abort_handle = tokio::spawn(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(prepare_shutdown_signals(shutdown_signal, tx));
        let graceful_shutdown_signal = async {
            // Set the server to be serving when we boot
            threshold_health_reporter.set_serving::<GrpcServer>().await;
            // await is the same as recv on a oneshot channel
            _ = rx.await;
            // Observe that the following is the shut down of the core (which communicates with the other cores)
            // That is, not the threshold KMS server itself which picks up requests from the blockchain.
            tracing::info!(
                "Starting graceful shutdown of core/experiments {}",
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
        // Use the TLS_NODELAY mode to ensure everything gets sent immediately by disabling Nagle's algorithm.
        // Note that this decreases latency but increases network bandwidth usage. If bandwidth is a concern,
        // then this should be changed
        let tcp_incoming = tcp_incoming.with_nodelay(Some(true));
        match tls_config {
            Some((server_config, _, _)) => {
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
            "Threshold core on {} shutdown completed successfully",
            mpc_socket_addr
        );
        Ok(())
    });

    // If no RedisConf is provided, we just use in-memory storage for storing preprocessing materials
    let preproc_factory = match &threshold_config.preproc_redis {
        None => create_memory_factory(),
        Some(conf) => {
            create_redis_factory(format!("REDIS_{}", base_kms.verf_key().address()), conf)
        }
    };

    let num_sessions_preproc = threshold_config
        .num_sessions_preproc
        .map_or(MINIMUM_SESSIONS_PREPROC, |x| {
            std::cmp::max(x, MINIMUM_SESSIONS_PREPROC)
        });

    let preproc_buckets = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let preproc_factory = Arc::new(Mutex::new(preproc_factory));
    let crs_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(crs_info)));
    let dkg_pubinfo_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info)));
    let pub_dec_meta_store = Arc::new(RwLock::new(MetaStore::new(
        threshold_config.dec_capacity,
        threshold_config.min_dec_cache,
    )));
    let user_decrypt_meta_store = Arc::new(RwLock::new(MetaStore::new(
        threshold_config.dec_capacity,
        threshold_config.min_dec_cache,
    )));
    let custodian_meta_store = Arc::new(RwLock::new(MetaStore::new_from_map(validation_material)));

    // TODO(zama-ai/kms-internal/issues/2758)
    // If we're still using peer config, we need to manually write the default context into storage.
    // This way we can load it into SessionMaker later when creating the ThresholdContextManager.
    ensure_default_threshold_context_in_storage(
        &mut private_storage,
        threshold_config,
        &base_kms.verf_key(),
    )
    .await?;

    let private_storage_info = private_storage.info();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        public_storage,
        private_storage,
        backup_storage,
        key_info_versioned,
    );

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
    // We are only serving after initialization
    core_service_health_reporter
        .set_not_serving::<CoreServiceEndpointServer<RealThresholdKms<PubS, PrivS>>>()
        .await;

    let session_maker = SessionMaker::new_initialized(
        threshold_config.my_id.map(Role::indexed_from_one),
        &crypto_storage,
        networking_manager,
        verifier,
        base_kms.new_rng().await,
    )
    .await?;
    let immutable_session_maker = session_maker.make_immutable();

    let tracker = Arc::new(TaskTracker::new());
    let rate_limiter = RateLimiter::new(rate_limiter_conf);

    // NOTE: context must be loaded before attempting to automatically start the PRSS
    // since the PRSS requires a context to be present.
    let context_manager = ThresholdContextManager::new(
        base_kms.new_instance().await,
        crypto_storage.inner.clone(),
        custodian_meta_store,
        session_maker.clone(),
    );
    if let Err(e) = context_manager.load_mpc_context_from_storage().await {
        tracing::warn!(
            "Failed to load all MPC contexts from storage during KMS startup: {}. \
             Server will continue in degraded mode (recovery operations only).",
            e
        );
    }

    let epoch_manager = RealThresholdEpochManager {
        crypto_storage: crypto_storage.clone(),
        session_maker: session_maker.clone(),
        base_kms: base_kms.new_instance().await,
        reshare_pubinfo_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        _init: PhantomData,
        _reshare: PhantomData,
    };
    if ensure_default_prss {
        let epoch_id_prss = *DEFAULT_EPOCH_ID;
        let default_context_id = *DEFAULT_MPC_CONTEXT;
        if session_maker.epoch_exists(&epoch_id_prss).await {
            tracing::warn!(
                "Default epoch {} already exists. Skipping regeneration",
                epoch_id_prss
            );
        } else {
            tracing::info!(
                "Initializing threshold KMS server and generating a new PRSS Setup for private storage {:?}",
                private_storage_info
            );
            epoch_manager
                .init_prss(&default_context_id, &epoch_id_prss)
                .await?;
        }
    }

    let slow_events = Arc::new(Mutex::new(HashMap::new()));

    let user_decryptor = RealUserDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        user_decrypt_meta_store: user_decrypt_meta_store.clone(),
        session_maker: immutable_session_maker.clone(),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode: threshold_config.decryption_mode,
        _dec: PhantomData,
    };

    let public_decryptor = RealPublicDecryptor {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        pub_dec_meta_store: pub_dec_meta_store.clone(),
        session_maker: immutable_session_maker.clone(),
        tracker: Arc::clone(&tracker),
        rate_limiter: rate_limiter.clone(),
        decryption_mode: threshold_config.decryption_mode,
        _dec: PhantomData,
    };

    let keygenerator = RealKeyGenerator {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        preproc_buckets: Arc::clone(&preproc_buckets),
        dkg_pubinfo_meta_store,
        session_maker: immutable_session_maker.clone(),
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
        _kg: PhantomData,
        serial_lock: Arc::new(Mutex::new(())),
    };

    #[cfg(feature = "insecure")]
    let insecure_keygenerator = RealInsecureKeyGenerator::from_real_keygen(&keygenerator).await;

    let keygen_preprocessor = RealPreprocessor {
        base_kms: base_kms.new_instance().await,
        session_maker: immutable_session_maker.clone(),
        preproc_buckets,
        preproc_factory,
        num_sessions_preproc,
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
        _producer_factory: PhantomData,
    };

    let crs_generator = RealCrsGenerator {
        base_kms: base_kms.new_instance().await,
        crypto_storage: crypto_storage.clone(),
        crs_meta_store,
        session_maker: immutable_session_maker.clone(),
        tracker: Arc::clone(&tracker),
        ongoing: Arc::clone(&slow_events),
        rate_limiter: rate_limiter.clone(),
        _ceremony: PhantomData,
    };

    #[cfg(feature = "insecure")]
    let insecure_crs_generator = RealInsecureCrsGenerator::from_real_crsgen(&crs_generator).await;

    let backup_operator = RealBackupOperator::new(
        base_kms.new_instance().await,
        crypto_storage.inner.clone(),
        security_module,
    );

    // Update backup vault if it exists
    // This ensures that all files in the private storage are also in the backup vault
    // Thus the vault gets automatically updated in case its location changes, or in case of a deletion
    // Note however that the data in the vault is not checked for corruption hence
    // existing values are not overwritten or backed up again
    if !crypto_storage
        .inner
        .update_backup_vault(false, OP_BOOT)
        .await
    {
        anyhow::bail!("Failed to update backup vault when booting");
    }
    tracing::info!("Successfully updated backup vault when booting");
    // Start updating system metrics
    update_threshold_kms_system_metrics(
        rate_limiter.clone(),
        immutable_session_maker.clone(),
        Arc::clone(&user_decrypt_meta_store),
        Arc::clone(&pub_dec_meta_store),
        telemetry_conf.refresh_interval(),
    );

    let kms = ThresholdKms::new(
        epoch_manager,
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
        immutable_session_maker,
        core_service_health_reporter.clone(),
        abort_handle,
    );

    Ok((
        kms,
        (core_service_health_reporter, core_service_health_service),
        metastore_status_service,
    ))
}

fn update_threshold_kms_system_metrics(
    rate_limiter: RateLimiter,
    session_maker: ImmutableSessionMaker,
    user_meta_store: Arc<RwLock<MetaStore<UserDecryptCallValues>>>,
    public_meta_store: Arc<RwLock<MetaStore<PubDecCallValues>>>,
    refresh_interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            metrics::METRICS.record_rate_limiter_usage(rate_limiter.tokens_used());
            metrics::METRICS.record_active_sessions(session_maker.active_sessions().await);
            metrics::METRICS.record_inactive_sessions(session_maker.inactive_sessions().await);
            {
                let user_meta_store_guard = user_meta_store.read().await;
                metrics::METRICS.record_meta_storage_user_decryptions(
                    user_meta_store_guard.get_processing_count() as u64,
                );
                metrics::METRICS.record_meta_storage_user_decryptions_total(
                    user_meta_store_guard.get_total_count() as u64,
                );
            }
            {
                let public_meta_store_guard = public_meta_store.read().await;
                metrics::METRICS.record_meta_storage_public_decryptions(
                    public_meta_store_guard.get_processing_count() as u64,
                );
                metrics::METRICS.record_meta_storage_public_decryptions_total(
                    public_meta_store_guard.get_total_count() as u64,
                );
            }
            tokio::time::sleep(refresh_interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
    use tfhe_versionable::Upgrade;
    use threshold_execution::tfhe_internals::{
        public_keysets::FhePubKeySet,
        test_feature::{gen_key_set, gen_uncompressed_key_set},
    };

    use crate::consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM};

    use super::*;

    // Minimal test-only wrapper for the historical V2 wire shape with the old fat nested
    // `PublicKeyMaterial::Compressed` variant. We need this because the current types _can_ deserialize
    // that payload, but due to `Versionize` limitations, they cannot serialize it anymore.
    mod v2_legacy {
        use super::*;

        #[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
        pub enum PublicKeyMaterialVersioned {
            V0(PublicKeyMaterial),
        }

        #[derive(Clone, Serialize, Deserialize, Versionize)]
        #[versionize(PublicKeyMaterialVersioned)]
        pub enum PublicKeyMaterial {
            Uncompressed {
                integer_server_key: Arc<ServerKey>,
                sns_key: Option<Arc<NoiseSquashingKey>>,
                decompression_key: Option<Arc<DecompressionKey>>,
            },
            Compressed {
                compressed_keyset: Arc<CompressedXofKeySet>,
                integer_server_key: Arc<ServerKey>,
                sns_key: Option<Arc<NoiseSquashingKey>>,
                decompression_key: Option<Arc<DecompressionKey>>,
            },
        }

        #[derive(Clone, Serialize, Deserialize, Version)]
        pub struct PlaceholderV0;

        #[derive(Clone, Serialize, Deserialize, Version)]
        pub struct PlaceholderV1;

        impl Upgrade<PlaceholderV1> for PlaceholderV0 {
            type Error = Infallible;

            fn upgrade(self) -> Result<PlaceholderV1, Self::Error> {
                unreachable!("placeholder variant is never serialized in this test")
            }
        }

        impl Upgrade<ThresholdFheKeys> for PlaceholderV1 {
            type Error = Infallible;

            fn upgrade(self) -> Result<ThresholdFheKeys, Self::Error> {
                unreachable!("placeholder variant is never serialized in this test")
            }
        }

        #[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
        pub enum ThresholdFheKeysVersioned {
            V0(PlaceholderV0),
            V1(PlaceholderV1),
            V2(ThresholdFheKeys),
        }

        #[derive(Clone, Serialize, Deserialize, Versionize)]
        #[versionize(ThresholdFheKeysVersioned)]
        pub struct ThresholdFheKeys {
            pub private_keys: Arc<
                PrivateKeySet<
                    { <ResiduePolyF4Z128 as algebra::structure_traits::Ring>::EXTENSION_DEGREE },
                >,
            >,
            pub public_material: PublicKeyMaterial,
            pub meta_data: KeyGenMetadata,
        }

        impl Named for ThresholdFheKeys {
            const NAME: &'static str = "ThresholdFheKeys";
        }
    }

    impl ThresholdFheKeys {
        /// Initializes a dummy private keyset with the given parameters and returns it along with a public key set.
        /// The keyset is *not* meant to be used for any computation or protocol,
        /// it's only used during testing with a mocked decryption protocol that does not actually load the keys.
        pub fn init_dummy<R: rand::Rng + rand::CryptoRng>(
            param: DKGParams,
            tag: tfhe::Tag,
            rng: &mut R,
        ) -> (Self, FhePubKeySet) {
            // TODO(dp): need to rewrite/rethink this. Switching to compressed is probably better I think? Also consider
            // moving to a test-helper as it's used in many places but not here?
            let keyset = gen_uncompressed_key_set(param, tag, rng);

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
                public_material: PublicKeyMaterial::new_uncompressed(
                    Arc::new(integer_server_key),
                    sns_key.map(Arc::new),
                    decompression_key.map(Arc::new),
                ),
                meta_data: KeyGenMetadata::new(
                    RequestId::zeros(),
                    RequestId::zeros(),
                    HashMap::new(),
                    vec![],
                ),
                key_cache: OnceLock::new(),
            };

            (priv_key_set, pub_key_set)
        }
    }

    /// Verify that upgrading a [`PublicKeyMaterialV0::Compressed`] produces a
    /// [`PublicKeyMaterial::Compressed`] that only retains the keyset, discarding the
    /// decompressed keys.
    #[test]
    fn upgrade_public_key_material_v0_compressed_drops_decompressed_keys() {
        let mut rng = AesRng::seed_from_u64(42);
        let (keyset, compressed_keyset) =
            gen_key_set(TEST_PARAM, tfhe::Tag::default(), &mut rng).unwrap();

        let (integer_server_key, _, _, decompression_key, sns_key, _, _, _) =
            keyset.public_keys.server_key.into_raw_parts();

        let v0 = PublicKeyMaterialV0::Compressed {
            compressed_keyset: Arc::new(compressed_keyset),
            integer_server_key: Arc::new(integer_server_key),
            sns_key: sns_key.map(Arc::new),
            decompression_key: decompression_key.map(Arc::new),
        };

        let v3: PublicKeyMaterial = v0.upgrade().unwrap();
        assert!(matches!(v3, PublicKeyMaterial::Compressed { .. }));
    }

    /// Verify that a V3 ThresholdFheKeys with Compressed keys can roundtrip through
    /// safe_serialize / safe_deserialize, and that lazy decompression works after.
    #[test]
    fn roundtrip_v3_compressed_and_lazy_decompress() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_keyset, compressed_keyset) =
            gen_key_set(TEST_PARAM, tfhe::Tag::default(), &mut rng).unwrap();

        let original = ThresholdFheKeys::new(
            Arc::new(PrivateKeySet::init_dummy(TEST_PARAM)),
            PublicKeyMaterial::new(compressed_keyset),
            KeyGenMetadata::new(
                RequestId::zeros(),
                RequestId::zeros(),
                HashMap::new(),
                vec![],
            ),
        );
        assert!(original.is_compressed());

        // Decompress the original before serialization so we have reference values
        let orig_srv_key = bc2wrap::serialize(&*original.integer_server_key()).unwrap();
        let orig_sns_key = original.sns_key().map(|k| bc2wrap::serialize(&*k).unwrap());
        let orig_dec_key = original
            .decompression_key()
            .map(|k| bc2wrap::serialize(&*k).unwrap());

        // Roundtrip through safe_serialize / safe_deserialize
        let mut buf = Vec::new();
        safe_serialize(&original, &mut buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let deserialized: ThresholdFheKeys =
            safe_deserialize(&mut std::io::Cursor::new(&buf), SAFE_SER_SIZE_LIMIT).unwrap();

        assert!(deserialized.is_compressed());
        assert!(deserialized.key_cache.get().is_none());

        // Lazy decompression on the deserialized value should produce identical keys
        let srv_key = bc2wrap::serialize(&*deserialized.integer_server_key()).unwrap();
        let sns_key = deserialized
            .sns_key()
            .map(|k| bc2wrap::serialize(&*k).unwrap());
        let dec_key = deserialized
            .decompression_key()
            .map(|k| bc2wrap::serialize(&*k).unwrap());

        assert_eq!(orig_srv_key, srv_key, "server key mismatch after roundtrip");
        assert_eq!(orig_sns_key, sns_key, "sns key mismatch after roundtrip");
        assert_eq!(orig_dec_key, dec_key, "decomp key mismatch after roundtrip");
    }

    #[test]
    fn deser_v2_compressed_upgrades_and_reserializes_smaller() {
        let mut rng = AesRng::seed_from_u64(42);
        let (keyset, compressed_keyset) =
            gen_key_set(TEST_PARAM, tfhe::Tag::default(), &mut rng).unwrap();
        let (integer_server_key, _, _, decompression_key, sns_key, _, _, _) =
            keyset.public_keys.server_key.into_raw_parts();

        // V3 control
        let expected_server_key = bc2wrap::serialize(&integer_server_key).unwrap();
        let expected_sns_key = sns_key.as_ref().map(|key| bc2wrap::serialize(key).unwrap());
        let expected_decompression_key = decompression_key
            .as_ref()
            .map(|key| bc2wrap::serialize(key).unwrap());

        // V2
        let legacy = v2_legacy::ThresholdFheKeys {
            private_keys: Arc::new(PrivateKeySet::init_dummy(TEST_PARAM)),
            public_material: v2_legacy::PublicKeyMaterial::Compressed {
                compressed_keyset: Arc::new(compressed_keyset),
                integer_server_key: Arc::new(integer_server_key),
                sns_key: sns_key.map(Arc::new),
                decompression_key: decompression_key.map(Arc::new),
            },
            meta_data: KeyGenMetadata::new(
                RequestId::zeros(),
                RequestId::zeros(),
                HashMap::new(),
                vec![],
            ),
        };

        let mut v2_bytes = Vec::new();
        safe_serialize(&legacy, &mut v2_bytes, SAFE_SER_SIZE_LIMIT).unwrap();

        let upgraded: ThresholdFheKeys =
            safe_deserialize(&mut std::io::Cursor::new(&v2_bytes), SAFE_SER_SIZE_LIMIT).unwrap();

        assert!(upgraded.is_compressed());

        // No Eq/PartialEq so we're stuck comparing bytes.
        let upgraded_server_key = bc2wrap::serialize(&*upgraded.integer_server_key()).unwrap();
        let upgraded_sns_key = upgraded
            .sns_key()
            .map(|key| bc2wrap::serialize(&*key).unwrap());
        let upgraded_decompression_key = upgraded
            .decompression_key()
            .map(|key| bc2wrap::serialize(&*key).unwrap());

        assert_eq!(upgraded_server_key, expected_server_key);
        assert_eq!(upgraded_sns_key, expected_sns_key);
        assert_eq!(upgraded_decompression_key, expected_decompression_key);

        let mut v3_bytes = Vec::new();
        safe_serialize(&upgraded, &mut v3_bytes, SAFE_SER_SIZE_LIMIT).unwrap();

        // V3 is smaller
        assert_eq!(v2_bytes.len(), 4_810_035);
        assert_eq!(v3_bytes.len(), 2_658_553);
    }
}
