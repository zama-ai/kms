// === Standard Library ===
use itertools::Itertools;
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Instant};
// === External Crates ===
use algebra::{
    base_ring::Z128,
    galois_rings::{
        common::ResiduePoly,
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
    },
    structure_traits::Ring,
};
use kms_grpc::{
    RequestId,
    identifiers::{ContextId, EpochId},
    kms::v1::{self, Empty, KeyDigest, KeyGenRequest, KeyGenResult, KeySetAddedInfo},
    rpc_types::PubDataType,
};
use observability::{
    metrics,
    metrics_names::{
        OP_DECOMPRESSION_KEYGEN, OP_INSECURE_DECOMPRESSION_KEYGEN, OP_INSECURE_KEYGEN_REQUEST,
        OP_INSECURE_KEYGEN_RESULT, OP_INSECURE_STANDARD_COMPRESSED_KEYGEN,
        OP_INSECURE_STANDARD_KEYGEN, OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT,
        OP_STANDARD_COMPRESSED_KEYGEN, OP_STANDARD_KEYGEN, TAG_PARTY_ID,
    },
};
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::prelude::Tagged;
use tfhe::xof_key_set::CompressedXofKeySet;
use threshold_execution::{
    endpoints::keygen::{
        OnlineDistributedKeyGen, distributed_decompression_keygen_z128,
        ensure_oprf_secret_key_share_z128,
    },
    keyset_config as ddec_keyset_config,
    online::preprocessing::DKGPreprocessing,
    runtime::sessions::{base_session::BaseSession, small_session::SmallSession},
    tfhe_internals::{
        parameters::DKGParams,
        private_keysets::{CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, PrivateKeySet},
        public_keysets::FhePubKeySet,
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate Imports ===
use crate::{
    cryptography::signatures::PrivateSigKey,
    engine::{
        base::{
            BaseKmsStruct, DSEP_PUBDATA_KEY, KeyGenMetadata, compute_info_compressed_keygen,
            compute_info_decompression_keygen, compute_info_uncompressed_keygen,
        },
        keyset_configuration::InternalKeySetConfig,
        threshold::{
            service::{
                PublicKeyMaterial, ThresholdFheKeys,
                session::{ImmutableSessionMaker, validate_context_and_epoch},
            },
            traits::KeyGenerator,
        },
        utils::{MetricedError, verify_public_key_digest_from_bytes},
        validation::{
            RequestIdParsingErr, parse_grpc_request_id, parse_optional_grpc_request_id,
            validate_key_gen_request,
        },
    },
    util::{
        meta_store::{
            EntryState, MetaStore, MetaStorePermit, add_req_to_meta_store,
            retrieve_from_meta_store, try_delete_in_meta_store, update_err_req_in_meta_store,
        },
        rate_limiter::RateLimiter,
    },
    vault::storage::{
        Storage, StorageExt,
        crypto_material::{CryptoMaterialReader, PublicKeySet, ThresholdCryptoMaterialStorage},
    },
};

// === Current Module Imports ===
use super::{BucketMetaStore, PreprocMaterial};

const DKG_Z64_SESSION_COUNTER: u64 = 1;
const DKG_Z128_SESSION_COUNTER: u64 = 2;
const ERR_FAILED_TO_READ_EXISTING_TAG: &str = "Failed to read existing tag";

struct DkgSessions {
    session_z64: SmallSession<ResiduePolyF4Z64>,
    session_z128: SmallSession<ResiduePolyF4Z128>,
}

/// Enum to handle both compressed and uncompressed DKG results.
/// This allows the same code path to handle both keygen and compressed_keygen outputs.
// It's ok to have a big enum here since the way this type is used is only temporary.
#[expect(clippy::large_enum_variant)]
enum ThresholdKeyGenResult {
    /// Standard keygen result with full public key set
    Uncompressed(
        FhePubKeySet,
        PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    ),
    /// Compressed keygen result with XOF-seeded compressed keys
    Compressed(
        CompressedXofKeySet,
        PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    ),
}

// === Insecure Feature-Specific Imports ===
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::InsecureKeyGenerator;
#[cfg(feature = "insecure")]
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
#[cfg(feature = "insecure")]
use threshold_execution::tfhe_internals::{
    compression_decompression_key::CompressionPrivateKeyShares,
    glwe_key::GlweSecretKeyShare,
    test_feature::{
        initialize_compressed_key_material,
        insecure_initialize_compressed_key_material_from_existing,
        insecure_initialize_key_material,
    },
};

pub struct RealKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    // TODO eventually add mode to allow for nlarge as well.
    pub preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    pub dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    pub(crate) session_maker: ImmutableSessionMaker,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    // Map of ongoing key generation tasks, indexed by the preprocessing ID
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
    pub(crate) _kg: PhantomData<KG>,
    // This is a lock to make sure calls to keygen do not happen concurrently.
    // It's needed because we lock the meta store at different times before starting the keygen
    // and if two concurrent keygen calls on the same key ID or preproc ID are made, they can interfere with each other.
    // So the lock should be held during the whole keygen request, which should not be a big
    // issue since starting the keygen should be fast as most of the expensive process happens in the background.
    pub(crate) serial_lock: Arc<Mutex<()>>,
}

#[cfg(feature = "insecure")]
pub struct RealInsecureKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
> {
    pub real_key_generator: RealKeyGenerator<PubS, PrivS, KG>,
}

#[cfg(feature = "insecure")]
impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>,
> RealInsecureKeyGenerator<PubS, PrivS, KG>
{
    pub async fn from_real_keygen(value: &RealKeyGenerator<PubS, PrivS, KG>) -> Self {
        Self {
            real_key_generator: RealKeyGenerator {
                base_kms: value.base_kms.new_instance().await,
                crypto_storage: value.crypto_storage.clone(),
                preproc_buckets: Arc::clone(&value.preproc_buckets),
                dkg_pubinfo_meta_store: Arc::clone(&value.dkg_pubinfo_meta_store),
                session_maker: value.session_maker.clone(),
                tracker: Arc::clone(&value.tracker),
                ongoing: Arc::clone(&value.ongoing),
                rate_limiter: value.rate_limiter.clone(),
                _kg: std::marker::PhantomData,
                serial_lock: Arc::clone(&value.serial_lock),
            },
        }
    }
}
#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
> InsecureKeyGenerator for RealInsecureKeyGenerator<PubS, PrivS, KG>
{
    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        tracing::info!("starting insecure key gen in RealInsecureKeyGenerator");
        self.real_key_generator.inner_key_gen(request, true).await
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenResult>, MetricedError> {
        self.real_key_generator
            .inner_get_result(request, true)
            .await
    }

    async fn abort_key_gen(&self, preproc_id: RequestId) -> Status {
        self.real_key_generator
            .inner_abort_key_gen(preproc_id)
            .await
    }
}

// This is an enum to determine whether to start the dkg
// in a secure mode. If the secure mode is selected,
// a preprocessing handle must be given.
// This is essentially the same as an Option, but it's
// more clear to label the variants as `Secure`
// and `Insecure`.
#[expect(clippy::type_complexity)]
#[derive(Clone)]
pub enum PreprocHandleWithMode {
    Secure(
        (
            RequestId,
            Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>,
        ),
    ),
    Insecure(RequestId),
}

impl PreprocHandleWithMode {
    fn preprocessing_id(&self) -> RequestId {
        match self {
            Self::Secure((preproc_id, _)) | Self::Insecure(preproc_id) => *preproc_id,
        }
    }
}

/// Outcome of [`RealKeyGenerator::resolve_preprocessing`]: everything the DKG
/// launch needs to know about the preprocessing backing a key generation request.
struct ResolvedPreprocessing {
    /// The preprocessing handle (real material or insecure marker) together with
    /// its preprocessing ID.
    handle: PreprocHandleWithMode,
    /// DKG parameters to run with. These are the parameters from the request if
    /// it set them, otherwise the parameters stored during preprocessing.
    dkg_params: DKGParams,
}

#[cfg(feature = "insecure")]
fn convert_to_bit(input: Vec<ResiduePolyF4Z128>) -> anyhow::Result<Vec<u64>> {
    let mut out = Vec::with_capacity(input.len());
    for i in input {
        let bit = i.coefs[0].0 as u64;
        if bit > 1 {
            anyhow::bail!("reconstructed failed, expected a bit but found {}", bit)
        }
        out.push(bit);
    }
    Ok(out)
}

impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
> RealKeyGenerator<PubS, PrivS, KG>
{
    #[expect(clippy::too_many_arguments)]
    async fn launch_dkg(
        &self,
        internal_keyset_config: InternalKeySetConfig,
        resolved_preprocessing: ResolvedPreprocessing,
        req_id: RequestId,
        eip712_domain: &alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
        context_id: ContextId,
        epoch_id: EpochId,
        permit: OwnedSemaphorePermit,
        meta_permit: MetaStorePermit<KeyGenMetadata>,
    ) -> Result<(), MetricedError> {
        let preproc_handle_w_mode = resolved_preprocessing.handle;
        let dkg_params = resolved_preprocessing.dkg_params;

        //Retrieve the right metric tag
        let op_tag = match (
            &preproc_handle_w_mode,
            internal_keyset_config.keyset_config(),
        ) {
            (
                PreprocHandleWithMode::Secure(_),
                ddec_keyset_config::KeySetConfig::Standard(inner),
            ) => match inner.compressed_key_config {
                ddec_keyset_config::CompressedKeyConfig::None => OP_STANDARD_KEYGEN,
                ddec_keyset_config::CompressedKeyConfig::All => OP_STANDARD_COMPRESSED_KEYGEN,
            },
            (
                PreprocHandleWithMode::Secure(_),
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_DECOMPRESSION_KEYGEN,
            (
                PreprocHandleWithMode::Insecure(_),
                ddec_keyset_config::KeySetConfig::Standard(inner),
            ) => match inner.compressed_key_config {
                ddec_keyset_config::CompressedKeyConfig::None => OP_INSECURE_STANDARD_KEYGEN,
                ddec_keyset_config::CompressedKeyConfig::All => {
                    OP_INSECURE_STANDARD_COMPRESSED_KEYGEN
                }
            },
            (
                PreprocHandleWithMode::Insecure(_),
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_INSECURE_DECOMPRESSION_KEYGEN,
        };

        // On top of the global KG request counter, we also increment the specific operation counter
        // as such, the sum of the specific operation counter is supposed to be equal the global KG
        // counter
        metrics::METRICS.increment_request_counter(op_tag);

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let my_role = self
            .session_maker
            .my_role(&context_id)
            .await
            .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
        let timer = metrics::METRICS
            .time_operation(op_tag)
            .tag(TAG_PARTY_ID, my_role.to_string());

        // Create the sessions necessary to run the DKG.
        // Note that not all the sessions is going to be needed,
        // but to keep the code clean, we just make all the possible sessions.
        let dkg_sessions = {
            let session_id_z64 = req_id
                .derive_session_id_with_counter(DKG_Z64_SESSION_COUNTER)
                .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
            let session_id_z128 = req_id
                .derive_session_id_with_counter(DKG_Z128_SESSION_COUNTER)
                .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
            let session_z64 = self
                .session_maker
                .make_small_async_session_z64(session_id_z64, context_id, epoch_id)
                .await
                .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
            let session_z128 = self
                .session_maker
                .make_small_async_session_z128(session_id_z128, context_id, epoch_id)
                .await
                .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
            DkgSessions {
                session_z64,
                session_z128,
            }
        };

        // Clone all the Arcs to give them to the tokio thread
        let meta_store = Arc::clone(&self.dkg_pubinfo_meta_store);
        let sk = self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(op_tag, Some(req_id), e, tonic::Code::FailedPrecondition)
        })?;
        let crypto_storage = self.crypto_storage.clone();
        let eip712_domain_copy = eip712_domain.clone();
        let ongoing = Arc::clone(&self.ongoing);

        let preproc_id = preproc_handle_w_mode.preprocessing_id();

        let preproc_bucket = self.preproc_buckets.clone();

        // we must validate the parameter before passing it into the background process
        internal_keyset_config.validate().map_err(|e| {
            MetricedError::new(op_tag, Some(req_id), e, tonic::Code::InvalidArgument)
        })?;

        // Read existing key tag from public storage if needed
        let existing_key_tag: Option<tfhe::Tag> = if internal_keyset_config.use_existing_key_tag() {
            let existing_keyset_id =
                internal_keyset_config
                    .get_existing_keyset_id()
                    .map_err(|e| {
                        MetricedError::new(op_tag, Some(req_id), e, tonic::Code::InvalidArgument)
                    })?;
            Some(
                Self::read_existing_key_tag(&crypto_storage, &existing_keyset_id)
                    .await
                    .map_err(|e| {
                        MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal)
                    })?,
            )
        } else {
            None
        };

        // For compressed keygen that recycles an existing private keyset, load the OLD
        // CompactPublicKey so we can sign and store it instead of the new one derived from
        // the newly-generated CompressedXofKeySet.
        let existing_compact_pk: Option<tfhe::CompactPublicKey> =
            match internal_keyset_config.keyset_config() {
                ddec_keyset_config::KeySetConfig::Standard(inner)
                    if matches!(
                        inner.secret_key_config,
                        ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting
                    ) && matches!(
                        inner.compressed_key_config,
                        ddec_keyset_config::CompressedKeyConfig::All
                    ) =>
                {
                    let existing_keyset_id = internal_keyset_config
                        .get_existing_keyset_id()
                        .map_err(|e| {
                            MetricedError::new(
                                op_tag,
                                Some(req_id),
                                e,
                                tonic::Code::InvalidArgument,
                            )
                        })?;
                    Some(
                        Self::read_existing_compact_public_key(
                            &crypto_storage,
                            &existing_keyset_id,
                            &epoch_id,
                        )
                        .await
                        .map_err(|e| {
                            MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal)
                        })?,
                    )
                }
                _ => None,
            };

        let token = CancellationToken::new();
        {
            let mut ongoing_lock = self.ongoing.lock().await;
            if ongoing_lock.contains_key(&preproc_id) {
                return Err(MetricedError::new(
                    op_tag,
                    Some(req_id),
                    anyhow::anyhow!(
                        "Key generation with preprocessing ID {preproc_id} is already ongoing"
                    ),
                    tonic::Code::AlreadyExists,
                ));
            }
            ongoing_lock.insert(preproc_id, token.clone());
        }

        let keygen_background = async move {
            // Remove the preprocessing entry from the meta store.
            tracing::info!("Deleting preprocessed material with ID {preproc_id} from meta store");
            match try_delete_in_meta_store(&preproc_bucket, &preproc_id).await {
                Ok(EntryState::Done(_)) => {
                    tracing::info!(
                        "Successfully deleted preprocessing ID {preproc_id} before running keygen for request ID {req_id}"
                    );
                }
                Ok(other) => {
                    MetricedError::handle_unreturnable_error(
                        op_tag,
                        Some(req_id),
                        anyhow::anyhow!(
                            "Preprocessing ID {preproc_id} deleted but was in state {other}"
                        ),
                    );
                }
                Err(e) => {
                    MetricedError::handle_unreturnable_error(op_tag, Some(req_id), e);
                }
            }

            match internal_keyset_config.keyset_config() {
                ddec_keyset_config::KeySetConfig::Standard(inner_config) => {
                    Self::key_gen_background(
                        &req_id,
                        &epoch_id,
                        dkg_sessions,
                        meta_store,
                        crypto_storage,
                        preproc_handle_w_mode,
                        sk,
                        dkg_params,
                        inner_config.to_owned(),
                        &internal_keyset_config,
                        eip712_domain_copy,
                        extra_data,
                        permit,
                        meta_permit,
                        token,
                        op_tag,
                        existing_key_tag,
                        existing_compact_pk,
                    )
                    .await
                }
                ddec_keyset_config::KeySetConfig::DecompressionOnly => {
                    Self::decompression_key_gen_background(
                        &req_id,
                        &epoch_id,
                        dkg_sessions.session_z128.base_session,
                        meta_store,
                        crypto_storage,
                        preproc_handle_w_mode,
                        sk,
                        dkg_params,
                        internal_keyset_config
                            .keyset_added_info().expect("keyset added info must be set for secure key generation and should have been validated before starting key generation").to_owned(),
                        eip712_domain_copy,
                        extra_data,
                        permit,
                        meta_permit,
                        token,
                    )
                    .await
                }
            }
        };
        // The background task owns the meta-store permit and the cancellation
        // token; it handles abort internally (racing the DKG against the token
        // and consuming the permit on every termination path).
        self.tracker.spawn(
            async move {
                //Start the metric timer, it will end on drop
                let _timer = timer.start();
                keygen_background.await;
                tracing::info!(
                    "Key generation of request {} with preproc id {} exiting.",
                    req_id,
                    preproc_id
                );
                ongoing.lock().await.remove(&preproc_id);
            }
            .instrument(tracing::Span::current()),
        );
        Ok(())
    }

    async fn inner_key_gen(
        &self,
        request: Request<KeyGenRequest>,
        insecure: bool,
    ) -> Result<Response<Empty>, MetricedError> {
        // Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_KEYGEN_REQUEST
        } else {
            OP_KEYGEN_REQUEST
        };
        // Acquire the serial lock to make sure no other keygen is running concurrently
        let _guard = self.serial_lock.lock().await;
        let permit = self.rate_limiter.start_keygen(op_tag).await?;

        let mut timer = metrics::METRICS.time_operation(op_tag).start();

        // Note: We increase the request counter only in launch_dkg
        // so we don't increase the error counter here either
        let inner = request.into_inner();
        let request_params_set = inner.params.is_some();
        let (
            req_id,
            preproc_id,
            context_id,
            epoch_id,
            dkg_params_of_request,
            internal_keyset_config,
            eip712_domain,
            extra_data,
        ) = validate_key_gen_request(inner, op_tag)?;
        let my_role = validate_context_and_epoch(
            op_tag,
            &self.session_maker,
            Some(req_id),
            &context_id,
            &epoch_id,
        )
        .await?;
        let metric_tags = vec![(TAG_PARTY_ID, my_role.to_string())];
        timer.tags(metric_tags);

        let resolved_preprocessing =
            // Processes the bucket meta information. This is slightly funky as in certain situations it may override the DKGParams specified in the request.
            Self::resolve_preprocessing(
                &self.preproc_buckets,
                req_id,
                preproc_id,
                dkg_params_of_request,
                request_params_set,
                insecure,
            )
            .await?;

        // Ensure that no key already exists for a given request.
        let already_exists = self
            .crypto_storage
            .fhe_keys_exists(&req_id, &epoch_id)
            .await
            .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
        if already_exists {
            return Err(MetricedError::new(
                op_tag,
                Some(req_id),
                anyhow::anyhow!(
                    "FHE key for request {} and epoch {} already exists in storage",
                    req_id,
                    epoch_id
                ),
                tonic::Code::AlreadyExists,
            ));
        }

        let meta_permit =
            add_req_to_meta_store(&self.dkg_pubinfo_meta_store, &req_id, op_tag).await?;

        tracing::info!(
            "Keygen starting with request_id={:?}, insecure={}",
            req_id,
            insecure
        );

        self.launch_dkg(
            internal_keyset_config,
            resolved_preprocessing,
            req_id,
            &eip712_domain,
            extra_data,
            context_id,
            epoch_id,
            permit,
            meta_permit,
        )
        .await?;

        //Always answer with Empty
        Ok(Response::new(Empty {}))
    }

    async fn inner_abort_key_gen(&self, preproc_id: RequestId) -> Status {
        match self.ongoing.lock().await.remove(&preproc_id) {
            Some(cancellation_token) => {
                // Observe that the cancellation arm handles the abortion and clean-up
                cancellation_token.cancel();
                tracing::info!("Aborted key generation with preprocessing {}", preproc_id);
                Status::ok("Key gen aborted successfully")
            }
            None => {
                // No keygen happening — nothing to cancel
                Status::not_found(
                    "No ongoing key generation found for the supplied preprocessing ID",
                )
            }
        }
    }

    /// Resolve the preprocessing handle, parameters and whether a stored entry should be consumed.
    async fn resolve_preprocessing(
        bucket_metastore: &RwLock<MetaStore<BucketMetaStore>>,
        key_req_id: RequestId,
        preproc_id: Option<RequestId>,
        request_dkg_params: DKGParams,
        request_params_set: bool,
        insecure: bool,
    ) -> Result<ResolvedPreprocessing, MetricedError> {
        // Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_KEYGEN_REQUEST
        } else {
            OP_KEYGEN_REQUEST
        };

        let preproc_id = preproc_id.ok_or_else(|| {
            MetricedError::new(
                op_tag,
                Some(key_req_id),
                anyhow::anyhow!("Missing preprocessing ID in key generation request"),
                tonic::Code::InvalidArgument,
            )
        })?;

        let preproc_bucket =
            match retrieve_from_meta_store(bucket_metastore, &preproc_id, op_tag).await {
                Ok(bucket) => bucket,
                Err(e) => {
                    // Remap the error to include the correct request ID
                    return Err(MetricedError::new(
                        op_tag,
                        Some(key_req_id),
                        anyhow::anyhow!(e.internal_err().to_string()),
                        e.code(),
                    ));
                }
            };
        if preproc_bucket.preprocessing_id != preproc_id {
            return Err(MetricedError::new(
                op_tag,
                Some(key_req_id),
                format!(
                    "Preprocessing ID mismatch: expected {}, found {}",
                    preproc_id, preproc_bucket.preprocessing_id
                ),
                tonic::Code::Internal,
            ));
        }
        // If params are set in the request they take precedence,
        // otherwise the parameters stored during preprocessing are used.
        let dkg_param = if request_params_set {
            request_dkg_params
        } else {
            preproc_bucket.dkg_param
        };
        // The mode of the keygen request must match the mode of the stored
        // preprocessing: real material is required for the secure keygen and
        // insecure (dummy) preprocessing may only be used by the insecure keygen.
        let preproc_handle = match &preproc_bucket.preprocessing_store {
            PreprocMaterial::Real(preprocessing_store) => {
                if insecure {
                    return Err(MetricedError::new(
                        op_tag,
                        Some(key_req_id),
                        format!(
                            "Insecure keygen requires an insecure preprocessing, but preprocessing ID {preproc_id} holds real preprocessing material"
                        ),
                        tonic::Code::FailedPrecondition,
                    ));
                }
                PreprocHandleWithMode::Secure((preproc_id, Arc::clone(preprocessing_store)))
            }
            #[cfg(feature = "insecure")]
            PreprocMaterial::Insecure => {
                if !insecure {
                    return Err(MetricedError::new(
                        op_tag,
                        Some(key_req_id),
                        format!(
                            "Secure keygen requires real preprocessing material, but preprocessing ID {preproc_id} was generated by the insecure preprocessing"
                        ),
                        tonic::Code::FailedPrecondition,
                    ));
                }
                PreprocHandleWithMode::Insecure(preproc_id)
            }
        };
        Ok(ResolvedPreprocessing {
            handle: preproc_handle,
            dkg_params: dkg_param,
        })
    }

    async fn inner_get_result(
        &self,
        request: Request<v1::RequestId>,
        insecure: bool,
    ) -> Result<Response<KeyGenResult>, MetricedError> {
        // Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_KEYGEN_RESULT
        } else {
            OP_KEYGEN_RESULT
        };
        let request_id =
            parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::KeyGenResponse)
                .map_err(|e| MetricedError::new(op_tag, None, e, tonic::Code::InvalidArgument))?;
        let key_gen_res =
            retrieve_from_meta_store(&self.dkg_pubinfo_meta_store, &request_id, op_tag).await?;

        match key_gen_res.as_ref() {
            KeyGenMetadata::Current(res) => {
                if res.key_id != request_id {
                    return Err(MetricedError::new(
                        op_tag,
                        Some(request_id),
                        anyhow::anyhow!(
                            "Key generation Request ID mismatch: expected {}, got {}",
                            request_id,
                            res.key_id
                        ),
                        tonic::Code::Internal,
                    ));
                }

                // Note: This relies on the ordering of the PubDataType enum
                // which must be kept stable (in particular, ServerKey must be before PublicKey)
                let key_digests = res
                    .key_digest_map
                    .iter()
                    .sorted_by_key(|x| x.0)
                    .map(|(key, digest)| KeyDigest {
                        key_type: key.to_string(),
                        digest: digest.clone(),
                    })
                    .collect::<Vec<_>>();

                Ok(Response::new(KeyGenResult {
                    request_id: Some(request_id.into()),
                    preprocessing_id: Some(res.preprocessing_id.into()),
                    key_digests,
                    external_signature: res.external_signature.clone(),
                }))
            }
            KeyGenMetadata::LegacyV0(_res) => {
                tracing::warn!(
                    "Legacy key generation result for request ID: {}",
                    request_id
                );
                // Because this is a legacy result and the call path will not reach here
                // (because a restart is needed to upgrade to the new version and the meta store is deleted from RAM),
                // we just return empty values for the fields below.
                Ok(Response::new(KeyGenResult {
                    request_id: Some(request_id.into()),
                    preprocessing_id: None,
                    // we do not attempt to convert the legacy key digest map
                    // because it does not match the format to the current one
                    // since no domain separation is used
                    key_digests: Vec::new(),
                    external_signature: vec![],
                }))
            }
        }
    }

    async fn decompression_key_gen_closure<P>(
        epoch_id: &EpochId,
        base_session: &mut BaseSession,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        preprocessing: &mut P,
    ) -> anyhow::Result<DecompressionKey>
    where
        P: DKGPreprocessing<ResiduePolyF4Z128> + Send + ?Sized,
    {
        let from_key_id = parse_optional_grpc_request_id(
            &keyset_added_info.from_keyset_id_decompression_only,
            RequestIdParsingErr::Other("invalid from keyset ID".to_string()),
        ).inspect_err(|e| {
                tracing::error!("missing *from* key ID for the keyset that contains the compression secret key share: {}", e)
            })?;
        let to_key_id = parse_optional_grpc_request_id(
            &keyset_added_info.to_keyset_id_decompression_only,
            RequestIdParsingErr::Other("invalid to keyset ID".to_string()),
        )
        .inspect_err(|e| {
            tracing::error!(
                "missing *to* key ID for the keyset that contains the glwe secret key share: {}",
                e
            )
        })?;

        let private_compression_share = {
            let threshold_keys = crypto_storage
                .read_guarded_fhe_keys(&from_key_id, epoch_id)
                .await?;
            let compression_sk_share = threshold_keys
                .private_keys
                .glwe_secret_key_share_compression
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing compression secret key share"))?;
            match compression_sk_share {
                CompressionPrivateKeySharesEnum::Z64(_share) => {
                    anyhow::bail!("z64 share is not supported")
                }
                CompressionPrivateKeySharesEnum::Z128(share) => share,
            }
        };
        let private_glwe_compute_share = {
            let threshold_keys = crypto_storage
                .read_guarded_fhe_keys(&to_key_id, epoch_id)
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
        epoch_id: &EpochId,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    ) -> anyhow::Result<(
        GlweSecretKeyShare<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        CompressionPrivateKeyShares<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    )> {
        let compression_req_id = parse_optional_grpc_request_id(
            &keyset_added_info.from_keyset_id_decompression_only,
            RequestIdParsingErr::Other("invalid from key ID".to_string())
        ).inspect_err(|e| {
                tracing::error!("missing from key ID for the keyset that contains the compression secret key share: {e}")
            })?;
        let glwe_req_id = parse_optional_grpc_request_id(
            &keyset_added_info.to_keyset_id_decompression_only,
            RequestIdParsingErr::Other("invalid to key ID".to_string()),
        )
        .inspect_err(|e| {
            tracing::error!(
                "missing to key ID for the keyset that contains the glwe secret key share: {e}"
            )
        })?;

        let glwe_shares = {
            let guard = crypto_storage
                .read_guarded_fhe_keys(&glwe_req_id, epoch_id)
                .await?;
            match &guard.private_keys.glwe_secret_key_share {
                GlweSecretKeyShareEnum::Z64(_) => anyhow::bail!("expected glwe shares to be z128"),
                GlweSecretKeyShareEnum::Z128(inner) => inner.clone(),
            }
        };

        let compression_shares = {
            let guard = crypto_storage
                .read_guarded_fhe_keys(&compression_req_id, epoch_id)
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
        req_id: &RequestId,
        base_session: &BaseSession,
        params: DKGParams,
        glwe_shares: GlweSecretKeyShare<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        compression_shares: CompressionPrivateKeyShares<
            Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >,
    ) -> anyhow::Result<DecompressionKey> {
        use itertools::Itertools;
        use tfhe::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
        use threshold_execution::{
            sharing::open::{RobustOpen, SecureRobustOpen},
            tfhe_internals::test_feature::{
                INPUT_PARTY_ID, to_hl_client_key, transfer_decompression_key,
            },
        };
        use threshold_types::role::Role;

        let output_party = Role::indexed_from_one(INPUT_PARTY_ID);

        // we need Vec<ResiduePoly> but we're given Vec<Share<ResiduePoly>>
        // so we need to call collect_vec()
        let opt_glwe_secret_key = SecureRobustOpen::default()
            .robust_open_list_to(
                base_session,
                glwe_shares.data.iter().map(|x| x.value()).collect_vec(),
                base_session.threshold() as usize,
                &output_party,
            )
            .await?;
        let opt_compression_secret_key = SecureRobustOpen::default()
            .robust_open_list_to(
                base_session,
                compression_shares
                    .post_packing_ks_key
                    .data
                    .iter()
                    .map(|x| x.value())
                    .collect_vec(),
                base_session.threshold() as usize,
                &output_party,
            )
            .await?;

        let compression_params = params
            .compression_decompression_params()
            .ok_or_else(|| anyhow::anyhow!("missing compression parameters"))?
            .raw_compression_parameters;
        let opt_decompression_key = match (opt_glwe_secret_key, opt_compression_secret_key) {
            (Some(glwe_secret_key), Some(compression_secret_key)) => {
                let bit_glwe_secret_key = GlweSecretKeyOwned::from_container(
                    convert_to_bit(glwe_secret_key)?,
                    params.polynomial_size(),
                );
                let bit_compression_secret_key =
                    tfhe::integer::compression_keys::CompressionPrivateKeys::from_raw_parts(
                        tfhe::shortint::list_compression::CompressionPrivateKeys {
                            post_packing_ks_key: GlweSecretKeyOwned::from_container(
                                convert_to_bit(compression_secret_key)?,
                                compression_params.packing_ks_polynomial_size,
                            ),
                            params: tfhe::shortint::parameters::CompressionParameters::Classic(
                                compression_params,
                            ),
                        },
                    );

                let dummy_lwe_secret_key =
                    LweSecretKeyOwned::from_container(vec![0u64; params.lwe_dimension().0]);

                // We need a dummy sns secret key otherwise [to_hl_client_key]
                // will fail because it will try to use this key when the parameter supports SnS
                let dummy_sns_secret_key = params.sns().map(|sns_param| {
                    let glwe_dim = sns_param.glwe_dimension_sns();
                    let poly_size = sns_param.polynomial_size_sns();
                    GlweSecretKeyOwned::from_container(
                        vec![0u128; glwe_dim.to_equivalent_lwe_dimension(poly_size).0],
                        sns_param.polynomial_size_sns(),
                    )
                });

                let (client_key, _, _, _, _, _, _, _) = to_hl_client_key(
                    &params,
                    req_id.into(),
                    dummy_lwe_secret_key,
                    bit_glwe_secret_key,
                    None,
                    None,
                    dummy_sns_secret_key,
                    None,
                    None,
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

    #[expect(clippy::too_many_arguments)]
    pub async fn decompression_key_gen_background(
        req_id: &RequestId,
        epoch_id: &EpochId,
        mut base_session: BaseSession,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        preproc_handle_w_mode: PreprocHandleWithMode,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        eip712_domain: alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
        permit: OwnedSemaphorePermit,
        meta_permit: MetaStorePermit<KeyGenMetadata>,
        cancel_token: CancellationToken,
    ) {
        let _permit = permit;
        let start = Instant::now();
        // Race the (potentially long-running) DKG against an abort.
        let outcome = tokio::select! {
            biased;
            () = cancel_token.cancelled() => None,
            res = async { match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure(insecure_prep_id) => {
                // sanity check to make sure we're using the insecure feature
                #[cfg(not(feature = "insecure"))]
                {
                    let _ = insecure_prep_id;
                    panic!(
                        "attempting to call insecure compression keygen when the insecure feature is not set"
                    );
                }
                #[cfg(feature = "insecure")]
                {
                    (
                        insecure_prep_id,
                        match Self::get_glwe_and_compression_key_shares(
                            keyset_added_info,
                            epoch_id,
                            crypto_storage.clone(),
                        )
                        .await
                        {
                            Ok((glwe_shares, compression_shares)) => {
                                Self::reconstruct_glwe_and_compression_key_shares(
                                    req_id,
                                    &base_session,
                                    params,
                                    glwe_shares,
                                    compression_shares,
                                )
                                .await
                            }
                            Err(e) => Err(e),
                        },
                    )
                }
            }
            PreprocHandleWithMode::Secure((prep_id, preproc_handle)) => {
                let mut preproc_handle = preproc_handle.lock().await;
                (
                    prep_id,
                    Self::decompression_key_gen_closure(
                        epoch_id,
                        &mut base_session,
                        crypto_storage.clone(),
                        params,
                        keyset_added_info,
                        preproc_handle.as_mut(),
                    )
                    .await,
                )
            }
        } } => Some(res),
        };

        let (prep_id, dkg_res) = match outcome {
            Some(res) => res,
            None => {
                crypto_storage.purge_fhe_keys(req_id, epoch_id).await;
                let _ = update_err_req_in_meta_store(
                    &meta_store,
                    meta_permit,
                    "Key generation was aborted".to_string(),
                    OP_DECOMPRESSION_KEYGEN,
                )
                .await;
                return;
            }
        };

        // Make sure the dkg ended nicely
        let decompression_key = match dkg_res {
            Ok(k) => k,
            Err(e) => {
                // If dkg errored out, update status
                let _ = update_err_req_in_meta_store(
                    &meta_store,
                    meta_permit,
                    format!("Failed to construct decompression key: {e}"),
                    OP_DECOMPRESSION_KEYGEN,
                )
                .await;
                return;
            }
        };

        // Compute all the info required for storing
        let info = match compute_info_decompression_keygen(
            &sk,
            &DSEP_PUBDATA_KEY,
            &prep_id,
            req_id,
            &decompression_key,
            &eip712_domain,
            extra_data,
        ) {
            Ok(info) => info,
            Err(e) => {
                let _ = update_err_req_in_meta_store(
                    &meta_store,
                    meta_permit,
                    format!("Failed to compute key info: {e}"),
                    OP_DECOMPRESSION_KEYGEN,
                )
                .await;
                return;
            }
        };

        if let Err(e) = crypto_storage
            .inner
            .write_decompression_key(req_id, info, decompression_key, meta_store, meta_permit)
            .await
        {
            tracing::error!(
                "Failed to write threshold decompression key for request {req_id}: {e}"
            );
            return;
        }

        tracing::info!(
            "Decompression DKG protocol took {} ms to complete for request {req_id}",
            start.elapsed().as_millis()
        );
    }

    async fn compressed_key_gen_from_existing_private_keyset<P>(
        dkg_sessions: &mut DkgSessions,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        params: DKGParams,
        existing_keyset_id: RequestId,
        epoch_id: EpochId,
        preprocessing: &mut P,
        tag: tfhe::Tag,
    ) -> anyhow::Result<(
        CompressedXofKeySet,
        PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    )>
    where
        P: DKGPreprocessing<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>
            + Send
            + ?Sized,
    {
        let existing_private_keys = {
            let threshold_keys = crypto_storage
                .read_guarded_fhe_keys(&existing_keyset_id, &epoch_id)
                .await?;
            threshold_keys.private_keys.as_ref().clone()
        };

        // First we need to do bit-lift
        let mut existing_private_keys = existing_private_keys
            .lift_to_z128_integrated(
                &mut dkg_sessions.session_z64,
                &mut dkg_sessions.session_z128,
            )
            .await?;
        ensure_oprf_secret_key_share_z128(
            &mut existing_private_keys,
            params,
            preprocessing,
            &mut dkg_sessions.session_z128,
        )
        .await?;

        let compressed_keyset = KG::compressed_keygen_from_existing_private_keyset(
            &mut dkg_sessions.session_z128,
            preprocessing,
            params,
            tag,
            &existing_private_keys,
        )
        .await?;
        Ok((compressed_keyset, existing_private_keys))
    }

    async fn key_gen_from_existing_private_keyset<P>(
        dkg_sessions: &mut DkgSessions,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        params: DKGParams,
        existing_keyset_id: RequestId,
        epoch_id: EpochId,
        preprocessing: &mut P,
        tag: tfhe::Tag,
    ) -> anyhow::Result<(
        FhePubKeySet,
        PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    )>
    where
        P: DKGPreprocessing<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>
            + Send
            + ?Sized,
    {
        let existing_private_keys = {
            let threshold_keys = crypto_storage
                .read_guarded_fhe_keys(&existing_keyset_id, &epoch_id)
                .await?;
            threshold_keys.private_keys.as_ref().clone()
        };

        // First we need to do bit-lift
        let mut existing_private_keys = existing_private_keys
            .lift_to_z128_integrated(
                &mut dkg_sessions.session_z64,
                &mut dkg_sessions.session_z128,
            )
            .await?;
        ensure_oprf_secret_key_share_z128(
            &mut existing_private_keys,
            params,
            preprocessing,
            &mut dkg_sessions.session_z128,
        )
        .await?;

        let pub_keyset = KG::keygen_from_existing_private_keyset(
            &mut dkg_sessions.session_z128,
            preprocessing,
            params,
            tag,
            &existing_private_keys,
        )
        .await?;
        Ok((pub_keyset, existing_private_keys))
    }

    #[expect(clippy::too_many_arguments)]
    async fn key_gen_background(
        req_id: &RequestId,
        epoch_id: &EpochId,
        mut dkg_sessions: DkgSessions,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        preproc_handle_w_mode: PreprocHandleWithMode,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        keyset_config: ddec_keyset_config::StandardKeySetConfig,
        internal_keyset_config: &InternalKeySetConfig,
        eip712_domain: alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
        permit: OwnedSemaphorePermit,
        meta_permit: MetaStorePermit<KeyGenMetadata>,
        cancel_token: CancellationToken,
        op_tag: &'static str,
        existing_key_tag: Option<tfhe::Tag>,
        existing_compact_pk: Option<tfhe::CompactPublicKey>,
    ) {
        let _permit = permit;
        let start = Instant::now();
        let outcome = tokio::select! {
            biased;
            () = cancel_token.cancelled() => None,
            res = async { match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure(insecure_prep_id) => {
                // sanity check to make sure we're using the insecure feature
                #[cfg(not(feature = "insecure"))]
                {
                    let _ = insecure_prep_id;
                    panic!(
                        "attempting to call insecure keygen when the insecure feature is not set"
                    );
                }
                #[cfg(feature = "insecure")]
                {
                    (
                        insecure_prep_id,
                        match (
                            keyset_config.secret_key_config,
                            keyset_config.computation_key_type,
                            keyset_config.compressed_key_config,
                        ) {
                            // Insecure standard keygen
                            (
                                ddec_keyset_config::KeyGenSecretKeyConfig::GenerateAll,
                                ddec_keyset_config::ComputeKeyType::Cpu,
                                ddec_keyset_config::CompressedKeyConfig::None,
                            ) => insecure_initialize_key_material(
                                &mut dkg_sessions.session_z128,
                                params,
                                req_id.into(),
                            )
                            .await
                            .map(|(pk, sk)| ThresholdKeyGenResult::Uncompressed(pk, sk)),
                            // Insecure compressed keygen
                            (
                                ddec_keyset_config::KeyGenSecretKeyConfig::GenerateAll,
                                ddec_keyset_config::ComputeKeyType::Cpu,
                                ddec_keyset_config::CompressedKeyConfig::All,
                            ) => initialize_compressed_key_material(
                                &mut dkg_sessions.session_z128,
                                params,
                                req_id.into(),
                            )
                            .await
                            .map(|(compressed_keyset, sk)| {
                                ThresholdKeyGenResult::Compressed(compressed_keyset, sk)
                            }),
                            // Insecure compressed keygen from an existing private keyset
                            // (the UseExisting migration flow). Party 1 reconstructs the
                            // existing secret key, regenerates the compressed keyset from it,
                            // and re-shares the (same) secret key to all parties.
                            (
                                ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting,
                                ddec_keyset_config::ComputeKeyType::Cpu,
                                ddec_keyset_config::CompressedKeyConfig::All,
                            ) => {
                                // Produce a Result here; error reporting and the
                                // meta_permit are handled once in the `outcome` match
                                // below (see the locking refactor on this branch).
                                async {
                                    let existing_keyset_id = internal_keyset_config
                                        .get_existing_keyset_id()
                                        .map_err(|e| anyhow::anyhow!(
                                            "insecure compressed keygen from existing keyset is missing a valid existing_keyset_id: {e}"
                                        ))?;
                                    let tag: tfhe::Tag =
                                        existing_key_tag.unwrap_or_else(|| req_id.into());
                                    let existing_private_keys = crypto_storage
                                        .read_guarded_fhe_keys(&existing_keyset_id, epoch_id)
                                        .await
                                        .map_err(|e| anyhow::anyhow!(
                                            "insecure compressed keygen failed to read the existing private keyset {existing_keyset_id}: {e}"
                                        ))?
                                        .private_keys
                                        .as_ref()
                                        .clone();
                                    insecure_initialize_compressed_key_material_from_existing(
                                        &mut dkg_sessions.session_z128,
                                        params,
                                        tag,
                                        &existing_private_keys,
                                    )
                                    .await
                                    .map(|(compressed_keyset, sk)| {
                                        ThresholdKeyGenResult::Compressed(compressed_keyset, sk)
                                    })
                                }
                                .await
                            }
                            _ => Err(anyhow::anyhow!(
                                "insecure keygen from an existing keyset is only supported for compressed keysets"
                            )),
                        },
                    )
                }
            }
            PreprocHandleWithMode::Secure((prep_id, preproc_handle)) => {
                let mut preproc_handle = preproc_handle.lock().await;
                (
                    prep_id,
                    match (
                        keyset_config.secret_key_config,
                        keyset_config.computation_key_type,
                        keyset_config.compressed_key_config,
                    ) {
                        (
                            ddec_keyset_config::KeyGenSecretKeyConfig::GenerateAll,
                            ddec_keyset_config::ComputeKeyType::Cpu,
                            ddec_keyset_config::CompressedKeyConfig::None,
                        ) => KG::keygen(
                            &mut dkg_sessions.session_z128,
                            preproc_handle.as_mut(),
                            params,
                            req_id.into(),
                        )
                        .await
                        .map(|(pk, sk)| ThresholdKeyGenResult::Uncompressed(pk, sk)),
                        (
                            ddec_keyset_config::KeyGenSecretKeyConfig::GenerateAll,
                            ddec_keyset_config::ComputeKeyType::Cpu,
                            ddec_keyset_config::CompressedKeyConfig::All,
                        ) => KG::compressed_keygen(
                            &mut dkg_sessions.session_z128,
                            preproc_handle.as_mut(),
                            params,
                            req_id.into(),
                        )
                        .await
                        .map(|(compressed_keyset, sk)| {
                            ThresholdKeyGenResult::Compressed(compressed_keyset, sk)
                        }),
                        (
                            ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting,
                            ddec_keyset_config::ComputeKeyType::Cpu,
                            ddec_keyset_config::CompressedKeyConfig::None,
                        ) => {
                            let existing_keyset_id = internal_keyset_config
                                .get_existing_keyset_id()
                                .expect("Standard UseExisting keygen must have a validated keyset_added_info.existing_keyset_id");
                            let tag: tfhe::Tag = existing_key_tag.unwrap_or_else(|| req_id.into());
                            Self::key_gen_from_existing_private_keyset(
                                &mut dkg_sessions,
                                crypto_storage.clone(),
                                params,
                                existing_keyset_id,
                                *epoch_id,
                                preproc_handle.as_mut(),
                                tag,
                            )
                            .await
                            .map(|(pk, sk)| ThresholdKeyGenResult::Uncompressed(pk, sk))
                        }
                        (
                            ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting,
                            ddec_keyset_config::ComputeKeyType::Cpu,
                            ddec_keyset_config::CompressedKeyConfig::All,
                        ) => {
                            let existing_keyset_id = internal_keyset_config
                                .get_existing_keyset_id()
                                .expect("Standard UseExisting compressed keygen must have a validated keyset_added_info.existing_keyset_id");
                            let tag: tfhe::Tag = existing_key_tag.unwrap_or_else(|| req_id.into());
                            Self::compressed_key_gen_from_existing_private_keyset(
                                &mut dkg_sessions,
                                crypto_storage.clone(),
                                params,
                                existing_keyset_id,
                                *epoch_id,
                                preproc_handle.as_mut(),
                                tag,
                            )
                            .await
                            .map(|(compressed_keyset, sk)| {
                                ThresholdKeyGenResult::Compressed(compressed_keyset, sk)
                            })
                        }
                    },
                )
            }
        } } => Some(res),
        };

        let (prep_id, dkg_res) = match outcome {
            Some(res) => res,
            None => {
                crypto_storage.purge_fhe_keys(req_id, epoch_id).await;
                let _ = update_err_req_in_meta_store(
                    &meta_store,
                    meta_permit,
                    "Key generation was aborted".to_string(),
                    op_tag,
                )
                .await;
                return;
            }
        };

        //Make sure the dkg ended nicely
        let dkg_result = match dkg_res {
            Ok(result) => result,
            Err(e) => {
                let _ = update_err_req_in_meta_store(
                    &meta_store,
                    meta_permit,
                    format!("Standard key generation failed: {e}"),
                    op_tag,
                )
                .await;
                return;
            }
        };

        // Handle both compressed and uncompressed keygen results
        match dkg_result {
            ThresholdKeyGenResult::Uncompressed(pub_key_set, private_keys) => {
                //Compute all the info required for storing
                let info = match compute_info_uncompressed_keygen(
                    &sk,
                    &DSEP_PUBDATA_KEY,
                    &prep_id,
                    req_id,
                    &pub_key_set,
                    &eip712_domain,
                    extra_data,
                ) {
                    Ok(info) => info,
                    Err(e) => {
                        let _ = update_err_req_in_meta_store(
                            &meta_store,
                            meta_permit,
                            format!(
                                "Computation of meta data in standard key generation failed: {e}"
                            ),
                            op_tag,
                        )
                        .await;
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
                        _raw_noise_squashing_compression_key,
                        _raw_rerandomization_key,
                        _raw_oprf_key,
                        _raw_tag,
                    ) = pub_key_set.server_key.clone().into_raw_parts();
                    (
                        raw_server_key,
                        raw_decompression_key,
                        raw_noise_squashing_key,
                    )
                };

                let threshold_fhe_keys = ThresholdFheKeys::new(
                    Arc::new(private_keys),
                    PublicKeyMaterial::new_uncompressed(
                        Arc::new(integer_server_key),
                        sns_key.map(Arc::new),
                        decompression_key.map(Arc::new),
                    ),
                    info,
                );

                //Note: We can't easily check here whether we succeeded writing to the meta store
                //thus we can't increment the error counter if it fails
                if let Err(e) = crypto_storage
                    .write_fhe_keys(
                        req_id,
                        epoch_id,
                        threshold_fhe_keys,
                        PublicKeySet::Uncompressed(Arc::new(pub_key_set)),
                        meta_store,
                        meta_permit,
                        op_tag,
                    )
                    .await
                {
                    tracing::error!("Failed to write threshold keys for request {req_id}: {e}");
                    return;
                }
            }
            ThresholdKeyGenResult::Compressed(compressed_keyset, private_keys) => {
                // When migrating from an existing keyset (UseExisting), preserve the OLD
                // CompactPublicKey so that signatures and stored bytes stay stable for
                // clients that already hold it. For a fresh keygen, use the public key
                // derived from the newly generated compressed keyset.
                let compact_public_key = match existing_compact_pk {
                    Some(old_pk) => old_pk,
                    None => match compressed_keyset.decompress() {
                        Ok(ks) => ks.into_raw_parts().0,
                        Err(e) => {
                            let _ = update_err_req_in_meta_store(
                                &meta_store,
                                meta_permit,
                                format!(
                                    "Failed to decompress freshly generated compressed keyset: {e}"
                                ),
                                op_tag,
                            )
                            .await;
                            return;
                        }
                    },
                };

                // Compute info for compressed keygen
                let info = match compute_info_compressed_keygen(
                    &sk,
                    &DSEP_PUBDATA_KEY,
                    &prep_id,
                    req_id,
                    &compressed_keyset,
                    &compact_public_key,
                    &eip712_domain,
                    extra_data,
                ) {
                    Ok(info) => info,
                    Err(e) => {
                        let _ = update_err_req_in_meta_store(
                            &meta_store,
                            meta_permit,
                            format!(
                                "Computation of meta data in standard compressed key generation failed: {e}"
                            ),
                            op_tag,
                        )
                        .await;
                        return;
                    }
                };

                let threshold_fhe_keys = ThresholdFheKeys::new(
                    Arc::new(private_keys),
                    PublicKeyMaterial::new(compressed_keyset),
                    info,
                );
                // Share the material's keyset allocation with the public-storage
                // set below — the keyset is multi-GiB.
                let compressed_keyset = threshold_fhe_keys
                    .public_material
                    .compressed_keyset()
                    .expect("material was just built compressed");

                // NOTE: when there is an existing compact pk from an older keygen (an older key ID),
                // then this pk is effectively copied to the new key ID.
                if let Err(e) = crypto_storage
                    .write_fhe_keys(
                        req_id,
                        epoch_id,
                        threshold_fhe_keys,
                        PublicKeySet::Compressed {
                            compact_public_key: Arc::new(compact_public_key),
                            compressed_keyset,
                        },
                        Arc::clone(&meta_store),
                        meta_permit,
                        op_tag,
                    )
                    .await
                {
                    tracing::error!(
                        "Failed to write compressed threshold keys for request {req_id}: {e}"
                    );
                    return;
                }

                // Compressed-UseExisting only: copy the compressed key to the original
                // key id. At this point the new keygen is already Done in the meta
                // store; a failure here only affects the migration target, so we log
                // loudly but don't fail the parent request.
                if matches!(
                    keyset_config.secret_key_config,
                    ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting
                ) && internal_keyset_config.copy_compressed_key_to_original()
                {
                    let old_key_id = internal_keyset_config
                        .get_existing_keyset_id()
                        .expect("copy_compressed_key_to_original requires the validated UseExisting keyset_added_info.existing_keyset_id");
                    // UseExisting reads the old private shares at the current
                    // epoch_id (see key_gen_from_existing_private_keyset), so
                    // the copy targets the same (old_key_id, epoch_id) pair.
                    if let Err(e) = crypto_storage
                        .copy_compressed_key_to_original(
                            req_id,
                            epoch_id,
                            &old_key_id,
                            epoch_id,
                            &sk,
                            &eip712_domain,
                            Arc::clone(&meta_store),
                        )
                        .await
                    {
                        tracing::error!(
                            "Compressed keygen for {req_id} committed successfully, but the \
                             follow-up copy to original key id {old_key_id} failed: {e}. \
                             The new keys at {req_id} are valid; \
                             the migration to {old_key_id} must be retried."
                        );
                    }
                }
            }
        }

        tracing::info!(
            "DKG protocol took {} ms to complete for request {req_id}",
            start.elapsed().as_millis()
        );
    }

    /// Reads the tag from an existing keyset in public storage.
    /// Tries CompressedXofKeySet first, then falls back to ServerKey.
    async fn read_existing_key_tag(
        crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
        existing_keyset_id: &RequestId,
    ) -> anyhow::Result<tfhe::Tag> {
        let pub_storage = crypto_storage.inner.public_storage.lock().await;

        let res = if let Ok(compressed_keyset) =
            <CompressedXofKeySet as CryptoMaterialReader>::read_from_storage(
                &*pub_storage,
                existing_keyset_id,
            )
            .await
        {
            Ok(compressed_keyset
                .clone()
                .into_raw_parts()
                .1
                .into_raw_parts()
                .1)
        } else {
            CryptoMaterialReader::read_from_storage(&*pub_storage, existing_keyset_id)
                .await
                .map(|server_key: tfhe::ServerKey| server_key.tag().clone())
        };

        res.map_err(|e| anyhow::anyhow!("{}: {e}", ERR_FAILED_TO_READ_EXISTING_TAG))
    }

    /// Reads the CompactPublicKey of an existing keyset in public storage and verifies its
    /// digest against the old `ThresholdFheKeys.meta_data`. Generating a
    /// `CompressedXofKeySet` from existing shares stays within the same epoch, so
    /// `epoch_id` must be the current epoch.
    ///
    /// The digest is computed over the raw bytes loaded from storage (never from a
    /// re-serialized value) so version upgrades of the serialized form do not cause a
    /// spurious mismatch.
    ///
    /// Errors out if the old `meta_data` has no `PubDataType::PublicKey` entry (e.g. a
    /// pre-dual-storage compressed keyset) or if the digests do not match.
    async fn read_existing_compact_public_key(
        crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
        existing_keyset_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<tfhe::CompactPublicKey> {
        let expected_digest = {
            let threshold_keys = crypto_storage
                .read_guarded_fhe_keys(existing_keyset_id, epoch_id)
                .await?;
            match &threshold_keys.meta_data {
                KeyGenMetadata::Current(inner) => inner
                    .key_digest_map
                    .get(&PubDataType::PublicKey)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Old ThresholdFheKeys for keyset {existing_keyset_id} has no \
                             PubDataType::PublicKey digest; cannot preserve the old compact \
                             public key during UseExisting keygen."
                        )
                    })?,
                KeyGenMetadata::LegacyV0(_) => {
                    anyhow::bail!(
                        "Old ThresholdFheKeys for keyset {existing_keyset_id} uses legacy \
                         metadata format; cannot verify the old compact public key digest."
                    );
                }
            }
        };

        let public_key_bytes = {
            let pub_storage = crypto_storage.inner.public_storage.lock().await;
            pub_storage
                .load_bytes(existing_keyset_id, &PubDataType::PublicKey.to_string())
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to load raw PublicKey bytes for keyset {existing_keyset_id}: {e}"
                    )
                })?
        };

        verify_public_key_digest_from_bytes(&public_key_bytes, &expected_digest).map_err(|e| {
            anyhow::anyhow!(
                "PublicKey digest mismatch for keyset {existing_keyset_id} (epoch {epoch_id}): \
                 {e}; expected={}, stored-bytes-hash={}",
                hex::encode(&expected_digest),
                hex::encode(hashing::hash_element(&DSEP_PUBDATA_KEY, &public_key_bytes)),
            )
        })?;

        tfhe::safe_serialization::safe_deserialize::<tfhe::CompactPublicKey>(
            std::io::Cursor::new(&public_key_bytes),
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize verified PublicKey bytes for keyset \
                 {existing_keyset_id}: {e}"
            )
        })
    }
}

#[tonic::async_trait]
impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
> KeyGenerator for RealKeyGenerator<PubS, PrivS, KG>
{
    async fn key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        self.inner_key_gen(request, false).await
    }

    async fn get_result(
        &self,
        request: tonic::Request<v1::RequestId>,
    ) -> Result<Response<KeyGenResult>, MetricedError> {
        self.inner_get_result(request, false).await
    }

    async fn abort_key_gen(&self, preproc_id: RequestId) -> Status {
        self.inner_abort_key_gen(preproc_id).await
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{FheParameter, KeySetConfig},
        rpc_types::{KMSType, alloy_to_protobuf_domain},
    };
    use rand::SeedableRng;
    use threshold_execution::{
        malicious_execution::endpoints::keygen::{
            DroppingOnlineDistributedKeyGen128, FailingOnlineDistributedKeyGen128,
            SlowOnlineDistributedKeyGen128,
        },
        online::preprocessing::dummy::DummyPreprocessing,
        small_execution::prss::PRSSSetup,
    };
    use threshold_types::network::NetworkMode;

    #[cfg(feature = "insecure")]
    use crate::consts::MAX_TRIES;
    use crate::{
        consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, TEST_PARAM},
        dummy_domain,
        engine::threshold::service::session::SessionMaker,
        util::meta_store::update_ok_req_in_meta_store,
        vault::storage::ram,
    };

    use super::*;

    impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: StorageExt + Sync + Send + 'static,
        KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
    > RealKeyGenerator<PubS, PrivS, KG>
    {
        async fn init_test(
            base_kms: BaseKmsStruct,
            pub_storage: PubS,
            priv_storage: PrivS,
            session_maker: ImmutableSessionMaker,
        ) -> Self {
            let crypto_storage = ThresholdCryptoMaterialStorage::new(
                pub_storage,
                priv_storage,
                None,
                HashMap::new(),
            );

            let tracker = Arc::new(TaskTracker::new());
            let rate_limiter = RateLimiter::default();
            let ongoing = Arc::new(Mutex::new(HashMap::new()));
            Self {
                base_kms,
                crypto_storage,
                preproc_buckets: MetaStore::new_unlimited(),
                dkg_pubinfo_meta_store: MetaStore::new_unlimited(),
                session_maker,
                tracker,
                ongoing,
                rate_limiter,
                _kg: PhantomData,
                serial_lock: Arc::new(Mutex::new(())),
            }
        }

        fn set_bucket_size(&mut self, bucket_size: usize) {
            let config = crate::util::rate_limiter::RateLimiterConfig {
                bucket_size,
                ..Default::default()
            };
            self.rate_limiter = RateLimiter::new(config);
        }
    }

    impl<KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static>
        RealKeyGenerator<ram::RamStorage, ram::RamStorage, KG>
    {
        async fn init_ram_keygen(
            base_kms: BaseKmsStruct,
            session_maker: ImmutableSessionMaker,
        ) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            Self::init_test(base_kms, pub_storage, priv_storage, session_maker).await
        }
    }

    async fn setup_key_generator<
        KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
    >() -> (
        [RequestId; 4],
        RealKeyGenerator<ram::RamStorage, ram::RamStorage, KG>,
    ) {
        use crate::cryptography::signatures::gen_sig_keys;
        let mut rng = AesRng::seed_from_u64(13371);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk).unwrap();
        let epoch_id = *DEFAULT_EPOCH_ID;
        let prss_setup_z128 = Some(PRSSSetup::new_testing_prss(vec![], vec![]));
        let prss_setup_z64 = Some(PRSSSetup::new_testing_prss(vec![], vec![]));
        let session_maker = SessionMaker::four_party_dummy_session(
            prss_setup_z128,
            prss_setup_z64,
            &epoch_id,
            base_kms.new_rng().await,
        );
        let kg = RealKeyGenerator::<ram::RamStorage, ram::RamStorage, KG>::init_ram_keygen(
            base_kms,
            session_maker.make_immutable(),
        )
        .await;

        let prep_ids: [RequestId; 4] = (0..4)
            .map(|_| RequestId::new_random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // We need to setup the preprocessor metastore so that keygen will pass
        let context_id = *DEFAULT_MPC_CONTEXT; // this context ID must be the one used in the session maker
        for prep_id in &prep_ids {
            let session_id = prep_id.derive_session_id().unwrap();
            let session = session_maker
                .make_base_session(session_id, context_id, NetworkMode::Sync)
                .await
                .unwrap();
            let dummy_prep = BucketMetaStore {
                preprocessing_id: *prep_id,
                external_signature: vec![],
                preprocessing_store: PreprocMaterial::Real(Arc::new(Mutex::new(Box::new(
                    DummyPreprocessing::new(42, &session),
                )))),
                dkg_param: TEST_PARAM,
            };
            let permit = add_req_to_meta_store(&kg.preproc_buckets, prep_id, OP_KEYGEN_REQUEST)
                .await
                .unwrap();
            update_ok_req_in_meta_store(&kg.preproc_buckets, permit, dummy_prep, OP_KEYGEN_REQUEST)
                .await;
        }
        (prep_ids, kg)
    }

    #[tokio::test]
    async fn invalid_argument() {
        //`InvalidArgument` - If the request is not valid or does not match the expected format.
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let prep_id = prep_ids[0];
        {
            // bad request ID format
            let bad_key_id = kms_grpc::kms::v1::RequestId {
                request_id: "badformat".to_string(),
            };
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let request = tonic::Request::new(KeyGenRequest {
                request_id: Some(bad_key_id.clone()),
                params: Some(FheParameter::Test as i32),
                preproc_id: Some(prep_id.into()),
                domain: Some(domain),
                keyset_config: None,
                keyset_added_info: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
                extra_data: vec![],
            });

            assert_eq!(
                kg.key_gen(request).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
            assert_eq!(
                kg.get_result(tonic::Request::new(bad_key_id))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // bad domain
            let key_id = RequestId::new_random(&mut AesRng::seed_from_u64(42));
            let mut domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            domain.verifying_contract = "bad_contract".to_string();

            let request = tonic::Request::new(KeyGenRequest {
                request_id: Some(key_id.into()),
                params: Some(FheParameter::Test as i32),
                preproc_id: Some(prep_id.into()),
                domain: Some(domain),
                keyset_config: None,
                keyset_added_info: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
                extra_data: vec![],
            });

            assert_eq!(
                kg.key_gen(request).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // bad keyset_config
            let key_id = RequestId::new_random(&mut AesRng::seed_from_u64(43));
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let keyset_config = KeySetConfig {
                keyset_type: 100, // bad keyset type
                standard_keyset_config: None,
            };

            let request = tonic::Request::new(KeyGenRequest {
                request_id: Some(key_id.into()),
                params: Some(FheParameter::Test as i32),
                preproc_id: Some(prep_id.into()),
                domain: Some(domain),
                keyset_config: Some(keyset_config),
                keyset_added_info: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
                extra_data: vec![],
            });

            assert_eq!(
                kg.key_gen(request).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn resource_exhausted() {
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        let (prep_ids, mut kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let mut rng = AesRng::seed_from_u64(11);
        let prep_id = prep_ids[0];
        let key_id = RequestId::new_random(&mut rng);

        // Set bucket size to zero, so no operations are allowed
        kg.set_bucket_size(0);

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(prep_id.into()),
            domain: Some(domain),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        });

        assert_eq!(
            kg.key_gen(request).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn not_found() {
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let mut rng = AesRng::seed_from_u64(2);
        // use a random prep ID and it should be not found
        {
            let key_id = RequestId::new_random(&mut rng);
            let bad_prep_id = RequestId::new_random(&mut rng);
            assert!(!prep_ids.contains(&bad_prep_id));
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let request = tonic::Request::new(KeyGenRequest {
                request_id: Some(key_id.into()),
                params: Some(FheParameter::Test as i32),
                preproc_id: Some(bad_prep_id.into()),
                domain: Some(domain),
                keyset_config: None,
                keyset_added_info: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
                extra_data: vec![],
            });

            assert_eq!(
                kg.key_gen(request).await.unwrap_err().code(),
                tonic::Code::NotFound
            );
        }

        {
            // the result is not found since it's a fresh key ID
            let key_id = RequestId::new_random(&mut rng);
            assert!(!prep_ids.contains(&key_id));
            assert_eq!(
                kg.get_result(tonic::Request::new(key_id.into()))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
        }
    }

    #[tokio::test]
    async fn internal() {
        let (prep_ids, kg) = setup_key_generator::<
            FailingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let prep_id = prep_ids[0];
        let mut rng = AesRng::seed_from_u64(123);
        let key_id = RequestId::new_random(&mut rng);

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(prep_id.into()),
            domain: Some(domain),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        });

        // keygen should pass because the failure occurs in background process
        kg.key_gen(request).await.unwrap();

        // The result endpoint is non-blocking; poll until the background keygen fails.
        assert_eq!(
            crate::testing::utils::poll_result_until_ready(
                || kg.get_result(Request::new(key_id.into()))
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Internal
        );
    }

    #[tokio::test]
    async fn already_exists() {
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let prep_id0 = prep_ids[0];
        let prep_id1 = prep_ids[1];
        let mut rng = AesRng::seed_from_u64(22);
        let key_id = RequestId::new_random(&mut rng);

        // do one keygen
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request0 = KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(prep_id0.into()),
            domain: Some(domain.clone()),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        };

        kg.key_gen(tonic::Request::new(request0)).await.unwrap();

        // try to do it again with the same key ID
        // NOTE: we need to use a different preproc ID to avoid the `NotFound` error
        let request1 = KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(prep_id1.into()),
            domain: Some(domain),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        };
        assert_eq!(
            kg.key_gen(tonic::Request::new(request1))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn aborted() {
        // TODO this is not easy to test since it requires meta store to fail
        // we don't have a trait for meta store
    }

    #[tokio::test]
    async fn use_existing_key_tag_with_wrong_keyset_id() {
        // When use_existing_key_tag is true but existing_keyset_id points to a
        // non-existent key in storage, launch_dkg should fail with Internal
        // because read_existing_key_tag cannot find any key material.
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let prep_id = prep_ids[0];
        let mut rng = AesRng::seed_from_u64(5);
        let key_id = RequestId::new_random(&mut rng);
        let wrong_keyset_id = RequestId::new_random(&mut rng);

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let keyset_config = KeySetConfig {
            keyset_type: kms_grpc::kms::v1::KeySetType::Standard as i32,
            standard_keyset_config: Some(kms_grpc::kms::v1::StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: kms_grpc::kms::v1::KeyGenSecretKeyConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        let keyset_added_info = KeySetAddedInfo {
            existing_keyset_id: Some(wrong_keyset_id.into()),
            use_existing_key_tag: true,
            ..Default::default()
        };

        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(prep_id.into()),
            domain: Some(domain),
            keyset_config: Some(keyset_config),
            keyset_added_info: Some(keyset_added_info),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        });

        let res = kg.key_gen(request).await.unwrap_err();
        assert_eq!(res.code(), tonic::Code::Internal);

        assert!(
            res.internal_err()
                .to_string()
                .contains(ERR_FAILED_TO_READ_EXISTING_TAG)
        );
    }

    #[tokio::test]
    async fn sunshine() {
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let prep_id = prep_ids[0];
        let mut rng = AesRng::seed_from_u64(6);
        let key_id = RequestId::new_random(&mut rng);

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let tonic_req = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            // The test parameters will be used under the hood
            // since we configured the dummy key generator with preprocessing materials from prep_ids.
            // Those preprocessing materials have the test parameters.
            params: None,
            preproc_id: Some(prep_id.into()),
            domain: Some(domain),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        });

        kg.key_gen(tonic_req).await.unwrap();

        // The result endpoint is non-blocking; poll until the background keygen completes.
        crate::testing::utils::poll_result_until_ready(|| {
            kg.get_result(Request::new(key_id.into()))
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn abort_key_gen_not_found() {
        let (_prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;

        // Abort with a preproc ID for which no key generation is running
        let mut rng = AesRng::seed_from_u64(7);
        let random_id = RequestId::new_random(&mut rng);
        let status = kg.abort_key_gen(random_id).await;
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    /// Insert an insecure (dummy) preprocessing bucket, as stored by the
    /// insecure preprocessing endpoint, into the key generator's bucket store.
    #[cfg(feature = "insecure")]
    async fn insert_insecure_bucket<
        KG: OnlineDistributedKeyGen<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }> + 'static,
    >(
        kg: &RealKeyGenerator<ram::RamStorage, ram::RamStorage, KG>,
        prep_id: &RequestId,
    ) {
        let bucket = BucketMetaStore {
            preprocessing_id: *prep_id,
            external_signature: vec![],
            preprocessing_store: PreprocMaterial::Insecure,
            dkg_param: TEST_PARAM,
        };
        let permit = add_req_to_meta_store(&kg.preproc_buckets, prep_id, "test")
            .await
            .unwrap();
        assert!(update_ok_req_in_meta_store(&kg.preproc_buckets, permit, bucket, "test").await)
    }

    #[cfg(feature = "insecure")]
    fn keygen_request(
        key_id: RequestId,
        prep_id: Option<RequestId>,
    ) -> tonic::Request<KeyGenRequest> {
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: prep_id.map(|id| id.into()),
            domain: Some(domain),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        })
    }

    /// The insecure keygen must reject a preprocessing bucket that holds real material.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_keygen_rejects_real_bucket() {
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let ikg = RealInsecureKeyGenerator::from_real_keygen(&kg).await;
        let mut rng = AesRng::seed_from_u64(9);
        let key_id = RequestId::new_random(&mut rng);

        // prep_ids hold real (dummy) preprocessing material
        assert_eq!(
            ikg.insecure_key_gen(keygen_request(key_id, Some(prep_ids[0])))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }

    /// The secure keygen must reject a preprocessing bucket that was created
    /// by the insecure preprocessing (i.e. holds no material).
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn secure_keygen_rejects_insecure_bucket() {
        let (_prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let mut rng = AesRng::seed_from_u64(10);
        let insecure_prep_id = RequestId::new_random(&mut rng);
        insert_insecure_bucket(&kg, &insecure_prep_id).await;
        let key_id = RequestId::new_random(&mut rng);

        assert_eq!(
            kg.key_gen(keygen_request(key_id, Some(insecure_prep_id)))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }

    /// The insecure keygen must fail if the preprocessing ID does not exist.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_keygen_not_found() {
        let (prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let ikg = RealInsecureKeyGenerator::from_real_keygen(&kg).await;
        let mut rng = AesRng::seed_from_u64(11);
        let key_id = RequestId::new_random(&mut rng);
        let bad_prep_id = RequestId::new_random(&mut rng);
        assert!(!prep_ids.contains(&bad_prep_id));

        assert_eq!(
            ikg.insecure_key_gen(keygen_request(key_id, Some(bad_prep_id)))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    /// The insecure keygen consumes the insecure preprocessing entry, so a
    /// second keygen with the same preprocessing ID must fail with `NotFound`.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_keygen_consumes_preproc() {
        let (_prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let ikg = RealInsecureKeyGenerator::from_real_keygen(&kg).await;
        let mut rng = AesRng::seed_from_u64(12);
        let insecure_prep_id = RequestId::new_random(&mut rng);
        insert_insecure_bucket(&kg, &insecure_prep_id).await;
        let key_id = RequestId::new_random(&mut rng);

        ikg.insecure_key_gen(keygen_request(key_id, Some(insecure_prep_id)))
            .await
            .unwrap();

        // The preprocessing entry is deleted at the start of the background task,
        // independently of whether the key generation itself succeeds.
        let mut deleted = false;
        for _ in 0..MAX_TRIES {
            if matches!(
                kg.preproc_buckets.read().await.retrieve(&insecure_prep_id),
                Some(EntryState::Deleted)
            ) {
                deleted = true;
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        assert!(deleted, "insecure preprocessing entry was not consumed");

        // A second keygen with the same preprocessing ID must fail
        let other_key_id = RequestId::new_random(&mut rng);
        assert_eq!(
            ikg.insecure_key_gen(keygen_request(other_key_id, Some(insecure_prep_id)))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    /// The insecure keygen must reject a request without a preprocessing ID.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_keygen_missing_preproc_id() {
        let (_prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let ikg = RealInsecureKeyGenerator::from_real_keygen(&kg).await;
        let mut rng = AesRng::seed_from_u64(13);
        let key_id = RequestId::new_random(&mut rng);

        assert_eq!(
            ikg.insecure_key_gen(keygen_request(key_id, None))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    /// The secure keygen must reject a request without a preprocessing ID.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn secure_keygen_missing_preproc_id() {
        let (_prep_ids, kg) = setup_key_generator::<
            DroppingOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let mut rng = AesRng::seed_from_u64(14);
        let key_id = RequestId::new_random(&mut rng);

        assert_eq!(
            kg.key_gen(keygen_request(key_id, None))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    /// Dummy preprocessing (pre-populated into the bucket by [`setup_key_generator`]) is
    /// consumed by the key generation, after which the slow DKG is aborted mid-execution.
    #[tokio::test]
    async fn abort_during_key_gen() {
        let (prep_ids, kg) = setup_key_generator::<
            SlowOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        >()
        .await;
        let prep_id = prep_ids[0];
        let mut rng = AesRng::seed_from_u64(8);
        let key_id = RequestId::new_random(&mut rng);

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let tonic_req = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: Some(FheParameter::Test as i32),
            preproc_id: Some(prep_id.into()),
            domain: Some(domain),
            keyset_config: None,
            keyset_added_info: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
            extra_data: vec![],
        });
        kg.key_gen(tonic_req).await.unwrap();

        // The slow DKG is still running — abort should cancel it
        let status = kg.abort_key_gen(prep_id).await;
        assert_eq!(status.code(), tonic::Code::Ok);
        // Check that a second abort returns NotFound
        let status = kg.abort_key_gen(prep_id).await;
        assert_eq!(status.code(), tonic::Code::NotFound);
        // Try to get the result and see it has been aborted (poll: non-blocking endpoint).
        let err = crate::testing::utils::poll_result_until_ready(|| {
            kg.get_result(Request::new(key_id.into()))
        })
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted);
    }
}
