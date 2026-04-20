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
    endpoints::keygen::{OnlineDistributedKeyGen, distributed_decompression_keygen_z128},
    keyset_config as ddec_keyset_config,
    online::preprocessing::DKGPreprocessing,
    runtime::sessions::{base_session::BaseSession, small_session::SmallSession},
    tfhe_internals::{
        parameters::DKGParams,
        private_keysets::{CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, PrivateKeySet},
        public_keysets::FhePubKeySet,
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, RwLockReadGuard};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate Imports ===
use crate::{
    cryptography::signatures::PrivateSigKey,
    engine::{
        base::{
            BaseKmsStruct, DSEP_PUBDATA_KEY, KeyGenMetadata, compute_info_compressed_keygen,
            compute_info_decompression_keygen, compute_info_standard_keygen, retrieve_parameters,
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
            MetaStore, add_req_to_meta_store, handle_res, retrieve_from_meta_store,
            retrieve_from_meta_store_with_timeout, update_err_req_in_meta_store,
        },
        rate_limiter::RateLimiter,
    },
    vault::storage::{
        Storage, StorageExt,
        crypto_material::{CryptoMaterialReader, ThresholdCryptoMaterialStorage},
    },
};

// === Current Module Imports ===
use super::BucketMetaStore;

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
#[allow(clippy::large_enum_variant)]
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
use crate::engine::base::INSECURE_PREPROCESSING_ID;
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::InsecureKeyGenerator;
#[cfg(feature = "insecure")]
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
#[cfg(feature = "insecure")]
use threshold_execution::tfhe_internals::{
    compression_decompression_key::CompressionPrivateKeyShares,
    glwe_key::GlweSecretKeyShare,
    test_feature::{initialize_compressed_key_material, insecure_initialize_key_material},
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
                serial_lock: Arc::new(Mutex::new(())),
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
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub enum PreprocHandleWithMode {
    Secure(
        (
            RequestId,
            Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>,
        ),
    ),
    Insecure,
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
    #[allow(clippy::too_many_arguments)]
    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        internal_keyset_config: InternalKeySetConfig,
        preproc_handle_w_mode: PreprocHandleWithMode,
        req_id: RequestId,
        eip712_domain: &alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
        context_id: ContextId,
        epoch_id: EpochId,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
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
                PreprocHandleWithMode::Insecure,
                ddec_keyset_config::KeySetConfig::Standard(inner),
            ) => match inner.compressed_key_config {
                ddec_keyset_config::CompressedKeyConfig::None => OP_INSECURE_STANDARD_KEYGEN,
                ddec_keyset_config::CompressedKeyConfig::All => {
                    OP_INSECURE_STANDARD_COMPRESSED_KEYGEN
                }
            },
            (
                PreprocHandleWithMode::Insecure,
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_INSECURE_DECOMPRESSION_KEYGEN,
        };

        // On top of the global KG request counter, we also increment the specific operation counter
        // as such, the sum of the specific operation counter is supposed to be equal the global KG
        // counter
        metrics::METRICS.increment_request_counter(op_tag);

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let my_role = self.session_maker.my_role(&context_id).await?;
        let timer = metrics::METRICS
            .time_operation(op_tag)
            .tag(TAG_PARTY_ID, my_role.to_string());

        // Create the sessions necessary to run the DKG.
        // Note that not all the sessions is going to be needed,
        // but to keep the code clean, we just make all the possible sessions.
        let dkg_sessions = {
            let session_id_z64 = req_id.derive_session_id_with_counter(DKG_Z64_SESSION_COUNTER)?;
            let session_id_z128 =
                req_id.derive_session_id_with_counter(DKG_Z128_SESSION_COUNTER)?;
            let session_z64 = self
                .session_maker
                .make_small_async_session_z64(session_id_z64, context_id, epoch_id)
                .await?;
            let session_z128 = self
                .session_maker
                .make_small_async_session_z128(session_id_z128, context_id, epoch_id)
                .await?;
            DkgSessions {
                session_z64,
                session_z128,
            }
        };

        // Clone all the Arcs to give them to the tokio thread
        let meta_store = Arc::clone(&self.dkg_pubinfo_meta_store);
        let meta_store_cancelled = Arc::clone(&self.dkg_pubinfo_meta_store);
        let sk = self.base_kms.sig_key()?;
        let crypto_storage = self.crypto_storage.clone();
        let crypto_storage_cancelled = self.crypto_storage.clone();
        let eip712_domain_copy = eip712_domain.clone();
        let ongoing = Arc::clone(&self.ongoing);

        let preproc_id = match &preproc_handle_w_mode {
            PreprocHandleWithMode::Secure((preproc_id, _)) => *preproc_id,
            PreprocHandleWithMode::Insecure => {
                #[cfg(not(feature = "insecure"))]
                {
                    panic!(
                        "attempting to call insecure keygen when the insecure feature is not set"
                    );
                }
                #[cfg(feature = "insecure")]
                {
                    // NOTE that using a static preprocessing ID for the insecure keygen
                    // This means that concurrent calls to the insecure keygen are not allowed!
                    *INSECURE_PREPROCESSING_ID
                }
            }
        };
        let token = CancellationToken::new();
        {
            self.ongoing.lock().await.insert(preproc_id, token.clone());
        }

        // we need to clone the req ID because async closures are not stable
        let req_id_clone = req_id;
        let epoch_id_clone = epoch_id;
        let preproc_bucket = self.preproc_buckets.clone();

        // we must validate the parameter before passing it into the background process
        internal_keyset_config.validate()?;

        // Read existing key tag from public storage if needed
        let existing_key_tag: Option<tfhe::Tag> = if internal_keyset_config.use_existing_key_tag() {
            let existing_keyset_id = internal_keyset_config.get_existing_keyset_id()?;
            Some(Self::read_existing_key_tag(&crypto_storage, &existing_keyset_id).await?)
        } else {
            None
        };

        // For compressed keygen that recycles an existing private keyset, load the OLD
        // CompactPublicKey so we can sign and store it instead of the new one derived from
        // the newly-generated CompressedXofKeySet. Keeps the externally-visible public key
        // stable for clients that already cached it. The digest of the loaded pk is
        // verified against the old ThresholdFheKeys.meta_data; generation from existing
        // shares stays within the same epoch, so the current epoch_id is used.
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
                    let existing_keyset_id = internal_keyset_config.get_existing_keyset_id()?;
                    Some(
                        Self::read_existing_compact_public_key(
                            &crypto_storage,
                            &existing_keyset_id,
                            &epoch_id,
                        )
                        .await?,
                    )
                }
                _ => None,
            };

        let keygen_background = async move {
            // Remove the preprocessing material
            match &preproc_handle_w_mode {
                PreprocHandleWithMode::Secure((preproc_id, _)) => {
                    tracing::info!(
                        "Deleting preprocessed material with ID {preproc_id} from meta store"
                    );
                    let handle = {
                        let mut meta_store_guard = preproc_bucket.write().await;
                        meta_store_guard.delete(preproc_id)
                    };
                    match handle_res(handle, preproc_id).await {
                        Ok(_) => {
                            tracing::info!(
                                "Successfully deleted preprocessing ID {preproc_id} after keygen completion for request ID {req_id}"
                            );
                        }
                        Err(e) => {
                            MetricedError::handle_unreturnable_error(op_tag, Some(req_id), e);
                        }
                    }
                }
                PreprocHandleWithMode::Insecure => {
                    // Nothing to remove
                }
            }

            match internal_keyset_config.keyset_config() {
                ddec_keyset_config::KeySetConfig::Standard(inner_config) => {
                    Self::key_gen_background(
                        &req_id_clone,
                        &epoch_id_clone,
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
                        op_tag,
                        existing_key_tag,
                        existing_compact_pk,
                    )
                    .await
                }
                ddec_keyset_config::KeySetConfig::DecompressionOnly => {
                    Self::decompression_key_gen_background(
                        &req_id_clone,
                        &epoch_id_clone,
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
                    )
                    .await
                }
            }
        };
        self.tracker
            .spawn(async move {
                //Start the metric timer, it will end on drop
                let _timer = timer.start();
                tokio::select! {
                    () = keygen_background => {
                        tracing::info!("Key generation of request {} with preproc id {} exiting normally.", req_id, preproc_id);
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&preproc_id);
                    },
                    () = token.cancelled() => {
                        MetricedError::handle_unreturnable_error(
                            OP_KEYGEN_REQUEST,
                            Some(req_id),
                            format!("Key generation background with preprocessing id {} failed since the task got aborted", preproc_id),
                        );
                        tracing::error!("Key generation of request {} exiting before completion because of an abort request.", &req_id);
                        let mut guarded_meta_store = meta_store_cancelled.write().await;
                        let _ = guarded_meta_store.update(&req_id, Result::Err("Key generation was aborted".to_string()));
                        // TODO(#2983) Meta store update will fail here. The helper methods will be rewritten to avoid this problem. 
                        // In connection with this the meta store update should be moved to AFTER the purging
                        crypto_storage_cancelled.purge_key_material(&req_id, &epoch_id, guarded_meta_store).await;
                    },
                }
            }.instrument(tracing::Span::current()));
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
        let params = inner.params;
        let (
            req_id,
            preproc_id,
            context_id,
            epoch_id,
            _dkg_params,
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

        let (preproc_handle, dkg_params) =
            // Processes the bucket meta information. This is a slightly funky as in certain situations it may override the DKGParams sepcified in the request
            Self::retrieve_preproc_handle(
                self.preproc_buckets.read().await,
                req_id,
                preproc_id,
                params,
                insecure,
            )
            .await?;

        add_req_to_meta_store(
            &mut self.dkg_pubinfo_meta_store.write().await,
            &req_id,
            op_tag,
        )?;

        tracing::info!(
            "Keygen starting with request_id={:?}, insecure={}",
            req_id,
            insecure
        );

        self.launch_dkg(
            dkg_params,
            internal_keyset_config,
            preproc_handle,
            req_id,
            &eip712_domain,
            extra_data,
            context_id,
            epoch_id,
            permit,
        )
        .await
        .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;

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

    /// Retrieve the preprocessing handle, parameters and preprocessing ID from the request.
    /// This method also does NOT delete the preprocessing entry from the meta store
    async fn retrieve_preproc_handle(
        bucket_metastore: RwLockReadGuard<'_, MetaStore<BucketMetaStore>>,
        key_req_id: RequestId,
        preproc_id: RequestId,
        params: Option<i32>,
        insecure: bool,
    ) -> Result<(PreprocHandleWithMode, DKGParams), MetricedError> {
        // Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_KEYGEN_REQUEST
        } else {
            OP_KEYGEN_REQUEST
        };
        let standard_dkg_params = retrieve_parameters(params)
            .map_err(|e| MetricedError::new(op_tag, Some(key_req_id), e, tonic::Code::Internal))?;
        // If params are not set, then we need to retrieve the preprocessing
        // unless we are in insecure mode.
        // In the insecure mode the default parameters will be used if not set.
        if insecure {
            Ok((PreprocHandleWithMode::Insecure, standard_dkg_params))
        } else {
            let preproc_bucket =
                retrieve_from_meta_store(bucket_metastore, &preproc_id, OP_KEYGEN_REQUEST)
                    .await
                    .map_err(|e| {
                        // Remap the error to include the correct request ID
                        MetricedError::new(
                            OP_KEYGEN_REQUEST,
                            Some(key_req_id),
                            anyhow::anyhow!(e.internal_err().to_string()),
                            e.code(),
                        )
                    })?;
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
            let dkg_param = match params {
                Some(_) => standard_dkg_params,
                None => preproc_bucket.dkg_param,
            };
            Ok((
                PreprocHandleWithMode::Secure((preproc_id, preproc_bucket.preprocessing_store)),
                dkg_param,
            ))
        }
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
        let key_gen_res = retrieve_from_meta_store_with_timeout(
            self.dkg_pubinfo_meta_store.read().await,
            &request_id,
            op_tag,
            crate::consts::DURATION_WAITING_ON_KEYGEN_RESULT_SECONDS,
        )
        .await?;

        match key_gen_res {
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
                    .into_iter()
                    .sorted_by_key(|x| x.0)
                    .map(|(key, digest)| KeyDigest {
                        key_type: key.to_string(),
                        digest,
                    })
                    .collect::<Vec<_>>();

                Ok(Response::new(KeyGenResult {
                    request_id: Some(request_id.into()),
                    preprocessing_id: Some(res.preprocessing_id.into()),
                    key_digests,
                    external_signature: res.external_signature,
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
                .read_guarded_threshold_fhe_keys(&from_key_id, epoch_id)
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
                .read_guarded_threshold_fhe_keys(&to_key_id, epoch_id)
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
                .read_guarded_threshold_fhe_keys(&glwe_req_id, epoch_id)
                .await?;
            match &guard.private_keys.glwe_secret_key_share {
                GlweSecretKeyShareEnum::Z64(_) => anyhow::bail!("expected glwe shares to be z128"),
                GlweSecretKeyShareEnum::Z128(inner) => inner.clone(),
            }
        };

        let compression_shares = {
            let guard = crypto_storage
                .read_guarded_threshold_fhe_keys(&compression_req_id, epoch_id)
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

        let params_handle = params.get_params_basics_handle();
        let compression_params = params_handle
            .get_compression_decompression_params()
            .ok_or_else(|| anyhow::anyhow!("missing compression parameters"))?
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
                            params: tfhe::shortint::parameters::CompressionParameters::Classic(
                                compression_params,
                            ),
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

                let (client_key, _, _, _, _, _, _, _) = to_hl_client_key(
                    &params,
                    req_id.into(),
                    dummy_lwe_secret_key,
                    bit_glwe_secret_key,
                    None,
                    None,
                    dummy_sns_secret_key,
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

    #[allow(clippy::too_many_arguments)]
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
    ) {
        let _permit = permit;
        let start = Instant::now();
        let (prep_id, dkg_res) = match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure => {
                // sanity check to make sure we're using the insecure feature
                #[cfg(not(feature = "insecure"))]
                {
                    panic!(
                        "attempting to call insecure compression keygen when the insecure feature is not set"
                    );
                }
                #[cfg(feature = "insecure")]
                {
                    (
                        *INSECURE_PREPROCESSING_ID,
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
        };

        // Make sure the dkg ended nicely
        let decompression_key = match dkg_res {
            Ok(k) => k,
            Err(e) => {
                // If dkg errored out, update status
                update_err_req_in_meta_store(
                    &mut meta_store.write().await,
                    req_id,
                    format!("Failed to construct decompression key: {e}"),
                    OP_DECOMPRESSION_KEYGEN,
                );
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
                update_err_req_in_meta_store(
                    &mut meta_store.write().await,
                    req_id,
                    format!("Failed to compute key info: {e}"),
                    OP_DECOMPRESSION_KEYGEN,
                );
                return;
            }
        };

        //Note: We can't easily check here whether we succeeded writing to the meta store
        //thus we can't increment the error counter if it fails
        crypto_storage
            .write_decompression_key_with_meta_store(req_id, decompression_key, info, meta_store)
            .await;

        tracing::info!(
            "Decompression DKG protocol took {} ms to complete for request {req_id}",
            start.elapsed().as_millis()
        );
    }

    #[allow(clippy::too_many_arguments)]
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
                .read_guarded_threshold_fhe_keys(&existing_keyset_id, &epoch_id)
                .await?;
            threshold_keys.private_keys.as_ref().clone()
        };

        // First we need to do bit-lift
        let existing_private_keys = existing_private_keys
            .lift_to_z128_integrated(
                &mut dkg_sessions.session_z64,
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

    #[allow(clippy::too_many_arguments)]
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
                .read_guarded_threshold_fhe_keys(&existing_keyset_id, &epoch_id)
                .await?;
            threshold_keys.private_keys.as_ref().clone()
        };

        // First we need to do bit-lift
        let existing_private_keys = existing_private_keys
            .lift_to_z128_integrated(
                &mut dkg_sessions.session_z64,
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

    #[allow(clippy::too_many_arguments)]
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
        op_tag: &'static str,
        existing_key_tag: Option<tfhe::Tag>,
        existing_compact_pk: Option<tfhe::CompactPublicKey>,
    ) {
        let _permit = permit;
        let start = Instant::now();
        let (prep_id, dkg_res) = match preproc_handle_w_mode {
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
                    (
                        *INSECURE_PREPROCESSING_ID,
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
                            _ => {
                                // insecure keygen from existing compression key is not supported
                                update_err_req_in_meta_store(&mut meta_store.write().await, req_id,  "insecure keygen from existing compression key is not supported".to_string(),  op_tag);
                                return;
                            }
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
                                .expect("validated");
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
                                .expect("validated");
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
        };

        //Make sure the dkg ended nicely
        let dkg_result = match dkg_res {
            Ok(result) => result,
            Err(e) => {
                update_err_req_in_meta_store(
                    &mut meta_store.write().await,
                    req_id,
                    format!("Standard key generation failed: {e}"),
                    op_tag,
                );
                return;
            }
        };

        // Handle both compressed and uncompressed keygen results
        match dkg_result {
            ThresholdKeyGenResult::Uncompressed(pub_key_set, private_keys) => {
                //Compute all the info required for storing
                let info = match compute_info_standard_keygen(
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
                        update_err_req_in_meta_store(
                            &mut meta_store.write().await,
                            req_id,
                            format!(
                                "Computation of meta data in standard key generation failed: {e}"
                            ),
                            op_tag,
                        );
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
                    .write_threshold_keys_with_dkg_meta_store(
                        req_id,
                        epoch_id,
                        threshold_fhe_keys,
                        pub_key_set,
                        meta_store,
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
                let compact_pk = match existing_compact_pk {
                    Some(old_pk) => old_pk,
                    None => match compressed_keyset.clone().decompress() {
                        Ok(ks) => ks.into_raw_parts().0,
                        Err(e) => {
                            update_err_req_in_meta_store(
                                &mut meta_store.write().await,
                                req_id,
                                format!(
                                    "Failed to decompress freshly generated compressed keyset: {e}"
                                ),
                                op_tag,
                            );
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
                    &compact_pk,
                    &eip712_domain,
                    extra_data,
                ) {
                    Ok(info) => info,
                    Err(e) => {
                        update_err_req_in_meta_store(
                            &mut meta_store.write().await,
                            req_id,
                            format!(
                                "Computation of meta data in standard compressed key generation failed: {e}"
                            ),
                            op_tag,
                        );
                        return;
                    }
                };

                let threshold_fhe_keys = ThresholdFheKeys::new(
                    Arc::new(private_keys),
                    PublicKeyMaterial::new(compressed_keyset.clone()),
                    info,
                );

                // NOTE: when there is an existing compact pk from an older keygen (an older key ID),
                // then this pk is effectively copied to the new key ID.
                if let Err(e) = crypto_storage
                    .write_threshold_keys_with_dkg_meta_store_compressed(
                        req_id,
                        epoch_id,
                        threshold_fhe_keys,
                        &compressed_keyset,
                        &compact_pk,
                        meta_store,
                    )
                    .await
                {
                    tracing::error!(
                        "Failed to write compressed threshold keys for request {req_id}: {e}"
                    );
                    return;
                }
            }
        }
        // Update the backup and handle potential failures by incrementing backup errors in the metrics
        crypto_storage
            .inner
            .update_backup_vault(false, op_tag)
            .await;

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
                .read_guarded_threshold_fhe_keys(existing_keyset_id, epoch_id)
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

    use crate::{
        consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, TEST_PARAM},
        dummy_domain,
        engine::threshold::service::session::SessionMaker,
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
                preproc_buckets: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                dkg_pubinfo_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
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
                preprocessing_store: Arc::new(Mutex::new(Box::new(DummyPreprocessing::new(
                    42, &session,
                )))),
                dkg_param: TEST_PARAM,
            };
            let mut guarded_prep_bucket = kg.preproc_buckets.write().await;
            (*guarded_prep_bucket).insert(prep_id).unwrap();
            (*guarded_prep_bucket)
                .update(prep_id, Ok(dummy_prep))
                .unwrap();
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

        // no need to wait because [get_result] is semi-blocking
        assert_eq!(
            kg.get_result(tonic::Request::new(key_id.into()))
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

        // no need to wait because [get_result] is semi-blocking
        kg.get_result(tonic::Request::new(key_id.into()))
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
        // Try to get the result and see it has been aborted
        let err = kg
            .get_result(Request::new(key_id.into()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted);
    }
}
