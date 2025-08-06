// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Instant};

// === External Crates ===
use kms_grpc::{
    kms::v1::{self, Empty, KeyGenRequest, KeyGenResult, KeySetAddedInfo},
    rpc_types::{protobuf_to_alloy_domain_option, PubDataType},
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        OP_DECOMPRESSION_KEYGEN, OP_INSECURE_DECOMPRESSION_KEYGEN, OP_INSECURE_KEYGEN,
        OP_INSECURE_SNS_COMPRESSION_KEYGEN, OP_KEYGEN, OP_SNS_COMPRESSION_KEYGEN, TAG_PARTY_ID,
    },
};
use tfhe::{
    integer::compression_keys::DecompressionKey,
    shortint::list_compression::NoiseSquashingCompressionKey,
};
use threshold_fhe::{
    algebra::{
        base_ring::Z128,
        galois_rings::{common::ResiduePoly, degree_4::ResiduePolyF4Z128},
    },
    execution::{
        endpoints::keygen::{
            distributed_decompression_keygen_z128,
            distributed_keygen_from_optional_compression_sk_z128,
            distributed_sns_compression_keygen_z128, CompressionPrivateKeySharesEnum, FhePubKeySet,
            GlweSecretKeyShareEnum, OnlineDistributedKeyGen128, PrivateKeySet,
        },
        keyset_config as ddec_keyset_config,
        online::preprocessing::DKGPreprocessing,
        runtime::session::BaseSession,
        tfhe_internals::{
            compression_decompression_key::SnsCompressionPrivateKeyShares, parameters::DKGParams,
        },
    },
    networking::NetworkMode,
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate Imports ===
use crate::{
    cryptography::internal_crypto_types::PrivateSigKey,
    engine::{
        base::{
            compute_info, convert_key_response, retrieve_parameters, BaseKmsStruct,
            KeyGenCallValues, DSEP_PUBDATA_KEY,
        },
        keyset_configuration::InternalKeySetConfig,
        threshold::{
            service::{kms_impl::compute_all_info, ThresholdFheKeys},
            traits::KeyGenerator,
        },
        validation::validate_request_id,
    },
    tonic_handle_potential_err, tonic_some_or_err,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{
        crypto_material::ThresholdCryptoMaterialStorage, read_pk_at_request_id,
        read_versioned_at_request_id, Storage,
    },
};

// === Current Module Imports ===
use super::{session::SessionPreparer, BucketMetaStore};

// === Insecure Feature-Specific Imports ===
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::InsecureKeyGenerator;
#[cfg(feature = "insecure")]
use tfhe::shortint::noise_squashing::NoiseSquashingPrivateKey;
#[cfg(feature = "insecure")]
use threshold_fhe::execution::runtime::session::ParameterHandles;
#[cfg(feature = "insecure")]
use threshold_fhe::execution::tfhe_internals::{
    compression_decompression_key::CompressionPrivateKeyShares,
    glwe_key::GlweSecretKeyShare,
    test_feature::{initialize_key_material, initialize_sns_compression_key_materials},
};

pub struct RealKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen128 + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    // TODO eventually add mode to allow for nlarge as well.
    pub preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    pub dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
    pub session_preparer: SessionPreparer,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    // Map of ongoing key generation tasks
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
    pub(crate) _kg: PhantomData<KG>,
}

#[cfg(feature = "insecure")]
pub struct RealInsecureKeyGenerator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    KG: OnlineDistributedKeyGen128 + 'static,
> {
    pub real_key_generator: RealKeyGenerator<PubS, PrivS, KG>,
}

#[cfg(feature = "insecure")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        KG: OnlineDistributedKeyGen128,
    > RealInsecureKeyGenerator<PubS, PrivS, KG>
{
    pub async fn from_real_keygen(value: &RealKeyGenerator<PubS, PrivS, KG>) -> Self {
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
                _kg: std::marker::PhantomData,
            },
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        KG: OnlineDistributedKeyGen128 + 'static,
    > InsecureKeyGenerator for RealInsecureKeyGenerator<PubS, PrivS, KG>
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
        request: Request<v1::RequestId>,
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
pub enum PreprocHandleWithMode {
    Secure(Arc<Mutex<Box<dyn DKGPreprocessing<ResiduePolyF4Z128>>>>),
    Insecure,
}

#[cfg(feature = "insecure")]
fn convert_to_bit(input: Vec<ResiduePoly<Z128, 4>>) -> anyhow::Result<Vec<u64>> {
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
        PrivS: Storage + Sync + Send + 'static,
        KG: OnlineDistributedKeyGen128 + 'static,
    > RealKeyGenerator<PubS, PrivS, KG>
{
    #[allow(clippy::too_many_arguments)]
    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        internal_keyset_config: InternalKeySetConfig,
        preproc_handle_w_mode: PreprocHandleWithMode,
        req_id: RequestId,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        //Retrieve the right metric tag
        let op_tag = match (
            &preproc_handle_w_mode,
            internal_keyset_config.keyset_config(),
        ) {
            (PreprocHandleWithMode::Secure(_), ddec_keyset_config::KeySetConfig::Standard(_)) => {
                OP_KEYGEN
            }
            (
                PreprocHandleWithMode::Secure(_),
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_DECOMPRESSION_KEYGEN,
            (
                PreprocHandleWithMode::Secure(_),
                ddec_keyset_config::KeySetConfig::AddSnsCompressionKey,
            ) => OP_SNS_COMPRESSION_KEYGEN,
            (PreprocHandleWithMode::Insecure, ddec_keyset_config::KeySetConfig::Standard(_)) => {
                OP_INSECURE_KEYGEN
            }
            (
                PreprocHandleWithMode::Insecure,
                ddec_keyset_config::KeySetConfig::DecompressionOnly,
            ) => OP_INSECURE_DECOMPRESSION_KEYGEN,
            (
                PreprocHandleWithMode::Insecure,
                ddec_keyset_config::KeySetConfig::AddSnsCompressionKey,
            ) => OP_INSECURE_SNS_COMPRESSION_KEYGEN,
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
            let session_id = req_id.derive_session_id()?;
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
            self.ongoing.lock().await.insert(req_id, token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);

        // we need to clone the req ID because async closures are not stable
        let req_id_clone = req_id;
        let keygen_background = async move {
            match internal_keyset_config.keyset_config() {
                ddec_keyset_config::KeySetConfig::Standard(inner_config) => {
                    Self::key_gen_background(
                        &req_id_clone,
                        base_session,
                        meta_store,
                        crypto_storage,
                        preproc_handle_w_mode,
                        sk,
                        dkg_params,
                        inner_config.to_owned(),
                        internal_keyset_config.get_compression_id(),
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
                        internal_keyset_config
                            .keyset_added_info().expect("keyset added info must be set for secure key generation and should have been validated before starting key generation").to_owned(),
                        eip712_domain_copy,
                        permit,
                    )
                    .await
                }
                ddec_keyset_config::KeySetConfig::AddSnsCompressionKey => {
                    Self::sns_compression_key_gen_background(
                        &req_id_clone,
                        base_session,
                        meta_store,
                        crypto_storage,
                        preproc_handle_w_mode,
                        sk,
                        dkg_params,
                        internal_keyset_config
                            .keyset_added_info().expect("keyset added info must be set for secure key generation and should have been validated before starting key generation").to_owned(),
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
            "Keygen starting with request_id={:?}, keyset_config={:?}, keyset_added_info={:?}, insecure={}",
            inner.request_id,
            inner.keyset_config,
            inner.keyset_added_info,
            insecure
        );
        let request_id: RequestId = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (inner key gen)".to_string(),
        )?
        .into();
        validate_request_id(&request_id)?;

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
            )?
            .into();
            let preproc = {
                let mut map = self.preproc_buckets.write().await;
                map.delete(&preproc_id)
            };
            PreprocHandleWithMode::Secure(
                handle_res_mapping(preproc, &preproc_id, "Preprocessing").await?,
            )
        };

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref());

        let internal_keyset_config = tonic_handle_potential_err(
            InternalKeySetConfig::new(inner.keyset_config, inner.keyset_added_info),
            "Invalid keyset config".to_string(),
        )?;

        tonic_handle_potential_err(
            self.launch_dkg(
                dkg_params,
                internal_keyset_config,
                preproc_handle,
                request_id,
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
        request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let request_id: RequestId = request.into_inner().into();
        validate_request_id(&request_id)?;
        let status = {
            let guarded_meta_store = self.dkg_pubinfo_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let res = handle_res_mapping(status, &request_id, "DKG").await?;
        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id.into()),
            key_results: convert_key_response(res),
        }))
    }

    async fn sns_compression_key_gen_closure<P>(
        base_session: &mut BaseSession,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        params: DKGParams,
        base_key_id: &RequestId,
        preprocessing: &mut P,
    ) -> anyhow::Result<(
        SnsCompressionPrivateKeyShares<Z128, 4>,
        NoiseSquashingCompressionKey,
    )>
    where
        P: DKGPreprocessing<ResiduePoly<Z128, 4>> + Send + ?Sized,
    {
        let private_sns_key_share = {
            let threshold_keys = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(base_key_id)
                .await?;
            threshold_keys
                .private_keys
                .glwe_secret_key_share_sns_as_lwe
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing sns secret key share"))?
        };
        let (sns_sk_share, shortint_sns_compression_key) = distributed_sns_compression_keygen_z128(
            base_session,
            preprocessing,
            params,
            &private_sns_key_share,
        )
        .await?;

        tracing::info!(
            "Internal SNS compression key generation completed for base key ID: {}",
            base_key_id
        );
        Ok((sns_sk_share, shortint_sns_compression_key))
    }

    async fn decompression_key_gen_closure<P>(
        base_session: &mut BaseSession,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        preprocessing: &mut P,
    ) -> anyhow::Result<DecompressionKey>
    where
        P: DKGPreprocessing<ResiduePoly<Z128, 4>> + Send + ?Sized,
    {
        let from_key_id = keyset_added_info
            .from_keyset_id_decompression_only
            .ok_or_else(|| {
                anyhow::anyhow!(
                "missing from key ID for the keyset that contains the compression secret key share"
            )
            })?
            .into();
        let to_key_id = keyset_added_info
            .to_keyset_id_decompression_only
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "missing to key ID for the keyset that contains the glwe secret key share"
                )
            })?
            .into();

        let private_compression_share = {
            let threshold_keys = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&from_key_id)
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

    // TODO(2674): remove this code once the SnS compression key upgrade is done
    #[cfg(feature = "insecure")]
    async fn reconstruct_sns_sk(
        base_session: &BaseSession,
        params: DKGParams,
        key_id: &RequestId,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    ) -> anyhow::Result<Option<NoiseSquashingPrivateKey>> {
        use itertools::Itertools;
        use tfhe::core_crypto::prelude::GlweSecretKeyOwned;
        use threshold_fhe::execution::{
            runtime::party::Role,
            sharing::open::{RobustOpen, SecureRobustOpen},
            tfhe_internals::test_feature::INPUT_PARTY_ID,
        };

        crypto_storage.refresh_threshold_fhe_keys(key_id).await?;
        let lwe_shares = {
            let guard = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(key_id)
                .await?;
            guard
                .private_keys
                .glwe_secret_key_share_sns_as_lwe
                .clone()
                .ok_or(anyhow::anyhow!("missing sns secret key share"))?
        };

        let output_party = Role::indexed_from_one(INPUT_PARTY_ID);

        // we need Vec<ResiduePoly> but we're given Vec<Share<ResiduePoly>>
        // so we need to call collect_vec()
        let opt_lwe_secret_key = SecureRobustOpen::default()
            .robust_open_list_to(
                base_session,
                lwe_shares.data.iter().map(|x| x.value()).collect_vec(),
                base_session.threshold() as usize,
                &output_party,
            )
            .await?;

        let sns_params = match params {
            DKGParams::WithoutSnS(_) => anyhow::bail!("missing sns params"),
            DKGParams::WithSnS(dkgparams_sn_s) => dkgparams_sn_s.sns_params,
        };

        let res = match opt_lwe_secret_key {
            Some(raw_sk) => Some(NoiseSquashingPrivateKey::from_raw_parts(
                GlweSecretKeyOwned::from_container(
                    convert_to_bit(raw_sk)?
                        .into_iter()
                        .map(|x| x as u128)
                        .collect(),
                    sns_params.polynomial_size,
                ),
                sns_params,
            )),
            None => {
                // sanity check for party ID
                if base_session.my_role() == output_party {
                    anyhow::bail!("the output party should have received the sns secret key");
                }
                None
            }
        };

        Ok(res)
    }

    #[cfg(feature = "insecure")]
    async fn get_glwe_and_compression_key_shares(
        keyset_added_info: KeySetAddedInfo,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    ) -> anyhow::Result<(
        GlweSecretKeyShare<Z128, 4>,
        CompressionPrivateKeyShares<Z128, 4>,
    )> {
        let compression_req_id = keyset_added_info
            .from_keyset_id_decompression_only
            .ok_or_else(|| {
                anyhow::anyhow!(
                "missing from key ID for the keyset that contains the compression secret key share"
            )
            })?
            .into();
        let glwe_req_id = keyset_added_info
            .to_keyset_id_decompression_only
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "missing to key ID for the keyset that contains the glwe secret key share"
                )
            })?
            .into();

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
        base_session: &BaseSession,
        params: DKGParams,
        glwe_shares: GlweSecretKeyShare<Z128, 4>,
        compression_shares: CompressionPrivateKeyShares<Z128, 4>,
    ) -> anyhow::Result<DecompressionKey> {
        use itertools::Itertools;
        use tfhe::core_crypto::prelude::{GlweSecretKeyOwned, LweSecretKeyOwned};
        use threshold_fhe::execution::{
            runtime::party::Role,
            sharing::open::{RobustOpen, SecureRobustOpen},
            tfhe_internals::test_feature::{
                to_hl_client_key, transfer_decompression_key, INPUT_PARTY_ID,
            },
        };

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

                let (client_key, _, _, _, _, _) = to_hl_client_key(
                    &params,
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
        mut base_session: BaseSession,
        meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
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
        let info = match compute_info(
            &sk,
            &DSEP_PUBDATA_KEY,
            &decompression_key,
            eip712_domain.as_ref(),
        ) {
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

    #[allow(clippy::too_many_arguments)]
    pub async fn sns_compression_key_gen_background(
        req_id: &RequestId,
        mut base_session: BaseSession,
        meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        preproc_handle_w_mode: PreprocHandleWithMode,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        keyset_added_info: KeySetAddedInfo,
        eip712_domain: Option<alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit;
        let start = Instant::now();
        tracing::info!("Starting SNS compression key generation for request {req_id}");

        let base_key_id: RequestId = match keyset_added_info
            .base_keyset_id_for_sns_compression_key
            .ok_or(anyhow::anyhow!(
            "missing key ID that should be used as the base for the sns compression key generation"
        )) {
            Ok(k) => k.into(),
            Err(e) => {
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(req_id, Err(e.to_string()));
                return;
            }
        };

        let dkg_res = match preproc_handle_w_mode {
            PreprocHandleWithMode::Insecure => {
                // sanity check to make sure we're using the insecure feature
                #[cfg(not(feature = "insecure"))]
                {
                    panic!("attempting to call insecure compression keygen when the insecure feature is not set");
                }
                #[cfg(feature = "insecure")]
                {
                    match Self::reconstruct_sns_sk(
                        &base_session,
                        params,
                        &base_key_id,
                        crypto_storage.clone(),
                    )
                    .await
                    {
                        Ok(sns_sk) => {
                            initialize_sns_compression_key_materials(
                                &mut base_session,
                                params,
                                sns_sk,
                            )
                            .await
                        }
                        Err(e) => Err(anyhow::anyhow!("sns sk reconstruction failed with {}", e)),
                    }
                }
            }
            PreprocHandleWithMode::Secure(preproc_handle) => {
                let mut preproc_handle = preproc_handle.lock().await;
                Self::sns_compression_key_gen_closure(
                    &mut base_session,
                    crypto_storage.clone(),
                    params,
                    &base_key_id,
                    preproc_handle.as_mut(),
                )
                .await
            }
        };

        // Make sure the dkg ended nicely
        let (sns_compression_sk_shares, sns_compression_key) = match dkg_res {
            Ok(k) => k,
            Err(e) => {
                // If dkg errored out, update status
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(req_id, Err(e.to_string()));
                return;
            }
        };

        let (threshold_fhe_keys, fhe_pub_key_set) = match Self::add_sns_compression_key_to_keyset(
            &base_key_id,
            crypto_storage.clone(),
            sns_compression_key,
            sns_compression_sk_shares,
        )
        .await
        {
            Ok(res) => res,
            Err(e) => {
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage.update(
                    req_id,
                    Err(format!("Failed to add sns compression key due to {e}")),
                );
                return;
            }
        };

        // Compute all the info required for storing
        let info = match compute_all_info(&sk, &fhe_pub_key_set, eip712_domain.as_ref()) {
            Ok(info) => info,
            Err(_) => {
                let mut guarded_meta_storage = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_storage
                    .update(req_id, Err("Failed to compute key info".to_string()));
                return;
            }
        };

        crypto_storage
            .write_threshold_keys_with_meta_store(
                req_id,
                threshold_fhe_keys,
                fhe_pub_key_set,
                info,
                meta_store,
            )
            .await;

        tracing::info!(
            "Sns compression DKG protocol took {} ms to complete for request {req_id}",
            start.elapsed().as_millis()
        );
    }

    // TODO(2674)
    async fn add_sns_compression_key_to_keyset(
        base_key_id: &RequestId,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        sns_compression_key: NoiseSquashingCompressionKey,
        sns_compression_sk_shares: SnsCompressionPrivateKeyShares<Z128, 4>,
    ) -> anyhow::Result<(ThresholdFheKeys, FhePubKeySet)> {
        // update the private keys
        let threshold_fhe_keys = crypto_storage
            .read_guarded_threshold_fhe_keys_from_cache(base_key_id)
            .await?;

        let mut new_threshold_fhe_keys = (*threshold_fhe_keys).clone();
        new_threshold_fhe_keys
            .private_keys
            .glwe_sns_compression_key_as_lwe = Some(
            sns_compression_sk_shares
                .post_packing_ks_key
                .into_lwe_secret_key(),
        );

        // update the server keys
        let pub_storage = crypto_storage.inner.public_storage.clone();
        let guarded_pub_storage = pub_storage.lock().await;
        let old_server_key: tfhe::ServerKey = read_versioned_at_request_id(
            &(*guarded_pub_storage),
            base_key_id,
            &PubDataType::ServerKey.to_string(),
        )
        .await?;

        let server_key_parts = old_server_key.into_raw_parts();
        let new_server_key = tfhe::ServerKey::from_raw_parts(
            server_key_parts.0,
            server_key_parts.1,
            server_key_parts.2,
            server_key_parts.3,
            server_key_parts.4,
            Some(
                tfhe::integer::ciphertext::NoiseSquashingCompressionKey::from_raw_parts(
                    sns_compression_key,
                ),
            ),
            server_key_parts.6,
        );

        // just read the public key since we need it in the return type, but no need to update it
        let kms_grpc::rpc_types::WrappedPublicKeyOwned::Compact(compact_pk) =
            read_pk_at_request_id(&(*guarded_pub_storage), base_key_id).await?;

        Ok((
            new_threshold_fhe_keys,
            FhePubKeySet {
                public_key: compact_pk,
                server_key: new_server_key,
            },
        ))
    }

    async fn key_gen_from_existing_compression_sk<P>(
        base_session: &mut BaseSession,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        params: DKGParams,
        compression_key_id: RequestId,
        preprocessing: &mut P,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<4>)>
    where
        P: DKGPreprocessing<ResiduePoly<Z128, 4>> + Send + ?Sized,
    {
        let existing_compression_sk = {
            let threshold_keys = crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&compression_key_id)
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
        mut base_session: BaseSession,
        meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        preproc_handle_w_mode: PreprocHandleWithMode,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        keyset_config: ddec_keyset_config::StandardKeySetConfig,
        compression_key_id: Option<RequestId>,
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
                        KG::keygen(&mut base_session, preproc_handle.as_mut(), params).await
                    }
                    (
                        ddec_keyset_config::KeySetCompressionConfig::UseExisting,
                        ddec_keyset_config::ComputeKeyType::Cpu,
                    ) => {
                        Self::key_gen_from_existing_compression_sk(
                            &mut base_session,
                            crypto_storage.clone(),
                            params,
                            compression_key_id.expect("compression key ID must be set for secure key generation and should have been validated before starting key generation"),
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
                _raw_noise_squashing_compression_key,
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
        KG: OnlineDistributedKeyGen128 + 'static,
    > KeyGenerator for RealKeyGenerator<PubS, PrivS, KG>
{
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        self.inner_key_gen(request, false).await
    }

    async fn get_result(
        &self,
        request: tonic::Request<v1::RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        self.inner_get_result(request).await
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::FheParameter;
    use rand::{rngs::OsRng, SeedableRng};
    use threshold_fhe::{
        algebra::{
            base_ring::Z64,
            structure_traits::{ErrorCorrect, Ring},
        },
        execution::{
            online::preprocessing::dummy::DummyPreprocessing, runtime::session::BaseSessionHandles,
        },
    };

    use crate::vault::storage::ram;

    use super::*;

    impl<
            PubS: Storage + Sync + Send + 'static,
            PrivS: Storage + Sync + Send + 'static,
            KG: OnlineDistributedKeyGen128 + 'static,
        > RealKeyGenerator<PubS, PrivS, KG>
    {
        async fn init_test(
            pub_storage: PubS,
            priv_storage: PrivS,
            session_preparer: SessionPreparer,
        ) -> Self {
            let crypto_storage = ThresholdCryptoMaterialStorage::new(
                pub_storage,
                priv_storage,
                None,
                HashMap::new(),
                HashMap::new(),
            );

            let tracker = Arc::new(TaskTracker::new());
            let rate_limiter = RateLimiter::default();
            let ongoing = Arc::new(Mutex::new(HashMap::new()));
            Self {
                base_kms: session_preparer.base_kms.new_instance().await,
                crypto_storage,
                preproc_buckets: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                dkg_pubinfo_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                session_preparer: session_preparer.new_instance().await,
                tracker,
                ongoing,
                rate_limiter,
                _kg: PhantomData,
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

    struct DroppingOnlineDistributedKeyGen128;

    struct FailingOnlineDistributedKeyGen128;

    #[tonic::async_trait]
    impl OnlineDistributedKeyGen128 for DroppingOnlineDistributedKeyGen128 {
        async fn keygen<
            S: BaseSessionHandles,
            P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
            const EXTENSION_DEGREE: usize,
        >(
            _base_session: &mut S,
            _preprocessing: &mut P,
            _params: DKGParams,
        ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
        where
            ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
            ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        {
            let param = crate::consts::TEST_PARAM;
            let mut rng = AesRng::seed_from_u64(42);

            // NOTE: we can't use the generated [_threshold_fhe_keys] because it is not generic over EXTENSION_DEGREE
            let (_threshold_fhe_keys, fhe_key_set) = ThresholdFheKeys::init_dummy(param, &mut rng);
            let private_key_set = PrivateKeySet::<EXTENSION_DEGREE>::init_dummy(param);

            Ok((fhe_key_set, private_key_set))
        }
    }

    #[tonic::async_trait]
    impl OnlineDistributedKeyGen128 for FailingOnlineDistributedKeyGen128 {
        async fn keygen<
            S: BaseSessionHandles,
            P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
            const EXTENSION_DEGREE: usize,
        >(
            _base_session: &mut S,
            _preprocessing: &mut P,
            _params: DKGParams,
        ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
        where
            ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
            ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        {
            Err(anyhow::anyhow!(
                "This keygen implementation is supposed to fail"
            ))
        }
    }

    impl<KG: OnlineDistributedKeyGen128 + 'static>
        RealKeyGenerator<ram::RamStorage, ram::RamStorage, KG>
    {
        pub async fn init_ram_keygen(session_preparer: SessionPreparer) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            Self::init_test(pub_storage, priv_storage, session_preparer).await
        }
    }

    async fn setup_key_generator<KG: OnlineDistributedKeyGen128 + 'static>() -> (
        RequestId,
        RealKeyGenerator<ram::RamStorage, ram::RamStorage, KG>,
    ) {
        let session_preparer = SessionPreparer::new_test_session(false);
        let kg = RealKeyGenerator::<ram::RamStorage, ram::RamStorage, KG>::init_ram_keygen(
            session_preparer.new_instance().await,
        )
        .await;

        let prep_id = RequestId::new_random(&mut OsRng);

        // We need to setup the preprocessor metastore so that keygen will pass
        {
            let session_id = prep_id.derive_session_id().unwrap();
            let dummy_prep = Box::new(DummyPreprocessing::<ResiduePolyF4Z128>::new(
                42,
                &session_preparer
                    .make_base_session(session_id, NetworkMode::Sync)
                    .await
                    .unwrap(),
            ));
            let mut guarded_prep_bucket = kg.preproc_buckets.write().await;
            (*guarded_prep_bucket).insert(&prep_id).unwrap();
            (*guarded_prep_bucket)
                .update(&prep_id, Ok(Arc::new(Mutex::new(dummy_prep))))
                .unwrap();
        }
        (prep_id, kg)
    }

    #[tokio::test]
    async fn invalid_argument() {
        //`InvalidArgument` - If the request ID is not valid or does not match the expected format.
        let (prep_id, kg) = setup_key_generator::<DroppingOnlineDistributedKeyGen128>().await;
        let bad_key_id = kms_grpc::kms::v1::RequestId {
            request_id: "badformat".to_string(),
        };

        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(bad_key_id.clone()),
            params: FheParameter::Test as i32,
            preproc_id: Some(prep_id.into()),
            domain: None,
            keyset_config: None,
            keyset_added_info: None,
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

    #[tokio::test]
    async fn resource_exhausted() {
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        let (prep_id, mut kg) = setup_key_generator::<DroppingOnlineDistributedKeyGen128>().await;
        let key_id = RequestId::new_random(&mut OsRng);

        // Set bucket size to zero, so no operations are allowed
        kg.set_bucket_size(0);

        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: FheParameter::Test as i32,
            preproc_id: Some(prep_id.into()),
            domain: None,
            keyset_config: None,
            keyset_added_info: None,
        });

        assert_eq!(
            kg.key_gen(request).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn not_found() {
        let (_prep_id, kg) = setup_key_generator::<DroppingOnlineDistributedKeyGen128>().await;
        let key_id = RequestId::new_random(&mut OsRng);

        // no need to wait because [get_result] is semi-blocking
        assert_eq!(
            kg.get_result(tonic::Request::new(key_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    #[tokio::test]
    async fn internal() {
        let (prep_id, kg) = setup_key_generator::<FailingOnlineDistributedKeyGen128>().await;
        let key_id = RequestId::new_random(&mut OsRng);

        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: FheParameter::Test as i32,
            preproc_id: Some(prep_id.into()),
            domain: None,
            keyset_config: None,
            keyset_added_info: None,
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
    async fn sunshine() {
        let (prep_id, kg) = setup_key_generator::<DroppingOnlineDistributedKeyGen128>().await;
        let key_id = RequestId::new_random(&mut OsRng);

        let request = tonic::Request::new(KeyGenRequest {
            request_id: Some(key_id.into()),
            params: FheParameter::Test as i32,
            preproc_id: Some(prep_id.into()),
            domain: None,
            keyset_config: None,
            keyset_added_info: None,
        });

        kg.key_gen(request).await.unwrap();

        // no need to wait because [get_result] is semi-blocking
        kg.get_result(tonic::Request::new(key_id.into()))
            .await
            .unwrap();
    }
}
