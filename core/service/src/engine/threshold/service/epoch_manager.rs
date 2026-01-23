use alloy_dyn_abi::Eip712Domain;
use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{
        DestroyMpcEpochRequest, Empty, EpochResultResponse, KeyDigest, NewMpcEpochRequest,
        PreviousEpochInfo, RequestId,
    },
    rpc_types::{optional_protobuf_to_alloy_domain, PrivDataType, PubDataType},
    utils::tonic_result::BoxedStatus,
    ContextId, EpochId,
};
use observability::metrics_names::OP_RESHARING;
use std::{collections::HashMap, future::Future, marker::PhantomData, sync::Arc};
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        endpoints::reshare_sk::{ResharePreprocRequired, ReshareSecretKeys},
        online::preprocessing::BasePreprocessing,
        runtime::{
            party::TwoSetsRole,
            sessions::{
                base_session::{BaseSession, TwoSetsBaseSession},
                session_parameters::GenericParameterHandles,
                small_session::SmallSession,
            },
        },
        small_execution::{
            offline::{Preprocessing, SecureSmallPreprocessing},
            prss::{PRSSInit, PRSSSetup},
        },
        tfhe_internals::{
            parameters::DKGParams, private_keysets::PrivateKeySet, public_keysets::FhePubKeySet,
        },
    },
    networking::NetworkMode,
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};

use crate::{
    consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT},
    cryptography::signatures::PrivateSigKey,
    engine::{
        base::{
            compute_info_standard_keygen, derive_request_id, retrieve_parameters, KeyGenMetadata,
            DSEP_PUBDATA_KEY,
        },
        threshold::service::{
            reshare_utils::get_verified_public_materials,
            session::{ImmutableSessionMaker, PRSSSetupCombined, SessionMaker},
            ThresholdFheKeys,
        },
        traits::EpochManager,
        utils::MetricedError,
        validation::{
            parse_optional_proto_context_id, parse_optional_proto_epoch_id,
            parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
        },
    },
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{
        crypto_material::ThresholdCryptoMaterialStorage,
        delete_at_request_id, read_versioned_at_request_id,
        s3::{ReadOnlyS3Storage, RealReadOnlyS3StorageGetter},
        store_versioned_at_request_id, Storage, StorageExt,
    },
};

// All sessions are dervied from the epoch ID,
// we thus define a set of counters to make sure
// the derived sessions are unique.
const PRSS_SESSION_COUNTER: u64 = 0;
const RESHARE_Z64_SESSION_COUNTER: u64 = 1;
const RESHARE_Z128_SESSION_COUNTER: u64 = 2;
const RESHARE_SESSION_ONLINE_SET_2_COUNTER: u64 = 3;
const RESHARE_COMMON_SESSION_ONLINE_COUNTER: u64 = 4;

#[derive(Debug)]
struct VerifiedPreviousEpochInfo {
    /// The KMS context of the parties that will reshare
    /// the shares of the private key
    pub context_id: ContextId,
    /// epochId we reshare the shares from.
    pub epoch_id: EpochId,
    /// keyID of the key to be reshared.
    pub key_id: kms_grpc::RequestId,
    /// Preprocessing ID that was used to generate the key initially
    /// required for the EIP struct
    pub preproc_id: kms_grpc::RequestId,
    /// Parameters of the key to be reshard
    pub key_parameters: DKGParams,
    /// Digest of the key to be reshared
    /// Mapping of key type string to digest
    /// e.g., ("ServerKey", vec!\[1,2,3,4\]), ("PublicKey", vec!\[2,3,4,5\]).
    /// The domain separator DSEP_PUBDATA_KEY="PDAT_KEY" is used when hashing the keys.
    /// If there are no key_digests, the digest verification is skipped.
    pub key_digests: HashMap<PubDataType, Vec<u8>>,
    pub eip712_domain: Eip712Domain,
}

/// Parses the [`PreviousEpochInfo`] proto message and verifies its contents.
fn verify_epoch_info(
    epoch_id_as_request_id: &kms_grpc::RequestId,
    previous_epoch: PreviousEpochInfo,
) -> Result<VerifiedPreviousEpochInfo, MetricedError> {
    let make_metriced_err = |e: BoxedStatus| {
        MetricedError::new(
            OP_RESHARING,
            Some(*epoch_id_as_request_id),
            e,
            tonic::Code::InvalidArgument,
        )
    };
    let context_id =
        parse_optional_proto_context_id(&previous_epoch.context_id).map_err(make_metriced_err)?;

    let epoch_id: EpochId =
        parse_optional_proto_epoch_id(&previous_epoch.epoch_id).map_err(make_metriced_err)?;

    let key_id = parse_optional_proto_request_id(
        &previous_epoch.key_id,
        RequestIdParsingErr::Other("Key ID in PreviousEpochInfo".to_string()),
    )
    .map_err(make_metriced_err)?;

    // Using the old PreprocId of the key request for now.
    let preproc_id = parse_optional_proto_request_id(
        &previous_epoch.preproc_id,
        RequestIdParsingErr::Other("Preproc ID in PreviousEpochInfo".to_string()),
    )
    .map_err(make_metriced_err)?;

    let eip712_domain =
        optional_protobuf_to_alloy_domain(previous_epoch.domain.as_ref()).map_err(|e| {
            MetricedError::new(
                OP_RESHARING,
                Some(*epoch_id_as_request_id),
                e,
                tonic::Code::InvalidArgument,
            )
        })?;

    let key_parameters =
        retrieve_parameters(Some(previous_epoch.key_parameters)).map_err(make_metriced_err)?;

    // collect key digests
    let key_digests: HashMap<PubDataType, Vec<u8>> = previous_epoch
        .key_digests
        .into_iter()
        .map(|kd| {
            let key_type = kd.key_type.parse::<PubDataType>()?; // we do not use safe serialize because these are not known by the gateway
            Ok((key_type, kd.digest))
        })
        .collect::<anyhow::Result<HashMap<PubDataType, Vec<u8>>>>()
        .map_err(|e| {
            MetricedError::new(
                OP_RESHARING,
                Some(*epoch_id_as_request_id),
                e,
                tonic::Code::InvalidArgument,
            )
        })?;

    Ok(VerifiedPreviousEpochInfo {
        context_id,
        epoch_id,
        key_id,
        preproc_id,
        key_parameters,
        key_digests,
        eip712_domain,
    })
}

#[derive(Clone)]
pub enum EpochOutput {
    PRSSInitOnly,
    Reshare(KeyGenMetadata),
}

impl From<KeyGenMetadata> for EpochOutput {
    fn from(meta: KeyGenMetadata) -> Self {
        EpochOutput::Reshare(meta)
    }
}
// The Epoch Manager takes over the role of the Initiator and Resharer
// For now the struct is thus a union of the RealInitiator and RealResharer structs
pub struct RealThresholdEpochManager<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    Init: PRSSInit<ResiduePolyF4Z64> + PRSSInit<ResiduePolyF4Z128>,
    Reshare: ReshareSecretKeys,
> {
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub(crate) session_maker: SessionMaker,
    pub base_kms: crate::engine::base::BaseKmsStruct,
    pub reshare_pubinfo_meta_store: Arc<RwLock<MetaStore<EpochOutput>>>,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub(crate) _init: PhantomData<Init>,
    pub(crate) _reshare: PhantomData<Reshare>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default
            + 'static,
        Reshare: ReshareSecretKeys + Default + 'static,
    > RealThresholdEpochManager<PubS, PrivS, Init, Reshare>
{
    /// This will load all PRSS setups from storage into session maker.
    ///
    /// It should be called after [init_legacy_prss_from_storage] so that
    /// if there is a new PRSS under the same epoch ID as a legacy one,
    /// then the legacy one is overwritten.
    pub async fn init_all_prss_from_storage(&self) -> anyhow::Result<()> {
        let all_prss = self.crypto_storage.inner.read_all_prss_info().await?;

        for (epoch_id, prss) in all_prss {
            self.session_maker.add_epoch(epoch_id.into(), prss).await;
            tracing::info!(
                "Loaded PRSS Setup from storage for request ID {}.",
                epoch_id
            );
        }
        Ok(())
    }

    /// This assumes the default context exists.
    /// It will overwrite the PRSS in session maker if it already exists,
    /// so make sure this is called before the normal (non-legacy) initialization.
    #[expect(deprecated)]
    pub async fn init_legacy_prss_from_storage(&self) -> anyhow::Result<()> {
        // TODO(zama-ai/kms-internal#2530) set the correct context ID here.
        let epoch_id = *DEFAULT_EPOCH_ID;
        let context_id = *DEFAULT_MPC_CONTEXT;
        let threshold = self.session_maker.threshold(&context_id).await?;
        let num_parties = self.session_maker.num_parties(&context_id).await?;

        let prss_from_storage = {
            let guarded_private_storage = self.crypto_storage.inner.private_storage.lock().await;
            let prss_128 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z128>>(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z128_ID_{}_{}_{}",
                    epoch_id, num_parties, threshold,
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z128 from file with error: {e}");
            });
            let prss_64 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z64>>(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z64_ID_{}_{}_{}",
                    epoch_id, num_parties, threshold,
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z64 from file with error: {e}");
            });

            (prss_128, prss_64)
        };

        match prss_from_storage {
            (Ok(prss_128), Ok(prss_64)) => {
                self.session_maker
                    .add_epoch(
                        epoch_id,
                        PRSSSetupCombined {
                            prss_setup_z128: prss_128,
                            prss_setup_z64: prss_64,
                            num_parties: num_parties as u8,
                            threshold,
                        },
                    )
                    .await;
            }
            (Err(e), Ok(_)) => return Err(e),
            (Ok(_), Err(e)) => return Err(e),
            (Err(_e), Err(e)) => return Err(e),
        }

        tracing::info!(
            "Loaded PRSS Setup from storage for request ID {}.",
            epoch_id
        );

        Ok(())
    }

    pub async fn init_prss(
        &self,
        context_id: &ContextId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()> {
        Self::internal_init_prss(
            self.session_maker.clone(),
            &self.crypto_storage,
            context_id,
            epoch_id,
        )
        .await
    }

    // NOTE: this function will overwrite the existing PRSS state
    // Also, this function doesn't store success in meta store
    // which is OK because it's blocking (only the reshare if any spawns its own task)
    async fn internal_init_prss(
        session_maker: SessionMaker,
        crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
        context_id: &ContextId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()> {
        // TODO(zama-ai/kms-internal/issues/2721),
        // we never try to store the PRSS in meta_store, so the ID is not guaranteed to be unique

        let own_identity = session_maker
            .my_identity(context_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("own identity not found in context {}", context_id))?;

        // Note: derive session ID from epoch ID with fixed counter for PRSS
        // this is because we might also use the epoch id to derive sessions for the reshare
        let session_id = epoch_id.derive_session_id_with_counter(PRSS_SESSION_COUNTER)?;

        // PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = session_maker
            .make_base_session(session_id, *context_id, NetworkMode::Sync)
            .await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        tracing::info!(
            "Session has {} parties with threshold {}",
            base_session.parameters.num_parties(),
            base_session.parameters.threshold()
        );
        tracing::info!("Role assignments: {:?}", base_session.parameters.roles());

        // It seems we cannot do something like
        // `Init::default().init(&mut base_session).await?;`
        // as the type inference gets confused even when using the correct return type.
        let prss_setup_obj_z128: PRSSSetup<ResiduePolyF4Z128> =
            PRSSInit::<ResiduePolyF4Z128>::init(&Init::default(), &mut base_session).await?;
        let prss_setup_obj_z64: PRSSSetup<ResiduePolyF4Z64> =
            PRSSInit::<ResiduePolyF4Z64>::init(&Init::default(), &mut base_session).await?;

        let prss = PRSSSetupCombined {
            prss_setup_z128: prss_setup_obj_z128,
            prss_setup_z64: prss_setup_obj_z64,
            num_parties: base_session.parameters.num_parties() as u8,
            threshold: base_session.parameters.threshold(),
        };

        // serialize and write PRSS Setup to storage into private storage
        let private_storage = Arc::clone(&crypto_storage.inner.private_storage);
        let mut priv_storage = private_storage.lock().await;

        // if PRSS already exists, overwrite it
        if priv_storage
            .data_exists(
                &(*epoch_id).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?
        {
            tracing::warn!(
                "PRSS Setup epoch ID {} already exists, overwriting.",
                epoch_id
            );
            delete_at_request_id(
                &mut (*priv_storage),
                &(*epoch_id).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?;
        }

        store_versioned_at_request_id(
            &mut (*priv_storage),
            &(*epoch_id).into(),
            &prss,
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;

        session_maker.add_epoch(*epoch_id, prss).await;

        tracing::info!(
            "PRSS on epoch ID {} completed successfully for identity {}.",
            epoch_id,
            own_identity
        );
        Ok(())
    }

    /// Read the old keys, need ownership because
    /// reshare zeroize it (although, probably a bit useless cause we don't want to delete it just now)
    async fn fetch_existing_keys(
        &self,
        epoch_id_as_request_id: kms_grpc::RequestId,
        verified_previous_epoch: &VerifiedPreviousEpochInfo,
    ) -> Result<(PrivateKeySet<4>, KeyGenMetadata), MetricedError> {
        let keys = self
            .crypto_storage
            .read_guarded_threshold_fhe_keys(
                &verified_previous_epoch.key_id,
                &verified_previous_epoch.epoch_id,
            )
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_RESHARING,
                    Some(epoch_id_as_request_id),
                    e,
                    tonic::Code::InvalidArgument,
                )
            })?;
        let private_keyset = keys.private_keys.as_ref().clone();
        let meta_data = keys.meta_data.clone();

        Ok((private_keyset, meta_data))
    }

    async fn reshare_as_set_1(
        &self,
        mut two_sets_session: TwoSetsBaseSession,
        new_epoch_id: EpochId,
        verified_previous_epoch: VerifiedPreviousEpochInfo,
    ) -> Result<impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>, Status>
    {
        let epoch_id_as_request_id = new_epoch_id.into();

        let (mut private_keys, key_metadata) = self
            .fetch_existing_keys(epoch_id_as_request_id, &verified_previous_epoch)
            .await?;

        let meta_store = Arc::clone(&self.reshare_pubinfo_meta_store);

        let task = async move {
            Reshare::reshare_sk_two_sets_as_s1(
                &mut two_sets_session,
                &mut private_keys,
                verified_previous_epoch.key_parameters,
            )
            .await?;

            // We update the meta store with the same metadata as in the epoch we reshare from
            meta_store.write().await.update(
                &epoch_id_as_request_id,
                Ok(EpochOutput::Reshare(key_metadata)),
            )?;

            Ok(())
        };

        Ok(task)
    }

    /// Creates the sessions needed by parties in set 2 for resharing
    async fn create_set2_sessions(
        session_maker_immutable: ImmutableSessionMaker,
        new_epoch_id: EpochId,
        new_context_id: ContextId,
        epoch_id_as_request_id: kms_grpc::RequestId,
    ) -> Result<
        (
            SmallSession<ResiduePolyF4Z128>,
            SmallSession<ResiduePolyF4Z64>,
            BaseSession,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let make_err = |e| {
            MetricedError::handle_unreturnable_error(OP_RESHARING, Some(epoch_id_as_request_id), e)
        };

        let session_z128 =
            async { new_epoch_id.derive_session_id_with_counter(RESHARE_Z128_SESSION_COUNTER) }
                .and_then(|id| {
                    session_maker_immutable.make_small_sync_session_z128(
                        id,
                        new_context_id,
                        new_epoch_id,
                    )
                })
                .await
                .map_err(make_err)?;

        let session_z64 =
            async { new_epoch_id.derive_session_id_with_counter(RESHARE_Z64_SESSION_COUNTER) }
                .and_then(|id| {
                    session_maker_immutable.make_small_sync_session_z64(
                        id,
                        new_context_id,
                        new_epoch_id,
                    )
                })
                .await
                .map_err(make_err)?;

        let session_online = async {
            new_epoch_id.derive_session_id_with_counter(RESHARE_SESSION_ONLINE_SET_2_COUNTER)
        }
        .and_then(|id| {
            session_maker_immutable.make_base_session(id, new_context_id, NetworkMode::Sync)
        })
        .await
        .map_err(make_err)?;

        Ok((session_z128, session_z64, session_online))
    }

    async fn compute_s2_preproc(
        epoch_id_as_request_id: &kms_grpc::RequestId,
        session_z64: &mut SmallSession<ResiduePolyF4Z64>,
        session_z128: &mut SmallSession<ResiduePolyF4Z128>,
        num_needed_preproc: &ResharePreprocRequired,
    ) -> Result<
        (
            impl BasePreprocessing<ResiduePolyF4Z64>,
            impl BasePreprocessing<ResiduePolyF4Z128>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok((
            SecureSmallPreprocessing::default()
                .execute(session_z64, num_needed_preproc.batch_params_64)
                .await
                .map_err(|e| {
                    MetricedError::handle_unreturnable_error(
                        OP_RESHARING,
                        Some(*epoch_id_as_request_id),
                        e,
                    )
                })?,
            SecureSmallPreprocessing::default()
                .execute(session_z128, num_needed_preproc.batch_params_128)
                .await
                .map_err(|e| {
                    MetricedError::handle_unreturnable_error(
                        OP_RESHARING,
                        Some(*epoch_id_as_request_id),
                        e,
                    )
                })?,
        ))
    }

    /// Stores the reshared keys and updates the meta store
    async fn store_reshared_keys(
        crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
        meta_store: Arc<RwLock<MetaStore<EpochOutput>>>,
        sk: &PrivateSigKey,
        new_epoch_id: EpochId,
        verified_previous_epoch: &VerifiedPreviousEpochInfo,
        fhe_pubkeys: &FhePubKeySet,
        new_private_keyset: PrivateKeySet<4>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let epoch_id_as_request_id = new_epoch_id.into();

        let info = match compute_info_standard_keygen(
            sk,
            &DSEP_PUBDATA_KEY,
            &verified_previous_epoch.preproc_id,
            &verified_previous_epoch.key_id,
            fhe_pubkeys,
            &verified_previous_epoch.eip712_domain,
        ) {
            Ok(info) => info,
            Err(e) => {
                let mut guarded_meta_storage = meta_store.write().await;
                let _ = guarded_meta_storage.update(
                    &epoch_id_as_request_id,
                    Err("Failed to compute key info".to_string()),
                );
                return Err(MetricedError::handle_unreturnable_error(
                    OP_RESHARING,
                    Some(epoch_id_as_request_id),
                    e,
                ));
            }
        };

        let (integer_server_key, _, _, decompression_key, sns_key, _, _, _) =
            fhe_pubkeys.server_key.clone().into_raw_parts();

        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: Arc::new(new_private_keyset),
            integer_server_key: Arc::new(integer_server_key),
            sns_key: sns_key.map(Arc::new),
            decompression_key: decompression_key.map(Arc::new),
            meta_data: info.clone(),
        };

        crypto_storage
            .write_threshold_keys_with_reshare_meta_store(
                &verified_previous_epoch.key_id,
                &new_epoch_id,
                threshold_fhe_keys,
                fhe_pubkeys.clone(),
                info,
                meta_store,
            )
            .await;
        Ok(())
    }

    async fn reshare_as_set_2(
        &self,
        two_sets_session: TwoSetsBaseSession,
        new_epoch_id: EpochId,
        new_context_id: ContextId,
        verified_previous_epoch: VerifiedPreviousEpochInfo,
    ) -> Result<impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>, Status>
    {
        let epoch_id_as_request_id = new_epoch_id.into();

        let fhe_pubkeys = get_verified_public_materials::<_, _, _, ReadOnlyS3Storage>(
            &self.crypto_storage,
            &epoch_id_as_request_id,
            &verified_previous_epoch.key_id,
            &verified_previous_epoch.context_id,
            &verified_previous_epoch.key_digests,
            &RealReadOnlyS3StorageGetter {},
        )
        .await?;

        let immutable_session_maker = self.session_maker.make_immutable();

        let sk = self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(
                OP_RESHARING,
                Some(epoch_id_as_request_id),
                e,
                tonic::Code::FailedPrecondition,
            )
        })?;

        let meta_store = Arc::clone(&self.reshare_pubinfo_meta_store);
        let crypto_storage = self.crypto_storage.clone();

        let task = async move {
            let (mut session_z128, mut session_z64, session_online) = Self::create_set2_sessions(
                immutable_session_maker,
                new_epoch_id,
                new_context_id,
                epoch_id_as_request_id,
            )
            .await?;

            let num_parties_set_1 = two_sets_session
                .roles()
                .iter()
                .filter(|p| p.is_set1())
                .count();

            let num_needed_preproc = ResharePreprocRequired::new(
                num_parties_set_1,
                verified_previous_epoch.key_parameters,
            );

            let (mut correlated_randomness_z64, mut correlated_randomness_z128) =
                Self::compute_s2_preproc(
                    &epoch_id_as_request_id,
                    &mut session_z64,
                    &mut session_z128,
                    &num_needed_preproc,
                )
                .await?;

            let new_private_keyset = Reshare::reshare_sk_two_sets_as_s2(
                &mut (two_sets_session, session_online),
                &mut correlated_randomness_z128,
                &mut correlated_randomness_z64,
                verified_previous_epoch.key_parameters,
            )
            .await
            .map_err(|e| {
                MetricedError::handle_unreturnable_error(
                    OP_RESHARING,
                    Some(epoch_id_as_request_id),
                    e,
                )
            })?;

            Self::store_reshared_keys(
                &crypto_storage,
                meta_store,
                &sk,
                new_epoch_id,
                &verified_previous_epoch,
                &fhe_pubkeys,
                new_private_keyset,
            )
            .await
        };

        //self.tracker.spawn(async move {
        //    match task(permit).await {
        //        Ok(_) => tracing::info!(
        //            "Resharing completed successfully for new epoch ID {:?} and key ID {:?}",
        //            new_epoch_id,
        //            key_id
        //        ),
        //        Err(e) => tracing::error!(
        //            "Resharing failed for new epoch ID {:?} and key ID {:?}: {}",
        //            new_epoch_id,
        //            key_id,
        //            e
        //        ),
        //    }
        //});

        Ok(task)
    }

    async fn reshare_as_both_sets(
        &self,
        two_sets_session: TwoSetsBaseSession,
        new_epoch_id: EpochId,
        new_context_id: ContextId,
        verified_previous_epoch: VerifiedPreviousEpochInfo,
    ) -> Result<impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>, Status>
    {
        let epoch_id_as_request_id = new_epoch_id.into();

        let fhe_pubkeys = get_verified_public_materials::<_, _, _, ReadOnlyS3Storage>(
            &self.crypto_storage,
            &epoch_id_as_request_id,
            &verified_previous_epoch.key_id,
            &verified_previous_epoch.context_id,
            &verified_previous_epoch.key_digests,
            &RealReadOnlyS3StorageGetter {},
        )
        .await?;

        let (mut mutable_keys, _) = self
            .fetch_existing_keys(epoch_id_as_request_id, &verified_previous_epoch)
            .await?;

        let immutable_session_maker = self.session_maker.make_immutable();
        let sk = self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(
                OP_RESHARING,
                Some(epoch_id_as_request_id),
                e,
                tonic::Code::FailedPrecondition,
            )
        })?;

        let meta_store = Arc::clone(&self.reshare_pubinfo_meta_store);
        let crypto_storage = self.crypto_storage.clone();

        let task = async move {
            let (mut session_z128, mut session_z64, session_online) = Self::create_set2_sessions(
                immutable_session_maker,
                new_epoch_id,
                new_context_id,
                epoch_id_as_request_id,
            )
            .await?;

            let num_parties_set_1 = two_sets_session
                .roles()
                .iter()
                .filter(|p| p.is_set1())
                .count();
            let num_needed_preproc = ResharePreprocRequired::new(
                num_parties_set_1,
                verified_previous_epoch.key_parameters,
            );

            let (mut correlated_randomness_z64, mut correlated_randomness_z128) =
                Self::compute_s2_preproc(
                    &epoch_id_as_request_id,
                    &mut session_z64,
                    &mut session_z128,
                    &num_needed_preproc,
                )
                .await?;

            let new_private_keyset = Reshare::reshare_sk_two_sets_as_both_sets(
                &mut (two_sets_session, session_online),
                &mut correlated_randomness_z128,
                &mut correlated_randomness_z64,
                &mut mutable_keys,
                verified_previous_epoch.key_parameters,
            )
            .await
            .map_err(|e| {
                MetricedError::handle_unreturnable_error(
                    OP_RESHARING,
                    Some(epoch_id_as_request_id),
                    e,
                )
            })?;

            Self::store_reshared_keys(
                &crypto_storage,
                meta_store,
                &sk,
                new_epoch_id,
                &verified_previous_epoch,
                &fhe_pubkeys,
                new_private_keyset,
            )
            .await
        };

        Ok(task)
    }

    async fn initiate_resharing(
        &self,
        new_context_id: &ContextId,
        new_epoch_id: &EpochId,
        previous_epoch: PreviousEpochInfo,
    ) -> Result<BoxFuture<'static, Result<(), Box<dyn std::error::Error + Send + Sync>>>, Status>
    {
        tracing::info!(
            "Received initiate resharing request from context {:?} to context {:?} for Key ID {:?} for epoch ID {:?}",
            previous_epoch.context_id,
            new_context_id,
            previous_epoch.key_id,
            new_epoch_id
        );

        let verified_previous_epoch = verify_epoch_info(&(*new_epoch_id).into(), previous_epoch)?;

        let epoch_id_as_request_id = (*new_epoch_id).into();

        let session_maker_immutable = self.session_maker.make_immutable();

        let two_sets_session = async {
            new_epoch_id.derive_session_id_with_counter(RESHARE_COMMON_SESSION_ONLINE_COUNTER)
        }
        .and_then(|id| {
            session_maker_immutable.make_two_sets_session(
                id,
                verified_previous_epoch.context_id,
                *new_context_id,
                NetworkMode::Async,
            )
        })
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_RESHARING,
                Some(epoch_id_as_request_id),
                e,
                tonic::Code::InvalidArgument,
            )
        })?;

        Ok(match two_sets_session.my_role() {
            TwoSetsRole::Set1(_) => self
                .reshare_as_set_1(two_sets_session, *new_epoch_id, verified_previous_epoch)
                .await?
                .boxed(),
            TwoSetsRole::Set2(_) => self
                .reshare_as_set_2(
                    two_sets_session,
                    *new_epoch_id,
                    *new_context_id,
                    verified_previous_epoch,
                )
                .await?
                .boxed(),
            TwoSetsRole::Both(_) => self
                .reshare_as_both_sets(
                    two_sets_session,
                    *new_epoch_id,
                    *new_context_id,
                    verified_previous_epoch,
                )
                .await?
                .boxed(),
        })
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default
            + 'static,
        Reshare: ReshareSecretKeys + Default + 'static,
    > EpochManager for RealThresholdEpochManager<PubS, PrivS, Init, Reshare>
{
    async fn new_mpc_epoch(
        &self,
        request: Request<NewMpcEpochRequest>,
    ) -> Result<Response<Empty>, Status> {
        let permit = self.rate_limiter.start_new_epoch().await?;

        let inner = request.into_inner();
        // the request ID of the init request is the epoch ID for PRSS and shares
        let epoch_id: EpochId =
            parse_optional_proto_request_id(&inner.epoch_id, RequestIdParsingErr::Init)?.into();

        if !epoch_id.is_valid() {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Epoch ID is not valid".to_string(),
            ));
        }

        let context_id: ContextId = match inner.context_id {
            Some(ctx_id) => parse_proto_request_id(&ctx_id, RequestIdParsingErr::Init)?.into(),
            None => *DEFAULT_MPC_CONTEXT,
        };

        if !context_id.is_valid() {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "MPC Context ID is not valid".to_string(),
            ));
        }

        if self.session_maker.epoch_exists(&epoch_id).await {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                "PRSS state already exists".to_string(),
            ));
        }

        let resharing_task = match inner.previous_epoch {
            Some(prev_epoch) => Some(
                self.initiate_resharing(&context_id, &epoch_id, prev_epoch)
                    .await?,
            ),
            None => None,
        };

        // Only run PRSS initialization if this party is involved in the new MPC context
        // note we also error out if the context does not exist
        let do_prss = self
            .session_maker
            .get_my_role_in_context(&context_id)
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("MPC context ID {context_id} does not exist: {e}"),
                )
            })?
            .is_some();

        let meta_store = Arc::clone(&self.reshare_pubinfo_meta_store);
        // Update status

        {
            let mut guarded_meta_store = self.reshare_pubinfo_meta_store.write().await;
            guarded_meta_store.insert(&epoch_id.into()).map_err(|e| {
                MetricedError::new(
                    OP_RESHARING,
                    Some(epoch_id.into()),
                    e,
                    // Note that there are other reason why insert can fail, but
                    // AlreadyExists seems the most appropriate
                    tonic::Code::AlreadyExists,
                )
            })?;
        }
        let session_maker = self.session_maker.clone();
        let crypto_storage = self.crypto_storage.clone();
        self.tracker.spawn(async move {
            let _permit = permit;
            let crypto_storage = crypto_storage;
            let context_id = context_id;
            let epoch_id = epoch_id;
            let meta_store = meta_store;
            if do_prss
                && Self::internal_init_prss(session_maker, &crypto_storage, &context_id, &epoch_id)
                    .await
                    .is_err()
            {
                let mut guarded_meta_store = meta_store.write().await;
                let _ = guarded_meta_store.update(
                    &epoch_id.into(),
                    Err("PRSS initialization failed".to_string()),
                );
                return;
            }
            if let Some(resharing_task) = resharing_task {
                if resharing_task.await.is_err() {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store
                        .update(&epoch_id.into(), Err("Resharing failed".to_string()));
                }
            } else {
                // Can't do much if inserts fails here
                let _ = meta_store
                    .write()
                    .await
                    .update(&epoch_id.into(), Ok(EpochOutput::PRSSInitOnly));
            }
        });

        Ok(Response::new(Empty {}))
    }

    async fn destroy_mpc_epoch(
        &self,
        _request: Request<DestroyMpcEpochRequest>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn get_epoch_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<EpochResultResponse>, Status> {
        let request_id =
            parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::EpochResponse)?;

        let status = {
            let guarded_meta_store = self.reshare_pubinfo_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };

        let res = handle_res_mapping(status, &request_id, "Epoch").await?;

        match res {
            EpochOutput::PRSSInitOnly => {
                tracing::info!(
                    "New Epoch with only PRSS initialization for request ID {:?}.",
                    request_id
                );
                Ok(Response::new(EpochResultResponse {
                    epoch_id: Some(request_id.into()),
                    key_id: None,
                    preprocessing_id: None,
                    key_digests: vec![],
                    external_signature: vec![],
                }))
            }
            EpochOutput::Reshare(res) => match res {
                KeyGenMetadata::Current(res) => {
                    tracing::info!(
                        "Retrieved reshare result for request ID {:?}. Key id is {}",
                        request_id,
                        res.key_id
                    );

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

                    Ok(Response::new(EpochResultResponse {
                        epoch_id: Some(request_id.into()),
                        key_id: Some(res.key_id.into()),
                        preprocessing_id: Some(res.preprocessing_id.into()),
                        key_digests,
                        external_signature: res.external_signature,
                    }))
                }
                KeyGenMetadata::LegacyV0(_res) => {
                    tracing::error!("Resharing should not return legacy metadata");
                    Err(Status::internal(
                        "Resharing returned legacy metadata, which should not happen",
                    ))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        client::test_tools::{self},
        consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL},
        cryptography::signatures::gen_sig_keys,
        engine::base::BaseKmsStruct,
        util::{key_setup::test_tools::purge, rate_limiter::RateLimiterConfig},
        vault::storage::{
            file::FileStorage,
            ram::{self, RamStorage},
            StorageType,
        },
    };
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{FheParameter, NewMpcEpochRequest},
        rpc_types::{alloy_to_protobuf_domain, KMSType},
    };
    use rand::SeedableRng;
    use threshold_fhe::{
        execution::endpoints::reshare_sk::SecureReshareSecretKeys,
        malicious_execution::small_execution::malicious_prss::{EmptyPrss, FailingPrss},
    };

    impl<
            Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
                + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>,
            Reshare: ReshareSecretKeys,
        > RealThresholdEpochManager<ram::RamStorage, ram::RamStorage, Init, Reshare>
    {
        fn init_test(base_kms: BaseKmsStruct, session_maker: SessionMaker) -> Self {
            Self {
                session_maker,
                _init: PhantomData,
                base_kms,
                crypto_storage: ThresholdCryptoMaterialStorage::new(
                    RamStorage::new(),
                    RamStorage::new(),
                    None,
                    HashMap::new(),
                    HashMap::new(),
                ),
                reshare_pubinfo_meta_store: Arc::new(RwLock::new(MetaStore::new(10, 10))),
                tracker: Arc::new(TaskTracker::new()),
                rate_limiter: RateLimiter::new(RateLimiterConfig::default()),
                _reshare: PhantomData,
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

    #[tokio::test]
    #[serial_test::serial]
    #[tracing_test::traced_test]
    async fn prss_from_storage_test() {
        // We're starting two sets of servers in this test, both sets of servers will load all the keys
        // but it seems that the when shutting down the first set of servers, the keys are not immediately removed from memory
        // and this leads to OOM. So we reduce the amount of parties to 4 for this test.
        const PRSS_AMOUNT_PARTIES: usize = 4;
        const PRSS_THRESHOLD: usize = 1;

        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        let mut vaults = Vec::new();
        let mut vaults2 = Vec::new();
        let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[..PRSS_AMOUNT_PARTIES];
        let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[..PRSS_AMOUNT_PARTIES];

        for (priv_prefix, pub_prefix) in priv_storage_prefixes
            .iter()
            .zip(pub_storage_prefixes.iter())
        {
            let cur_pub = FileStorage::new(None, StorageType::PUB, pub_prefix.as_deref()).unwrap();
            pub_storage.push(cur_pub);
            let cur_priv =
                FileStorage::new(None, StorageType::PRIV, priv_prefix.as_deref()).unwrap();

            // make sure the store does not contain any PRSS info (currently stored under ID 1)
            let req_id = derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{PRSS_AMOUNT_PARTIES}_{PRSS_THRESHOLD}",
                *DEFAULT_EPOCH_ID
            ))
            .unwrap();
            purge(
                None,
                None,
                &req_id,
                pub_storage_prefixes,
                priv_storage_prefixes,
            )
            .await;

            let req_id = derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{PRSS_AMOUNT_PARTIES}_{PRSS_THRESHOLD}",
                *DEFAULT_EPOCH_ID
            ))
            .unwrap();
            purge(
                None,
                None,
                &req_id,
                pub_storage_prefixes,
                priv_storage_prefixes,
            )
            .await;

            priv_storage.push(cur_priv);
            vaults.push(None);
            vaults2.push(None);
        }

        // create parties and run PrssSetup
        let server_handles = test_tools::setup_threshold_no_client(
            PRSS_THRESHOLD as u8,
            pub_storage.clone(),
            priv_storage.clone(),
            vaults,
            true,
            None,
            None,
        )
        .await;
        assert_eq!(server_handles.len(), PRSS_AMOUNT_PARTIES);

        // shut parties down
        for server_handle in server_handles.into_values() {
            server_handle.assert_shutdown().await;
        }

        // check that PRSS setups were created
        assert!(logs_contain(
            "Initializing threshold KMS server and generating a new PRSS Setup for"
        ));
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // create parties again without running PrssSetup this time (it should now be read from storage)
        let server_handles = test_tools::setup_threshold_no_client(
            PRSS_THRESHOLD as u8,
            pub_storage,
            priv_storage,
            vaults2,
            false,
            None,
            None,
        )
        .await;
        assert_eq!(server_handles.len(), PRSS_AMOUNT_PARTIES);

        // check that PRSS setups were not created, but instead read from storage now
        assert!(logs_contain("Loaded PRSS Setup from storage"));
    }

    // write prss to storage using the legacy method
    async fn write_legacy_empty_prss_to_storage(private_storage: &mut ram::RamStorage) {
        let epoch_id = *DEFAULT_EPOCH_ID;
        let num_parties = 4;
        let threshold = 1u8;

        let prss_setup_obj_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
        let prss_setup_obj_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);

        // serialize and write PRSS Setup to storage into private storage
        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z128,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z64,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn legacy_prss() {
        let mut rng = AesRng::seed_from_u64(42);

        // initially the storage should be empty
        let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;
        {
            let private_storage = epoch_manager.crypto_storage.get_private_storage();
            let mut guarded_private_storage = private_storage.lock().await;
            write_legacy_empty_prss_to_storage(&mut guarded_private_storage).await;
        }

        epoch_manager.init_legacy_prss_from_storage().await.unwrap();

        let default_epoch_id = *DEFAULT_EPOCH_ID;
        assert!(
            epoch_manager
                .session_maker
                .epoch_exists(&default_epoch_id)
                .await
        );
    }

    #[tokio::test]
    async fn load_all_prss() {
        let mut rng = AesRng::seed_from_u64(42);

        // initially the storage should be empty
        let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;
        let epoch_ids: Vec<EpochId> = (0..3).map(|_| EpochId::new_random(&mut rng)).collect();
        for epoch_id in epoch_ids.iter() {
            let private_storage = epoch_manager.crypto_storage.get_private_storage();
            let mut guarded_private_storage = private_storage.lock().await;
            let prss_setup_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
            let prss_setup_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);

            let prss = PRSSSetupCombined {
                prss_setup_z128,
                prss_setup_z64,
                num_parties: 4,
                threshold: 1,
            };

            store_versioned_at_request_id(
                &mut (*guarded_private_storage),
                &(*epoch_id).into(),
                &prss,
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap();
        }

        assert_eq!(0, epoch_manager.session_maker.epoch_count().await);
        epoch_manager.init_all_prss_from_storage().await.unwrap();
        assert_eq!(
            epoch_ids.len(),
            epoch_manager.session_maker.epoch_count().await
        );

        for epoch_id in epoch_ids {
            assert!(epoch_manager.session_maker.epoch_exists(&epoch_id).await);
        }
    }

    async fn make_epoch_manager<
        I: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>,
    >(
        rng: &mut AesRng,
    ) -> RealThresholdEpochManager<ram::RamStorage, ram::RamStorage, I, SecureReshareSecretKeys>
    {
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk).unwrap();
        let epoch_id = *DEFAULT_EPOCH_ID;
        let session_maker =
            SessionMaker::four_party_dummy_session(None, None, &epoch_id, base_kms.new_rng().await);

        RealThresholdEpochManager::<ram::RamStorage, ram::RamStorage, I, SecureReshareSecretKeys>::init_test(
            base_kms,
            session_maker,
        )
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;
        let epoch_id = EpochId::new_random(&mut rng);
        epoch_manager
            .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                epoch_id: Some(epoch_id.into()),
                context_id: None,
                previous_epoch: None,
            }))
            .await
            .unwrap();
        let result = epoch_manager
            .get_epoch_result(tonic::Request::new(epoch_id.into()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.epoch_id.unwrap(), epoch_id.into());
    }

    #[tokio::test]
    async fn test_resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(42);
        let mut epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;
        epoch_manager.set_bucket_size(0);
        let epoch_id = EpochId::new_random(&mut rng);

        assert_eq!(
            epoch_manager
                .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                    epoch_id: Some(epoch_id.into()),
                    context_id: None,
                    previous_epoch: None,
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;

        {
            // bad epoch ID
            let bad_epoch_id = kms_grpc::kms::v1::RequestId {
                request_id: "bad epoch id".to_string(),
            };
            assert_eq!(
                epoch_manager
                    .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                        epoch_id: Some(bad_epoch_id),
                        context_id: None,
                        previous_epoch: None,
                    }))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            assert_eq!(
                epoch_manager
                    .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                        epoch_id: None,
                        context_id: None,
                        previous_epoch: None,
                    }))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;

        let epoch_id = EpochId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng); // should not exist
        let err = epoch_manager
            .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                epoch_id: Some(epoch_id.into()),
                context_id: Some(context_id.into()),
                previous_epoch: None,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;

        let epoch_id = EpochId::new_random(&mut rng);
        epoch_manager
            .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                epoch_id: Some(epoch_id.into()),
                context_id: None,
                previous_epoch: None,
            }))
            .await
            .unwrap();

        // try the same again and we should see an AlreadyExists error
        assert_eq!(
            epoch_manager
                .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                    epoch_id: Some(epoch_id.into()),
                    context_id: None,
                    previous_epoch: None,
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn internal() {
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_manager = make_epoch_manager::<FailingPrss>(&mut rng).await;

        let epoch_id = EpochId::new_random(&mut rng);
        assert_eq!(
            epoch_manager
                .new_mpc_epoch(tonic::Request::new(NewMpcEpochRequest {
                    epoch_id: Some(epoch_id.into()),
                    context_id: None,
                    previous_epoch: None,
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
    }

    #[test]
    fn test_verify_epoch_info() {
        let new_epoch_id = derive_request_id("new_epoch_id").unwrap();
        let old_epoch_id = derive_request_id("old_epoch_id").unwrap();
        let context_id = derive_request_id("context_id").unwrap();
        let key_id = derive_request_id("key_id").unwrap();
        let preproc_id = derive_request_id("preproc_id").unwrap();

        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();

        let valid_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: Some(old_epoch_id.into()),
            key_id: Some(key_id.into()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, valid_previous_epoch).unwrap();

        // Define a bad request ID
        let bad_req_id = kms_grpc::kms::v1::RequestId {
            request_id: ['x'; crate::consts::ID_LENGTH].iter().collect(),
        };

        // Test with invalid context id
        let invalid_previous_epoch = PreviousEpochInfo {
            context_id: Some(bad_req_id.clone()),
            epoch_id: Some(old_epoch_id.into()),
            key_id: Some(key_id.into()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, invalid_previous_epoch).unwrap_err();

        // Test with missing context id
        let missing_field_previous_epoch = PreviousEpochInfo {
            context_id: None,
            epoch_id: Some(old_epoch_id.into()),
            key_id: Some(key_id.into()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, missing_field_previous_epoch).unwrap_err();

        // Test with invalid epoch id
        let invalid_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: Some(bad_req_id.clone()),
            key_id: Some(key_id.into()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, invalid_previous_epoch).unwrap_err();

        // Test with missing epoch id
        let missing_field_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: None,
            key_id: Some(key_id.into()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, missing_field_previous_epoch).unwrap_err();

        // Test with invalid key id
        let invalid_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: Some(old_epoch_id.into()),
            key_id: Some(bad_req_id.clone()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, invalid_previous_epoch).unwrap_err();

        // Test with missing key id
        let missing_field_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: Some(old_epoch_id.into()),
            key_id: None,
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, missing_field_previous_epoch).unwrap_err();

        // Test with invalid preproc id
        let invalid_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: Some(old_epoch_id.into()),
            key_id: Some(key_id.into()),
            preproc_id: Some(bad_req_id.clone()),
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain.clone()),
        };
        verify_epoch_info(&new_epoch_id, invalid_previous_epoch).unwrap_err();

        // Test with missing preproc id
        let missing_field_previous_epoch = PreviousEpochInfo {
            context_id: Some(context_id.into()),
            epoch_id: Some(old_epoch_id.into()),
            key_id: Some(key_id.into()),
            preproc_id: None,
            key_parameters: FheParameter::Test as i32,
            key_digests: vec![], //Empty vec shouldn't fail verification, although in practice it's an issue
            domain: Some(domain),
        };
        verify_epoch_info(&new_epoch_id, missing_field_previous_epoch).unwrap_err();
    }
}
