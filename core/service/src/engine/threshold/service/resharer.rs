use std::sync::Arc;

use itertools::Itertools;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{
        InitiateResharingRequest, InitiateResharingResponse, KeyDigest, ResharingResultResponse,
    },
    rpc_types::{optional_protobuf_to_alloy_domain, WrappedPublicKeyOwned},
    IdentifierError,
};
use threshold_fhe::{
    execution::{
        endpoints::reshare_sk::{
            ResharePreprocRequired, ReshareSecretKeys, SecureReshareSecretKeys,
        },
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
        tfhe_internals::public_keysets::FhePubKeySet,
    },
    networking::NetworkMode,
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};

use crate::{
    consts::{DEFAULT_MPC_CONTEXT, PRSS_INIT_REQ_ID},
    engine::{
        base::{
            compute_info_standard_keygen, retrieve_parameters, BaseKmsStruct, KeyGenMetadata,
            DSEP_PUBDATA_KEY,
        },
        threshold::{
            service::{session::ImmutableSessionMaker, ThresholdFheKeys},
            traits::Resharer,
        },
        validation::{
            parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
        },
    },
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};

pub struct RealResharer<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub(crate) session_maker: ImmutableSessionMaker,
    pub reshare_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
}

#[tonic::async_trait]
impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static> Resharer
    for RealResharer<PubS, PrivS>
{
    async fn initiate_resharing(
        &self,
        request: Request<InitiateResharingRequest>,
    ) -> Result<Response<InitiateResharingResponse>, Status> {
        let inner = request.into_inner();

        tracing::info!(
            "Received initiate resharing request in context {:?} for Key ID {:?} with request ID {:?}",
            inner.context_id,
            inner.key_id,
            inner.request_id
        );

        let old_context: ContextId = match &inner.context_id {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => *DEFAULT_MPC_CONTEXT,
        };

        let new_epoch_id: EpochId = match &inner.epoch_id {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => EpochId::try_from(PRSS_INIT_REQ_ID).unwrap(), // safe to unwrap here because PRSS ID is hardcoded
        };

        let key_id_to_reshare =
            parse_optional_proto_request_id(&inner.key_id, RequestIdParsingErr::ReshareRequest)?;

        let preproc_id = parse_optional_proto_request_id(
            &inner.preproc_id,
            RequestIdParsingErr::ReshareRequest,
        )?;

        let request_id = parse_optional_proto_request_id(
            &inner.request_id,
            RequestIdParsingErr::ReshareRequest,
        )?;

        let eip712_domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;

        let dkg_params = retrieve_parameters(Some(inner.key_parameters))?;

        // Check for resource exhaustion once all the other checks are ok
        // because resource exhaustion can be recovered by sending the exact same request
        // but the errors above cannot be tried again.
        let permit = self.rate_limiter.start_reshare().await?;

        // Refresh keys but ignore any error as we might not have them yet
        // (e.g. resharing due to a failed DKG)
        let _ = self
            .crypto_storage
            .refresh_threshold_fhe_keys(&key_id_to_reshare)
            .await
            .inspect_err(|e|tracing::warn!("During reshare, failed to refresh keys with id {}: {}. Will try to do the reshare anyway.", key_id_to_reshare, e));

        // We assume the operators have manually copied the public keys to the public storage
        let public_key = self
            .crypto_storage
            .read_cloned_pk(&key_id_to_reshare)
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Internal,
                    format!("Failed to fetch public key from public storage: {}", e),
                )
            })?;

        let WrappedPublicKeyOwned::Compact(public_key) = public_key;

        let server_key = self
            .crypto_storage
            .read_cloned_server_key(&key_id_to_reshare)
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Internal,
                    format!("Failed to fetch server key from public storage: {}", e),
                )
            })?;

        let (integer_server_key, _, _, decompression_key, sns_key, _, _, _) =
            server_key.clone().into_raw_parts();

        let fhe_pubkeys = FhePubKeySet {
            public_key,
            server_key,
        };

        let crypto_storage = self.crypto_storage.clone();

        // Do the resharing
        let sk = self.base_kms.sig_key().map_err(|e| {
            tonic::Status::new(
                tonic::Code::FailedPrecondition,
                format!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
            )
        })?;
        let meta_store = Arc::clone(&self.reshare_pubinfo_meta_store);

        // Update status
        {
            let mut guarded_meta_store = meta_store.write().await;
            guarded_meta_store.insert(&request_id).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Internal,
                    format!(
                        "Failed to insert reshare status for request {} : {}",
                        request_id, e
                    ),
                )
            })?;
        }

        // Need to move the session_maker inside the task otherwise we'll have lifetime issues
        let session_maker = self.session_maker.clone();
        let task = move |_permit| async move {
            let (session_id_z128, session_id_z64, session_id_reshare) = {
                (
                    request_id.derive_session_id_with_counter(0)?,
                    request_id.derive_session_id_with_counter(1)?,
                    request_id.derive_session_id_with_counter(2)?,
                )
            };

            // First thing, if I have a key, send the public material to everyone else.

            // Require 1 session in Z64 and 1 session in Z128
            // TODO(zama-ai/kms-internal/issues/2810)
            // when resharing is fully implemented, we need to use the new context *and* the old context
            let mut session_z64 = session_maker
                .make_small_sync_session_z64(session_id_z64, old_context, new_epoch_id)
                .await?;

            let mut session_z128 = session_maker
                .make_small_sync_session_z128(session_id_z128, old_context, new_epoch_id)
                .await?;

            // Figure out how much preprocessing we need
            // Slightly unclear how we should do that if we don't have the keys
            // (Could be done from the parameters, but then again we also don't have them right now)
            // (Note that it's the parties in S2 that need to know how much preprocessing they need,
            // so this will be an issue also when resharing to a different set of parties)
            let num_needed_preproc =
                ResharePreprocRequired::new(session_z64.num_parties(), dkg_params);

            let mut correlated_randomness_z64 = SecureSmallPreprocessing::default()
                .execute(&mut session_z64, num_needed_preproc.batch_params_64)
                .await?;

            let mut correlated_randomness_z128 = SecureSmallPreprocessing::default()
                .execute(&mut session_z128, num_needed_preproc.batch_params_128)
                .await?;

            // Perform online
            let mut base_session = session_maker
                .make_base_session(session_id_reshare, old_context, NetworkMode::Sync)
                .await?;

            // Read the old keys if they exists, otherwise we enter resharing with no keys
            let mut mutable_keys = {
                let old_fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id_to_reshare)
                    .await
                    .ok();
                // Note: the function is supposed to zeroize the keys (hence requires mut access),
                // so we clone it, cause we can't zeroize storage from here
                old_fhe_keys_rlock
                    .as_deref()
                    .map(|r| r.private_keys.as_ref().clone())
            };

            let new_private_key_set = SecureReshareSecretKeys::secure_reshare_same_sets(
                &mut base_session,
                &mut correlated_randomness_z128,
                &mut correlated_randomness_z64,
                &mut mutable_keys,
                dkg_params,
            )
            .await?;

            //Compute all the info required for storing
            // using the same IDs and domain as we should've had the
            // DKG went through successfully
            let info = match compute_info_standard_keygen(
                &sk,
                &DSEP_PUBDATA_KEY,
                &preproc_id,
                &key_id_to_reshare,
                &fhe_pubkeys,
                &eip712_domain,
            ) {
                Ok(info) => info,
                Err(_) => {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage
                        .update(&request_id, Err("Failed to compute key info".to_string()));
                    anyhow::bail!("Failed to compute key info")
                }
            };

            let threshold_fhe_keys = ThresholdFheKeys {
                private_keys: Arc::new(new_private_key_set),
                integer_server_key: Arc::new(integer_server_key),
                sns_key: sns_key.map(Arc::new),
                decompression_key: decompression_key.map(Arc::new),
                meta_data: info.clone(),
            };

            // Purge before we can overwrite, use a dummy_meta_store
            // as this was meant to update the meta store of DKG upon failing
            let dummy_meta_store = RwLock::new(MetaStore::<KeyGenMetadata>::new(1, 1));
            // Dummy insert to avoid error logs during purge
            dummy_meta_store.write().await.insert(&key_id_to_reshare)?;
            crypto_storage
                .purge_key_material(&key_id_to_reshare, dummy_meta_store.write().await)
                .await;

            // HOTFIX(keygen-recovery): Note that this overwrites the private storage
            // at the given key ID. It's needed as long as reshare shortcuts the
            // GW, but should be fixed long term.
            crypto_storage
                .write_threshold_keys_with_reshare_meta_store(
                    &request_id,
                    &key_id_to_reshare,
                    threshold_fhe_keys,
                    fhe_pubkeys,
                    info.clone(),
                    Arc::clone(&meta_store),
                )
                .await;

            Ok(())
        };
        self.tracker.spawn(async move {
            match task(permit).await {
                Ok(_) => tracing::info!(
                    "Resharing completed successfully for request ID {:?} and key ID {:?}",
                    request_id,
                    key_id_to_reshare
                ),
                Err(e) => tracing::error!(
                    "Resharing failed for request ID {:?} and key ID {:?}: {}",
                    request_id,
                    key_id_to_reshare,
                    e
                ),
            }
        });
        Ok(Response::new(InitiateResharingResponse {
            request_id: Some(request_id.into()),
        }))
    }

    async fn get_resharing_result(
        &self,
        request: Request<kms_grpc::kms::v1::RequestId>,
    ) -> Result<Response<ResharingResultResponse>, Status> {
        let request_id =
            parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::ReshareResponse)?;

        let status = {
            let guarded_meta_store = self.reshare_pubinfo_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };

        let res = handle_res_mapping(status, &request_id, "Reshare").await?;

        match res {
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

                Ok(Response::new(ResharingResultResponse {
                    request_id: Some(request_id.into()),
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
        }
    }
}
