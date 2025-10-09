use std::sync::Arc;

use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{
        InitiateResharingRequest, InitiateResharingResponse, ResharingResultRequest,
        ResharingResultResponse,
    },
    rpc_types::{optional_protobuf_to_alloy_domain, PrivDataType, WrappedPublicKeyOwned},
    IdentifierError, RequestId,
};
use threshold_fhe::{
    execution::{
        online::reshare::{reshare_sk_same_sets, ResharePreprocRequired},
        runtime::session::ParameterHandles,
        small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
        tfhe_internals::public_keysets::FhePubKeySet,
    },
    networking::NetworkMode,
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};

use crate::{
    consts::DEFAULT_MPC_CONTEXT,
    engine::{
        base::{
            compute_info_standard_keygen, retrieve_parameters, BaseKmsStruct, KeyGenMetadata,
            DSEP_PUBDATA_KEY,
        },
        threshold::{
            service::{session::SessionPreparerGetter, ThresholdFheKeys},
            traits::Resharer,
        },
        validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    },
    util::{
        meta_store::{self, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{
        crypto_material::{log_storage_success, ThresholdCryptoMaterialStorage},
        store_versioned_at_request_id, Storage,
    },
};

pub struct RealResharer<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub session_preparer_getter: SessionPreparerGetter,
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
        let _permit = self.rate_limiter.start_reshare().await?;

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

        // Refresh keys but ignore any error as we might not have them yet
        // (e.g. resharing due to a failed DKG)
        let _ = self
            .crypto_storage
            .refresh_threshold_fhe_keys(&key_id_to_reshare)
            .await;

        // We assume the operators have manually copied the public keys to the public storage
        let public_key = self
            .crypto_storage
            .read_cloned_pk(&key_id_to_reshare)
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Internal,
                    format!(
                        "Failed to fetch public key from public storage: {}",
                        e.to_string()
                    ),
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
        let session_preparer = self
            .session_preparer_getter
            .get(&old_context)
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::Internal, e.to_string()))?;

        let sk = Arc::clone(&self.base_kms.sig_key);
        let meta_store = Arc::clone(&self.reshare_pubinfo_meta_store);

        let task = async move {
            let (session_id_z128, session_id_z64, session_id_reshare) = {
                (
                    request_id.derive_session_id_with_counter(0)?,
                    request_id.derive_session_id_with_counter(1)?,
                    request_id.derive_session_id_with_counter(2)?,
                )
            };

            // First thing, if I have a key, send the public material to everyone else.

            // Require 1 session in Z64 and 1 session in Z128
            let mut session_z64 = session_preparer
                .make_small_sync_session_z64(session_id_z64, old_context)
                .await?;

            let mut session_z128 = session_preparer
                .make_small_sync_session_z128(session_id_z128, old_context)
                .await?;

            // Figure out how much preprocessing we need
            // Slightly unclear how we should do that if we don't have the keys
            // (Could be done from the parameters, but then again we also don't have them right now)
            // (Note that it's the parties in S2 that need to know how much preprocessing they need,
            // so this will be an issue also when resharing to a different set of parties)
            let num_needed_preproc =
                ResharePreprocRequired::new_same_set(session_z64.num_parties(), dkg_params);

            let mut correlated_randomness_z64 = SecureSmallPreprocessing::default()
                .execute(&mut session_z64, num_needed_preproc.batch_params_64)
                .await
                .unwrap();

            let mut correlated_randomness_z128 = SecureSmallPreprocessing::default()
                .execute(&mut session_z128, num_needed_preproc.batch_params_128)
                .await
                .unwrap();

            //Perform online
            let mut base_session = session_preparer
                .make_base_session(session_id_reshare, old_context, NetworkMode::Sync)
                .await?;

            // Read the old keys if they exists, otherwise we enter resharing with no keys
            // NOTE: Will need to drop this unwrap somehow
            let (mut mutable_keys, metadata) = {
                let old_fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id_to_reshare)
                    .await
                    .ok();
                // Note: the function is supposed to zeroize the keys (hence requires mut access),
                // so we clone it, cause we can't zeroize storage from here
                let key = old_fhe_keys_rlock
                    .as_ref()
                    .map(|r| r.private_keys.as_ref().clone());

                let metadata = old_fhe_keys_rlock.map(|r| r.meta_data.clone());
                (key, metadata)
            };

            let new_private_key_set = reshare_sk_same_sets(
                &mut correlated_randomness_z128,
                &mut correlated_randomness_z64,
                &mut base_session,
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
                    todo!("ERROR")
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
            let dummy_meta_store = RwLock::new(MetaStore::<KeyGenMetadata>::new(0, 0));
            crypto_storage
                .purge_key_material(&key_id_to_reshare, dummy_meta_store.write().await)
                .await;

            crypto_storage
                .write_threshold_keys_with_meta_store(
                    &key_id_to_reshare,
                    threshold_fhe_keys,
                    fhe_pubkeys,
                    info,
                    meta_store,
                )
                .await;
            //NOTE: Probably need to modify the storage
            // such that we can overwrite only the private keys
            // (assuming the public keys are here, either because DKG succeeded or we
            // fetched and verified them from all the other parties)

            //crypto_storage.overwrite_private_key(
            //    key_id,
            //    new_private_key_set,
            //);

            Ok::<(), anyhow::Error>(())
        };
        self.tracker.spawn(task);
        Ok(Response::new(InitiateResharingResponse {
            request_id: Some(request_id.into()),
        }))
    }

    async fn get_resharing_result(
        &self,
        request: Request<ResharingResultRequest>,
    ) -> Result<Response<ResharingResultResponse>, Status> {
        todo!()
    }
}
