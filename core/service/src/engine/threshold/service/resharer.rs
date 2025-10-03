use std::sync::Arc;

use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{
        InitiateResharingRequest, InitiateResharingResponse, ResharingStatusRequest,
        ResharingStatusResponse,
    },
    rpc_types::PrivDataType,
    IdentifierError, RequestId,
};
use threshold_fhe::{
    execution::{
        online::reshare::{reshare_sk_same_sets, ResharePreprocRequired},
        runtime::session::ParameterHandles,
        small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
    },
    networking::NetworkMode,
};
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};

use crate::{
    consts::DEFAULT_MPC_CONTEXT,
    engine::{
        base::{retrieve_parameters, BaseKmsStruct},
        threshold::{service::session::SessionPreparerGetter, traits::Resharer},
        validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    },
    util::{meta_store, rate_limiter::RateLimiter},
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
            "Received initiate resharing request from context {:?} to context: {:?}",
            inner.current_context,
            inner.new_context
        );

        let old_context: ContextId = match &inner.current_context {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => *DEFAULT_MPC_CONTEXT,
        };

        let new_context: ContextId = match &inner.new_context {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => *DEFAULT_MPC_CONTEXT,
        };

        // For now that's an error, in the future the opposite will be the error :)
        if old_context != new_context {
            return Err(Status::invalid_argument(
                "Old and new context MUST be the same (for now)",
            ));
        }

        let key_id_to_reshare =
            parse_optional_proto_request_id(&inner.key_id, RequestIdParsingErr::ReshareRequest)?;

        let request_id = parse_optional_proto_request_id(
            &inner.request_id,
            RequestIdParsingErr::ReshareRequest,
        )?;

        let dkg_params = retrieve_parameters(Some(inner.key_parameters))?;

        // Refresh keys but ignore any error as we might not have them yet
        // (e.g. resharing due to a failed DKG)
        let _ = self
            .crypto_storage
            .refresh_threshold_fhe_keys(&key_id_to_reshare)
            .await;

        let crypto_storage = self.crypto_storage.clone();
        // Do the resharing
        let session_preparer = self
            .session_preparer_getter
            .get(&old_context)
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::Internal, e.to_string()))?;

        let task = async move {
            let (session_id_z128, session_id_z64, session_id_base) = {
                (
                    request_id.derive_session_id_with_counter(0)?,
                    request_id.derive_session_id_with_counter(1)?,
                    request_id.derive_session_id_with_counter(2)?,
                )
            };

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
                .make_base_session(session_id_base, old_context, NetworkMode::Sync)
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

            // Go and fetch the public material from everyone's public storage and search for the majority,
            // Qu: How do we get the @ of the other's public storage ?
            // Can it come from the reshare request (at least for now)?
            // Other qu: How easy is it to access the other parties' public storage from here ?
            // Last option for a very first version: have the public keys in the request
            // and make the agreement on the correct public key out of band (e.g. in the client)
            todo!("Do what's written above :)");

            let new_private_key_set = reshare_sk_same_sets(
                &mut correlated_randomness_z128,
                &mut correlated_randomness_z64,
                &mut base_session,
                &mut mutable_keys,
                dkg_params,
            )
            .await?;

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
        todo!()
    }

    async fn get_resharing_status(
        &self,
        request: Request<ResharingStatusRequest>,
    ) -> Result<Response<ResharingStatusResponse>, Status> {
        todo!()
    }
}
