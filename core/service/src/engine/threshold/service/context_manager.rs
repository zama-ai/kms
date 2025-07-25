use crate::backup::custodian::{InternalCustodianContext, InternalCustodianSetupMessage};
use crate::{
    engine::{
        base::BaseKmsStruct, threshold::traits::ContextManager, validation::validate_request_id,
    },
    grpc::metastore_status_service::CustodianMetaStore,
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};
use kms_grpc::kms::v1::CustodianContext;
use kms_grpc::RequestId;
use kms_grpc::{kms::v1::Empty, utils::tonic_result::tonic_handle_potential_err};
use std::{collections::HashMap, sync::Arc};
use threshold_fhe::execution::runtime::party::Role;
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::Response;

pub struct RealContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
    pub tracker: Arc<TaskTracker>,
}

#[tonic::async_trait]
impl<PubS, PrivS> ContextManager for RealContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn new_kms_context(
        &self,
        _request: tonic::Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        todo!()
    }

    async fn destroy_kms_context(
        &self,
        _request: tonic::Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        todo!()
    }

    async fn new_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let inner = request.into_inner().new_context.ok_or_else(|| {
            tonic::Status::invalid_argument("new_context is required in NewCustodianContextRequest")
        })?;
        tracing::info!(
            "Custodian context addition starting with context_id={:?}, threshold={}, previous_context_id={:?}, from {} custodians",
            inner.context_id,
            inner.threshold,
            inner.previous_context_id,
            inner.custodian_nodes.len()
        );
        tonic_handle_potential_err(
            self.inner_new_custodian_context(inner).await,
            "Could not create new custodian context".to_string(),
        )?;

        //Always answer with Empty
        Ok(Response::new(Empty {}))
    }

    async fn destroy_custodian_context(
        &self,
        _request: tonic::Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        todo!()
    }
}

impl<PubS, PrivS> RealContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn inner_new_custodian_context(&self, context: CustodianContext) -> anyhow::Result<()> {
        let context_id: RequestId = match context.context_id {
            Some(id) => id.into(),
            None => {
                return Err(anyhow::anyhow!(
                    "Context ID is required in NewCustodianContextRequest"
                ))
            }
        };
        validate_request_id(&context_id)?;

        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        // Optimize lock hold time by minimizing operations under lock
        let (lock_acquired_time, total_lock_time) = {
            let lock_start = std::time::Instant::now();
            let mut custodian_meta_store = self.custodian_meta_store.write().await;
            let lock_acquired_time = lock_start.elapsed();
            tonic_handle_potential_err(
                custodian_meta_store.insert(&context_id),
                format!("Could not insert new custodian context {context_id} into meta store"),
            )?;
            let mut node_map = HashMap::new();
            for setup_message in context.custodian_nodes.iter() {
                let internal_msg: InternalCustodianSetupMessage =
                    setup_message.to_owned().try_into()?;
                node_map.insert(
                    Role::indexed_from_one(setup_message.custodian_role as usize),
                    internal_msg,
                );
            }
            let custodian_context = InternalCustodianContext {
                context_id,
                threshold: context.threshold,
                previous_context_id: context.previous_context_id.map(Into::into),
                custodian_nodes: node_map,
            };
            // We don't need to check the result of this write, since insert above fails if an element already exists
            let _ = custodian_meta_store.update(&context_id, Ok(custodian_context))?;

            let total_lock_time = lock_start.elapsed();
            (lock_acquired_time, total_lock_time)
        };
        // Log after lock is released
        tracing::info!(
            "MetaStore INITIAL insert for custodian context - context_id={}, lock_acquired_in={:?}, total_lock_held={:?}",
            context_id, lock_acquired_time, total_lock_time
        );
        Ok(())
    }
}
