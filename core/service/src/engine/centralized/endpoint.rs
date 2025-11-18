use crate::engine::centralized::central_kms::CentralizedKms;
use crate::engine::centralized::service::{
    get_preprocessing_res_impl, init_impl, preprocessing_impl,
};
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::utils::query_key_material_availability;
use crate::vault::storage::Storage;
use kms_grpc::kms::v1::{
    self, CustodianRecoveryRequest, Empty, HealthStatusResponse, InitRequest, KeyGenPreprocRequest,
    KeyGenPreprocResult, KeyMaterialAvailabilityResponse, NodeType, OperatorPublicKey,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use kms_grpc::rpc_types::KMSType;
use tonic::{Request, Response, Status};

use crate::engine::centralized::service::{crs_gen_impl, get_crs_gen_result_impl};
use crate::engine::centralized::service::{get_key_gen_result_impl, key_gen_impl};
use crate::engine::centralized::service::{
    get_public_decryption_result_impl, get_user_decryption_result_impl, public_decrypt_impl,
    user_decrypt_impl,
};
#[cfg(feature = "insecure")]
use observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST;
use observability::{
    metrics::METRICS,
    metrics_names::{
        map_tonic_code_to_metric_tag, OP_CRS_GEN_REQUEST, OP_CRS_GEN_RESULT,
        OP_CUSTODIAN_BACKUP_RECOVERY, OP_CUSTODIAN_RECOVERY_INIT, OP_DESTROY_CUSTODIAN_CONTEXT,
        OP_DESTROY_KMS_CONTEXT, OP_FETCH_PK, OP_INIT, OP_KEYGEN_PREPROC_REQUEST,
        OP_KEYGEN_PREPROC_RESULT, OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT, OP_NEW_CUSTODIAN_CONTEXT,
        OP_NEW_KMS_CONTEXT, OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT,
        OP_RESTORE_FROM_BACKUP, OP_USER_DECRYPT_REQUEST, OP_USER_DECRYPT_RESULT,
    },
};

#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > CoreServiceEndpoint for CentralizedKms<PubS, PrivS, CM, BO>
{
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_INIT);
        init_impl(self, request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(observability::metrics_names::OP_INIT, tag);
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_KEYGEN_PREPROC_REQUEST);
        preprocessing_impl(self, request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(
                observability::metrics_names::OP_KEYGEN_PREPROC_REQUEST,
                tag,
            );
        })
    }

    // In the centralized case it makes no diffrence whether it's partial or not
    // as it's dummy anyway
    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn partial_key_gen_preproc(
        &self,
        request: Request<kms_grpc::kms::v1::PartialKeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.key_gen_preproc(Request::new(request.into_inner().base_request.ok_or_else(
            || tonic::Status::new(tonic::Code::Aborted, "Missing preproc base_request"),
        )?))
        .await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_key_gen_preproc_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        METRICS.increment_request_counter(OP_KEYGEN_PREPROC_RESULT);
        get_preprocessing_res_impl(self, request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(
                    observability::metrics_names::OP_KEYGEN_PREPROC_RESULT,
                    tag,
                );
            })
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_key_gen(
        &self,
        request: Request<kms_grpc::kms::v1::KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_INSECURE_KEYGEN_REQUEST);
        key_gen_impl(self, request, false).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(OP_INSECURE_KEYGEN_REQUEST, tag);
        })
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_key_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::KeyGenResult>, Status> {
        METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_RESULT);
        self.get_key_gen_result(request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(
                observability::metrics_names::OP_INSECURE_KEYGEN_RESULT,
                tag,
            );
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn key_gen(
        &self,
        request: Request<kms_grpc::kms::v1::KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_KEYGEN_REQUEST);
        // if we're doing a "secure" keygen
        // even if it's compiled with the "insecure" feature
        // we still want to check the preprocessing ID
        key_gen_impl(
            self,
            request,
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(OP_KEYGEN_REQUEST, tag);
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_key_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::KeyGenResult>, Status> {
        METRICS.increment_request_counter(OP_KEYGEN_RESULT);
        get_key_gen_result_impl(self, request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_KEYGEN_RESULT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn user_decrypt(
        &self,
        request: Request<kms_grpc::kms::v1::UserDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_USER_DECRYPT_REQUEST);
        user_decrypt_impl(self, request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(OP_USER_DECRYPT_REQUEST, tag);
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_user_decryption_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::UserDecryptionResponse>, Status> {
        METRICS.increment_request_counter(OP_USER_DECRYPT_RESULT);
        get_user_decryption_result_impl(self, request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_USER_DECRYPT_RESULT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn public_decrypt(
        &self,
        request: Request<kms_grpc::kms::v1::PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST);
        public_decrypt_impl(self, request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, tag);
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_public_decryption_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::PublicDecryptionResponse>, Status> {
        METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_RESULT);
        get_public_decryption_result_impl(self, request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_PUBLIC_DECRYPT_RESULT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn crs_gen(
        &self,
        request: Request<kms_grpc::kms::v1::CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_CRS_GEN_REQUEST);
        crs_gen_impl(self, request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(OP_CRS_GEN_REQUEST, tag);
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_crs_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::CrsGenResult>, Status> {
        METRICS.increment_request_counter(OP_CRS_GEN_RESULT);
        get_crs_gen_result_impl(self, request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_CRS_GEN_RESULT, tag);
            })
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_crs_gen(
        &self,
        request: Request<kms_grpc::kms::v1::CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS
            .increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST);
        self.crs_gen(request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(
                observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST,
                tag,
            );
        })
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_crs_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::CrsGenResult>, Status> {
        METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT);
        self.get_crs_gen_result(request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(
                observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT,
                tag,
            );
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn new_kms_context(
        &self,
        request: Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        METRICS.increment_request_counter(OP_NEW_KMS_CONTEXT);
        self.context_manager
            .new_mpc_context(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_NEW_KMS_CONTEXT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn destroy_kms_context(
        &self,
        request: Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_DESTROY_KMS_CONTEXT);
        self.context_manager
            .destroy_mpc_context(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_DESTROY_KMS_CONTEXT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn new_custodian_context(
        &self,
        request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_NEW_CUSTODIAN_CONTEXT);
        self.context_manager
            .new_custodian_context(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_NEW_CUSTODIAN_CONTEXT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn destroy_custodian_context(
        &self,
        request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_DESTROY_CUSTODIAN_CONTEXT);
        self.context_manager
            .destroy_custodian_context(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_DESTROY_CUSTODIAN_CONTEXT, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_operator_public_key(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status> {
        METRICS.increment_request_counter(OP_FETCH_PK);
        self.backup_operator
            .get_operator_public_key(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_FETCH_PK, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn custodian_backup_recovery(
        &self,
        request: Request<CustodianRecoveryRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_CUSTODIAN_BACKUP_RECOVERY);
        self.backup_operator
            .custodian_backup_recovery(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_CUSTODIAN_BACKUP_RECOVERY, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn restore_from_backup(
        &self,
        request: Request<kms_grpc::kms::v1::Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        METRICS.increment_request_counter(OP_RESTORE_FROM_BACKUP);
        self.backup_operator
            .restore_from_backup(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_RESTORE_FROM_BACKUP, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn custodian_recovery_init(
        &self,
        request: Request<kms_grpc::kms::v1::CustodianRecoveryInitRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::RecoveryRequest>, Status> {
        METRICS.increment_request_counter(OP_CUSTODIAN_RECOVERY_INIT);
        self.backup_operator
            .custodian_recovery_init(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_CUSTODIAN_RECOVERY_INIT, tag);
            })
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_key_material_availability(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<KeyMaterialAvailabilityResponse>, Status> {
        // Get storage references
        let priv_storage = self.crypto_storage.inner.get_private_storage();
        let priv_guard = priv_storage.lock().await;

        let response = query_key_material_availability(
            &*priv_guard,
            KMSType::Centralized,
            Vec::new(), // Centralized KMS doesn't support preprocessing material
        )
        .await?;

        Ok(Response::new(response))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_health_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::HealthStatusResponse>, Status> {
        // Get own key material
        let own_material = self
            .get_key_material_availability(Request::new(Empty {}))
            .await?;
        let own_material = own_material.into_inner();

        // Centralized mode has no peers, always optimal if reachable
        let response = HealthStatusResponse {
            peers_from_all_contexts: Vec::new(),
            my_fhe_key_ids: own_material.fhe_key_ids,
            my_crs_ids: own_material.crs_ids,
            my_preprocessing_key_ids: Vec::new(), // Centralized doesn't use preprocessing
            my_storage_info: own_material.storage_info,
            node_type: NodeType::Centralized.into(), // NODE_TYPE_CENTRALIZED
        };

        Ok(Response::new(response))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn initiate_resharing(
        &self,
        _request: Request<kms_grpc::kms::v1::InitiateResharingRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::InitiateResharingResponse>, Status> {
        unimplemented!("Resharing is not supported in Centralized KMS");
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_resharing_result(
        &self,
        _request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::ResharingResultResponse>, Status> {
        unimplemented!("Resharing is not supported in Centralized KMS");
    }
}
