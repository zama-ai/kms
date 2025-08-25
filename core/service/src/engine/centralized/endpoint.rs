use crate::engine::centralized::central_kms::CentralizedKms;
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::tonic_some_or_err;
use crate::vault::storage::Storage;
use kms_grpc::kms::v1::{
    self, BackupRecoveryRequest, Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocResult,
    OperatorPublicKey,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use tonic::{Request, Response, Status};

use crate::engine::centralized::service::{crs_gen_impl, get_crs_gen_result_impl};
use crate::engine::centralized::service::{get_key_gen_result_impl, key_gen_impl};
use crate::engine::centralized::service::{
    get_public_decryption_result_impl, get_user_decryption_result_impl, public_decrypt_impl,
    user_decrypt_impl,
};
use observability::{
    metrics::METRICS,
    metrics_names::{
        map_tonic_code_to_metric_tag, ERR_INVALID_REQUEST, OP_BACKUP_RESTORE, OP_CRS_GEN_REQUEST,
        OP_CRS_GEN_RESULT, OP_CUSTODIAN_BACKUP_RECOVERY, OP_CUSTODIAN_RECOVERY_INIT,
        OP_DESTROY_CUSTODIAN_CONTEXT, OP_DESTROY_KMS_CONTEXT, OP_FETCH_PK, OP_INIT,
        OP_KEYGEN_PREPROC_REQUEST, OP_KEYGEN_PREPROC_RESULT, OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT,
        OP_NEW_CUSTODIAN_CONTEXT, OP_NEW_KMS_CONTEXT, OP_PUBLIC_DECRYPT_REQUEST,
        OP_PUBLIC_DECRYPT_RESULT, OP_USER_DECRYPT_REQUEST, OP_USER_DECRYPT_RESULT,
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
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_INIT);
        METRICS.increment_error_counter(OP_INIT, ERR_INVALID_REQUEST);
        tonic_some_or_err(
            None,
            "Requesting init on centralized kms is not suported".to_string(),
        )
        .map_err(Status::from)
    }

    #[tracing::instrument(skip(self, _request))]
    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(OP_KEYGEN_PREPROC_REQUEST);
        METRICS.increment_error_counter(OP_KEYGEN_PREPROC_REQUEST, ERR_INVALID_REQUEST);
        tonic_some_or_err(
            None,
            "Requesting preproc on centralized kms is not suported".to_string(),
        )
        .map_err(Status::from)
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_key_gen_preproc_result(
        &self,
        _request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        METRICS.increment_request_counter(OP_KEYGEN_PREPROC_RESULT);
        METRICS.increment_error_counter(OP_KEYGEN_PREPROC_RESULT, ERR_INVALID_REQUEST);
        tonic_some_or_err(
            None,
            "Requesting preproc status on centralized kms is not suported".to_string(),
        )
        .map_err(Status::from)
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_key_gen(
        &self,
        request: Request<kms_grpc::kms::v1::KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST);
        self.key_gen(request).await.inspect_err(|err| {
            let tag = map_tonic_code_to_metric_tag(err.code());
            let _ = METRICS.increment_error_counter(
                observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST,
                tag,
            );
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
        key_gen_impl(self, request).await.inspect_err(|err| {
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
            .new_kms_context(request)
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
            .destroy_kms_context(request)
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
        request: Request<BackupRecoveryRequest>,
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
    async fn backup_restore(
        &self,
        request: Request<kms_grpc::kms::v1::Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        METRICS.increment_request_counter(OP_BACKUP_RESTORE);
        self.backup_operator
            .backup_restore(request)
            .await
            .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS.increment_error_counter(OP_BACKUP_RESTORE, tag);
            })
    }

    #[tracing::instrument(skip(self, request))]
    async fn custodian_recovery_init(
        &self,
        request: Request<kms_grpc::kms::v1::Empty>,
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
}
