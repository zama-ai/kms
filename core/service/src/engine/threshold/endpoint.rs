use crate::engine::threshold::threshold_kms::ThresholdKms;
use crate::engine::threshold::traits::{
    BackupOperator, ContextManager, CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator,
    PublicDecryptor, UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, DestroyKmsContextRequest, Empty, InitRequest,
    KeyGenPreprocRequest, KeyGenPreprocResult, KeyGenRequest, KeyGenResult,
    KeyMaterialAvailabilityResponse, NewKmsContextRequest, PublicDecryptionRequest,
    PublicDecryptionResponse, RequestId, UserDecryptionRequest, UserDecryptionResponse,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use observability::{
    metrics::METRICS,
    metrics_names::{
        map_tonic_code_to_metric_tag, OP_BACKUP_RESTORE, OP_CRS_GEN_REQUEST, OP_CRS_GEN_RESULT,
        OP_CUSTODIAN_BACKUP_RECOVERY, OP_DESTROY_CUSTODIAN_CONTEXT, OP_DESTROY_KMS_CONTEXT,
        OP_FETCH_PK, OP_INIT, OP_KEYGEN_PREPROC_REQUEST, OP_KEYGEN_PREPROC_RESULT,
        OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT, OP_NEW_CUSTODIAN_CONTEXT, OP_NEW_KMS_CONTEXT,
        OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, OP_USER_DECRYPT_REQUEST,
        OP_USER_DECRYPT_RESULT,
    },
};
use tonic::{Request, Response, Status};

macro_rules! impl_endpoint {
    { impl CoreServiceEndpoint $implementations:tt } => {
        #[cfg(not(feature="insecure"))]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                UD: UserDecryptor + Sync + Send + 'static,
                PD: PublicDecryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                CM: ContextManager + Sync + Send + 'static,
                BO: BackupOperator + Sync + Send + 'static,
            > CoreServiceEndpoint for ThresholdKms<IN, UD, PD, KG, PP, CG, CM, BO> $implementations

        #[cfg(feature="insecure")]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                UD: UserDecryptor + Sync + Send + 'static,
                PD: PublicDecryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                IKG: InsecureKeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                ICG: InsecureCrsGenerator + Sync + Send + 'static,
                CM: ContextManager + Sync + Send + 'static,
                BO: BackupOperator + Sync + Send + 'static,
            > CoreServiceEndpoint for ThresholdKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM, BO> $implementations
    }
}

impl_endpoint! {
    // See the proto file for the documentation of each method.
    impl CoreServiceEndpoint {
        async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_INIT);
            self.initiator.init(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_INIT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen_preproc(
            &self,
            request: Request<KeyGenPreprocRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_REQUEST);
            self.keygen_preprocessor.key_gen_preproc(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_PREPROC_REQUEST, tag);
            })
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_preproc_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenPreprocResult>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_RESULT);
            self.keygen_preprocessor.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_PREPROC_RESULT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_REQUEST);
            self.key_generator.key_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_RESULT);
            self.key_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_RESULT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn user_decrypt(
            &self,
            request: Request<UserDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_USER_DECRYPT_REQUEST);
            self.user_decryptor.user_decrypt(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_USER_DECRYPT_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_user_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<UserDecryptionResponse>, Status> {
            METRICS.increment_request_counter(OP_USER_DECRYPT_RESULT);
            self.user_decryptor.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_USER_DECRYPT_RESULT, tag);
            })


        }

        #[tracing::instrument(skip(self, request))]
        async fn public_decrypt(
            &self,
            request: Request<PublicDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST);
            self.decryptor.public_decrypt(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_public_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<PublicDecryptionResponse>, Status> {
            METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_RESULT);
            self.decryptor.get_result(request).await .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_PUBLIC_DECRYPT_RESULT, tag);
            })
       }


        #[tracing::instrument(skip(self, request))]
        async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_CRS_GEN_REQUEST);
            self.crs_generator.crs_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CRS_GEN_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            METRICS.increment_request_counter(OP_CRS_GEN_RESULT);
            self.crs_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CRS_GEN_RESULT, tag);
            })


        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST);
            self.insecure_key_generator.insecure_key_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST, tag);
            })

        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_RESULT);
            self.insecure_key_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_KEYGEN_RESULT, tag);
            })


        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST);
            self.insecure_crs_generator.insecure_crs_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST, tag);
            })

        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT);
            self.insecure_crs_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT, tag);
            })


        }

        #[tracing::instrument(skip(self, request))]
        async fn new_kms_context(
            &self,
            request: Request<NewKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_NEW_KMS_CONTEXT);
            self.context_manager.new_kms_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_NEW_KMS_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_kms_context(
            &self,
            request: Request<DestroyKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_DESTROY_KMS_CONTEXT);
            self.context_manager.destroy_kms_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_DESTROY_KMS_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn new_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_NEW_CUSTODIAN_CONTEXT);
            self.context_manager.new_custodian_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_NEW_CUSTODIAN_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_DESTROY_CUSTODIAN_CONTEXT);
            self.context_manager.destroy_custodian_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_DESTROY_CUSTODIAN_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_operator_public_key(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::OperatorPublicKey>, Status> {
            METRICS.increment_request_counter(OP_FETCH_PK);
            self.backup_operator.get_operator_public_key(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_FETCH_PK, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn custodian_backup_recovery(
            &self,
            request: Request<kms_grpc::kms::v1::BackupRecoveryRequest>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            METRICS.increment_request_counter(OP_CUSTODIAN_BACKUP_RECOVERY);
            self.backup_operator.custodian_backup_recovery(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CUSTODIAN_BACKUP_RECOVERY, tag);
            })
        }

        #[tracing::instrument(skip(self, request))]
        async fn backup_restore(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            METRICS.increment_request_counter(OP_BACKUP_RESTORE);
            self.backup_operator.backup_restore(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_BACKUP_RESTORE, tag);
            })
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_material_availability(
            &self,
            request: Request<Empty>,
        ) -> Result<Response<KeyMaterialAvailabilityResponse>, Status> {
            // Delegate to backup_operator which has access to crypto_storage
            self.backup_operator.get_key_material_availability(request).await
        }

        #[tracing::instrument(skip(self, _request))]
        async fn custodian_recovery_init(
            &self,
            _request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::RecoveryRequest>, Status> {
            Err(Status::unimplemented(
                "custodian_recovery_init is not implemented",
            ))
        }
    }
}
