use crate::engine::threshold::threshold_kms::ThresholdKms;
use crate::engine::threshold::traits::{
    BackupOperator, ContextManager, CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator,
    PublicDecryptor, UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use kms_grpc::kms::v1::*;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
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
            self.initiator.init(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen_preproc(
            &self,
            request: Request<KeyGenPreprocRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.keygen_preprocessor.key_gen_preproc(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_preproc_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenPreprocResult>, Status> {
            self.keygen_preprocessor.get_result(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            self.key_generator.key_gen(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            self.key_generator.get_result(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn user_decrypt(
            &self,
            request: Request<UserDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.user_decryptor.user_decrypt(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_user_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<UserDecryptionResponse>, Status> {
            self.user_decryptor.get_result(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn public_decrypt(
            &self,
            request: Request<PublicDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.decryptor.public_decrypt(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_public_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<PublicDecryptionResponse>, Status> {
            self.decryptor.get_result(request).await
        }


        #[tracing::instrument(skip(self, request))]
        async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            self.crs_generator.crs_gen(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            self.crs_generator.get_result(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            self.insecure_key_generator.insecure_key_gen(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            self.insecure_key_generator.get_result(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            self.insecure_crs_generator.insecure_crs_gen(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            self.insecure_crs_generator.get_result(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn new_kms_context(
            &self,
            request: Request<NewKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.new_kms_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_kms_context(
            &self,
            request: Request<DestroyKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.destroy_kms_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn new_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.new_custodian_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.destroy_custodian_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_operator_public_key(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::OperatorPublicKey>, Status> {
            self.backup_operator.get_operator_public_key(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn custodian_backup_restore(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            self.backup_operator.custodian_backup_restore(request).await
        }
    }
}
