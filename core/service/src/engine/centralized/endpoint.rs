use crate::engine::centralized::central_kms::RealCentralizedKms;
use crate::engine::centralized::service::{delete_kms_context_impl, new_kms_context_impl};
use crate::tonic_some_or_err;
use crate::vault::storage::Storage;
use kms_grpc::kms::v1::{
    self, Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocResult, OperatorPublicKey,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use tonic::{Request, Response, Status};

use crate::engine::centralized::service::{crs_gen_impl, get_crs_gen_result_impl};
use crate::engine::centralized::service::{get_key_gen_result_impl, key_gen_impl};
use crate::engine::centralized::service::{
    get_public_decryption_result_impl, get_user_decryption_result_impl, public_decrypt_impl,
    user_decrypt_impl,
};

#[tonic::async_trait]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    CoreServiceEndpoint for RealCentralizedKms<PubS, PrivS>
{
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
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
        self.key_gen(request).await
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_key_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::KeyGenResult>, Status> {
        self.get_key_gen_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn key_gen(
        &self,
        request: Request<kms_grpc::kms::v1::KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        key_gen_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_key_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::KeyGenResult>, Status> {
        get_key_gen_result_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn user_decrypt(
        &self,
        request: Request<kms_grpc::kms::v1::UserDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_decrypt_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_user_decryption_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::UserDecryptionResponse>, Status> {
        get_user_decryption_result_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn public_decrypt(
        &self,
        request: Request<kms_grpc::kms::v1::PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        public_decrypt_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_public_decryption_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::PublicDecryptionResponse>, Status> {
        get_public_decryption_result_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn crs_gen(
        &self,
        request: Request<kms_grpc::kms::v1::CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        crs_gen_impl(self, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_crs_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::CrsGenResult>, Status> {
        get_crs_gen_result_impl(self, request).await
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_crs_gen(
        &self,
        request: Request<kms_grpc::kms::v1::CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.crs_gen(request).await
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_crs_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::CrsGenResult>, Status> {
        self.get_crs_gen_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn new_kms_context(
        &self,
        request: Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        new_kms_context_impl(&self.crypto_storage, request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn destroy_kms_context(
        &self,
        request: Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<Response<Empty>, Status> {
        delete_kms_context_impl(&self.crypto_storage, request).await
    }

    #[tracing::instrument(skip(self, _request))]
    async fn new_custodian_context(
        &self,
        _request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "new_custodian_context is not implemented",
        ))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn destroy_custodian_context(
        &self,
        _request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "destroy_custodian_context is not implemented",
        ))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_operator_public_key(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status> {
        Err(Status::unimplemented(
            "get_operator_public_key is not implemented",
        ))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn custodian_backup_restore(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented(
            "custodian_backup_restore is not implemented",
        ))
    }
}
