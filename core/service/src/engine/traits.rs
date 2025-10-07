use kms_grpc::kms::v1::CiphertextFormat;
use kms_grpc::kms::v1::CustodianRecoveryInitRequest;
use kms_grpc::kms::v1::CustodianRecoveryRequest;
use kms_grpc::kms::v1::DestroyCustodianContextRequest;
use kms_grpc::kms::v1::DestroyKmsContextRequest;
use kms_grpc::kms::v1::Empty;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::kms::v1::NewCustodianContextRequest;
use kms_grpc::kms::v1::NewKmsContextRequest;
use kms_grpc::kms::v1::OperatorPublicKey;
use kms_grpc::kms::v1::RecoveryRequest;
use kms_grpc::kms::v1::TypedPlaintext;
use rand::CryptoRng;
use rand::RngCore;
use serde::Serialize;
use tfhe::FheTypes;
use threshold_fhe::hashing::DomainSep;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::cryptography::internal_crypto_types::PublicSigKey;
use crate::cryptography::internal_crypto_types::Signature;
use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;

use super::base::KmsFheKeyHandles;

pub trait BaseKms {
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        dsep: &DomainSep,
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()>;
    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<Signature>;
    fn digest<T: ?Sized + AsRef<[u8]>>(
        domain_separator: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<Vec<u8>>;
}
/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms: BaseKms {
    fn public_decrypt(
        keys: &KmsFheKeyHandles,
        ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
    ) -> anyhow::Result<TypedPlaintext>;
    #[allow(clippy::too_many_arguments)]
    fn user_decrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        ct_type: FheTypes,
        ct_format: CiphertextFormat,
        digest_link: &[u8],
        enc_key: &UnifiedPublicEncKey,
        client_address: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}

#[tonic::async_trait]
pub trait ContextManager {
    async fn new_kms_context(
        &self,
        request: Request<NewKmsContextRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn destroy_kms_context(
        &self,
        request: Request<DestroyKmsContextRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn new_custodian_context(
        &self,
        request: Request<NewCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn destroy_custodian_context(
        &self,
        request: Request<DestroyCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status>;
}

#[tonic::async_trait]
pub trait BackupOperator {
    async fn get_operator_public_key(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status>;

    async fn custodian_recovery_init(
        &self,
        request: Request<CustodianRecoveryInitRequest>,
    ) -> Result<Response<RecoveryRequest>, Status>;

    async fn custodian_backup_recovery(
        &self,
        request: Request<CustodianRecoveryRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn restore_from_backup(&self, request: Request<Empty>)
        -> Result<Response<Empty>, Status>;

    async fn get_key_material_availability(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<KeyMaterialAvailabilityResponse>, Status>;
}
