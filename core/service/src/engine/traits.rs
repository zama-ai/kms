use hashing::DomainSep;
use kms_grpc::kms::v1::*;
use kms_grpc::{ContextId, EpochId};
use rand::CryptoRng;
use rand::RngCore;
use serde::Serialize;
use std::sync::Arc;
use tfhe::FheTypes;
use tonic::Request;
use tonic::Response;

use super::base::KmsFheKeyHandles;
use crate::cryptography::encryption::UnifiedPublicEncKey;
use crate::cryptography::signatures::{NodeSigningIdentity, Signature};
use crate::engine::base::KeyGenMetadata;
use crate::engine::utils::MetricedError;
use crate::engine::validation::VerifiedDestroyMpcContext;

pub trait BaseKms {
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

    #[expect(clippy::too_many_arguments)]
    fn user_decrypt(
        keys: &KmsFheKeyHandles,
        identity: Arc<NodeSigningIdentity>,
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
    async fn new_mpc_context(
        &self,
        request: Request<NewMpcContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    /// Check a destroy request without changing anything: parse it, resolve the signing schemes and
    /// domain, check the node can sign them, and check the context exists and is not the last one.
    async fn validate_destroy_mpc_context(
        &self,
        request: &DestroyMpcContextRequest,
    ) -> Result<VerifiedDestroyMpcContext, MetricedError>;

    /// Destroy an MPC context.
    async fn destroy_mpc_context(
        &self,
        verified: VerifiedDestroyMpcContext,
        destroyed_epochs: Vec<EpochId>,
    ) -> Result<Response<DestroyMpcContextResponse>, MetricedError>;

    async fn new_custodian_context(
        &self,
        request: Request<NewCustodianContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn destroy_custodian_context(
        &self,
        request: Request<DestroyCustodianContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn mpc_context_exists_and_consistent(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<bool>;

    async fn mpc_context_exists_in_cache(&self, context_id: &ContextId) -> bool;
}

#[tonic::async_trait]
pub trait EpochManager {
    async fn new_mpc_epoch(
        &self,
        request: Request<NewMpcEpochRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn get_epoch_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<EpochResultResponse>, MetricedError>;

    /// Destroy every epoch in `epoch_ids` as part of a context destruction.
    ///
    /// Idempotent and best-effort: an epoch that is not present (already destroyed, or never
    /// created on this party) is skipped; every listed epoch is attempted even if an earlier one
    /// fails; the first deletion error is returned only after all attempts, so a failed run can be
    /// retried until no shares remain.
    async fn destroy_mpc_epoch(
        &self,
        request: Request<DestroyMpcEpochRequest>,
    ) -> Result<Response<DestroyMpcEpochResponse>, MetricedError>;

    /// Destroy every epoch associated with `context_id`.
    /// This is needed for context destruction since the Context manager does not compose with the epoch manager.
    async fn destroy_epochs_for_context(
        &self,
        context_id: &ContextId,
    ) -> Result<Vec<EpochId>, MetricedError>;
}

#[tonic::async_trait]
pub trait BackupOperator {
    async fn get_operator_public_key(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, MetricedError>;

    async fn custodian_recovery_init(
        &self,
        request: Request<CustodianRecoveryInitRequest>,
    ) -> Result<Response<RecoveryRequest>, MetricedError>;

    async fn custodian_backup_recovery(
        &self,
        request: Request<CustodianRecoveryRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn restore_from_backup(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn get_key_material_availability(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<KeyMaterialAvailabilityResponse>, MetricedError>;
}

pub trait PrivateKeyMaterialMetadata {
    fn get_metadata(&self) -> &KeyGenMetadata;
}
