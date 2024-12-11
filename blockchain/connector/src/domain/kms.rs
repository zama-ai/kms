use events::kms::{FheParameter, KmsEvent, OperationValue};
use tokio::sync::oneshot::Receiver;
use tonic::async_trait;

use super::blockchain::KmsOperationResponse;

/// Enum we use during catchup.
pub enum CatchupResult {
    /// Result was available on Core
    Now(anyhow::Result<KmsOperationResponse>),
    /// Request existed but Core is currently computing the result
    Later(Receiver<anyhow::Result<KmsOperationResponse>>),
    /// Request does not exist
    NotFound,
}

#[async_trait]
pub trait Kms {
    /// Process a KMS Event from the connector to the core
    /// - _event_ is the event emitted by the KMS BC
    /// - _operation_ is the operation fetched from the KMS BC based on the event
    /// - _param_choice_ is the parameter choice fetched from the CSC
    async fn run(
        &self,
        event: KmsEvent,
        operation: OperationValue,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>>;

    /// Poll the KMS for an event that may have already been queried
    /// this is used in catchup mechanism by the connector
    ///
    /// - _event_ is the event emited by the KMS BC
    /// - _operation_ is the operation fetched from the KMS BC based on the event
    /// - _param_choice_ is the parameter choice fetched from the CSC
    ///
    /// Returns a [`CatchupResult`] variant that correctly deals
    /// with (a)synchronicity of the task.
    ///
    /// This __HEAVILY__ rely on the assumption that the KMS Core
    /// will return a [`Code::NotFound`] error if there
    /// has been no request for the given [`RequestId`]
    ///
    /// It also assumes the parameter choice has __NOT__ changed
    /// as we are using the current one to treat old requests
    async fn run_catchup(
        &self,
        event: KmsEvent,
        operation: OperationValue,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult>;
}
