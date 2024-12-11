use crate::contract::BackendContract;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{DepsMut, Empty, Response, StdResult};
use events::kms::{KmsConfig, KmsEvent, KmsOperation, OperationValue, TransactionId};

// Query message for getting the KMS configuration
// Note that we need to do this instead of importing the msg directly from the CSC's
// crate because having a contract as a dependency of another one creates some conflict when
// building them
// This means:
// - the struct must contain the targeted method's name as a field
// - this field must provide the necessary inputs as specified in the method's definition (here,
// it is empty since we are only querying the KMS configuration)
#[cw_serde]
struct KmsConfigQueryMsg {
    get_kms_configuration: Empty,
}

pub trait EventEmitStrategy {
    fn emit_event(
        &self,
        deps: &DepsMut,
        txn_id: &TransactionId,
        operation: &OperationValue,
    ) -> StdResult<Response>;

    fn should_emit_event(
        &self,
        deps: &DepsMut,
        txn_id: &TransactionId,
        operation: &KmsOperation,
    ) -> StdResult<bool>;
}

impl EventEmitStrategy for BackendContract {
    /// Emit a KmsEvent if relevant
    ///
    /// An event is always emitted if the operation is a request. For responses, the event is emitted
    /// if the transaction has received enough operations (of the same response type) to satisfy the
    /// KMS configuration's thresholds.
    fn emit_event(
        &self,
        deps: &DepsMut,
        txn_id: &TransactionId,
        operation: &OperationValue,
    ) -> StdResult<Response> {
        let mut response = Response::new();

        let operation = operation.into_kms_operation();
        let should_emit = self.should_emit_event(deps, txn_id, &operation)?;

        if should_emit {
            response = response.add_event(
                KmsEvent::builder()
                    .txn_id(txn_id.to_vec())
                    .operation(operation)
                    .build(),
            );
        }

        Ok(response)
    }

    /// Check if an event should be emitted for a given operation
    ///
    /// An event is always emitted if the operation is a request. For responses, the event is emitted
    /// if the transaction has received enough operations (of the same response type) to satisfy the
    /// KMS configuration's thresholds.
    fn should_emit_event(
        &self,
        deps: &DepsMut,
        txn_id: &TransactionId,
        operation: &KmsOperation,
    ) -> StdResult<bool> {
        // Always emit events for requests
        if operation.is_request() {
            return Ok(true);
        }

        // Emit events for responses if the configuration's thresholds are met
        if operation.is_response() {
            let response_values = self.storage.get_values_from_transaction_and_operation(
                deps.storage,
                txn_id,
                operation,
            )?;

            // Get the KMS configuration from the CSC
            let kms_configuration = deps.querier.query_wasm_smart::<KmsConfig>(
                self.storage.get_csc_address(deps.storage)?,
                &KmsConfigQueryMsg {
                    get_kms_configuration: Empty {},
                },
            )?;

            return Ok(operation.should_emit_response_event(&kms_configuration, &response_values));
        }

        // This should never happen: currently, an operation is either a request or a response
        Ok(false)
    }
}

/// Check if a given number of operations of a certain type have been received
fn reach<F>(operation_values: &[OperationValue], amount: usize, check_type: F) -> bool
where
    F: FnMut(&&OperationValue) -> bool,
{
    operation_values.iter().filter(check_type).count() >= amount
}

/// Check if a given number of operations of a certain type have been received to satisfy the
/// majority vote threshold
fn reach_majority_vote_threshold<F>(
    kms_configuration: &KmsConfig,
    operation_values: &[OperationValue],
    check_type: F,
) -> bool
where
    F: FnMut(&&OperationValue) -> bool,
{
    reach(
        operation_values,
        kms_configuration.response_count_for_majority_vote(),
        check_type,
    )
}

/// Check if a given number of operations of a certain type have been received to satisfy the
/// reconstruction threshold
fn reach_reconstruction_threshold<F>(
    kms_configuration: &KmsConfig,
    operation_values: &[OperationValue],
    check_type: F,
) -> bool
where
    F: FnMut(&&OperationValue) -> bool,
{
    reach(
        operation_values,
        kms_configuration.response_count_for_reconstruction(),
        check_type,
    )
}

pub trait EmitEventVerifier {
    fn should_emit_response_event(
        &self,
        kms_configuration: &KmsConfig,
        operation_values: &[OperationValue],
    ) -> bool;
}

impl EmitEventVerifier for KmsOperation {
    /// Check if a response event should be emitted for a given operation
    ///
    /// A response event is emitted if the transaction has received enough operations (of the same
    /// response type) to satisfy the KMS configuration's thresholds.
    fn should_emit_response_event(
        &self,
        kms_configuration: &KmsConfig,
        operation_values: &[OperationValue],
    ) -> bool {
        match self {
            KmsOperation::VerifyProvenCtResponse => {
                reach_majority_vote_threshold(kms_configuration, operation_values, |t| {
                    t.is_verify_proven_ct_response()
                })
            }
            KmsOperation::ReencryptResponse => {
                reach_reconstruction_threshold(kms_configuration, operation_values, |t| {
                    t.is_reencrypt_response()
                })
            }
            KmsOperation::DecryptResponse => {
                reach_majority_vote_threshold(kms_configuration, operation_values, |t| {
                    t.is_decrypt_response()
                })
            }
            KmsOperation::KeyGenResponse => {
                reach_majority_vote_threshold(kms_configuration, operation_values, |t| {
                    t.is_key_gen_response()
                })
            }
            KmsOperation::CrsGenResponse => {
                reach_majority_vote_threshold(kms_configuration, operation_values, |t| {
                    t.is_crs_gen_response()
                })
            }
            KmsOperation::KeyGenPreprocResponse => true,

            _ => false,
        }
    }
}
