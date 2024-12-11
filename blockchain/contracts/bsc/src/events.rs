use crate::contract::BackendContract;
use crate::external_queries::KmsConfigQuery;
use cosmwasm_std::{DepsMut, Response, StdResult};
use events::kms::{KmsEvent, KmsOperation, OperationValue, TransactionId};

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

            // Get the CSC address
            let csc_address = self.storage.get_csc_address(deps.storage)?;

            return operation.should_emit_response_event(deps, csc_address, &response_values);
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
    deps: &DepsMut,
    csc_address: String,
    operation_values: &[OperationValue],
    check_type: F,
) -> StdResult<bool>
where
    F: FnMut(&&OperationValue) -> bool,
{
    // Get the response_count_for_majority_vote from the CSC
    let amount: usize = deps.querier.query_wasm_smart(
        csc_address,
        &KmsConfigQuery::GetResponseCountForMajorityVote {},
    )?;

    Ok(reach(operation_values, amount, check_type))
}

/// Check if a given number of operations of a certain type have been received to satisfy the
/// reconstruction threshold
fn reach_reconstruction_threshold<F>(
    deps: &DepsMut,
    csc_address: String,
    operation_values: &[OperationValue],
    check_type: F,
) -> StdResult<bool>
where
    F: FnMut(&&OperationValue) -> bool,
{
    // Get the response_count_for_reconstruction from the CSC
    let amount: usize = deps.querier.query_wasm_smart(
        csc_address,
        &KmsConfigQuery::GetResponseCountForReconstruction {},
    )?;

    Ok(reach(operation_values, amount, check_type))
}

pub trait EmitEventVerifier {
    fn should_emit_response_event(
        &self,
        deps: &DepsMut,
        csc_address: String,
        operation_values: &[OperationValue],
    ) -> StdResult<bool>;
}

impl EmitEventVerifier for KmsOperation {
    /// Check if a response event should be emitted for a given operation
    ///
    /// A response event is emitted if the transaction has received enough operations (of the same
    /// response type) to satisfy the KMS configuration's thresholds.
    fn should_emit_response_event(
        &self,
        deps: &DepsMut,
        csc_address: String,
        operation_values: &[OperationValue],
    ) -> StdResult<bool> {
        match self {
            KmsOperation::VerifyProvenCtResponse => {
                reach_majority_vote_threshold(deps, csc_address, operation_values, |t| {
                    t.is_verify_proven_ct_response()
                })
            }
            KmsOperation::ReencryptResponse => {
                reach_reconstruction_threshold(deps, csc_address, operation_values, |t| {
                    t.is_reencrypt_response()
                })
            }
            KmsOperation::DecryptResponse => {
                reach_majority_vote_threshold(deps, csc_address, operation_values, |t| {
                    t.is_decrypt_response()
                })
            }
            KmsOperation::KeyGenResponse => {
                reach_majority_vote_threshold(deps, csc_address, operation_values, |t| {
                    t.is_key_gen_response()
                })
            }
            KmsOperation::CrsGenResponse => {
                reach_majority_vote_threshold(deps, csc_address, operation_values, |t| {
                    t.is_crs_gen_response()
                })
            }
            KmsOperation::KeyGenPreprocResponse => Ok(true),

            _ => Ok(false),
        }
    }
}
