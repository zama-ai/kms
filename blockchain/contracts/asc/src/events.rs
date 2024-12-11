use crate::external_queries::KmsConfigQuery;
use cosmwasm_std::{DepsMut, Response, StdResult};
use events::kms::{KmsOperation, OperationValue, TransactionId};

pub trait EventEmitStrategy {
    // TODO: remove this dead_code allowing once the BSC is fully implemented
    #![allow(dead_code)]
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
