use cosmwasm_std::{Response, StdResult, Storage};
use events::kms::{KmsCoreConf, KmsOperation, OperationValue, TransactionId};

pub trait EventEmitStrategy {
    // TODO: remove this dead_code allowing once the BSC is fully implemented
    #![allow(dead_code)]
    fn emit_event(
        &self,
        storage: &mut dyn Storage,
        txn_id: &TransactionId,
        operation: &OperationValue,
    ) -> StdResult<Response>;

    fn should_emit_event(
        &self,
        storage: &mut dyn Storage,
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
    core_conf: &KmsCoreConf,
    operation_values: &[OperationValue],
    check_type: F,
) -> bool
where
    F: FnMut(&&OperationValue) -> bool,
{
    reach(
        operation_values,
        core_conf.response_count_for_majority_vote(),
        check_type,
    )
}

/// Check if a given number of operations of a certain type have been received to satisfy the
/// reconstruction threshold
fn reach_reconstruction_threshold<F>(
    core_conf: &KmsCoreConf,
    operation_values: &[OperationValue],
    check_type: F,
) -> bool
where
    F: FnMut(&&OperationValue) -> bool,
{
    reach(
        operation_values,
        core_conf.response_count_for_reconstruction(),
        check_type,
    )
}

pub trait EmitEventVerifier {
    fn should_emit_response_event(
        &self,
        core_conf: &KmsCoreConf,
        operation_values: &[OperationValue],
    ) -> bool;
}

impl EmitEventVerifier for KmsOperation {
    /// Check if a response event should be emitted for a given operation
    ///
    /// A response event is emitted if the transaction has received enough operations (of the same
    /// response type) to satisfy the core configuration's thresholds.
    fn should_emit_response_event(
        &self,
        core_conf: &KmsCoreConf,
        operation_values: &[OperationValue],
    ) -> bool {
        match self {
            KmsOperation::VerifyProvenCtResponse => {
                reach_majority_vote_threshold(core_conf, operation_values, |t| {
                    t.is_verify_proven_ct_response()
                })
            }
            KmsOperation::ReencryptResponse => {
                reach_reconstruction_threshold(core_conf, operation_values, |t| {
                    t.is_reencrypt_response()
                })
            }
            KmsOperation::DecryptResponse => {
                reach_majority_vote_threshold(core_conf, operation_values, |t| {
                    t.is_decrypt_response()
                })
            }
            KmsOperation::KeyGenResponse => {
                reach_majority_vote_threshold(core_conf, operation_values, |t| {
                    t.is_key_gen_response()
                })
            }
            KmsOperation::CrsGenResponse => {
                reach_majority_vote_threshold(core_conf, operation_values, |t| {
                    t.is_crs_gen_response()
                })
            }
            KmsOperation::KeyGenPreprocResponse => true,

            _ => false,
        }
    }
}
