use crate::contract::KmsContract;
use crate::state::KmsCoreConf;
use cosmwasm_std::{Response, StdResult};
use events::kms::{KmsEvent, OperationValue, Transaction};
use events::HexVector;
use sylvia::types::ExecCtx;

pub trait EventEmitStrategy {
    fn emit_event<T>(
        &self,
        ctx: &ExecCtx,
        txn_id: &[u8],
        proof: HexVector,
        operation: &T,
    ) -> StdResult<Response>
    where
        T: Into<OperationValue> + Clone;
}

impl EventEmitStrategy for KmsContract {
    fn emit_event<T>(
        &self,
        ctx: &ExecCtx,
        txn_id: &[u8],
        proof: HexVector,
        operation: &T,
    ) -> StdResult<Response>
    where
        T: Into<OperationValue> + Clone,
    {
        let mut response = Response::new();
        let operation = operation.clone().into();
        let transaction = self
            .storage
            .load_transaction(ctx.deps.storage, txn_id.to_vec().into())?;
        let core_conf = self.storage.load_core_conf(ctx.deps.storage)?;
        if operation.should_emit_event(&core_conf, &transaction) {
            response = response.add_event(
                KmsEvent::builder()
                    .txn_id(txn_id.to_vec())
                    .operation(operation)
                    .proof(proof)
                    .build()
                    .into(),
            );
        }

        Ok(response)
    }
}

trait EmitEventVerifier {
    fn should_emit_event(&self, core_conf: &KmsCoreConf, tx: &Transaction) -> bool;

    fn reach<F>(&self, tx: &Transaction, amount: usize, check_type: F) -> bool
    where
        F: FnMut(&&OperationValue) -> bool,
    {
        tx.operations().iter().filter(check_type).count() >= amount
    }

    fn reach_threshold<F>(&self, core_conf: &KmsCoreConf, tx: &Transaction, check_type: F) -> bool
    where
        F: FnMut(&&OperationValue) -> bool,
    {
        self.reach(tx, core_conf.calculate_threshold() + 1, check_type)
    }
}

impl EmitEventVerifier for OperationValue {
    fn should_emit_event(&self, core_conf: &KmsCoreConf, transaction: &Transaction) -> bool {
        if self.is_request() {
            return true;
        }
        match self {
            OperationValue::ReencryptResponse(values) => {
                self.reach(transaction, values.servers_needed() as usize, |t| {
                    t.is_reencrypt_response()
                })
            }
            OperationValue::DecryptResponse(_) => {
                self.reach_threshold(core_conf, transaction, |t| t.is_decrypt_response())
            }
            OperationValue::KeyGenResponse(_) => {
                self.reach_threshold(core_conf, transaction, |t| t.is_key_gen_response())
            }
            OperationValue::CrsGenResponse(_) => {
                self.reach_threshold(core_conf, transaction, |t| t.is_crs_gen_response())
            }
            OperationValue::KeyGenPreprocResponse(_) => true,

            _ => false,
        }
    }
}
