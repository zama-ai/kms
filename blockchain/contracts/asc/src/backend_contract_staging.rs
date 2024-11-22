use super::state::KmsContractStorage;
use crate::events::EmitEventVerifier as _;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_json_binary, Env, Response, StdError, StdResult, Storage, WasmMsg};
use cw_utils::must_pay;
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, InsecureCrsGenValues,
    KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues, KmsEvent,
    KmsOperation, OperationType, OperationValue, ReencryptResponseValues, ReencryptValues,
    SenderAllowedEvent, TransactionId, VerifyProvenCtValues,
};
use events::kms::{InsecureKeyGenValues, VerifyProvenCtResponseValues};
use sha3::{Digest, Sha3_256};
use std::ops::Deref;
use sylvia::types::ExecCtx;

const UCOSM: &str = "ucosm";

#[cw_serde]
pub struct ProofPayload {
    pub proof: String,
    pub ciphertext_handles: String,
}

#[cw_serde]
pub struct ProofMessage {
    pub verify_proof: ProofPayload,
}

/// Backend Smart Contract staging
/// - The following is a transitional implementation for the incoming CosmWasm smart contract.
/// - Part of the issue [#1468](https://github.com/zama-ai/kms-core/issues/1468)
pub struct BackendContract;

impl BackendContract {
    /// Processes a decryption request by performing these steps:
    /// - Verify the sender's payment capacity
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a proof verification message to the response
    pub fn process_decryption_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        decrypt: DecryptValues,
    ) -> StdResult<Response> {
        let ciphertext_handle_vectors: Vec<Vec<u8>> = decrypt
            .ciphertext_handles()
            .0
            .iter()
            .map(|ct| ct.to_vec())
            .collect();
        BackendContract::verify_payment_capacity(ctx, &ciphertext_handle_vectors)?;

        let external_handles_vector: Vec<Vec<u8>> = decrypt
            .external_handles()
            .clone()
            .ok_or(StdError::generic_err(
                "Error: external ciphertext handles are empty",
            ))?
            .into();
        let external_handles_string =
            BackendContract::stringify_ciphertext_handles(&external_handles_vector)?;
        let response =
            BackendContract::process_request_transaction(ctx, kms_storage, decrypt.clone().into())?;

        BackendContract::add_proof_verification_message(
            ctx,
            kms_storage,
            response,
            decrypt.proof().to_string(),
            external_handles_string,
        )
    }

    /// Processes a decryption response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_decryption_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    ) -> StdResult<Response> {
        let operation = "decryption_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            decrypt_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes a reencryption request by performing these steps:
    /// - Verify the sender's payment capacity
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a proof verification message to the response
    pub fn process_reencryption_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        reencrypt: ReencryptValues,
    ) -> StdResult<Response> {
        let ciphertext_handle_vector: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        BackendContract::verify_payment_capacity(ctx, &[ciphertext_handle_vector])?;

        let external_ciphertext_handle_vector: Vec<u8> = reencrypt
            .external_ciphertext_handle()
            .clone()
            .deref()
            .into();
        let external_handles_string =
            BackendContract::stringify_ciphertext_handles(&[external_ciphertext_handle_vector])?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            reencrypt.clone().into(),
        )?;
        BackendContract::add_proof_verification_message(
            ctx,
            kms_storage,
            response,
            reencrypt.proof().to_string(),
            external_handles_string,
        )
    }

    /// Processes a reencryption response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_reencryption_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    ) -> StdResult<Response> {
        let operation = "reencryption_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            reencrypt_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes a proven ciphertext verification request (which emits a KmsEvent)
    pub fn process_proven_ct_verification_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> StdResult<Response> {
        BackendContract::process_request_transaction(ctx, kms_storage, verify_proven_ct.into())
    }

    /// Processes a proven ciphertext verification response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_proven_ct_verification_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    ) -> StdResult<Response> {
        let operation = "proven_ct_verification_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            verify_proven_ct_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes a key generation preproc request by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_key_generation_preproc_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
    ) -> StdResult<Response> {
        let operation = "key_generation_preproc";
        BackendContract::check_sender_is_allowed(ctx, kms_storage, OperationType::Gen, operation)?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            KeyGenPreprocValues::default().into(),
        )?;
        BackendContract::add_sender_allowed_event(ctx, response, operation)
    }

    /// Processes a key generation preproc request response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_key_generation_preproc_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
    ) -> StdResult<Response> {
        let operation = "key_generation_preproc_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            KeyGenPreprocResponseValues::default().into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes a key generation request by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_key_generation_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        keygen: KeyGenValues,
    ) -> StdResult<Response> {
        let operation = "key_generation";
        BackendContract::check_sender_is_allowed(ctx, kms_storage, OperationType::Gen, operation)?;
        let response =
            BackendContract::process_request_transaction(ctx, kms_storage, keygen.into())?;
        BackendContract::add_sender_allowed_event(ctx, response, operation)
    }

    /// Processes a key generation response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_key_generation_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "key_generation_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            keygen_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes an insecure key generation request by skipping the
    /// preproc step by performing these steps:
    ///
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_insecure_key_generation_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        insecure_key_gen: InsecureKeyGenValues,
    ) -> StdResult<Response> {
        let operation = "insecure_key_generation";
        BackendContract::check_sender_is_allowed(ctx, kms_storage, OperationType::Gen, operation)?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            insecure_key_gen.into(),
        )?;
        BackendContract::add_sender_allowed_event(ctx, response, operation)
    }

    /// Processes an insecure key generation response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_insecure_key_generation_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "insecure_key_generation_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            keygen_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes a CRS generation request by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_crs_generation_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        crs_gen: CrsGenValues,
    ) -> StdResult<Response> {
        let operation = "crs_generation";
        BackendContract::check_sender_is_allowed(ctx, kms_storage, OperationType::Gen, operation)?;
        let response =
            BackendContract::process_request_transaction(ctx, kms_storage, crs_gen.into())?;
        BackendContract::add_sender_allowed_event(ctx, response, operation)
    }

    /// Processes a CRS generation response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_crs_generation_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "crs_generation_response";
        BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            crs_gen_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Processes an insecure CRS generation request by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_insecure_crs_generation_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        insecure_crs_gen: InsecureCrsGenValues,
    ) -> StdResult<Response> {
        let operation = "insecure_crs_generation";
        BackendContract::check_sender_is_allowed(ctx, kms_storage, OperationType::Gen, operation)?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            insecure_crs_gen.into(),
        )?;
        BackendContract::add_sender_allowed_event(ctx, response, operation)
    }

    /// Processes an insecure CRS generation response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a sender allowed event to the response
    pub fn process_insecure_crs_generation_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "insecure_crs_generation_response";
        BackendContract::check_sender_is_allowed(&ctx, kms_storage, OperationType::Gen, operation)?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            crs_gen_response.into(),
        )?;
        BackendContract::add_sender_allowed_event(&ctx, response, operation)
    }

    /// Returns the transaction ID by hashing the combination of the current block height
    /// and transaction index, i.e. the tuple (height, txn_idx)
    pub fn compute_transaction_id(env: &Env) -> StdResult<TransactionId> {
        let block_height = env.block.height;
        let transaction_index = env
            .transaction
            .as_ref()
            .ok_or_else(|| StdError::generic_err("Cannot find transaction index in env"))?
            .index;
        // TODO: Redesign the hashing algorithm [#1518](https://github.com/zama-ai/kms-core/issues/1518)
        let mut hasher = Sha3_256::new();
        hasher.update("KMS_BLOCK_HEIGHT");
        hasher.update(block_height.to_string().len().to_le_bytes());
        hasher.update(block_height.to_string());
        hasher.update("KMS_TRANSACTION_INDEX");
        hasher.update(transaction_index.to_string().len().to_be_bytes());
        hasher.update(transaction_index.to_string());
        let result = hasher.finalize();
        Ok(result[..20].to_vec().into())
    }

    /// Process request transaction
    ///
    /// Processes a request transaction and emits the corresponding event
    fn process_request_transaction(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        operation: OperationValue,
    ) -> StdResult<Response> {
        let txn_id = BackendContract::compute_transaction_id(&ctx.env)?;
        kms_storage.update_request_transaction(ctx.deps.storage, &ctx.env, &txn_id, &operation)?;
        let response =
            BackendContract::emit_event(kms_storage, ctx.deps.storage, &txn_id, &operation)?;
        Ok(response)
    }

    /// Process response transaction
    ///
    /// Processes a response transaction and emits the corresponding event if conditions are met.
    /// More info on the conditions to meet can be found in `events.rs`
    /// Note that response values cannot be saved along a transaction ID if this ID cannot be found
    /// in the `transactions` map, which means not request has been saved for this transaction.
    fn process_response_transaction(
        storage: &mut dyn Storage,
        kms_storage: &KmsContractStorage,
        transaction_id: &TransactionId,
        operation: OperationValue,
    ) -> StdResult<Response> {
        // Check that the transaction exists. We should not store response values for a
        // transaction if the transaction does not exist
        // Note that we might also check that this transaction (if it exists) also has the corresponding
        // request value in the future
        if !kms_storage.has_transaction(storage, transaction_id) {
            return Err(StdError::generic_err(format!(
                "Transaction with id {:?} not found while trying to save response operation value `{:?}`",
                transaction_id,
                operation
            )));
        }

        kms_storage.save_response_value(storage, transaction_id, &operation)?;

        let response =
            BackendContract::emit_event(kms_storage, storage, transaction_id, &operation)?;
        Ok(response)
    }

    /// Verifies that sender has sufficient funds to cover the ciphertext storage payment amount.
    fn verify_payment_capacity(
        ctx: &ExecCtx,
        ciphertext_handle_vectors: &[Vec<u8>],
    ) -> StdResult<()> {
        let ciphertext_handles_size: u32 = ciphertext_handle_vectors
            .iter()
            .map(|handle| BackendContract::calculate_ciphertext_handle_size(&handle[..4]))
            .sum();

        // This implicitly ensures the payment amount is included in the message
        let payment_amount = must_pay(&ctx.info, UCOSM).map_err(|_| {
            StdError::generic_err(
                format!("Unable to find ciphertext storage payment message in context - ciphertext_handles_size: {}", ciphertext_handles_size)
            )
        })?;

        if payment_amount < ciphertext_handles_size.into() {
            return Err(
                StdError::generic_err(
                    format!(
                        "Insufficient funds sent to cover the ciphertext storage size - payment_amount: {}, ciphertext_handles_size: {}",
                        payment_amount,
                        ciphertext_handles_size
                    )
                )
            );
        }
        Ok(())
    }

    /// Adds a "fire and forget" message to the response for proof verification: if the stored debug proof field is disabled.
    fn add_proof_verification_message(
        ctx: &ExecCtx,
        kms_storage: &KmsContractStorage,
        response: Response,
        proof: String,
        ciphertext_handles: String,
    ) -> StdResult<Response> {
        if !kms_storage.get_debug_proof(ctx.deps.storage)? {
            let msg = ProofMessage {
                verify_proof: ProofPayload {
                    proof,
                    ciphertext_handles,
                },
            };
            let msg = WasmMsg::Execute {
                contract_addr: kms_storage.get_verify_proof_contract_address(ctx.deps.storage)?,
                msg: to_json_binary(&msg)?,
                funds: vec![],
            };
            Ok(response.add_message(msg))
        } else {
            Ok(response)
        }
    }

    fn add_sender_allowed_event(
        ctx: &ExecCtx,
        response: Response,
        operation: &str,
    ) -> StdResult<Response> {
        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());
        Ok(response.add_event(sender_allowed_event))
    }

    /// Check that the sender's address is allowed to trigger the given operation type.
    pub fn check_sender_is_allowed(
        ctx: &ExecCtx,
        kms_storage: &KmsContractStorage,
        operation_type: OperationType,
        operation: &str,
    ) -> StdResult<()> {
        kms_storage
            .check_address_is_allowed(ctx.deps.storage, ctx.info.sender.as_str(), operation_type)
            .map_err(|e| StdError::generic_err(format!("Operation `{}`: {}", operation, e)))
    }

    /// Returns a String representation of the given handles. Serialization is done using serde_json.
    fn stringify_ciphertext_handles(ciphertext_handles: &[Vec<u8>]) -> StdResult<String> {
        serde_json::to_string(&ciphertext_handles).map_err(|e| {
            StdError::generic_err(format!(
                "Error serializing external ciphertext handles: {}",
                e
            ))
        })
    }

    /// Returns ciphertext size from given handle. Size is encoded as u32 in the first 4 bytes of the handle.
    fn calculate_ciphertext_handle_size(ciphertext_handle: &[u8]) -> u32 {
        ((ciphertext_handle[0] as u32) << 24)
            | ((ciphertext_handle[1] as u32) << 16)
            | ((ciphertext_handle[2] as u32) << 8)
            | (ciphertext_handle[3] as u32)
    }

    /// TODO: This function must be implemented as part of the EventEmitStrategy trait (/events.rs)
    /// but is included here in staging mode until implementing the proper CosmWasm smart contract.
    ///
    /// Emit a KmsEvent if relevant
    ///
    /// An event is always emitted if the operation is a request. For responses, the event is emitted
    /// if the transaction has received enough operations (of the same response type) to satisfy the
    /// core configuration's thresholds.
    fn emit_event(
        kms_storage: &KmsContractStorage,
        storage: &mut dyn Storage,
        txn_id: &TransactionId,
        operation: &OperationValue,
    ) -> StdResult<Response> {
        let mut response = Response::new();

        let operation = operation.into_kms_operation();
        let should_emit =
            BackendContract::should_emit_event(kms_storage, storage, txn_id, &operation)?;

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

    /// TODO: This function must be implemented as part of the EventEmitStrategy trait (/events.rs)
    /// but is included here in staging mode until implementing the proper CosmWasm smart contract.
    ///
    /// Check if an event should be emitted for a given operation
    ///
    /// An event is always emitted if the operation is a request. For responses, the event is emitted
    /// if the transaction has received enough operations (of the same response type) to satisfy the
    /// core configuration's thresholds.
    fn should_emit_event(
        kms_storage: &KmsContractStorage,
        storage: &mut dyn Storage,
        txn_id: &TransactionId,
        operation: &KmsOperation,
    ) -> StdResult<bool> {
        // Always emit events for requests
        if operation.is_request() {
            return Ok(true);
        }

        // Emit events for responses if the core configuration's thresholds are met
        if operation.is_response() {
            let response_values = kms_storage
                .get_values_from_transaction_and_operation(storage, txn_id, operation)?;
            let core_conf = kms_storage.load_core_conf(storage)?;
            return Ok(operation.should_emit_response_event(&core_conf, &response_values));
        }

        // This should never happen: currently, an operation is either a request or a response
        Ok(false)
    }
}
