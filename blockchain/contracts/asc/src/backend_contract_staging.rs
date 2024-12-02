use super::state::KmsContractStorage;
use crate::events::EmitEventVerifier as _;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_json_binary, Env, Response, StdError, StdResult, Storage, WasmMsg};
use cw_utils::must_pay;
use events::kms::{
    ContractAclUpdatedEvent, CrsGenResponseValues, CrsGenValues, DecryptResponseValues,
    DecryptValues, InsecureCrsGenValues, KeyAccessAllowedEvent, KeyGenPreprocResponseValues,
    KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues, KmsEvent, KmsOperation, OperationType,
    OperationValue, ReencryptResponseValues, ReencryptValues, SenderAllowedEvent, TransactionId,
    VerifyProvenCtValues,
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
    /// - Add a proof verification message and key access allowed event to the response
    pub fn process_decryption_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        decrypt: DecryptValues,
    ) -> StdResult<Response> {
        let key_access_allowed_event = BackendContract::check_key_access_is_allowed(
            ctx,
            kms_storage,
            decrypt.key_id().to_string(),
        )?;

        let ciphertext_handle_vectors: Vec<Vec<u8>> = decrypt
            .ciphertext_handles()
            .0
            .iter()
            .map(|ct| ct.to_vec())
            .collect();
        BackendContract::verify_sender_payment_capacity(ctx, &ciphertext_handle_vectors)?;

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
            BackendContract::process_request_transaction(ctx, kms_storage, decrypt.clone().into())?
                .add_event(key_access_allowed_event);
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
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
        )?
        .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a reencryption request by performing these steps:
    /// - Verify the sender's payment capacity
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add a proof verification message and key access allowed event to the response
    pub fn process_reencryption_request(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        reencrypt: ReencryptValues,
    ) -> StdResult<Response> {
        let key_access_allowed_event = BackendContract::check_key_access_is_allowed(
            ctx,
            kms_storage,
            reencrypt.key_id().to_string(),
        )?;

        let ciphertext_handle_vector: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        BackendContract::verify_sender_payment_capacity(ctx, &[ciphertext_handle_vector])?;

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
        )?
        .add_event(key_access_allowed_event);
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
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
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
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
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            ctx,
            kms_storage,
            OperationType::Gen,
            operation,
        )?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            KeyGenPreprocValues::default().into(),
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
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
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            ctx,
            kms_storage,
            OperationType::Gen,
            operation,
        )?;
        let response =
            BackendContract::process_request_transaction(ctx, kms_storage, keygen.into())?
                .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a key generation response by performing these steps:
    /// - Check if the sender is allowed to execute this operation
    /// - Include the sender in the stored ACL for generated key ID
    /// - Process the transaction (which emits a KmsEvent)
    /// - Add contract ACL updated and sender allowed events to the response
    pub fn process_key_generation_response(
        ctx: ExecCtx,
        kms_storage: &KmsContractStorage,
        transaction_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "key_generation_response";
        let key_id = keygen_response.request_id().to_string();

        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;

        let transaction_sender =
            kms_storage.get_transaction_sender(ctx.deps.storage, &transaction_id)?;
        kms_storage.add_address_to_acl(ctx.deps.storage, &key_id, &transaction_sender)?;
        let contract_acl_updated_event =
            ContractAclUpdatedEvent::new(key_id, ctx.info.sender.to_string());

        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            keygen_response.into(),
        )?
        .add_event(sender_allowed_event)
        .add_event(contract_acl_updated_event);

        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            ctx,
            kms_storage,
            OperationType::Gen,
            operation,
        )?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            insecure_key_gen.into(),
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let key_id = keygen_response.request_id().to_string();

        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Response,
            operation,
        )?;

        let transaction_sender =
            kms_storage.get_transaction_sender(ctx.deps.storage, &transaction_id)?;
        kms_storage.add_address_to_acl(ctx.deps.storage, &key_id, &transaction_sender)?;
        let contract_acl_updated_event =
            ContractAclUpdatedEvent::new(key_id, ctx.info.sender.to_string());

        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            keygen_response.into(),
        )?;
        Ok(response
            .add_event(sender_allowed_event)
            .add_event(contract_acl_updated_event))
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            ctx,
            kms_storage,
            OperationType::Gen,
            operation,
        )?;
        let response =
            BackendContract::process_request_transaction(ctx, kms_storage, crs_gen.into())?
                .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
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
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            ctx,
            kms_storage,
            OperationType::Gen,
            operation,
        )?;
        let response = BackendContract::process_request_transaction(
            ctx,
            kms_storage,
            insecure_crs_gen.into(),
        )?
        .add_event(sender_allowed_event);
        Ok(response)
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
        let sender_allowed_event = BackendContract::check_sender_is_allowed(
            &ctx,
            kms_storage,
            OperationType::Gen,
            operation,
        )?;
        let response = BackendContract::process_response_transaction(
            ctx.deps.storage,
            kms_storage,
            &transaction_id,
            crs_gen_response.into(),
        )?
        .add_event(sender_allowed_event);
        Ok(response)
    }

    pub fn grant_key_access_to_address(
        ctx: &mut ExecCtx,
        kms_storage: &KmsContractStorage,
        key_id: String,
        new_address: String,
    ) -> StdResult<Response> {
        let key_access_allowed_event =
            BackendContract::check_key_access_is_allowed(ctx, kms_storage, key_id.clone())?;
        kms_storage.add_address_to_acl(ctx.deps.storage, &key_id, &new_address)?;
        let contract_acl_updated_event = ContractAclUpdatedEvent::new(key_id, new_address);
        let response = Response::new()
            .add_event(key_access_allowed_event)
            .add_event(contract_acl_updated_event);
        Ok(response)
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

        // We only store the sender of the transaction for key generation operations
        // This sender is then retrieved at the key generation response stage to add it to the ACL.
        if operation.is_key_gen() || operation.is_insecure_key_gen() {
            kms_storage.save_transaction_sender(
                ctx.deps.storage,
                &txn_id,
                &ctx.info.sender.to_string(),
            )?;
        }
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
        if !kms_storage.has_transaction(storage, transaction_id) {
            return Err(StdError::generic_err(format!(
                "Transaction with id {:?} not found while trying to save response operation value `{:?}`",
                transaction_id,
                operation
            )));
        }

        // Get all request values associated to the transaction
        let request_values =
            kms_storage.get_request_values_from_transaction(storage, transaction_id, None)?;

        // Get the list of request operations associated to the response operation
        // This is a list because in case of generation (key or CRS) responses, which can be associated
        // to two different request operations: the normal one and the insecure one.
        let associated_requests =
            operation
                .into_kms_operation()
                .to_requests()
                .unwrap_or_else(|_| {
                    panic!(
                        "No associated requests found for response operation: {:?}",
                        operation
                    )
                });
        // Check that at least one of the request values matches one of the associated request operations
        let has_matching_request = request_values
            .iter()
            .any(|req_val| associated_requests.contains(&req_val.into_kms_operation()));

        // A response operation must be associated with a request operation of relevant type (ex:
        // `DecryptResponse` must be associated to `Decrypt`)
        if !has_matching_request {
            return Err(StdError::generic_err(format!(
                "No matching request operation found for response operation `{:?}`. A response 
                operation must be associated with a request operation of relevant type.",
                operation
            )));
        }

        kms_storage.save_response_value(storage, transaction_id, &operation)?;

        let response =
            BackendContract::emit_event(kms_storage, storage, transaction_id, &operation)?;
        Ok(response)
    }

    /// Verifies that sender has sufficient funds to cover the ciphertext storage payment amount.
    fn verify_sender_payment_capacity(
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

    /// Check that the sender's address is allowed to trigger the given operation type.
    fn check_sender_is_allowed(
        ctx: &ExecCtx,
        kms_storage: &KmsContractStorage,
        operation_type: OperationType,
        operation: &str,
    ) -> StdResult<SenderAllowedEvent> {
        kms_storage
            .check_address_is_allowed(ctx.deps.storage, ctx.info.sender.as_str(), operation_type)
            .map_err(|e| StdError::generic_err(format!("Operation `{}`: {}", operation, e)))?;
        Ok(SenderAllowedEvent::new(
            operation.to_string(),
            ctx.info.sender.to_string(),
        ))
    }

    /// Check that the sender's address is allowed to access given key ID.
    fn check_key_access_is_allowed(
        ctx: &ExecCtx,
        kms_storage: &KmsContractStorage,
        key_id: String,
    ) -> StdResult<KeyAccessAllowedEvent> {
        let address_set = kms_storage.get_acl_address_set(ctx.deps.storage, &key_id)?;
        let sender = ctx.info.sender.to_string();
        if !address_set.contains(&sender) {
            return Err(StdError::generic_err(format!(
                "Sender {} is not allowed to access key with ID: {}",
                sender, key_id
            )));
        }
        Ok(KeyAccessAllowedEvent::new(key_id, sender))
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
