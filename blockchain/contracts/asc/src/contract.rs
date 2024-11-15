use super::state::KmsContractStorage;
use crate::events::EventEmitStrategy as _;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_json_binary, Env, Event, Response, StdError, StdResult, Storage, WasmMsg};
use cw2::{ensure_from_older_version, set_contract_version};
use cw_utils::must_pay;
use events::kms::{
    AllowedAddresses, CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues,
    InsecureCrsGenValues, KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues,
    KeyGenValues, KmsCoreConf, KmsEvent, KmsOperation, OperationType, OperationValue,
    ReencryptResponseValues, ReencryptValues, SenderAllowedEvent, Transaction, TransactionId,
    UpdateAllowedAddressesEvent, VerifyProvenCtValues,
};
use events::kms::{InsecureKeyGenValues, MigrationEvent, VerifyProvenCtResponseValues};
use serde_json;
use sha3::{Digest, Sha3_256};
use std::ops::Deref;
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx, QueryCtx},
};

const UCOSM: &str = "ucosm";

// Info for migration
const CONTRACT_NAME: &str = "kms-asc";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cw_serde]
pub struct ProofPayload {
    pub proof: String,
    pub ciphertext_handles: String,
}

#[cw_serde]
pub struct ProofMessage {
    pub verify_proof: ProofPayload,
}

#[derive(Default)]
pub struct KmsContract {
    pub(crate) storage: KmsContractStorage,
}

#[entry_points]
#[contract]
impl KmsContract {
    pub fn new() -> Self {
        Self::default()
    }

    fn derive_transaction_id(&self, env: &Env) -> StdResult<Vec<u8>> {
        let block_height = env.block.height;
        let transaction_index = env
            .transaction
            .clone()
            .ok_or_else(|| StdError::generic_err("Cannot find transaction index in env"))?
            .index;
        Ok(Self::hash_transaction_id(block_height, transaction_index))
    }

    pub fn hash_transaction_id(block_height: u64, transaction_index: u32) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update("KMS_BLOCK_HEIGHT");
        hasher.update(block_height.to_string().len().to_le_bytes());
        hasher.update(block_height.to_string());
        hasher.update("KMS_TRANSACTION_INDEX");
        hasher.update(transaction_index.to_string().len().to_be_bytes());
        hasher.update(transaction_index.to_string());
        let result = hasher.finalize();
        result[..20].to_vec()
    }

    /// Process transaction
    ///
    /// Processes a transaction.
    fn process_transaction(
        &self,
        storage: &mut dyn Storage,
        env: &Env,
        txn_id: &[u8],
        operation: OperationValue,
    ) -> StdResult<Response> {
        self.storage
            .update_transaction(storage, env, txn_id, &operation)?;
        let response = self.emit_event(storage, txn_id, &operation)?;
        Ok(response)
    }

    fn process_request_transaction(
        &self,
        ctx: &mut ExecCtx,
        operation: OperationValue,
    ) -> StdResult<Response> {
        let txn_id = self.derive_transaction_id(&ctx.env)?;
        self.process_transaction(ctx.deps.storage, &ctx.env, &txn_id, operation)
    }

    #[allow(dead_code)]
    fn chain_verify_proof_contract_call(
        &self,
        ctx: ExecCtx,
        response: Response,
        proof: String,
        external_ciphertext_handles: String,
    ) -> StdResult<Response> {
        if !self.storage.get_debug_proof(ctx.deps.storage)? {
            let msg = ProofMessage {
                verify_proof: ProofPayload {
                    proof,
                    ciphertext_handles: external_ciphertext_handles,
                },
            };
            let msg = WasmMsg::Execute {
                contract_addr: self
                    .storage
                    .get_verify_proof_contract_address(ctx.deps.storage)?,
                msg: to_json_binary(&msg)?,
                funds: vec![],
            };
            Ok(response.add_message(msg))
        } else {
            Ok(response)
        }
    }

    /// Check that the sender's address is allowed to trigger the given operation type.
    pub fn check_sender_is_allowed(
        &self,
        ctx: &ExecCtx,
        operation_type: OperationType,
        operation: &str,
    ) -> std::result::Result<(), cosmwasm_std::StdError> {
        self.storage
            .check_address_is_allowed(
                ctx.deps.storage,
                ctx.info.sender.as_str(),
                operation_type.clone(),
            )
            .map_err(|e| StdError::generic_err(format!("Operation `{}`: {}", operation, e)))
    }

    /// ASC contract instantiation
    ///
    /// The Application Smart Contract instantiation.
    ///
    /// # Arguments
    ///
    /// * `allowed_addresses` - an optional struct containing several lists of addresses that define
    /// who can trigger certain operations (ex: `gen`, `response` or `admin` operations).
    /// Providing None will default to use the sender's address for all operation types.
    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        debug_proof: Option<bool>,
        verify_proof_contract_addr: String,
        kms_core_conf: KmsCoreConf,
        allowed_addresses: Option<AllowedAddresses>,
    ) -> StdResult<Response> {
        // Check conformance of threshold config
        if !kms_core_conf.is_conformant() {
            return Err(cosmwasm_std::StdError::generic_err(
                "KMS core configuration is not conformant.",
            ));
        }

        // Inclusion proof debug configuration
        // While developing without a blockchain against which to verify we might need to skip the
        // call to a inclusion proof smart contract altogether. This allows that
        if let Some(debug_proof) = debug_proof {
            self.storage
                .set_debug_proof(ctx.deps.storage, debug_proof)?;
        } else {
            self.storage.set_debug_proof(ctx.deps.storage, false)?;
        }

        // Configure allowed addresses for some operations
        let allowed_addresses = match allowed_addresses {
            Some(addresses) => {
                addresses.check_all_addresses_are_valid(ctx.deps.api)?;
                addresses
            }
            None => {
                // Default to only allowing the contract instantiator
                AllowedAddresses::default_all_to(ctx.info.sender.as_str())
            }
        };

        self.storage
            .set_allowed_addresses(ctx.deps.storage, allowed_addresses)?;

        // Inclusion proof smart contract configuration
        self.storage
            .set_verify_proof_contract_address(ctx.deps.storage, verify_proof_contract_addr)?;

        // KMS Core configuration
        self.storage
            .update_core_conf(ctx.deps.storage, kms_core_conf)?;

        // Set contract name and version in the storage
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get_kms_core_conf(&self, ctx: QueryCtx) -> StdResult<KmsCoreConf> {
        self.storage.load_core_conf(ctx.deps.storage)
    }

    /// Update KMS core configuration
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn update_kms_core_conf(&self, ctx: ExecCtx, conf: KmsCoreConf) -> StdResult<Response> {
        let operation = "update_kms_core_conf";

        self.check_sender_is_allowed(&ctx, OperationType::Admin, operation)?;
        self.storage.update_core_conf(ctx.deps.storage, conf)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());
        let response = Response::new().add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Allow an address to trigger the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn add_allowed_address(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: OperationType,
    ) -> StdResult<Response> {
        let operation = "add_allowed_address";

        self.check_sender_is_allowed(&ctx, OperationType::SuperAdmin, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        self.storage.add_allowed_address(
            ctx.deps.storage,
            &address,
            operation_type.clone(),
            ctx.deps.api,
        )?;

        let update_allowed_addresses_event = UpdateAllowedAddressesEvent {
            new_addresses: vec![address.to_string()],
            operation: operation.to_string(),
            operation_type,
            sender: ctx.info.sender.to_string(),
        };

        let response = Response::new()
            .add_event(Into::<Event>::into(sender_allowed_event))
            .add_event(Into::<Event>::into(update_allowed_addresses_event));
        Ok(response)
    }

    /// Forbid an address from triggering the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn remove_allowed_address(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: OperationType,
    ) -> StdResult<Response> {
        let operation = "remove_allowed_address";

        self.check_sender_is_allowed(&ctx, OperationType::SuperAdmin, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        self.storage
            .remove_allowed_address(ctx.deps.storage, &address, operation_type.clone())?;

        let update_allowed_addresses_event = UpdateAllowedAddressesEvent {
            new_addresses: vec![address.to_string()],
            operation: operation.to_string(),
            operation_type,
            sender: ctx.info.sender.to_string(),
        };

        let response = Response::new()
            .add_event(Into::<Event>::into(sender_allowed_event))
            .add_event(Into::<Event>::into(update_allowed_addresses_event));
        Ok(response)
    }

    /// Replace all of the allowed addresses for the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn replace_allowed_addresses(
        &self,
        ctx: ExecCtx,
        addresses: Vec<String>,
        operation_type: OperationType,
    ) -> StdResult<Response> {
        let operation = "replace_allowed_addresses";

        self.check_sender_is_allowed(&ctx, OperationType::SuperAdmin, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        self.storage.replace_allowed_addresses(
            ctx.deps.storage,
            addresses.clone(),
            operation_type.clone(),
            ctx.deps.api,
        )?;

        let update_allowed_addresses_event = UpdateAllowedAddressesEvent {
            new_addresses: addresses,
            operation: operation.to_string(),
            operation_type,
            sender: ctx.info.sender.to_string(),
        };

        let response = Response::new()
            .add_event(Into::<Event>::into(sender_allowed_event))
            .add_event(Into::<Event>::into(update_allowed_addresses_event));
        Ok(response)
    }

    #[sv::msg(query)]
    pub fn get_transaction(&self, ctx: QueryCtx, txn_id: TransactionId) -> StdResult<Transaction> {
        self.storage.load_transaction(ctx.deps.storage, txn_id)
    }

    #[sv::msg(query)]
    pub fn get_operations_value(
        &self,
        ctx: QueryCtx,
        event: KmsEvent,
    ) -> StdResult<Vec<OperationValue>> {
        self.storage.get_operations_value(ctx.deps.storage, event)
    }

    #[sv::msg(query)]
    pub fn get_all_operations_values(&self, ctx: QueryCtx) -> StdResult<Vec<OperationValue>> {
        self.storage.get_all_operations_values(ctx.deps.storage)
    }

    #[sv::msg(query)]
    pub fn get_all_values_from_operation(
        &self,
        ctx: QueryCtx,
        operation: KmsOperation,
    ) -> StdResult<Vec<OperationValue>> {
        self.storage
            .get_all_values_from_operation(ctx.deps.storage, operation)
    }

    /// return ciphertext size from handle. Size is encoded as u32 in the first 4 bytes of the handle
    fn parse_ciphertext_handle_size(ciphertext_handle: &[u8]) -> u32 {
        ((ciphertext_handle[0] as u32) << 24)
            | ((ciphertext_handle[1] as u32) << 16)
            | ((ciphertext_handle[2] as u32) << 8)
            | (ciphertext_handle[3] as u32)
    }

    /// Verify payment
    ///
    /// Verify payment for ciphertext storage
    fn verify_payment(&self, ctx: &ExecCtx, ciphertext_handles: &[Vec<u8>]) -> StdResult<()> {
        let mut data_size = 0;
        for handle in ciphertext_handles {
            data_size += Self::parse_ciphertext_handle_size(&handle[..4]);
        }

        // Ensure the payment is included in the message
        let payment = must_pay(&ctx.info, UCOSM).map_err(|_| {
            StdError::generic_err(format!(
                "Unable to find ciphertext storage payment in the message - required: {}",
                data_size
            ))
        })?;

        if payment < data_size.into() {
            return Err(StdError::generic_err(format!(
                "Insufficient funds sent to cover the ciphertext storage size - payment: {}, required: {}",
                payment,
                data_size
            )));
        }
        Ok(())
    }

    #[sv::msg(exec)]
    pub fn decrypt(&self, mut ctx: ExecCtx, decrypt: DecryptValues) -> StdResult<Response> {
        // decipher the size encoding and ensure the payment is included in the message
        let ciphertext_handles = decrypt.ciphertext_handles();

        let ctvecs: Vec<Vec<u8>> = ciphertext_handles.0.iter().map(|ct| ct.to_vec()).collect();

        self.verify_payment(&ctx, &ctvecs).map_err(|e| {
            StdError::generic_err(format!(
                "Error verifying payment for ciphertext storage - {}",
                e
            ))
        })?;

        let external_ciphertext_handles: String;
        match decrypt.external_handles() {
            None => {
                return Err(StdError::generic_err(
                    "Error: external ciphertext handles are empty",
                ))
            }
            Some(hex_vector_list) => {
                let hex_vector_list: Vec<Vec<u8>> = hex_vector_list.clone().into();
                match serde_json::to_string(&hex_vector_list) {
                    Ok(json_string) => {
                        external_ciphertext_handles = json_string;
                    }
                    Err(e) => {
                        return Err(StdError::generic_err(format!(
                            "Error serializing external ciphertext handles: {}",
                            e
                        )))
                    }
                }
            }
        }
        let response = self.process_request_transaction(&mut ctx, decrypt.clone().into())?;
        self.chain_verify_proof_contract_call(
            ctx,
            response,
            decrypt.proof().to_string(),
            external_ciphertext_handles,
        )
    }

    /// Decrypt response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn decrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    ) -> StdResult<Response> {
        let operation = "decrypt_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            decrypt_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Keygen preproc
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn keygen_preproc(&self, mut ctx: ExecCtx) -> StdResult<Response> {
        let operation = "keygen_preproc";

        self.check_sender_is_allowed(&ctx, OperationType::Gen, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response =
            self.process_request_transaction(&mut ctx, KeyGenPreprocValues::default().into())?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Keygen preproc response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn keygen_preproc_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
    ) -> StdResult<Response> {
        let operation = "keygen_preproc_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            KeyGenPreprocResponseValues::default().into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Insecure keygen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn insecure_key_gen(
        &self,
        mut ctx: ExecCtx,
        insecure_key_gen: InsecureKeyGenValues,
    ) -> StdResult<Response> {
        let operation = "insecure_key_gen";

        self.check_sender_is_allowed(&ctx, OperationType::Gen, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_request_transaction(
            &mut ctx,
            OperationValue::InsecureKeyGen(insecure_key_gen),
        )?;
        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Insecure keygen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn insecure_key_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "insecure_key_gen_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            keygen_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Keygen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn keygen(&self, mut ctx: ExecCtx, keygen: KeyGenValues) -> StdResult<Response> {
        let operation = "keygen";

        self.check_sender_is_allowed(&ctx, OperationType::Gen, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_request_transaction(&mut ctx, keygen.into())?;
        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Keygen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn keygen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "keygen_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            keygen_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn reencrypt(&self, mut ctx: ExecCtx, reencrypt: ReencryptValues) -> StdResult<Response> {
        // decipher the size encoding and ensure the payment is included in the message
        let ciphertext_handle: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        self.verify_payment(&ctx, &[ciphertext_handle.clone()])?;

        let external_ciphertext_handles: String;

        let external_ciphertext_handles_vec: Vec<Vec<u8>> =
            vec![reencrypt.external_ciphertext_handle().deref().into()];
        match serde_json::to_string(&external_ciphertext_handles_vec) {
            Ok(json_string) => {
                external_ciphertext_handles = json_string;
            }
            Err(e) => {
                return Err(StdError::generic_err(format!(
                    "Error serializing external ciphertext handles: {}",
                    e
                )))
            }
        }

        let response = self.process_request_transaction(&mut ctx, reencrypt.clone().into())?;
        self.chain_verify_proof_contract_call(
            ctx,
            response,
            reencrypt.proof().to_string(),
            external_ciphertext_handles,
        )
    }

    /// Reencrypt response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn reencrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    ) -> StdResult<Response> {
        let operation = "reencrypt_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            reencrypt_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn verify_proven_ct(
        &self,
        mut ctx: ExecCtx,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> StdResult<Response> {
        self.process_request_transaction(&mut ctx, verify_proven_ct.into())
    }

    /// Verify proven ct response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn verify_proven_ct_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    ) -> StdResult<Response> {
        let operation = "verify_proven_ct_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            verify_proven_ct_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// CRS gen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn crs_gen(&self, mut ctx: ExecCtx, crs_gen: CrsGenValues) -> StdResult<Response> {
        let operation = "crs_gen";

        self.check_sender_is_allowed(&ctx, OperationType::Gen, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response =
            self.process_request_transaction(&mut ctx, OperationValue::CrsGen(crs_gen))?;
        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// CRS gen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "crs_gen_response";

        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            crs_gen_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Insecure CRS gen
    ///
    /// This call might be restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn insecure_crs_gen(
        &self,
        mut ctx: ExecCtx,
        insecure_crs_gen: InsecureCrsGenValues,
    ) -> StdResult<Response> {
        let operation = "insecure_crs_gen";

        self.check_sender_is_allowed(&ctx, OperationType::Gen, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_request_transaction(
            &mut ctx,
            OperationValue::InsecureCrsGen(insecure_crs_gen),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    /// Insecure CRS gen response
    ///
    /// This call might be restricted to specific addresses defined at instantiation (`AllowedAddresses`).
    #[sv::msg(exec)]
    pub fn insecure_crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        let operation = "insecure_crs_gen_response";
        self.check_sender_is_allowed(&ctx, OperationType::Response, operation)?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        let response = self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            crs_gen_response.into(),
        )?;

        let response = response.add_event(Into::<Event>::into(sender_allowed_event));
        Ok(response)
    }

    // Migrate function to migrate from old version to new version
    // As there is only one version of the ASC for now, this function has no real use. Future
    // versions of the ASC will be required to provide this function, with additional migration
    // logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> StdResult<Response> {
        // Check that the given storage (representing the old contract's storage) is compatible with
        // the new version of the ASC by :
        // - checking that the new contract name is the same
        // - checking that the new contract version is more recent than the current version
        // If both conditions are met, the storage is updated with the new contract version
        let original_version =
            ensure_from_older_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION).map_err(
                |e| {
                    StdError::generic_err(format!(
                        "ASC migration failed while checking version compatibility: {}",
                        e
                    ))
                },
            )?;

        let mut migration_event =
            MigrationEvent::new(original_version.to_string(), CONTRACT_VERSION.to_string());

        // Since there no real migration logic for now, we set it to successful
        migration_event.set_success();

        let response = Response::new().add_event(Into::<Event>::into(migration_event));
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::sv::mt::KmsContractProxy;
    use crate::contract::sv::mt::CodeId;
    use crate::contract::KmsContract;
    use cosmwasm_std::coin;
    use cosmwasm_std::coins;
    use cosmwasm_std::Addr;
    use cosmwasm_std::Binary;
    use cosmwasm_std::Event;
    use cw_multi_test::{App as CwApp, Executor};
    use events::kms::AllowedAddresses;
    use events::kms::CrsGenResponseValues;
    use events::kms::CrsGenValues;
    use events::kms::DecryptResponseValues;
    use events::kms::DecryptValues;
    use events::kms::FheParameter;
    use events::kms::FheType;
    use events::kms::KeyGenPreprocResponseValues;
    use events::kms::KeyGenPreprocValues;
    use events::kms::KeyGenResponseValues;
    use events::kms::KeyGenValues;
    use events::kms::KmsCoreConf;
    use events::kms::KmsCoreParty;
    use events::kms::KmsEvent;
    use events::kms::KmsOperation;
    use events::kms::OperationType;
    use events::kms::OperationValue;
    use events::kms::ReencryptResponseValues;
    use events::kms::ReencryptValues;
    use events::kms::TransactionId;
    use events::kms::VerifyProvenCtResponseValues;
    use events::kms::VerifyProvenCtValues;
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;
    use tendermint_ipsc::mock::sv::mt::CodeId as ProofCodeId;

    const UCOSM: &str = "ucosm";

    // let DUMMY_BECH32_ADDR: ADDR = "contract".into_addr();
    const DUMMY_BECH32_ADDR: &str =
        "cosmwasm1ejpjr43ht3y56pplm5pxpusmcrk9rkkvna4tklusnnwdxpqm0zls40599z";

    #[test]
    fn test_instantiate() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        // first make a few tries that will fail
        // `degree_for_reconstruction` is too high
        assert!(code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 2,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // `response_count_for_majority_vote` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 5,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // `response_count_for_reconstruction` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 5,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_err());

        // finally we make a successful attempt
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        let value = contract.get_kms_core_conf();
        assert!(value.is_ok());

        let value = contract.get_transaction(TransactionId::default());
        assert!(value.is_err());
    }

    #[test]
    fn test_update_kms_core_conf() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let value = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };

        contract
            .update_kms_core_conf(value.clone())
            .call(&owner)
            .unwrap();

        let result = contract.get_kms_core_conf().unwrap();
        assert_eq!(result, value);
    }

    fn extract_ciphertext_size(ciphertext_handle: &[u8]) -> u32 {
        ((ciphertext_handle[0] as u32) << 24)
            | ((ciphertext_handle[1] as u32) << 16)
            | ((ciphertext_handle[2] as u32) << 8)
            | (ciphertext_handle[3] as u32)
    }

    #[test]
    fn test_verify_proven_ct() {
        let gateway = Addr::unchecked("gateway");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &gateway, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let proven_val = VerifyProvenCtValues::new(
            vec![1, 2, 3],
            vec![2, 3, 4],
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            vec![4, 5, 6],
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![101; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract
            .verify_proven_ct(proven_val.clone())
            .call(&gateway)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::VerifyProvenCt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let proven_ct_response = VerifyProvenCtResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let response = contract
            .verify_proven_ct_response(txn_id.clone(), proven_ct_response.clone())
            .call(&owner)
            .unwrap();
        // one event because there's always an execute event + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .verify_proven_ct_response(txn_id.clone(), proven_ct_response)
            .call(&owner)
            .unwrap();
        // two events because there's always an execute event
        // plus the verify ct request since it reached the threshold
        // plus the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::VerifyProvenCtResponse(
                VerifyProvenCtResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_transaction(txn_id.clone()).unwrap();
        assert_eq!(response.block_height(), 12345);
        assert_eq!(response.transaction_index(), 0);
        // three operations: one verify ct and two verify ct responses
        assert_eq!(response.operations().len(), 3);
    }

    #[test]
    fn test_decrypt() {
        let gateway = Addr::unchecked("gateway");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &gateway, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();

        let batch_size = 2_usize;

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
        assert_eq!(data_size, 661448 * batch_size as u32);

        let decrypt = DecryptValues::new(
            vec![1, 2, 3],
            vec![ciphertext_handle; batch_size],
            vec![FheType::Euint8; batch_size],
            Some(vec![vec![23_u8; 32]]),
            1,
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "some proof".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![101; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        // test insufficient funds
        let _failed_response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&gateway)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&gateway)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .unwrap();
        // one event because there's always an execute event + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();
        // two events because there's always an execute event
        // plus the decryption request since it reached the threshold
        // plus the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::DecryptResponse(DecryptResponseValues::new(
                vec![4, 5, 6],
                vec![6, 7, 8],
            )))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_transaction(txn_id.clone()).unwrap();
        assert_eq!(response.block_height(), 12345);
        assert_eq!(response.transaction_index(), 0);
        // three operations: one decrypt and two decrypt response
        assert_eq!(response.operations().len(), 3);
    }

    #[test]
    fn test_decrypt_with_proof() {
        let test = Addr::unchecked("test");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &test, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let proof_code_id = ProofCodeId::store_code(&app);
        let owner = "owner".into_addr();
        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();

        let batch_size = 2_usize;
        let contract_proof = proof_code_id.instantiate().call(&owner).unwrap();

        let proof_addr = &contract_proof.contract_addr;

        let contract = code_id
            .instantiate(
                Some(false),
                proof_addr.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
        assert_eq!(data_size, 661448 * batch_size as u32);

        let decrypt = DecryptValues::new(
            vec![1, 2, 3],
            vec![ciphertext_handle; batch_size],
            vec![FheType::Euint8; batch_size],
            Some(vec![vec![23_u8; 32]]),
            1,
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "some proof".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![101; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        // test insufficient funds
        let _failed_response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&test)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&test)
            .unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .unwrap();
        // one event because there's always an execute event + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();
        // two events because there's always an execute event
        // plus the decryption request since it reached the threshold
        // plus the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::DecryptResponse(DecryptResponseValues::new(
                vec![4, 5, 6],
                vec![6, 7, 8],
            )))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_transaction(txn_id.clone()).unwrap();
        assert_eq!(response.block_height(), 12345);
        assert_eq!(response.transaction_index(), 0);
        // three operations: one decrypt and two decrypt response
        assert_eq!(response.operations().len(), 3);
    }

    #[test]
    fn test_preproc() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc().call(&owner).unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .keygen_preproc_response(txn_id.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreprocResponse(
                KeyGenPreprocResponseValues {},
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_keygen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let keygen_val = KeyGenValues::new(
            "preproc_id".as_bytes().to_vec(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract.keygen(keygen_val).call(&owner).unwrap();
        println!("response: {:#?}", response);
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let keygen_response = KeyGenResponseValues::new(
            txn_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            FheParameter::Test,
        );

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // one exec and two response events + the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_reencrypt() {
        let owner = Addr::unchecked("owner");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &owner, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);

        //let app = App::default();
        let code_id = CodeId::store_code(&app);
        //let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                None,
            )
            .call(&owner)
            .unwrap();

        let dummy_external_ciphertext_handle = hex::decode("0".repeat(64)).unwrap();
        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();
        let data_size = extract_ciphertext_size(&ciphertext_handle);
        assert_eq!(data_size, 661448);

        let reencrypt = ReencryptValues::new(
            vec![1],
            1,
            "0x1234".to_string(),
            vec![4],
            FheType::Euint8,
            vec![5],
            dummy_external_ciphertext_handle.clone(),
            ciphertext_handle.clone(),
            vec![9],
            "dummy_acl_address".to_string(),
            "some proof".to_string(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let _failed_response = contract
            .reencrypt(reencrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .reencrypt(reencrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();

        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Reencrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response_values = ReencryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let response = contract
            .reencrypt_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .reencrypt_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .reencrypt_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        // one exec and one response event (+ the check sender event) since we hit the threshold of 3
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::ReencryptResponse(response_values))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_crs_gen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        let user = "user".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let crsgen_val = CrsGenValues::new(
            192,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract.crs_gen(crsgen_val.clone()).call(&owner).unwrap();

        contract
            .crs_gen(crsgen_val)
            .call(&user)
            .expect_err("User wasn't allowed to call CRS gen but somehow succeeded.");

        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let crs_gen_response = CrsGenResponseValues::new(
            txn_id.to_hex(),
            "my digest".to_string(),
            vec![4, 5, 6],
            256,
            FheParameter::Test,
        );

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response)
            .call(&owner)
            .unwrap();
        // one exec and two response events + the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGenResponse)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    fn assert_event(events: &[Event], kms_event: &KmsEvent) {
        let mut kms_event: Event = kms_event.clone().into();
        kms_event.ty = format!("wasm-{}", kms_event.ty);
        let event = events.iter().find(|e| e.ty == kms_event.ty);
        assert!(event.is_some());
        let mut event = event.unwrap().clone();
        let position = event
            .attributes
            .iter()
            .position(|x| x.key == "_contract_address");
        if let Some(idx) = position {
            event.attributes.remove(idx);
        }
        assert_eq!(event, kms_event);
    }

    #[test]
    fn test_get_operation_values_functions() {
        let caller = Addr::unchecked("caller");
        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &caller, coins(5000000, UCOSM))
                .unwrap();
        });
        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        // First, trigger a keygen operation
        let keygen = KeyGenValues::new(
            "preproc_id".as_bytes().to_vec(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();
        let response = contract.keygen(keygen.clone()).call(&owner).unwrap();

        // Transaction id: 0
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 3);

        let keygen_response = KeyGenResponseValues::new(
            txn_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            FheParameter::Test,
        );

        // Two keygen response event
        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        // Test `get_operations_value` function
        let keygen_data = contract.get_operations_value(expected_event).unwrap();
        assert_eq!(keygen_data.len(), 2);

        let not_expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        // There should not be any decrypt operation
        let not_expected_data = contract.get_operations_value(not_expected_event);
        assert!(not_expected_data.is_err());

        // Test `get_all_values_from_operation` function for KeyGenResponse
        let keygen_response_operation = KmsOperation::KeyGenResponse;
        let keygen_response_values =
            contract.get_all_values_from_operation(keygen_response_operation);
        assert!(keygen_response_values.is_ok());

        // Two keygen operations give two KeyGenResponseValues
        let keygen_response_values = keygen_response_values.unwrap();
        assert_eq!(
            keygen_response_values.len(),
            2,
            "Unexpected number of keygen response values: {:?}",
            keygen_response_values
        );

        // Check that values are actually KeyGenResponse
        for keygen_response_value in keygen_response_values {
            assert!(
                matches!(keygen_response_value, OperationValue::KeyGenResponse(_)),
                "Unexpected keygen response value: {:?}",
                keygen_response_value
            );
        }

        // There should not be any Decrypt operation
        let not_expected_operation = KmsOperation::Decrypt;
        let not_expected_values = contract.get_all_values_from_operation(not_expected_operation);
        assert!(not_expected_values.is_err());

        // Then, trigger a decrypt operation
        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();

        let batch_size = 2_usize;

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
        assert_eq!(data_size, 661448 * batch_size as u32);

        let decrypt = DecryptValues::new(
            vec![1, 2, 3],
            vec![ciphertext_handle; batch_size],
            vec![FheType::Euint8; batch_size],
            Some(vec![vec![23_u8; 32]]),
            1,
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "some proof".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![101; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&caller)
            .unwrap();
        println!("response: {:#?}", response);

        // Transaction id: 1
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 1).into();
        assert_eq!(response.events.len(), 2);

        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        // Decrypt response event
        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        // Test `get_all_operations_values` function
        let operations_response_values = contract.get_all_operations_values();
        assert!(operations_response_values.is_ok());

        // Two keygen and one decrypt operations give two (KeyGenValues + KeyGenResponseValues) and
        // one (DecryptValues + DecryptResponseValues) = 5 response values
        let operations_response_values = operations_response_values.unwrap();
        assert_eq!(
            operations_response_values.len(),
            5,
            "Unexpected number of operation values: {:?}",
            operations_response_values
        );

        // Check that values are actually either KeyGen, Decrypt or one of their responses
        for operations_response_value in operations_response_values {
            assert!(
                matches!(
                    operations_response_value,
                    OperationValue::KeyGen(_)
                        | OperationValue::KeyGenResponse(_)
                        | OperationValue::Decrypt(_)
                        | OperationValue::DecryptResponse(_)
                ),
                "Unexpected operation value: {:?}",
                operations_response_value
            );
        }

        // There should not be any Reencrypt operation
        let not_expected_operation = KmsOperation::Reencrypt;
        let not_expected_values = contract.get_all_values_from_operation(not_expected_operation);
        assert!(not_expected_values.is_err());
    }

    /// Test the `allowed_to_gen` list's logic. In particular this test makes sure to consider all
    /// kinds of possible inputs for this list.
    #[test]
    fn test_is_allowed_to_gen() {
        let owner = "owner".into_addr();
        let user = "user".into_addr();
        let another_user = "another_user".into_addr();
        let connector = "connector".into_addr();
        let app = App::default();

        let allowed_to_response = vec![connector.to_string()];
        let admins = vec![owner.to_string()];
        let super_admins = vec![owner.to_string()];

        let crsgen_val = CrsGenValues::new(
            192,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        for (allowed_to_gen, allowed, instantiation_ok) in [
            (None, vec![true, false, false], true), // Defaults to owner only
            (Some(vec![]), vec![false, false, false], true), // Empty -> no one can operate (not sure this is really useful)
            (Some(vec!["".to_string()]), vec![false, false, false], false), // Instantiation error -> not a valid address
            (
                Some(vec![user.to_string(), owner.to_string()]),
                vec![true, true, false],
                true,
            ), // Both user and owner can
            (Some(vec![user.to_string()]), vec![false, true, false], true), // User only allowed
            (
                Some(vec![owner.to_string()]),
                vec![true, false, false],
                true,
            ), // Owner only allowed
        ] {
            let code_id = CodeId::store_code(&app);

            if instantiation_ok {
                let contract = code_id
                    .instantiate(
                        Some(true),
                        DUMMY_BECH32_ADDR.to_string(),
                        KmsCoreConf {
                            parties: vec![KmsCoreParty::default(); 4],
                            response_count_for_majority_vote: 2,
                            response_count_for_reconstruction: 3,
                            degree_for_reconstruction: 1,
                            param_choice: FheParameter::Test,
                        },
                        allowed_to_gen
                            .clone()
                            .map(|allowed_to_gen| AllowedAddresses {
                                allowed_to_gen,
                                allowed_to_response: allowed_to_response.clone(),
                                admins: admins.clone(),
                                super_admins: super_admins.clone(),
                            }),
                    )
                    .call(&owner)
                    .unwrap();

                for ((wallet, wallet_allowed), wallet_name) in std::iter::zip(
                    std::iter::zip([owner.clone(), user.clone(), another_user.clone()], allowed),
                    vec!["owner", "user", "another_user"],
                ) {
                    if wallet_allowed {
                        // Success
                        let response = contract.crs_gen(crsgen_val.clone()).call(&wallet).unwrap();
                        assert_eq!(response.events.len(), 3);
                    } else {
                        // Failure
                        contract.crs_gen(crsgen_val.clone()).call(&wallet).expect_err(
                            format!(
                                "{} ({}) wasn't allowed to call CRS gen but somehow succeeded with `allowed_to_gen` list: {:?}.",
                                wallet_name,
                                wallet,
                                allowed_to_gen,
                            )
                            .as_str(),
                        );
                    }
                }
            } else {
                code_id
                    .instantiate(
                        Some(true),
                        DUMMY_BECH32_ADDR.to_string(),
                        KmsCoreConf {
                            parties: vec![KmsCoreParty::default(); 4],
                            response_count_for_majority_vote: 2,
                            response_count_for_reconstruction: 3,
                            degree_for_reconstruction: 1,
                            param_choice: FheParameter::Test,
                        },
                        allowed_to_gen.clone().map(|allowed_to_gen: Vec<String>| {
                            AllowedAddresses {
                                allowed_to_gen,
                                allowed_to_response: allowed_to_response.clone(),
                                admins: admins.clone(),
                                super_admins: super_admins.clone(),
                            }
                        }),
                    )
                    .call(&owner)
                    .expect_err(
                        format!(
                            "Instantiation didn't fail as expected with allow-list: {:?}.",
                            allowed_to_gen
                        )
                        .as_str(),
                    );
            }
        }
    }

    /// Test the `allowed_to_response` list's logic. Not all kinds of inputs (for this list) are
    /// tested here since this has already been done in `test_is_allowed_to_gen` (which shares
    /// the same logic).
    #[test]
    fn test_is_allowed_to_response() {
        let gateway = Addr::unchecked("gateway");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &gateway, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let fake_owner = "fake_owner".into_addr();
        let friend_owner = "friend_owner".into_addr();

        let allowed_to_gen = vec![owner.to_string()];
        let admins = vec![owner.to_string()];
        let super_admins = vec![owner.to_string()];

        // Only the `owner` and `friend_owner` are allowed to trigger a decrypt response
        let allowed_to_response = vec![owner.to_string(), friend_owner.to_string()];

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                },
                Some(AllowedAddresses {
                    allowed_to_gen,
                    allowed_to_response: allowed_to_response.clone(),
                    admins: admins.clone(),
                    super_admins: super_admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        // Trigger a decrypt response
        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let txn_id = TransactionId::default();

        // Owner has been allowed to call a decrypt response
        contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .unwrap();

        // `friend_owner` has been allowed to call a decrypt response
        contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&friend_owner)
            .unwrap();

        // `fake_owner` is not allowed to call a decrypt response
        contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call a decrypt response with address {} and whitelist {:?}",
                    fake_owner,
                    allowed_to_response
                )
                .as_str(),
            );
    }

    #[test]
    fn test_is_allowed_to_admin() {
        let gateway = Addr::unchecked("gateway");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &gateway, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let fake_owner = "fake_owner".into_addr();

        let allowed_to_gen = vec![owner.to_string()];
        let allowed_to_response = vec![owner.to_string()];
        let super_admins = vec![owner.to_string()];

        // Only the `owner` is allowed to trigger admin operations for now
        let admins = vec![owner.to_string()];

        let initial_kms_core_conf = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 2,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                initial_kms_core_conf.clone(),
                Some(AllowedAddresses {
                    allowed_to_gen,
                    allowed_to_response: allowed_to_response.clone(),
                    admins: admins.clone(),
                    super_admins: super_admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        // Fake owner is not allowed to trigger admin operations, like updating the KMS
        // core configuration
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&fake_owner)
            .unwrap_err();

        // Only the owner can do so
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&owner)
            .unwrap();
    }

    #[test]
    fn test_is_allowed_to_super_admin() {
        let gateway = Addr::unchecked("gateway");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &gateway, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let friend_owner = "friend_owner".into_addr();

        let allowed_to_gen = vec![owner.to_string()];
        let allowed_to_response = vec![owner.to_string()];

        // Only the `owner` is allowed to trigger super-admin operations for now
        let admins = vec![owner.to_string()];

        // Only the `owner` is allowed to trigger super-admin operations
        let super_admins = vec![owner.to_string()];

        let initial_kms_core_conf = KmsCoreConf {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 2,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        };

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                initial_kms_core_conf.clone(),
                Some(AllowedAddresses {
                    allowed_to_gen,
                    allowed_to_response: allowed_to_response.clone(),
                    admins: admins.clone(),
                    super_admins: super_admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        // Friend owner is still not allowed to trigger admin operations, like updating the KMS
        // core configuration
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&friend_owner)
            .unwrap_err();

        // Owner can do so
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&owner)
            .unwrap();

        // Owner can add friend owner to the admin list
        contract
            .add_allowed_address(friend_owner.to_string(), OperationType::Admin)
            .call(&owner)
            .unwrap();

        // Now, friend owner can update the KMS core configuration
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&friend_owner)
            .unwrap();

        // Owner can also remove friend owner from the admin list
        contract
            .remove_allowed_address(friend_owner.to_string(), OperationType::Admin)
            .call(&owner)
            .unwrap();

        // Friend owner is no longer an admin
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&friend_owner)
            .unwrap_err();

        // Owner cannot remove himself from the super-admin list since there is only one super-admin
        contract
            .remove_allowed_address(owner.to_string(), OperationType::SuperAdmin)
            .call(&owner)
            .unwrap_err();

        // Owner replaces the entire admin list
        contract
            .replace_allowed_addresses(vec![friend_owner.to_string()], OperationType::Admin)
            .call(&owner)
            .unwrap();

        // Friend owner can now update the KMS core configuration again
        contract
            .update_kms_core_conf(initial_kms_core_conf.clone())
            .call(&friend_owner)
            .unwrap();

        // Owner cannot update the KMS core configuration anymore
        contract
            .update_kms_core_conf(initial_kms_core_conf)
            .call(&owner)
            .unwrap_err();

        // Owner cannot replace the admin list with an empty one
        contract
            .replace_allowed_addresses(vec![], OperationType::Admin)
            .call(&owner)
            .unwrap_err();
    }
    // Provide an "old" dummy versioned smart contract implementation
    mod v0 {
        use cosmwasm_std::{Addr, Response, StdResult};
        use cw2::set_contract_version;
        use sylvia::types::{InstantiateCtx, QueryCtx};
        use sylvia::{contract, entry_points};

        use crate::versioned_storage::tests::v0::{MyStruct, VersionedStorage};

        // Info for migration
        const CONTRACT_NAME: &str = "my_contract_name";
        const CONTRACT_VERSION: &str = "1.0.0";

        #[derive(Default)]
        pub struct MyContract {
            pub storage: VersionedStorage,
        }

        #[entry_points]
        #[contract]
        impl MyContract {
            pub fn new() -> Self {
                Self::default()
            }

            // Entrypoint for instantiating the contract
            // It also sets the contract name and version in the storage
            #[sv::msg(instantiate)]
            pub fn instantiate(&self, ctx: InstantiateCtx) -> StdResult<Response> {
                set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

                self.storage
                    .my_versioned_item
                    .save(ctx.deps.storage, &MyStruct::new("v0"))?;
                Ok(Response::default())
            }

            // Entrypoint for querying the contract
            #[sv::msg(query)]
            pub fn load_my_struct(&self, ctx: QueryCtx) -> StdResult<MyStruct> {
                self.storage.my_versioned_item.load(ctx.deps.storage)
            }

            // Get the contract's address
            #[sv::msg(query)]
            pub fn get_address(&self, ctx: QueryCtx) -> StdResult<Addr> {
                Ok(ctx.env.contract.address)
            }

            // Note that there is no entrypoint for migrating the contract since this is the first
            // version
        }
    }

    // Provide a "new" dummy versioned smart contract implementation with a migrate entrypoint
    mod v1 {
        use cosmwasm_std::{Addr, Binary, Response, StdResult};
        use cw2::{ensure_from_older_version, set_contract_version};
        use sylvia::types::{InstantiateCtx, MigrateCtx, QueryCtx};
        use sylvia::{contract, entry_points};

        use crate::versioned_storage::tests::v1::{MyStruct, VersionedStorage};

        // Info for migration
        const CONTRACT_NAME: &str = "my_contract_name";
        const CONTRACT_VERSION: &str = "2.0.0";

        #[derive(Default)]
        pub struct MyContract {
            pub storage: VersionedStorage,
        }

        #[entry_points]
        #[contract]
        impl MyContract {
            pub fn new() -> Self {
                Self::default()
            }

            // Entrypoint for instantiating the contract
            // It also sets the contract name and version in the storage
            // None: since we are going to migrate the old contract to this new code, this
            // instantiation entrypoint should not be called
            #[sv::msg(instantiate)]
            pub fn instantiate(&self, ctx: InstantiateCtx) -> StdResult<Response> {
                set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

                self.storage
                    .my_versioned_item
                    .save(ctx.deps.storage, &MyStruct::new("v1"))?;
                Ok(Response::default())
            }

            // Entrypoint for querying the contract
            #[sv::msg(query)]
            pub fn load_my_struct(&self, ctx: QueryCtx) -> StdResult<MyStruct<u8>> {
                self.storage.my_versioned_item.load(ctx.deps.storage)
            }

            // Entrypoint for migrating the contract from old to new version
            // Use a `_test` parameter for testing purposes only
            // It also checks that the given storage (representing the old contract's storage) is
            // compatible with the new version
            #[allow(unused_variables)]
            #[sv::msg(migrate)]
            pub fn migrate(&self, ctx: MigrateCtx, _test: Binary) -> StdResult<Response> {
                let _original_version =
                    ensure_from_older_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
                Ok(Response::default())
            }

            // Get the contract's address
            #[sv::msg(query)]
            pub fn get_address(&self, ctx: QueryCtx) -> StdResult<Addr> {
                Ok(ctx.env.contract.address)
            }
        }
    }

    #[test]
    fn test_contract_migration() {
        use crate::versioned_storage::tests::v1::MyStruct as MyNewStruct;
        use v0::sv::mt::MyContractProxy;

        // Define the blockchain application simulator
        let cw_app = CwApp::default();
        let sylvia_app = App::new(cw_app);

        // Define the contract's owner
        let owner = "owner".into_addr();

        // Instantiate the old contract
        let old_code_id = v0::sv::mt::CodeId::store_code(&sylvia_app);
        let old_contract = old_code_id
            .instantiate()
            .with_admin(owner.as_str())
            .call(&owner)
            .unwrap();

        // Load the old struct. This requires `MyContractProxy` to be in scope
        let old_item = old_contract.load_my_struct().unwrap();
        assert_eq!(old_item.attribute_0, "v0");

        // Get the old contract's address and make sure it matches the address of CosmWasm's proxy contract
        let old_address = old_contract.get_address().unwrap();
        assert_eq!(old_address, old_contract.contract_addr);

        // Store the new code and get its code id
        // Note that the new contract must not be instantiated at any time
        let new_code_id = v1::sv::mt::CodeId::store_code(&sylvia_app);

        // Build the migrate message for the new code
        // There might be a way to automatically build this message (via the `Sylvia` framework)
        let migrate_msg = v1::sv::MigrateMsg {
            _test: Binary::default(),
        };

        // Define a fake owner for the contract
        let fake_owner = "fake_owner".into_addr();

        // Check that the migration fails when using the wrong owner as the sender. This is because
        // this fake owner has not been registered as an admin when instantiating the old contract.
        // Note that CosmWasm does provide a way to update admins for a contract
        sylvia_app
            .app_mut()
            .migrate_contract(
                fake_owner.clone(),
                old_contract.contract_addr.clone(),
                &migrate_msg,
                new_code_id.code_id(),
            )
            .unwrap_err();

        // Define a fake code id
        let fake_code_id = new_code_id.code_id() + 10;

        // Check that the migration fails when using a non-registered code id. This is because this
        // `fake_code_id` has not been stored in the blockchain app at any time
        sylvia_app
            .app_mut()
            .migrate_contract(
                fake_owner.clone(),
                old_contract.contract_addr.clone(),
                &migrate_msg,
                fake_code_id,
            )
            .unwrap_err();

        // Migrate the old contract to the new code using the underlying CosmWasm app
        // The `Sylvia` framework does provide a migrate feature but does not seem to fully support
        // it when testing it. More specifically, it does not allow migrate a contract to a new code
        // without having the old contract exposing a migrate entrypoint. Additionally, it will pass
        // the old contract's migrate message (after building it automatically) instead of the new one,
        // which does not make much sense. This is why we directly use the underlying CosmWasm app to
        // perform the migration
        // Note that this requires the `Executor` trait from `cw_multi_test` to be in scope
        sylvia_app
            .app_mut()
            .migrate_contract(
                owner.clone(),
                old_contract.contract_addr.clone(),
                &migrate_msg,
                new_code_id.code_id(),
            )
            .unwrap();

        // Build the new query message for the new contract
        // Similarly, there might be a way to automatically build this message (via the `Sylvia`
        // framework)
        let query_msg = v1::sv::QueryMsg::LoadMyStruct {};

        // Query the new contract to load the new struct
        // Similarly, the `Sylvia` framework does not support querying the new contract after
        // migration. Because the new contract is never really built, meaning we need to keep using
        // the old contract instance, which does not provide the right methods and/or signatures
        // (i.e. the ones of the new contract). This is why we directly use the underlying CosmWasm
        // app to query the new contract
        let new_item: MyNewStruct<u8> = sylvia_app
            .app()
            .wrap()
            .query_wasm_smart(&old_contract.contract_addr, &query_msg)
            .unwrap();

        // Test that the old struct has been loaded and updated to its new version
        assert_eq!(new_item.attribute_0, "v0");
        assert_eq!(new_item.attribute_1, 0);

        // Get the new contract's address and make sure it matches the old contract's one
        let query_msg = v1::sv::QueryMsg::GetAddress {};
        let new_address: Addr = sylvia_app
            .app()
            .wrap()
            .query_wasm_smart(&old_contract.contract_addr, &query_msg)
            .unwrap();

        assert_eq!(new_address, old_address);
    }
}
