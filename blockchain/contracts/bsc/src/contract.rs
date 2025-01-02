use std::ops::Deref;

use crate::error::BackendError;
use crate::events::EventEmitStrategy;
use crate::state::BackendStorage;
use contracts_common::{
    allowlists::{AllowlistsContractManager, AllowlistsManager, AllowlistsStateManager},
    migrations::Migration,
};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Env, Response};
use cw2::set_contract_version;
use cw_utils::must_pay;
use events::kms::{
    ContractAclUpdatedEvent, CrsGenResponseValues, CrsGenValues, DecryptResponseValues,
    DecryptValues, GenResponseValuesSavedEvent, InsecureCrsGenValues, InsecureKeyGenValues,
    KeyAccessAllowedEvent, KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues,
    KeyGenValues, KmsEvent, OperationValue, ReencryptResponseValues, ReencryptValues, Transaction,
    TransactionId, VerifyProvenCtResponseValues, VerifyProvenCtValues,
};
use sha3::{Digest, Sha3_256};
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx, QueryCtx},
};

// Info for migration
const CONTRACT_NAME: &str = "kms-backend";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const UCOSM: &str = "ucosm";

// Type aliases for the allowlists and operation types to use in the BSC
// We recover them from the storage for better maintainability
type Allowlists = <BackendStorage as AllowlistsStateManager>::Allowlists;
type AllowlistType = <Allowlists as AllowlistsManager>::AllowlistType;

#[cw_serde]
pub struct GrantKeyAccessRequest {
    key_id: String,
    address: String,
}

#[derive(Default)]
pub struct BackendContract {
    pub(crate) storage: BackendStorage,
}

/// Implement the `AllowlistsContractManager` trait
///
/// This allows to check that the sender is allowed to trigger a given operation
impl AllowlistsContractManager for BackendContract {
    type Allowlists = Allowlists;

    fn storage(&self) -> &dyn AllowlistsStateManager<Allowlists = Allowlists> {
        &self.storage
    }
}

/// Implement the `Migration` trait
///
/// This allows to migrate the contract's state from an old version to a new version, without
/// changing its address. This will automatically use versioning to ensure compatibility between
/// versions
impl Migration for BackendContract {}

#[entry_points]
#[contract]
#[sv::error(BackendError)]
impl BackendContract {
    pub fn new() -> Self {
        Self::default()
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        csc_address: String,
        allowlists: Option<Allowlists>,
    ) -> Result<Response, BackendError> {
        self.storage
            .set_csc_address(ctx.deps.storage, csc_address)?;

        let allowlists = match allowlists {
            Some(addresses) => {
                addresses.check_all_addresses_are_valid(ctx.deps.api)?;
                addresses
            }
            None => {
                // Default to only allowing the contract instantiation sender
                Allowlists::default_all_to(ctx.info.sender.as_str())
            }
        };
        self.storage.set_allowlists(ctx.deps.storage, allowlists)?;

        // Set contract name and version in the storage
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        Ok(Response::default())
    }

    /// Function to migrate from old version to new version
    ///
    /// As there is only one version of the contract for now, this function has no real use. Future
    /// versions of the contract will be required to provide this function, with additional migration
    /// logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> Result<Response, BackendError> {
        self.apply_migration(ctx.deps.storage)
            .map_err(BackendError::StdError)
    }

    /// Gets the transaction details and its response values found in the storage
    /// for a given transaction ID.
    #[sv::msg(query)]
    pub fn get_transaction(
        &self,
        ctx: QueryCtx,
        txn_id: TransactionId,
    ) -> Result<Transaction, BackendError> {
        self.storage
            .get_transaction_with_response_values(ctx.deps.storage, &txn_id)
            .map_err(BackendError::StdError)
    }

    /// Gets the list of all operation values found in the storage and associated to the given
    /// KMS event (a KMS operation and a transaction ID).
    #[sv::msg(query)]
    pub fn get_operations_values_from_event(
        &self,
        ctx: QueryCtx,
        event: KmsEvent,
    ) -> Result<Vec<OperationValue>, BackendError> {
        self.storage
            .get_values_from_transaction_and_operation(
                ctx.deps.storage,
                &event.txn_id,
                &event.operation,
            )
            .map_err(BackendError::StdError)
    }

    /// Gets the list of all key generation response values found in the storage
    /// for a given key ID
    #[sv::msg(query)]
    pub fn get_key_gen_response_values(
        &self,
        ctx: QueryCtx,
        key_id: String,
    ) -> Result<Vec<KeyGenResponseValues>, BackendError> {
        self.storage
            .get_key_gen_response_values(ctx.deps.storage, &key_id)
            .map_err(BackendError::StdError)
    }

    /// Gets the list of all CRS gen response values for a given CRS ID
    #[sv::msg(query)]
    pub fn get_crs_gen_response_values(
        &self,
        ctx: QueryCtx,
        crs_id: String,
    ) -> Result<Vec<CrsGenResponseValues>, BackendError> {
        self.storage
            .get_crs_gen_response_values(ctx.deps.storage, &crs_id)
            .map_err(BackendError::StdError)
    }

    /// Processes a decryption request by performing these steps:
    /// - Check sender access for given key ID
    /// - Verify sender's payment capacity
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add a key access allowed event to the response
    #[sv::msg(exec)]
    pub fn decryption_request(
        &self,
        mut ctx: ExecCtx,
        decrypt: DecryptValues,
    ) -> Result<Response, BackendError> {
        let key_access_allowed_event =
            self.check_key_access_is_allowed(&ctx, decrypt.key_id().to_string())?;

        let ciphertext_handle_vectors: Vec<Vec<u8>> = decrypt
            .ciphertext_handles()
            .0
            .iter()
            .map(|ct| ct.to_vec())
            .collect();
        Self::verify_sender_payment_capacity(&ctx, &ciphertext_handle_vectors)?;

        let response = self
            .process_request_transaction(&mut ctx, decrypt.clone().into())?
            .add_event(key_access_allowed_event);
        Ok(response)
    }

    /// Processes a decryption response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn decryption_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "decryption_response";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;
        let response = self
            .process_response_transaction(&mut ctx, &transaction_id, decrypt_response.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a reencryption request by performing these steps:
    /// - Check sender access for given key ID
    /// - Verify sender's payment capacity
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add a key access allowed event to the response
    #[sv::msg(exec)]
    pub fn reencryption_request(
        &self,
        mut ctx: ExecCtx,
        reencrypt: ReencryptValues,
    ) -> Result<Response, BackendError> {
        let key_access_allowed_event =
            self.check_key_access_is_allowed(&ctx, reencrypt.key_id().to_string())?;

        let ciphertext_handle_vector: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        Self::verify_sender_payment_capacity(&ctx, &[ciphertext_handle_vector])?;

        let response = self
            .process_request_transaction(&mut ctx, reencrypt.clone().into())?
            .add_event(key_access_allowed_event);
        Ok(response)
    }

    /// Processes a reencryption response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn reencryption_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "reencryption_response";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;
        let response = self
            .process_response_transaction(&mut ctx, &transaction_id, reencrypt_response.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a key generation preproc request by performing these steps:
    /// - Check sender permission to execute generate operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn key_gen_preproc_request(&self, mut ctx: ExecCtx) -> Result<Response, BackendError> {
        let operation = "key_generation_preproc_request";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Generate, operation)?;
        let response = self
            .process_request_transaction(&mut ctx, KeyGenPreprocValues::default().into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a key generation preproc request response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn key_gen_preproc_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
    ) -> Result<Response, BackendError> {
        let operation = "key_generation_preproc_response";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;
        let response = self
            .process_response_transaction(
                &mut ctx,
                &transaction_id,
                KeyGenPreprocResponseValues::default().into(),
            )?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a key generation request by performing these steps:
    /// - Check sender permission to execute generate operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn key_gen_request(
        &self,
        mut ctx: ExecCtx,
        keygen: KeyGenValues,
    ) -> Result<Response, BackendError> {
        let operation = "key_generation_request";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Generate, operation)?;
        let response = self
            .process_request_transaction(&mut ctx, keygen.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a key generation response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Include sender of given transaction ID in the ACL for generated key ID
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add contract ACL updated, sender allowed, and generation response saved events
    #[sv::msg(exec)]
    pub fn key_gen_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "key_generation_response";
        let key_id = keygen_response.request_id().to_string();

        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;

        let transaction_sender = self
            .storage
            .get_transaction_sender(ctx.deps.storage, &transaction_id)?;

        self.storage
            .add_address_to_acl(ctx.deps.storage, &key_id, &transaction_sender)?;

        let contract_acl_updated_event =
            ContractAclUpdatedEvent::new(key_id, ctx.info.sender.to_string());

        let response = self
            .process_response_transaction(&mut ctx, &transaction_id, keygen_response.into())?
            .add_event(sender_allowed_event)
            .add_event(contract_acl_updated_event);

        Ok(response)
    }

    /// Processes an insecure key generation request (skipping the preproc step)
    /// by performing these steps:
    ///
    /// - Check sender permission to execute generate operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn insecure_key_gen_request(
        &self,
        mut ctx: ExecCtx,
        insecure_key_gen: InsecureKeyGenValues,
    ) -> Result<Response, BackendError> {
        let operation = "insecure_key_generation_request";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Generate, operation)?;
        let response = self
            .process_request_transaction(&mut ctx, insecure_key_gen.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes an insecure key generation response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed, and contract ACL updated events to the response
    #[sv::msg(exec)]
    pub fn insecure_key_gen_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "insecure_key_generation_response";
        let key_id = keygen_response.request_id().to_string();

        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;

        let transaction_sender = self
            .storage
            .get_transaction_sender(ctx.deps.storage, &transaction_id)?;
        self.storage
            .add_address_to_acl(ctx.deps.storage, &key_id, &transaction_sender)?;
        let contract_acl_updated_event =
            ContractAclUpdatedEvent::new(key_id, ctx.info.sender.to_string());

        let response =
            self.process_response_transaction(&mut ctx, &transaction_id, keygen_response.into())?;
        Ok(response
            .add_event(sender_allowed_event)
            .add_event(contract_acl_updated_event))
    }

    /// Processes a CRS generation request by performing these steps:
    /// - Check sender permission to execute generate operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn crs_gen_request(
        &self,
        mut ctx: ExecCtx,
        crs_gen: CrsGenValues,
    ) -> Result<Response, BackendError> {
        let operation = "crs_generation_request";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Generate, operation)?;
        let response = self
            .process_request_transaction(&mut ctx, crs_gen.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a CRS generation response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed, and gen response values saved events
    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "crs_generation_response";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;
        let response = self
            .process_response_transaction(&mut ctx, &transaction_id, crs_gen_response.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes an insecure CRS generation request by performing these steps:
    /// - Check sender permission to execute generate operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn insecure_crs_gen_request(
        &self,
        mut ctx: ExecCtx,
        insecure_crs_gen: InsecureCrsGenValues,
    ) -> Result<Response, BackendError> {
        let operation = "insecure_crs_generation_request";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Generate, operation)?;
        let response = self
            .process_request_transaction(&mut ctx, insecure_crs_gen.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes an insecure CRS generation response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed, and gen response values saved events
    #[sv::msg(exec)]
    pub fn insecure_crs_gen_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "insecure_crs_generation_response";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;
        let response = self
            .process_response_transaction(&mut ctx, &transaction_id, crs_gen_response.into())?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Processes a proven ciphertext verification request (which adds KMS operation event to the response)
    #[sv::msg(exec)]
    pub fn verify_proven_ct_request(
        &self,
        mut ctx: ExecCtx,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> Result<Response, BackendError> {
        self.process_request_transaction(&mut ctx, verify_proven_ct.into())
    }

    /// Processes a proven ciphertext verification response by performing these steps:
    /// - Check sender permission to execute response operations
    /// - Process the transaction (which adds KMS operation event to the response)
    /// - Add sender allowed event to the response
    #[sv::msg(exec)]
    pub fn verify_proven_ct_response(
        &self,
        mut ctx: ExecCtx,
        transaction_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    ) -> Result<Response, BackendError> {
        let operation = "proven_ct_verification_response";
        let sender_allowed_event =
            self.check_sender_is_allowed(&ctx, AllowlistType::Response, operation)?;
        let response = self
            .process_response_transaction(
                &mut ctx,
                &transaction_id,
                verify_proven_ct_response.into(),
            )?
            .add_event(sender_allowed_event);
        Ok(response)
    }

    /// Allow an address to trigger the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn add_allowlist(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: AllowlistType,
    ) -> Result<Response, BackendError> {
        self.impl_add_allowlist(ctx, address, operation_type)
            .map_err(BackendError::StdError)
    }

    /// Forbid an address from triggering the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn remove_allowlist(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: AllowlistType,
    ) -> Result<Response, BackendError> {
        self.impl_remove_allowlist(ctx, address, operation_type)
            .map_err(BackendError::StdError)
    }

    /// Replace all of the allowlists for the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn replace_allowlists(
        &self,
        ctx: ExecCtx,
        addresses: Vec<String>,
        operation_type: AllowlistType,
    ) -> Result<Response, BackendError> {
        self.impl_replace_allowlists(ctx, addresses, operation_type)
            .map_err(BackendError::StdError)
    }

    /// Grants access to a given key ID to a given address
    /// - Check sender access for given key ID
    /// - Add the given address to the ACL for given key ID
    /// - Emit key access allowed, and contract ACL updated events
    #[sv::msg(exec)]
    pub fn grant_key_access(
        &self,
        ctx: ExecCtx,
        request: GrantKeyAccessRequest,
    ) -> Result<Response, BackendError> {
        let key_access_allowed_event =
            self.check_key_access_is_allowed(&ctx, request.key_id.clone())?;
        self.storage
            .add_address_to_acl(ctx.deps.storage, &request.key_id, &request.address)?;
        let contract_acl_updated_event =
            ContractAclUpdatedEvent::new(request.key_id, request.address);
        let response = Response::new()
            .add_event(key_access_allowed_event)
            .add_event(contract_acl_updated_event);
        Ok(response)
    }

    /// Process request transaction
    ///
    /// Processes a request transaction and emits the corresponding event
    fn process_request_transaction(
        &self,
        ctx: &mut ExecCtx,
        operation: OperationValue,
    ) -> Result<Response, BackendError> {
        let transaction_id = Self::compute_transaction_id(&ctx.env)?;
        self.storage.save_request_on_transaction(
            ctx.deps.storage,
            &ctx.env,
            &transaction_id,
            &operation,
        )?;

        // Save the sender address separately for subsequent ACL inclusion at response processing
        if operation.is_key_gen() || operation.is_insecure_key_gen() {
            self.storage.save_transaction_sender(
                ctx.deps.storage,
                &transaction_id,
                &ctx.info.sender.to_string(),
            )?;
        }
        let response = self.emit_event(&ctx.deps, &transaction_id, &operation)?;
        Ok(response)
    }

    /// Process response transaction
    ///
    /// Processes a response transaction and emits the corresponding event if conditions are met.
    /// More info on the conditions to meet can be found in `events.rs`
    /// Note that response values cannot be saved along a transaction ID if this ID cannot be found
    /// in the `transactions` map, which means not request has been saved for this transaction.
    fn process_response_transaction(
        &self,
        ctx: &mut ExecCtx,
        transaction_id: &TransactionId,
        operation: OperationValue,
    ) -> Result<Response, BackendError> {
        // Check that the transaction exists. We should not store response values for a
        // transaction if the transaction does not exist
        if !self
            .storage
            .has_transaction(ctx.deps.storage, transaction_id)
        {
            return Err(BackendError::from(format!(
                "transaction with id <{}> not found for response operation value <{}>",
                transaction_id.to_hex(),
                operation
            )));
        }

        // Get all request values associated to the transaction
        let request_values = self.storage.get_request_values_from_transaction(
            ctx.deps.storage,
            transaction_id,
            None,
        )?;

        // Get the list of request operations associated to the response operation
        // This is a list because in case of generation (key or CRS) responses, which can be associated
        // to two different request operations: the normal one and the insecure one.
        let associated_requests = operation.into_kms_operation().to_requests().map_err(|e| {
            BackendError::from(format!(
                "unable to get request operations from response operation <{}>: {}",
                operation, e,
            ))
        })?;

        // Check that at least one of the request values matches one of the associated request operations
        let has_matching_request = request_values
            .iter()
            .any(|req_val| associated_requests.contains(&req_val.into_kms_operation()));

        // A response operation must be associated with a request operation of relevant type (ex:
        // `DecryptResponse` must be associated to `Decrypt`)
        if !has_matching_request {
            return Err(BackendError::from(format!(
                "no matching request operation found for response operation <{}>. A response
                operation must be associated with a request operation of relevant type.",
                operation
            )));
        }

        self.storage
            .save_response_on_transaction(ctx.deps.storage, transaction_id, &operation)?;

        let mut response = self.emit_event(&ctx.deps, transaction_id, &operation)?;

        // Save the KEY and CRS generation response values separately for more efficient queries
        response = match &operation {
            OperationValue::KeyGenResponse(keygen_response_values) => {
                self.storage.save_key_gen_response_values(
                    ctx.deps.storage,
                    keygen_response_values.clone(),
                )?;
                let gen_response_saved_event = GenResponseValuesSavedEvent::new(operation);
                response.add_event(gen_response_saved_event)
            }
            OperationValue::CrsGenResponse(crs_response_values) => {
                self.storage
                    .save_crs_response_values(ctx.deps.storage, crs_response_values.clone())?;
                let gen_response_saved_event = GenResponseValuesSavedEvent::new(operation);
                response.add_event(gen_response_saved_event)
            }
            _ => response,
        };
        Ok(response)
    }

    /// Check that the sender's address is allowed to access given key ID.
    fn check_key_access_is_allowed(
        &self,
        ctx: &ExecCtx,
        key_id: String,
    ) -> Result<KeyAccessAllowedEvent, BackendError> {
        let address_set = self
            .storage
            .get_acl_address_set(ctx.deps.storage, &key_id)?;
        let sender = ctx.info.sender.to_string();
        if !address_set.contains(&sender) {
            return Err(BackendError::from(format!(
                "Access not allowed for key ID <{}>",
                key_id
            )));
        }
        Ok(KeyAccessAllowedEvent::new(key_id, sender))
    }

    /// Returns a 20-length unique ID by hashing the combination of the current block height,
    /// the transaction index and the chain id, i.e. the triple (height, txn_idx, chain_id)
    fn compute_transaction_id(env: &Env) -> Result<TransactionId, BackendError> {
        let block_height = env.block.height;
        let transaction_index = env
            .transaction
            .as_ref()
            .ok_or_else(|| BackendError::from("Transaction index not found in env".to_string()))?
            .index;
        let chain_id = env.block.chain_id.to_string();

        let mut hasher = Sha3_256::new();
        hasher.update("KMS_BLOCK_HEIGHT");
        hasher.update(block_height.to_le_bytes());
        hasher.update("KMS_TRANSACTION_INDEX");
        hasher.update(transaction_index.to_le_bytes());
        hasher.update("KMS_CHAIN_ID");
        hasher.update(chain_id.as_bytes());
        let result = hasher.finalize();
        Ok(result[..20].to_vec().into())
    }

    /// Returns ciphertext size from given handle. Size is encoded as u32 in the first 4 bytes of the handle.
    fn calculate_ciphertext_handle_size(ciphertext_handle: &[u8]) -> u32 {
        ((ciphertext_handle[0] as u32) << 24)
            | ((ciphertext_handle[1] as u32) << 16)
            | ((ciphertext_handle[2] as u32) << 8)
            | (ciphertext_handle[3] as u32)
    }

    /// Verifies that sender has sufficient funds to cover the ciphertext storage payment amount.
    fn verify_sender_payment_capacity(
        ctx: &ExecCtx,
        ciphertext_handle_vectors: &[Vec<u8>],
    ) -> Result<(), BackendError> {
        let ciphertext_handles_size: u32 = ciphertext_handle_vectors
            .iter()
            .map(|handle| Self::calculate_ciphertext_handle_size(&handle[..4]))
            .sum();

        // This implicitly ensures the payment amount is included in the message
        let payment_amount = must_pay(&ctx.info, UCOSM).map_err(|_| {
            BackendError::from(format!("Ciphertext storage payment message not found in context (ciphertext_handles_size: {})", ciphertext_handles_size))
        })?;

        if payment_amount < ciphertext_handles_size.into() {
            return Err(BackendError::from(format!(
                "Insufficient funds for ciphertext storage payment (payment_amount: {})",
                payment_amount
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        allowlists::{AllowlistTypeBsc, AllowlistsBsc},
        contract::{
            sv::mt::{BackendContractProxy, CodeId},
            BackendContract, GrantKeyAccessRequest,
        },
    };
    use contracts_common::allowlists::AllowlistsManager;
    use cosmwasm_std::{coin, coins, testing::mock_env, Addr, Event, TransactionInfo};
    use csc::{allowlists::AllowlistsCsc, contract::sv::mt::CodeId as CSCCodeId};
    use cw_multi_test::{App as MtApp, IntoAddr as _};
    use events::{
        kms::{
            CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, FheParameter,
            FheType, InsecureCrsGenValues, InsecureKeyGenValues, KeyGenPreprocResponseValues,
            KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues, KmsCoreParty, KmsEvent,
            KmsOperation, OperationValue, ReencryptResponseValues, ReencryptValues, TransactionId,
            VerifyProvenCtResponseValues, VerifyProvenCtValues,
        },
        HexVector,
    };
    use std::collections::HashMap;
    use sylvia::multitest::{App, Proxy};

    const UCOSM: &str = "ucosm";
    const MOCK_BLOCK_HEIGHT: u64 = 12_345;
    const MOCK_TRANSACTION_INDEX: u32 = 0;

    // Helper function to set up test environment
    fn setup_test_env(app_default: bool) -> (App<MtApp>, Addr, String) {
        let owner = "owner".into_addr();

        let app: App<MtApp> = if app_default {
            App::default()
        } else {
            // Set up the app with initial balance for owner
            let mt_app = cw_multi_test::App::new(|router, _api, storage| {
                router
                    .bank
                    .init_balance(storage, &owner, coins(5000000, UCOSM))
                    .unwrap();
            });
            App::new(mt_app)
        };

        let parties = HashMap::from([
            ("signing_key_handle_1".to_string(), KmsCoreParty::default()),
            ("signing_key_handle_2".to_string(), KmsCoreParty::default()),
            ("signing_key_handle_3".to_string(), KmsCoreParty::default()),
            ("signing_key_handle_4".to_string(), KmsCoreParty::default()),
        ]);
        let storage_base_url = "https://new_storage_base_url.com".to_string();
        let allowlists_config = AllowlistsCsc::default_all_to(owner.as_str());

        // Store and instantiate CSC
        let config_code_id = CSCCodeId::store_code(&app);
        let csc_address = config_code_id
            .instantiate(
                parties.clone(),
                2,
                3,
                1,
                FheParameter::Test,
                storage_base_url,
                Some(allowlists_config),
            )
            .call(&owner)
            .unwrap()
            .contract_addr
            .to_string();

        (app, owner, csc_address)
    }

    // Helper function to compute a mocked transaction ID
    fn mock_transaction_id() -> TransactionId {
        let mut env = mock_env();
        env.block.height = MOCK_BLOCK_HEIGHT;
        env.transaction = Some(TransactionInfo {
            index: MOCK_TRANSACTION_INDEX,
        });
        BackendContract::compute_transaction_id(&env).unwrap()
    }

    // Helper function to assert that an event is present in the list of events
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

    /// Helper function that triggers the key generation process for a given key ID and
    /// a sender address (implicit ACL inclusion).
    fn add_address_to_contract_acl(
        contract: &Proxy<'_, MtApp, BackendContract>,
        key_id: &[u8],
        address: &Addr,
    ) {
        let keygen_val = KeyGenValues::new(
            "preproc_id".as_bytes().to_vec(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();
        contract
            .key_gen_request(keygen_val.clone())
            .call(address)
            .unwrap();

        let keygen_txn_id = mock_transaction_id();
        let keygen_response = KeyGenResponseValues::new(
            key_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![7, 8, 9],
            FheParameter::Test,
        );

        contract
            .key_gen_response(keygen_txn_id, keygen_response.clone())
            .call(address)
            .unwrap();
    }

    #[test]
    fn test_instantiate() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let is_contract_instantiated = code_id
            .instantiate(
                csc_address.to_string(),
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .is_ok();

        assert!(is_contract_instantiated);
    }

    #[test]
    fn test_migrate() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);
        let new_code_id = CodeId::store_code(&app);
        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .with_admin(Some(owner.as_str()))
            .call(&owner)
            .unwrap();
        let is_contract_migrated = contract
            .migrate()
            .call(&owner, new_code_id.code_id())
            .is_ok();
        assert!(is_contract_migrated);
    }

    #[test]
    fn test_decryption() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let key_id = vec![1, 2, 3];

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();

        let batch_size = 2_usize;

        let data_size = BackendContract::calculate_ciphertext_handle_size(&ciphertext_handle)
            * batch_size as u32;
        assert_eq!(data_size, 661448 * batch_size as u32);

        let decrypt = DecryptValues::new(
            key_id.clone(),
            vec![ciphertext_handle; batch_size],
            vec![FheType::Euint8; batch_size],
            Some(vec![vec![23_u8; 32]]),
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "some proof".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![101; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        contract
            .decryption_request(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .expect_err("An address not included into contract ACL was allowed to encrypt");

        add_address_to_contract_acl(&contract, &key_id, &owner);

        // test insufficient funds
        contract
            .decryption_request(decrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decryption_request(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 3);

        let txn_id = mock_transaction_id();
        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let response = contract
            .decryption_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .unwrap();

        // Two events because there's always an execute event
        // + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .decryption_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the decryption request since it reached the threshold
        // + the check sender event
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
        assert_eq!(response.block_height(), MOCK_BLOCK_HEIGHT);
        assert_eq!(response.transaction_index(), MOCK_TRANSACTION_INDEX);
        // Five operations: one decrypt, two decrypt and two from key generation
        assert_eq!(response.operations().len(), 5);
    }

    #[test]
    fn test_reencryption() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let key_id = vec![5];

        let contract = code_id.instantiate(csc_address, None).call(&owner).unwrap();

        let dummy_external_ciphertext_handle = hex::decode("0".repeat(64)).unwrap();
        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();
        let data_size = BackendContract::calculate_ciphertext_handle_size(&ciphertext_handle);
        assert_eq!(data_size, 661448);

        let reencrypt = ReencryptValues::new(
            vec![1],
            "0x1234".to_string(),
            vec![4],
            FheType::Euint8,
            key_id.clone(),
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

        contract
            .reencryption_request(reencrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .expect_err("An address not included into contract ACL was allowed to reencrypt");

        add_address_to_contract_acl(&contract, &key_id, &owner);

        contract
            .reencryption_request(reencrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .reencryption_request(reencrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        let txn_id = mock_transaction_id();

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Reencrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response_values = ReencryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let response = contract
            .reencryption_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .reencryption_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let response = contract
            .reencryption_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the reencrypt request since it reached the threshold
        // + the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::ReencryptResponse(response_values))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_key_gen_preproc() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let response = contract.key_gen_preproc_request().call(&owner).unwrap();
        let txn_id = mock_transaction_id();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract
            .key_gen_preproc_request()
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to init key generation with address {}",
                    fake_owner
                )
                .as_str(),
            );

        let response = contract
            .key_gen_preproc_response(txn_id.clone())
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

        contract
            .key_gen_preproc_response(txn_id.clone())
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call init key generation response with address {}",
                    fake_owner
                )
                .as_str(),
            );
    }

    #[test]
    fn test_key_gen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();
        let fake_txn_id = vec![1, 2, 3];
        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
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

        let response = contract
            .key_gen_request(keygen_val.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 3);

        let txn_id = mock_transaction_id();
        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract
            .key_gen_request(keygen_val)
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call key generation with address {}",
                    fake_owner
                )
                .as_str(),
            );

        // Key id should be a hex string
        let key_id = "a1b2c3d4e5f67890123456789abcdef0fedcba98";

        let keygen_response = KeyGenResponseValues::new(
            hex::decode(key_id).unwrap(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![7, 8, 9],
            FheParameter::Test,
        );

        contract
            .key_gen_response(fake_txn_id.into(), keygen_response.clone())
            .call(&owner)
            .expect_err("A non-existent transaction sender was included into contract ACL");

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Four events because there's always an execute event
        // + the check sender event
        // + ACL update event
        // + keygen response saved event
        assert_eq!(response.events.len(), 4);

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Five events because there's always an execute event
        // + the keygen request since it reached the threshold
        // + the check sender event
        // + ACL update event
        // + keygen response saved event
        assert_eq!(response.events.len(), 5);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

        contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call key generation response with address {}",
                    fake_owner
                )
                .as_str(),
            );

        // Key id should be a hex string
        let new_key_id = "a7f391e4d8c2b5f6e09d3c1a4b7852e9f0d6c3b9";

        let new_keygen_response = KeyGenResponseValues::new(
            hex::decode(new_key_id).unwrap(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![7, 8, 9],
            FheParameter::Test,
        );

        let response = contract
            .key_gen_response(txn_id.clone(), new_keygen_response.clone())
            .call(&owner)
            .unwrap();

        // We now have one more response event
        assert_eq!(response.events.len(), 5);

        // Test `get_key_gen_response_values` function
        let keygen_response_values = contract.get_key_gen_response_values(key_id.to_string());
        if let Err(err) = keygen_response_values {
            panic!(
                "Failed to get key gen response values for key id {}: {}",
                key_id, err
            );
        }

        // We triggered two response events for `key_id` so we should get two KeyGenResponseValues
        let keygen_response_values = keygen_response_values.unwrap();
        assert_eq!(
            keygen_response_values.len(),
            2,
            "Unexpected number of keygen response values for key id {}: {:?}",
            key_id,
            keygen_response_values
        );
    }

    #[test]
    fn test_insecure_key_gen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();
        let fake_txn_id = vec![1, 2, 3];
        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let insecure_keygen_val = InsecureKeyGenValues::new(
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract
            .insecure_key_gen_request(insecure_keygen_val.clone())
            .call(&owner)
            .unwrap();
        let txn_id = mock_transaction_id();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::InsecureKeyGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract
            .insecure_key_gen_request(insecure_keygen_val)
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call insecure key generation with address {}",
                    fake_owner
                )
                .as_str(),
            );

        let keygen_response = KeyGenResponseValues::new(
            txn_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![7, 8, 9],
            FheParameter::Test,
        );

        contract
            .insecure_key_gen_response(fake_txn_id.into(), keygen_response.clone())
            .call(&owner)
            .expect_err("A non-existent transaction sender was included into contract ACL");

        let response = contract
            .insecure_key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 4);

        let response = contract
            .insecure_key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 5);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

        contract
            .insecure_key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call insecure key generation response with address {}",
                    fake_owner
                )
                .as_str(),
            );
    }

    #[test]
    fn test_crs_gen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
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

        contract
            .crs_gen_request(crsgen_val.clone())
            .call(&fake_owner)
            .expect_err("User wasn't allowed to call CRS gen but somehow succeeded.");

        let response = contract.crs_gen_request(crsgen_val).call(&owner).unwrap();

        let txn_id = mock_transaction_id();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let crs_id = "crs_id";

        let crs_gen_response = CrsGenResponseValues::new(
            crs_id.to_string(),
            "my digest".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            256,
            FheParameter::Test,
        );

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the check sender event
        // + crsgen response saved event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // Four events because there's always an execute event
        // + the crs gen request since it reached the threshold
        // + the check sender event
        // + crsgen response saved event
        assert_eq!(response.events.len(), 4);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGenResponse)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&fake_owner)
            .expect_err("User wasn't allowed to call CRS gen response but somehow succeeded.");

        let new_crs_id = "new_crs_id";

        let new_crs_gen_response = CrsGenResponseValues::new(
            new_crs_id.to_string(),
            "my digest".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            256,
            FheParameter::Test,
        );

        let response = contract
            .crs_gen_response(txn_id.clone(), new_crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // We now have one more response event
        assert_eq!(response.events.len(), 4);

        // Test `get_crs_gen_response_values` function
        let crs_response_values = contract.get_crs_gen_response_values(crs_id.to_string());
        if let Err(err) = crs_response_values {
            panic!(
                "Failed to get CRS gen response values for CRS id {}: {}",
                crs_id, err
            );
        }

        // We triggered two response events for `crs_id` so we should get two CRSGenResponseValues
        let crs_response_values = crs_response_values.unwrap();
        assert_eq!(
            crs_response_values.len(),
            2,
            "Unexpected number of CRS gen response values for CRS id {}: {:?}",
            crs_id,
            crs_response_values
        );
    }

    #[test]
    fn test_insecure_crs_gen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let insecure_crsgen_val = InsecureCrsGenValues::new(
            192,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        contract
            .insecure_crs_gen_request(insecure_crsgen_val.clone())
            .call(&fake_owner)
            .expect_err("User wasn't allowed to call CRS gen but somehow succeeded.");

        let response = contract
            .insecure_crs_gen_request(insecure_crsgen_val)
            .call(&owner)
            .unwrap();

        let txn_id = mock_transaction_id();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::InsecureCrsGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let crs_id = "crs_id";

        let crs_gen_response = CrsGenResponseValues::new(
            crs_id.to_string(),
            "my digest".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            256,
            FheParameter::Test,
        );

        let response = contract
            .insecure_crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the check sender event
        // + gen response saved event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .insecure_crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the crs gen request since it reached the threshold
        // + the check sender event
        // + gen response saved event
        assert_eq!(response.events.len(), 4);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGenResponse)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract
            .insecure_crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&fake_owner)
            .expect_err("User wasn't allowed to call CRS gen response but somehow succeeded.");

        let new_crs_id = "new_crs_id";

        let new_crs_gen_response = CrsGenResponseValues::new(
            new_crs_id.to_string(),
            "my digest".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            256,
            FheParameter::Test,
        );

        let response = contract
            .insecure_crs_gen_response(txn_id.clone(), new_crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // We now have one more response event
        assert_eq!(response.events.len(), 4);

        // Test `get_crs_gen_response_values` function
        let crs_response_values = contract.get_crs_gen_response_values(crs_id.to_string());
        if let Err(err) = crs_response_values {
            panic!(
                "Failed to get CRS gen response values for CRS id {}: {}",
                crs_id, err
            );
        }

        // We triggered two response events for `crs_id` so we should get two CRSGenResponseValues
        let crs_response_values = crs_response_values.unwrap();
        assert_eq!(
            crs_response_values.len(),
            2,
            "Unexpected number of CRS gen response values for CRS id {}: {:?}",
            crs_id,
            crs_response_values
        );
    }

    #[test]
    fn test_verify_proven_ct() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
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
            .verify_proven_ct_request(proven_val.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let txn_id = mock_transaction_id();
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

        // Two events because there's always an execute event
        // + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .verify_proven_ct_response(txn_id.clone(), proven_ct_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the verify ct request since it reached the threshold
        // + the check sender event
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::VerifyProvenCtResponse(
                VerifyProvenCtResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_transaction(txn_id.clone()).unwrap();
        assert_eq!(response.block_height(), MOCK_BLOCK_HEIGHT);
        assert_eq!(response.transaction_index(), MOCK_TRANSACTION_INDEX);
        // three operations: one verify ct and two verify ct responses
        assert_eq!(response.operations().len(), 3);

        contract
            .verify_proven_ct_response(txn_id.clone(), proven_ct_response.clone())
            .call(&fake_owner)
            .expect_err(
                format!(
                    "Fake owner was allowed to call a verify proven ciphertext response with address {}",
                    fake_owner
                )
                .as_str(),
            );
    }

    #[test]
    fn test_grant_key_access_to_address() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let new_address = "new_address".into_addr();
        let key_id = HexVector::from(vec![1, 2, 3]);

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let grant_key_access_request = GrantKeyAccessRequest {
            address: new_address.to_string(),
            key_id: key_id.to_hex(),
        };

        contract
            .grant_key_access(grant_key_access_request.clone())
            .call(&owner)
            .expect_err(
                "An address without key access was allowed to grant access to other address",
            );

        add_address_to_contract_acl(&contract, &key_id, &owner);

        let response = contract
            .grant_key_access(grant_key_access_request)
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);
    }

    #[test]
    fn test_get_operations_values_from_event() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc::default_all_to(owner.as_str())),
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
        let response = contract
            .key_gen_request(keygen.clone())
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        // Get the transaction id from the decrypt event, since response values can only be stored
        // along an already-existing transaction ID
        let txn_id: TransactionId = hex::decode(
            response.events[1]
                .attributes
                .iter()
                .find(|attr| attr.key == "txn_id")
                .unwrap()
                .value
                .clone(),
        )
        .unwrap()
        .into();

        let keygen_response = KeyGenResponseValues::new(
            txn_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![7, 8, 9],
            FheParameter::Test,
        );

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Four events because there's always an execute event
        // + the check sender event
        // + ACL update event
        // + keygen response saved event
        assert_eq!(response.events.len(), 4);

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Five events because there's always an execute event
        // + the keygen response since it reached the threshold
        // + the check sender event
        // + ACL update event
        // + keygen response saved event
        assert_eq!(response.events.len(), 5);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        // Test `get_operations_values_from_event` function
        let keygen_data = contract
            .get_operations_values_from_event(expected_event)
            .unwrap();
        assert_eq!(keygen_data.len(), 2);

        let not_expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        // There should not be any decrypt operation
        let not_expected_data = contract.get_operations_values_from_event(not_expected_event);
        assert!(not_expected_data.unwrap().is_empty());
    }

    /// Test the `generate` list's logic. In particular this test makes sure to consider all
    /// kinds of possible inputs for this list.
    #[test]
    fn test_is_allowed_to_generate() {
        let (app, owner, csc_address) = setup_test_env(true);

        let user = "user".into_addr();
        let another_user = "another_user".into_addr();
        let connector = "connector".into_addr();

        let allowed_to_response = vec![connector.to_string()];
        let admins = vec![owner.to_string()];

        let crsgen_val = CrsGenValues::new(
            192,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        for (allowed_to_generate, allowed, instantiation_ok) in [
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
                        csc_address.clone(),
                        allowed_to_generate
                            .clone()
                            .map(|allowed_to_generate| AllowlistsBsc {
                                generate: allowed_to_generate,
                                response: allowed_to_response.clone(),
                                admin: admins.clone(),
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
                        let response = contract
                            .crs_gen_request(crsgen_val.clone())
                            .call(&wallet)
                            .unwrap();
                        assert_eq!(response.events.len(), 3);
                    } else {
                        // Failure
                        contract.crs_gen_request(crsgen_val.clone()).call(&wallet).expect_err(
                            format!(
                                "{} ({}) wasn't allowed to call CRS gen but somehow succeeded with `generate` list: {:?}.",
                                wallet_name,
                                wallet,
                                allowed_to_generate,
                            )
                            .as_str(),
                        );
                    }
                }
            } else {
                code_id
                    .instantiate(
                        csc_address.clone(),
                        allowed_to_generate
                            .clone()
                            .map(|allowed_to_generate: Vec<String>| AllowlistsBsc {
                                generate: allowed_to_generate,
                                response: allowed_to_response.clone(),
                                admin: admins.clone(),
                            }),
                    )
                    .call(&owner)
                    .expect_err(
                        format!(
                            "Instantiation didn't fail as expected with allow-list: {:?}.",
                            allowed_to_generate
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
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();
        let friend_owner = "friend_owner".into_addr();

        let allowed_to_generate = vec![owner.to_string()];
        let admins = vec![owner.to_string()];

        // Only the `owner` and `friend_owner` are allowed to trigger a decryption response
        let allowed_to_response = vec![owner.to_string(), friend_owner.to_string()];

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc {
                    generate: allowed_to_generate,
                    response: allowed_to_response.clone(),
                    admin: admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        // Trigger a decrypt response
        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        // Owner is allowed to call a decryption response but there's an expected error because the
        // transaction ID doesn't exist
        let txn_id = TransactionId::default();
        contract
            .decryption_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .expect_err("Owner was able to call a decryption response for a transaction that does not exist");

        // fake_owner is not allowed to call a decryption response
        contract
            .decryption_response(txn_id.clone(), decrypt_response.clone())
            .call(&fake_owner)
            .expect_err("Fake owner was allowed to call a decrypt response");
    }

    #[test]
    fn test_is_allowed_to_admin() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let friend_owner = "friend_owner".into_addr();

        let allowed_to_generate = vec![owner.to_string()];
        let allowed_to_response = vec![owner.to_string()];

        // Only the `owner` is allowed to trigger admin operations for now
        let admins = vec![owner.to_string()];

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                csc_address,
                Some(AllowlistsBsc {
                    generate: allowed_to_generate,
                    response: allowed_to_response.clone(),
                    admin: admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        contract
            .add_allowlist(friend_owner.to_string(), AllowlistTypeBsc::Admin)
            .call(&friend_owner)
            .expect_err("Friend owner added an address to the admin list before being allowed");

        // Owner can add friend owner to the admin list
        contract
            .add_allowlist(friend_owner.to_string(), AllowlistTypeBsc::Admin)
            .call(&owner)
            .unwrap();

        // Now, friend owner can remove owner from the admin list
        contract
            .remove_allowlist(owner.to_string(), AllowlistTypeBsc::Admin)
            .call(&friend_owner)
            .unwrap();

        // Owner is no longer an admin
        contract
            .add_allowlist(owner.to_string(), AllowlistTypeBsc::Admin)
            .call(&owner)
            .expect_err("Owner added an address to the admin list after being removed");

        contract
            .remove_allowlist(friend_owner.to_string(), AllowlistTypeBsc::Admin)
            .call(&friend_owner)
            .expect_err("Friend owner removed himself from the admin list");

        // Friend owner replaces the entire admin list with [owner]
        contract
            .replace_allowlists(vec![owner.to_string()], AllowlistTypeBsc::Admin)
            .call(&friend_owner)
            .unwrap();

        contract
            .replace_allowlists(vec![], AllowlistTypeBsc::Admin)
            .call(&owner)
            .expect_err("Owner replaced the admin list with an empty list");
    }
}
