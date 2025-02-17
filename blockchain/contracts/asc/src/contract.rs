use super::state::KmsContractStorage;
use crate::external_queries::{BscExecMsg, BscQueryMsg};
use contracts_common::{
    allowlists::{AllowlistsContractManager, AllowlistsManager, AllowlistsStateManager},
    migrations::Migration,
};
use cosmwasm_std::{wasm_execute, Response, StdResult};
use cw2::set_contract_version;
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, InsecureCrsGenValues,
    InsecureKeyGenValues, KeyGenResponseValues, KeyGenValues, KmsEvent, OperationValue,
    ReencryptResponseValues, ReencryptValues, Transaction, TransactionId,
    VerifyProvenCtResponseValues, VerifyProvenCtValues,
};
use serde::de::DeserializeOwned;
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx, QueryCtx},
};

// Info for migration
const CONTRACT_NAME: &str = "kms-asc";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// Type aliases for the allowlists and operation types to use in the ASC
// We recover them from the storage for better maintainability
pub type Allowlists = <KmsContractStorage as AllowlistsStateManager>::Allowlists;
pub type AllowlistType = <Allowlists as AllowlistsManager>::AllowlistType;

#[derive(Default)]
pub struct KmsContract {
    pub(crate) storage: KmsContractStorage,
}

/// Implement the `AllowlistsContractManager` trait
///
/// This allows to set and update allowed lists in the contract. It also provides a way to check
/// that the sender is allowed to trigger a given operation
impl AllowlistsContractManager for KmsContract {
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
impl Migration for KmsContract {}

#[entry_points]
#[contract]
impl KmsContract {
    pub fn new() -> Self {
        Self::default()
    }

    /// ASC instantiation
    ///
    /// The Application Smart Contract instantiation.
    ///
    /// # Arguments
    ///
    /// * `allowlists` - an optional struct containing several lists of addresses that define
    /// who can trigger certain operations (ex: `gen`, `response` or `admin` operations).
    /// Providing None will default to use the sender's address for all operation types.
    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        debug_proof: Option<bool>,
        verify_proof_contract_addr: String,
        csc_address: String,
        bsc_address: String,
        allowlists: Option<Allowlists>,
    ) -> StdResult<Response> {
        // Inclusion proof debug configuration
        // While developing without a blockchain against which to verify we might need to skip the
        // call to a inclusion proof smart contract altogether. This allows that
        if let Some(debug_proof) = debug_proof {
            self.storage
                .set_debug_proof(ctx.deps.storage, debug_proof)?;
        } else {
            self.storage.set_debug_proof(ctx.deps.storage, false)?;
        }

        // Configure allowlists for some operations
        let allowlists = match allowlists {
            Some(addresses) => {
                addresses.check_all_addresses_are_valid(ctx.deps.api)?;
                addresses
            }
            None => {
                // Default to only allowing the contract instantiator
                Allowlists::default_all_to(ctx.info.sender.as_str())
            }
        };

        self.storage.set_allowlists(ctx.deps.storage, allowlists)?;

        // Inclusion proof smart contract configuration
        self.storage
            .set_verify_proof_contract_address(ctx.deps.storage, verify_proof_contract_addr)?;

        // CSC configuration
        self.storage
            .set_csc_address(ctx.deps.storage, csc_address)?;

        self.storage
            .set_bsc_address(ctx.deps.storage, bsc_address)?;

        // Set contract name and version in the storage
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        Ok(Response::default())
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
    ) -> StdResult<Response> {
        self.impl_add_allowlist(ctx, address, operation_type)
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
    ) -> StdResult<Response> {
        self.impl_remove_allowlist(ctx, address, operation_type)
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
    ) -> StdResult<Response> {
        self.impl_replace_allowlists(ctx, addresses, operation_type)
    }

    #[sv::msg(query)]
    pub fn get_transaction(&self, ctx: QueryCtx, txn_id: TransactionId) -> StdResult<Transaction> {
        let bsc_query_msg = BscQueryMsg::Transaction { txn_id };
        self.process_bsc_query(ctx, bsc_query_msg)
    }

    /// Get the list of all operation values found in the storage and associated to the given
    /// KMS event (a KMS operation and a transaction ID).
    #[sv::msg(query)]
    pub fn get_operations_values_from_event(
        &self,
        ctx: QueryCtx,
        event: KmsEvent,
    ) -> StdResult<Vec<OperationValue>> {
        let bsc_query_msg = BscQueryMsg::OperationsValuesFromEvent { event };
        self.process_bsc_query(ctx, bsc_query_msg)
    }

    /// Get the list of all key gen response values for a given key ID
    #[sv::msg(query)]
    pub fn get_key_gen_response_values(
        &self,
        ctx: QueryCtx,
        key_id: String,
    ) -> StdResult<Vec<KeyGenResponseValues>> {
        let bsc_query_msg = BscQueryMsg::KeyGenResponseValues { key_id };
        self.process_bsc_query(ctx, bsc_query_msg)
    }

    /// Get the list of all CRS gen response values for a given CRS ID
    #[sv::msg(query)]
    pub fn get_crs_gen_response_values(
        &self,
        ctx: QueryCtx,
        crs_id: String,
    ) -> StdResult<Vec<CrsGenResponseValues>> {
        let bsc_query_msg = BscQueryMsg::CrsGenResponseValues { crs_id };
        self.process_bsc_query(ctx, bsc_query_msg)
    }

    #[sv::msg(exec)]
    pub fn decryption_request(&self, ctx: ExecCtx, decrypt: DecryptValues) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::DecryptionRequest { decrypt };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Decrypt response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn decryption_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::DecryptionResponse {
            txn_id,
            decrypt_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Keygen preproc
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn key_gen_preproc_request(&self, ctx: ExecCtx) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::KeyGenPreprocRequest {};
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Keygen preproc response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn key_gen_preproc_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::KeyGenPreprocResponse { txn_id };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Insecure keygen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_key_gen_request(
        &self,
        ctx: ExecCtx,
        insecure_key_gen: InsecureKeyGenValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::InsecureKeyGenRequest { insecure_key_gen };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Insecure keygen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_key_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::InsecureKeyGenResponse {
            txn_id,
            keygen_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Keygen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn key_gen_request(&self, ctx: ExecCtx, keygen: KeyGenValues) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::KeyGenRequest { keygen };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Keygen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn key_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::KeyGenResponse {
            txn_id,
            keygen_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    #[sv::msg(exec)]
    pub fn reencryption_request(
        &self,
        ctx: ExecCtx,
        reencrypt: ReencryptValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::ReencryptionRequest { reencrypt };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Reencrypt response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn reencryption_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::ReencryptionResponse {
            txn_id,
            reencrypt_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    #[sv::msg(exec)]
    pub fn verify_proven_ct_request(
        &self,
        ctx: ExecCtx,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::VerifyProvenCtRequest { verify_proven_ct };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Verify proven ct response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn verify_proven_ct_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::VerifyProvenCtResponse {
            txn_id,
            verify_proven_ct_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// CRS gen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn crs_gen_request(&self, ctx: ExecCtx, crs_gen: CrsGenValues) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::CrsGenRequest { crs_gen };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// CRS gen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::CrsGenResponse {
            txn_id,
            crs_gen_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Insecure CRS gen
    ///
    /// This call might be restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_crs_gen_request(
        &self,
        ctx: ExecCtx,
        insecure_crs_gen: InsecureCrsGenValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::InsecureCrsGenRequest { insecure_crs_gen };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Insecure CRS gen response
    ///
    /// This call might be restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        let bsc_exec_msg = BscExecMsg::InsecureCrsGenResponse {
            txn_id,
            crs_gen_response,
        };
        self.process_bsc_exec(ctx, bsc_exec_msg)
    }

    /// Queries the BSC at the stored address during ASC instantiation
    fn process_bsc_query<T: DeserializeOwned>(
        &self,
        ctx: QueryCtx,
        bsc_query_msg: BscQueryMsg,
    ) -> StdResult<T> {
        let bsc_address = self.storage.get_bsc_address(ctx.deps.storage)?;
        let query_result = ctx
            .deps
            .querier
            .query_wasm_smart(bsc_address, &bsc_query_msg)?;
        Ok(query_result)
    }

    /// Dispatches an execution call to the BSC at the stored address during ASC instantiation
    fn process_bsc_exec(&self, ctx: ExecCtx, bsc_exec_msg: BscExecMsg) -> StdResult<Response> {
        let bsc_address = self.storage.get_bsc_address(ctx.deps.storage)?;
        let exec_msg = wasm_execute(bsc_address, &bsc_exec_msg, ctx.info.funds)?;
        Ok(Response::default().add_message(exec_msg))
    }

    /// Function to migrate from old version to new version
    ///
    /// As there is only one version of the contract for now, this function has no real use. Future
    /// versions of the contract will be required to provide this function, with additional migration
    /// logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> StdResult<Response> {
        self.apply_migration(ctx.deps.storage)
    }
}

#[cfg(test)]
mod tests {
    use super::sv::mt::KmsContractProxy;
    use crate::{
        allowlists::{AllowlistTypeAsc, AllowlistsAsc},
        contract::sv::mt::CodeId,
    };
    use bsc::{
        allowlists::AllowlistTypeBsc,
        contract::sv::mt::{BackendContractProxy, CodeId as BSCCodeId},
        contract::BackendContract,
    };
    use contracts_common::allowlists::AllowlistsManager;
    use cosmwasm_std::{coin, coins, Addr, Event};
    use csc::{allowlists::AllowlistsCsc, contract::sv::mt::CodeId as CSCCodeId};
    use cw_multi_test::{App as MtApp, IntoAddr as _};
    use events::kms::{
        CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, FheParameter,
        FheType, InsecureKeyGenValues, KeyGenPreprocResponseValues, KeyGenPreprocValues,
        KeyGenResponseValues, KeyGenValues, KmsCoreParty, KmsEvent, KmsOperation, OperationValue,
        ReencryptResponseValues, ReencryptValues, TransactionId, VerifyProvenCtResponseValues,
        VerifyProvenCtValues,
    };
    use serde::Serialize;
    use std::collections::HashMap;
    use sylvia::multitest::{App, Proxy};
    use tendermint_ipsc::mock::sv::mt::CodeId as ProofCodeId;

    const UCOSM: &str = "ucosm";

    const DUMMY_PROOF_CONTRACT_ADDR: &str =
        "cosmwasm1ejpjr43ht3y56pplm5pxpusmcrk9rkkvna4tklusnnwdxpqm0zls40599z";

    const MOCK_BLOCK_HEIGHT: u64 = 12_345;
    const MOCK_TRANSACTION_INDEX: u32 = 0;

    /// Triggers the key generation process for a given key ID and sender address (implicit ACL inclusion).
    fn add_address_to_bsc_acl(
        app: &App<MtApp>,
        bsc_address: &String,
        key_id: &[u8],
        address: &Addr,
    ) {
        let bsc: Proxy<'_, MtApp, BackendContract> =
            Proxy::from((Addr::unchecked(bsc_address), app));
        let keygen_val = KeyGenValues::new(
            "preproc_id".as_bytes().to_vec(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();
        let response = bsc
            .key_gen_request(keygen_val.clone())
            .call(address)
            .unwrap();
        let txn_id = find_transaction_id_from_events(&response.events);
        let keygen_response = KeyGenResponseValues::new(
            key_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![9, 9, 9],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![9, 9, 9],
            FheParameter::Test,
        );

        // Call the keygen response function using the owner address if provided
        // Else we use the address and consider that the address is already the owner (or is simply
        // allowed to response)
        bsc.key_gen_response(txn_id, keygen_response.clone())
            .call(address)
            .unwrap();
    }

    /// Helper function to add an address to the BSC allowlist
    fn add_address_to_bsc_allowlist(
        app: &App<MtApp>,
        bsc_address: &String,
        sender: &Addr,
        address: &Addr,
    ) {
        let bsc: Proxy<'_, MtApp, BackendContract> =
            Proxy::from((Addr::unchecked(bsc_address), app));
        bsc.add_allowlist(address.to_string(), AllowlistTypeBsc::Generate)
            .call(sender)
            .unwrap();
        bsc.add_allowlist(address.to_string(), AllowlistTypeBsc::Response)
            .call(sender)
            .unwrap();
    }

    /// Helper function to find the transaction ID from given KMS blockchain events
    fn find_transaction_id_from_events(events: &[Event]) -> TransactionId {
        let keygen_event = events
            .iter()
            .find(|e| {
                e.ty == "wasm-keygen"
                    || e.ty == "wasm-decrypt"
                    || e.ty == "wasm-reencrypt"
                    || e.ty == "wasm-crs_gen"
                    || e.ty == "wasm-keygen_preproc"
                    || e.ty == "wasm-insecure_key_gen"
                    || e.ty == "wasm-verify_proven_ct"
            })
            .unwrap();
        hex::decode(
            keygen_event
                .attributes
                .iter()
                .find(|attr| attr.key == "txn_id")
                .unwrap()
                .value
                .clone(),
        )
        .unwrap()
        .into()
    }

    /// Helper function to assert that a given KMS event is present in the given list of events
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

    // Helper function to set up test environment
    fn setup_test_env(app_default: bool) -> (App<MtApp>, Addr, String, String) {
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

        // Store and instantiate BSC
        let bsc_code_id = BSCCodeId::store_code(&app);
        let bsc_address = bsc_code_id
            .instantiate(csc_address.clone(), None)
            .call(&owner)
            .unwrap()
            .contract_addr
            .to_string();
        (app, owner, csc_address, bsc_address)
    }

    #[test]
    fn test_instantiate() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        // finally we make a successful attempt
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let value = contract.get_transaction(TransactionId::default());
        assert!(value.is_err());
    }

    fn extract_ciphertext_size(ciphertext_handle: &[u8]) -> u32 {
        ((ciphertext_handle[0] as u32) << 24)
            | ((ciphertext_handle[1] as u32) << 16)
            | ((ciphertext_handle[2] as u32) << 8)
            | (ciphertext_handle[3] as u32)
    }

    #[test]
    fn test_verify_proven_ct() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);

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
        // Three events:
        // - ASC's execute event
        // - BSC's execute event
        // - Verify proven CT request event
        assert_eq!(response.events.len(), 3);

        let txn_id = find_transaction_id_from_events(&response.events);
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
        // Three events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Sender allowed event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .verify_proven_ct_response(txn_id.clone(), proven_ct_response.clone())
            .call(&owner)
            .unwrap();
        // Four events (threshold reached):
        // - ASC's execute event
        // - BSC's execute event
        // - Verify proven CT response event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

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
    }

    #[test]
    fn test_decrypt() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let key_id = vec![1, 2, 3];

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);
        add_address_to_bsc_acl(&app, &bsc_address, &key_id, &contract.contract_addr);

        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();

        let batch_size = 2_usize;

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
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

        let response = contract
            .decryption_request(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Decrypt request event
        // - Key access allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
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
        // Three events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Sender allowed event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .decryption_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();
        // Four events (threshold reached):
        // - ASC's execute event
        // - BSC's execute event
        // - Decrypt response event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

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
    fn test_decrypt_with_proof() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);
        let proof_code_id = ProofCodeId::store_code(&app);

        let key_id = vec![1, 2, 3];

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
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);
        add_address_to_bsc_acl(&app, &bsc_address, &key_id, &contract.contract_addr);

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
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

        let response = contract
            .decryption_request(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Decrypt request event
        // - Key access allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
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
        // Three events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Sender allowed event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .decryption_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();
        // Four events (threshold reached):
        // - ASC's execute event
        // - BSC's execute event
        // - Decrypt response event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

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
    fn test_preproc() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);

        let response = contract.key_gen_preproc_request().call(&owner).unwrap();
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Key gen preproc request event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .key_gen_preproc_response(txn_id.clone())
            .call(&owner)
            .unwrap();
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Key gen preproc response event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreprocResponse(
                KeyGenPreprocResponseValues {},
            ))
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);
    }

    use strum_macros::EnumString;

    #[derive(EnumString, Serialize, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Exec {
        #[serde(rename = "test_exec")]
        AddAllowlist {},
    }

    #[test]
    fn test_keygen() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);
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
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Key gen request event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

        // Key id should be a hex string
        let key_id = "a1b2c3d4e5f67890123456789abcdef0fedcba98";
        let keygen_response = KeyGenResponseValues::new(
            hex::decode(key_id).unwrap(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![9, 9, 9],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![9, 9, 9],
            FheParameter::Test,
        );
        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // Five events (threshold not reached yet):
        // - ASC execute event
        // - BSC execute event
        // - Gen response values saved event
        // - Sender allowed event
        // - BSC acl updated event
        assert_eq!(response.events.len(), 5);

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // Six events (threshold reached):
        // - ASC execute event
        // - BSC execute event
        // - Key gen response event
        // - Gen response values saved event
        // - Sender allowed event
        // - BSC acl updated event
        assert_eq!(response.events.len(), 6);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

        // Test `get_key_gen_response_values` function
        let keygen_response_values = contract
            .get_key_gen_response_values(key_id.to_string())
            .unwrap();
        // We triggered two response events for `key_id` so we should get two KeyGenResponseValues
        assert_eq!(
            keygen_response_values.len(),
            2,
            "Unexpected number of keygen response values for key id {}: {:?}",
            key_id,
            keygen_response_values
        );
    }

    #[test]
    fn test_insecure_keygen() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);

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
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Insecure key gen request event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::InsecureKeyGen)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

        let keygen_response = KeyGenResponseValues::new(
            txn_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![9, 9, 9],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![9, 9, 9],
            FheParameter::Test,
        );

        let response = contract
            .insecure_key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // Five events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Gen response values saved event
        // - Sender allowed event
        // - BSC acl updated event
        assert_eq!(response.events.len(), 5);

        let response = contract
            .insecure_key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // Six events (threshold reached):
        // - ASC execute event
        // - BSC execute event
        // - Key gen response event
        // - Gen response values saved event
        // - Sender allowed event
        // - BSC acl updated event
        assert_eq!(response.events.len(), 6);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_reencrypt() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);
        let key_id = vec![5];

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                None,
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);
        add_address_to_bsc_acl(&app, &bsc_address, &key_id, &contract.contract_addr);

        let dummy_external_ciphertext_handle = hex::decode("0".repeat(64)).unwrap();
        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();
        let data_size = extract_ciphertext_size(&ciphertext_handle);
        assert_eq!(data_size, 661448);

        let reencrypt = ReencryptValues::new(
            vec![1],
            "0x1234".to_string(),
            vec![4],
            FheType::Euint8,
            key_id.clone(),
            vec![dummy_external_ciphertext_handle.clone()],
            vec![ciphertext_handle.clone()],
            vec![vec![9]],
            "dummy_acl_address".to_string(),
            "some proof".to_string(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract
            .reencryption_request(reencrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Reencrypt request event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
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
        // Three events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Sender allowed event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .reencryption_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        // Three events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Sender allowed event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .reencryption_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        // Four events (threshold reached):
        // - ASC's execute event
        // - BSC's execute event
        // - Reencrypt response event
        // - Sender allowed even
        assert_eq!(response.events.len(), 4);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::ReencryptResponse(response_values))
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_crs_gen() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);

        let crsgen_val = CrsGenValues::new(
            192,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();

        let response = contract
            .crs_gen_request(crsgen_val.clone())
            .call(&owner)
            .unwrap();
        // Four events:
        // - ASC execute event
        // - BSC execute event
        // - CRS gen request event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
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
            vec![9, 8, 7],
            256,
            FheParameter::Test,
        );

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();
        // Four events (threshold not reached yet):
        // - ASC execute event
        // - BSC execute event
        // - Gen response values saved event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response)
            .call(&owner)
            .unwrap();
        // Five events (threshold reached):
        // - ASC execute event
        // - BSC execute event
        // - CRS gen response event
        // - Gen response values saved event
        // - Sender allowed event
        assert_eq!(response.events.len(), 5);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

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
    fn test_get_operations_values_from_event() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address.clone(),
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();
        add_address_to_bsc_allowlist(&app, &bsc_address, &owner, &contract.contract_addr);

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
        // Four events:
        // - ASC's execute event
        // - BSC's execute event
        // - Key gen request event
        // - Sender allowed event
        assert_eq!(response.events.len(), 4);

        let txn_id = find_transaction_id_from_events(&response.events);
        let keygen_response = KeyGenResponseValues::new(
            txn_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            vec![9, 9, 9],
            "digest2".to_string(),
            vec![7, 8, 9],
            vec![9, 9, 9],
            FheParameter::Test,
        );

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // Five events (threshold not reached yet):
        // - ASC's execute event
        // - BSC's execute event
        // - Gen response values saved event
        // - Sender allowed event
        // - BSC acl updated event
        assert_eq!(response.events.len(), 5);

        let response = contract
            .key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // Six events (threshold reached):
        // - ASC's execute event
        // - BSC's execute event
        // - Key gen response event
        // - Gen response values saved event
        // - Sender allowed event
        // - BSC acl updated event
        println!("{:?}", response.events);
        assert_eq!(response.events.len(), 6);

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

    #[test]
    fn test_is_allowed_to_admin() {
        let (app, owner, csc_address, bsc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let friend_owner = "friend_owner".into_addr();

        let allowed_to_generate = vec![owner.to_string()];
        let allowed_to_response = vec![owner.to_string()];

        // Only the `owner` is allowed to trigger admin operations for now
        let admins = vec![owner.to_string()];

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                bsc_address,
                Some(AllowlistsAsc {
                    generate: allowed_to_generate,
                    response: allowed_to_response.clone(),
                    admin: admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        // Friend owner is not allowed to trigger admin operations
        contract
            .add_allowlist(friend_owner.to_string(), AllowlistTypeAsc::Admin)
            .call(&friend_owner)
            .unwrap_err();

        // Owner can add friend owner to the admin list
        contract
            .add_allowlist(friend_owner.to_string(), AllowlistTypeAsc::Admin)
            .call(&owner)
            .unwrap();

        // Now, friend owner can remove owner from the admin list
        contract
            .remove_allowlist(owner.to_string(), AllowlistTypeAsc::Admin)
            .call(&friend_owner)
            .unwrap();

        // Owner is no longer an admin
        contract
            .add_allowlist(owner.to_string(), AllowlistTypeAsc::Admin)
            .call(&owner)
            .unwrap_err();

        // Friend owner cannot remove himself from the admin list since there is only one
        // admin
        contract
            .remove_allowlist(friend_owner.to_string(), AllowlistTypeAsc::Admin)
            .call(&friend_owner)
            .unwrap_err();

        // Friend owner replaces the entire admin list with [owner]
        contract
            .replace_allowlists(vec![owner.to_string()], AllowlistTypeAsc::Admin)
            .call(&friend_owner)
            .unwrap();

        // Owner can update the admin list back again, but cannot replace it with an empty one
        contract
            .replace_allowlists(vec![], AllowlistTypeAsc::Admin)
            .call(&owner)
            .unwrap_err();
    }
}
