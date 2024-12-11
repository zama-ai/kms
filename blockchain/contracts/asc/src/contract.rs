use super::state::KmsContractStorage;
use crate::backend_contract_staging::{AllowlistType, Allowlists, BackendContract};
use contracts_common::{
    allowlists::{AllowlistsContractManager, AllowlistsManager, AllowlistsStateManager},
    migrations::Migration,
};
use cosmwasm_std::{Response, StdResult};
use cw2::set_contract_version;
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, InsecureCrsGenValues,
    InsecureKeyGenValues, KeyGenResponseValues, KeyGenValues, KmsEvent, OperationValue,
    ReencryptResponseValues, ReencryptValues, Transaction, TransactionId,
    VerifyProvenCtResponseValues, VerifyProvenCtValues,
};
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx, QueryCtx},
};

// Info for migration
const CONTRACT_NAME: &str = "kms-asc";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    #[sv::msg(exec)]
    pub fn grant_key_access_to_address(
        &self,
        mut ctx: ExecCtx,
        key_id: String,
        new_address: String,
    ) -> StdResult<Response> {
        BackendContract::grant_key_access_to_address(&mut ctx, &self.storage, key_id, new_address)
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
        self.storage
            .load_transaction_with_response_values(ctx.deps.storage, &txn_id)
    }

    /// Get the list of all operation values found in the storage and associated to the given
    /// KMS event (a KMS operation and a transaction ID).
    #[sv::msg(query)]
    pub fn get_operations_values_from_event(
        &self,
        ctx: QueryCtx,
        event: KmsEvent,
    ) -> StdResult<Vec<OperationValue>> {
        self.storage.get_values_from_transaction_and_operation(
            ctx.deps.storage,
            &event.txn_id,
            &event.operation,
        )
    }

    /// Get the list of all key gen response values for a given key ID
    #[sv::msg(query)]
    pub fn get_key_gen_response_values(
        &self,
        ctx: QueryCtx,
        key_id: String,
    ) -> StdResult<Vec<KeyGenResponseValues>> {
        self.storage
            .get_key_gen_response_values(ctx.deps.storage, &key_id)
    }

    /// Get the list of all CRS gen response values for a given CRS ID
    #[sv::msg(query)]
    pub fn get_crs_gen_response_values(
        &self,
        ctx: QueryCtx,
        crs_id: String,
    ) -> StdResult<Vec<CrsGenResponseValues>> {
        self.storage
            .get_crs_gen_response_values(ctx.deps.storage, &crs_id)
    }

    #[sv::msg(exec)]
    pub fn decrypt(&self, mut ctx: ExecCtx, decrypt: DecryptValues) -> StdResult<Response> {
        BackendContract::process_decryption_request(&mut ctx, &self.storage, decrypt)
    }

    /// Decrypt response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn decrypt_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_decryption_response(
            &mut ctx,
            &self.storage,
            txn_id,
            decrypt_response,
        )
    }

    /// Keygen preproc
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn keygen_preproc(&self, mut ctx: ExecCtx) -> StdResult<Response> {
        BackendContract::process_key_generation_preproc_request(&mut ctx, &self.storage)
    }

    /// Keygen preproc response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn keygen_preproc_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
    ) -> StdResult<Response> {
        BackendContract::process_key_generation_preproc_response(&mut ctx, &self.storage, txn_id)
    }

    /// Insecure keygen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_key_gen(
        &self,
        mut ctx: ExecCtx,
        insecure_key_gen: InsecureKeyGenValues,
    ) -> StdResult<Response> {
        BackendContract::process_insecure_key_generation_request(
            &mut ctx,
            &self.storage,
            insecure_key_gen,
        )
    }

    /// Insecure keygen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_key_gen_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_insecure_key_generation_response(
            &mut ctx,
            &self.storage,
            txn_id,
            keygen_response,
        )
    }

    /// Keygen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn keygen(&self, mut ctx: ExecCtx, keygen: KeyGenValues) -> StdResult<Response> {
        BackendContract::process_key_generation_request(&mut ctx, &self.storage, keygen)
    }

    /// Keygen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn keygen_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_key_generation_response(
            &mut ctx,
            &self.storage,
            txn_id,
            keygen_response,
        )
    }

    #[sv::msg(exec)]
    pub fn reencrypt(&self, mut ctx: ExecCtx, reencrypt: ReencryptValues) -> StdResult<Response> {
        BackendContract::process_reencryption_request(&mut ctx, &self.storage, reencrypt)
    }

    /// Reencrypt response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn reencrypt_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_reencryption_response(
            &mut ctx,
            &self.storage,
            txn_id,
            reencrypt_response,
        )
    }

    #[sv::msg(exec)]
    pub fn verify_proven_ct(
        &self,
        mut ctx: ExecCtx,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> StdResult<Response> {
        BackendContract::process_proven_ct_verification_request(
            &mut ctx,
            &self.storage,
            verify_proven_ct,
        )
    }

    /// Verify proven ct response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn verify_proven_ct_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_proven_ct_verification_response(
            &mut ctx,
            &self.storage,
            txn_id,
            verify_proven_ct_response,
        )
    }

    /// CRS gen
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn crs_gen(&self, mut ctx: ExecCtx, crs_gen: CrsGenValues) -> StdResult<Response> {
        BackendContract::process_crs_generation_request(&mut ctx, &self.storage, crs_gen)
    }

    /// CRS gen response
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_crs_generation_response(
            &mut ctx,
            &self.storage,
            txn_id,
            crs_gen_response,
        )
    }

    /// Insecure CRS gen
    ///
    /// This call might be restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_crs_gen(
        &self,
        mut ctx: ExecCtx,
        insecure_crs_gen: InsecureCrsGenValues,
    ) -> StdResult<Response> {
        BackendContract::process_insecure_crs_generation_request(
            &mut ctx,
            &self.storage,
            insecure_crs_gen,
        )
    }

    /// Insecure CRS gen response
    ///
    /// This call might be restricted to specific addresses defined at instantiation (`Allowlists`).
    #[sv::msg(exec)]
    pub fn insecure_crs_gen_response(
        &self,
        mut ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        BackendContract::process_insecure_crs_generation_response(
            &mut ctx,
            &self.storage,
            txn_id,
            crs_gen_response,
        )
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
    use super::KmsContract;
    use crate::{
        allowlists::{AllowlistTypeAsc, AllowlistsAsc},
        backend_contract_staging::BackendContract,
        contract::sv::mt::CodeId,
    };
    use contracts_common::allowlists::AllowlistsManager;
    use cosmwasm_std::{coin, coins, testing::mock_env, Addr, Env, Event, TransactionInfo};
    use csc::{allowlists::AllowlistsCsc, contract::sv::mt::CodeId as CSCCodeId};
    use cw_multi_test::{App as MtApp, IntoAddr as _};
    use events::{
        kms::{
            CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, FheParameter,
            FheType, InsecureKeyGenValues, KeyGenPreprocResponseValues, KeyGenPreprocValues,
            KeyGenResponseValues, KeyGenValues, KmsCoreParty, KmsEvent, KmsOperation,
            OperationValue, ReencryptResponseValues, ReencryptValues, TransactionId,
            VerifyProvenCtResponseValues, VerifyProvenCtValues,
        },
        HexVector,
    };
    use sylvia::multitest::{App, Proxy};
    use tendermint_ipsc::mock::sv::mt::CodeId as ProofCodeId;

    const UCOSM: &str = "ucosm";

    const DUMMY_PROOF_CONTRACT_ADDR: &str =
        "cosmwasm1ejpjr43ht3y56pplm5pxpusmcrk9rkkvna4tklusnnwdxpqm0zls40599z";

    const MOCK_BLOCK_HEIGHT: u64 = 12_345;
    const MOCK_TRANSACTION_INDEX: u32 = 0;

    // Helper function to get a mocked environment with the mock block height and transaction index
    fn get_mock_env() -> Env {
        let mut mocked_env = mock_env();
        mocked_env.block.height = MOCK_BLOCK_HEIGHT;
        mocked_env.transaction = Some(TransactionInfo {
            index: MOCK_TRANSACTION_INDEX,
        });
        mocked_env
    }

    /// Triggers the key generation process for a given key ID and sender address (implicit ACL inclusion).
    fn add_address_to_contract_acl(
        contract: &Proxy<'_, MtApp, KmsContract>,
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
        contract.keygen(keygen_val.clone()).call(address).unwrap();

        let mocked_env = get_mock_env();
        let keygen_txn_id = BackendContract::compute_transaction_id(&mocked_env).unwrap();
        let keygen_response = KeyGenResponseValues::new(
            key_id.to_vec(),
            "digest1".to_string(),
            vec![4, 5, 6],
            "digest2".to_string(),
            vec![7, 8, 9],
            FheParameter::Test,
        );

        // Call the keygen response function using the owner address if provided
        // Else we use the address and consider that the address is already the owner (or is simply
        // allowed to response)
        contract
            .keygen_response(keygen_txn_id, keygen_response.clone())
            .call(address)
            .unwrap();
    }

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

        let storage_base_urls = vec!["https://dummy-storage-base-url.example.com".to_string()];
        let allowlists_config = AllowlistsCsc::default_all_to(owner.as_str());

        // Store and instantiate CSC
        let config_code_id = CSCCodeId::store_code(&app);
        let csc_address = config_code_id
            .instantiate(
                vec![KmsCoreParty::default(); 4],
                2,
                3,
                1,
                FheParameter::Test,
                storage_base_urls,
                Some(allowlists_config),
            )
            .call(&owner)
            .unwrap()
            .contract_addr
            .to_string();

        (app, owner, csc_address)
    }

    #[test]
    fn test_instantiate() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        // finally we make a successful attempt
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address.to_string(),
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
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
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
            .call(&owner)
            .unwrap();

        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
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
    fn test_decrypt() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let key_id = vec![1, 2, 3];

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
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
            key_id.clone(),
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

        contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .expect_err("An address not included into contract ACL was allowed to encrypt");

        add_address_to_contract_acl(&contract, &key_id, &owner);

        // test insufficient funds
        contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 3);

        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
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

        // Two events because there's always an execute event
        // + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response)
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
    fn test_decrypt_with_proof() {
        let (app, owner, csc_address) = setup_test_env(false);
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
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
        assert_eq!(data_size, 661448 * batch_size as u32);

        let decrypt = DecryptValues::new(
            key_id.clone(),
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

        add_address_to_contract_acl(&contract, &key_id, &owner);

        // test insufficient funds
        contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decrypt(decrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();

        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
        assert_eq!(response.events.len(), 4);

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

        // Two events because there's always an execute event
        // + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response)
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
    fn test_preproc() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc().call(&owner).unwrap();
        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract.keygen_preproc().call(&fake_owner).expect_err(
            format!(
                "Fake owner was allowed to init key generation with address {}",
                fake_owner
            )
            .as_str(),
        );

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

        contract
            .keygen_preproc_response(txn_id.clone())
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
    fn test_keygen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();
        let fake_txn_id = vec![1, 2, 3];

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
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

        let response = contract.keygen(keygen_val.clone()).call(&owner).unwrap();
        assert_eq!(response.events.len(), 3);

        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract.keygen(keygen_val).call(&fake_owner).expect_err(
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
            "digest2".to_string(),
            vec![7, 8, 9],
            FheParameter::Test,
        );

        contract
            .keygen_response(fake_txn_id.into(), keygen_response.clone())
            .call(&owner)
            .expect_err("A non-existent transaction sender was included into contract ACL");

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Two events because there's always an execute event
        // + the check sender event
        // + ACL update event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the keygen request since it reached the threshold
        // + the check sender event
        // + ACL update event
        assert_eq!(response.events.len(), 4);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .build();
        assert_event(&response.events, &expected_event);

        contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
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
            "digest2".to_string(),
            vec![7, 8, 9],
            FheParameter::Test,
        );

        let response = contract
            .keygen_response(txn_id.clone(), new_keygen_response.clone())
            .call(&owner)
            .unwrap();

        // We now have one more response event
        assert_eq!(response.events.len(), 4);

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
    fn test_insecure_keygen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();
        let fake_txn_id = vec![1, 2, 3];

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
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
            .insecure_key_gen(insecure_keygen_val.clone())
            .call(&owner)
            .unwrap();
        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
        assert_eq!(response.events.len(), 3);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::InsecureKeyGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        contract
            .insecure_key_gen(insecure_keygen_val)
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
            "digest2".to_string(),
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
        assert_eq!(response.events.len(), 3);

        let response = contract
            .insecure_key_gen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 4);

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
    fn test_reencrypt() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let key_id = vec![5];

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
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
            .reencrypt(reencrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .expect_err("An address not included into contract ACL was allowed to reencrypt");

        add_address_to_contract_acl(&contract, &key_id, &owner);

        contract
            .reencrypt(reencrypt.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .reencrypt(reencrypt.clone())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);

        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();

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
    fn test_crs_gen() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let fake_owner = "fake_owner".into_addr();

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
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
            .call(&fake_owner)
            .expect_err("User wasn't allowed to call CRS gen but somehow succeeded.");

        let txn_id = BackendContract::compute_transaction_id(&get_mock_env()).unwrap();
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
            256,
            FheParameter::Test,
        );

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // Two events because there's always an execute event
        // + the check sender event
        assert_eq!(response.events.len(), 2);

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the crs gen request since it reached the threshold
        // + the check sender event
        assert_eq!(response.events.len(), 3);

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
            256,
            FheParameter::Test,
        );

        let response = contract
            .crs_gen_response(txn_id.clone(), new_crs_gen_response.clone())
            .call(&owner)
            .unwrap();

        // We now have one more response event
        assert_eq!(response.events.len(), 3);

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
    fn test_get_operations_values_from_event() {
        let (app, owner, csc_address) = setup_test_env(false);
        let code_id = CodeId::store_code(&app);

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
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
            "digest2".to_string(),
            vec![7, 8, 9],
            FheParameter::Test,
        );

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Two events because there's always an execute event
        // + the check sender event
        // + ACL update event
        assert_eq!(response.events.len(), 3);

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();

        // Three events because there's always an execute event
        // + the keygen response since it reached the threshold
        // + the check sender event
        // + ACL update event
        assert_eq!(response.events.len(), 4);

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
                        Some(true),
                        DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                        csc_address.clone(),
                        allowed_to_generate
                            .clone()
                            .map(|allowed_to_generate| AllowlistsAsc {
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
                        let response = contract.crs_gen(crsgen_val.clone()).call(&wallet).unwrap();
                        assert_eq!(response.events.len(), 3);
                    } else {
                        // Failure
                        contract.crs_gen(crsgen_val.clone()).call(&wallet).expect_err(
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
                        Some(true),
                        DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                        csc_address.clone(),
                        allowed_to_generate
                            .clone()
                            .map(|allowed_to_generate: Vec<String>| AllowlistsAsc {
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

        // Only the `owner` and `friend_owner` are allowed to trigger a decrypt response
        let allowed_to_response = vec![owner.to_string(), friend_owner.to_string()];

        // Instantiate the contract
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc {
                    generate: allowed_to_generate,
                    response: allowed_to_response.clone(),
                    admin: admins.clone(),
                }),
            )
            .call(&owner)
            .unwrap();

        // Trigger a decrypt response
        let decrypt_response = DecryptResponseValues::new(vec![4, 5, 6], vec![6, 7, 8]);

        let txn_id = TransactionId::default();

        // Owner has been allowed to call a decrypt response, but it should be able to because the
        // given transaction ID does not exist (meaning no request transaction has been triggered
        // using this ID yet)
        let response_not_possible_error = contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&owner)
            .unwrap_err()
            .to_string();

        assert!(
            response_not_possible_error
                .contains("not found while trying to save response operation value"),
            "Owner was able to call a decrypt response for a transaction that does not exist: {}",
            response_not_possible_error
        );

        // `fake_owner` is not allowed to call a decrypt response, so the first error should be about
        // the address not being allowed
        let response_not_allowed_error = contract
            .decrypt_response(txn_id.clone(), decrypt_response.clone())
            .call(&fake_owner)
            .unwrap_err()
            .to_string();

        assert!(
            response_not_allowed_error.contains("is not allowed"),
            "Fake owner was allowed to call a decrypt response with address {}, allowlist {:?} and error: {}",
            fake_owner,
            allowed_to_response,
            response_not_allowed_error
        );
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
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
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

    #[test]
    fn test_grant_key_access_to_address() {
        let (app, owner, csc_address) = setup_test_env(true);
        let code_id = CodeId::store_code(&app);

        let new_address = "new_address".into_addr();
        let key_id = HexVector::from(vec![1, 2, 3]);

        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_PROOF_CONTRACT_ADDR.to_string(),
                csc_address,
                Some(AllowlistsAsc::default_all_to(owner.as_str())),
            )
            .call(&owner)
            .unwrap();

        contract
            .grant_key_access_to_address(key_id.to_hex(), new_address.to_string())
            .call(&owner)
            .expect_err(
                "An address without key access was allowed to grant access to other address",
            );

        add_address_to_contract_acl(&contract, &key_id, &owner);

        let response = contract
            .grant_key_access_to_address(key_id.to_hex(), new_address.to_string())
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 3);
    }
}
