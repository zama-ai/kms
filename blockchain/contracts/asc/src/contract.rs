use super::state::KmsContractStorage;
use crate::events::EventEmitStrategy as _;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_json_binary, Env, Response, StdError, StdResult, Storage, WasmMsg};
use cw_controllers::Admin;
use cw_utils::must_pay;
use events::kms::{
    AllowListConf, CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues,
    KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues,
    KmsCoreConf, KmsEvent, KmsOperation, OperationValue, ReencryptResponseValues, ReencryptValues,
    Transaction, TransactionId, VerifyProvenCtValues,
};
use events::kms::{InsecureKeyGenValues, VerifyProvenCtResponseValues};
use sha3::{Digest, Sha3_256};
use std::ops::Deref;
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, QueryCtx},
};

const UCOSM: &str = "ucosm";

pub(crate) const ADMIN: Admin = Admin::new("kms-conf-admin");

#[cw_serde]
pub struct ProofPayload {
    pub proof: String,
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
    ) -> StdResult<Response> {
        if !self.storage.get_debug_proof(ctx.deps.storage)? {
            let msg = ProofMessage {
                verify_proof: ProofPayload { proof },
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

    /// Verifies that the caller is in the allow-list
    ///
    /// Some operations aren't meant for users like key-gen and crs-gen.
    /// Thus a list of addresses allowed to call restricted operators is set in the instantiation
    /// of this contract. This method verifies that the caller is in the configured allowed-list.
    pub fn verify_allow_list(
        &self,
        ctx: &ExecCtx,
        operation: &str,
    ) -> std::result::Result<(), cosmwasm_std::StdError> {
        let sender_string_address = ctx.info.sender.as_str().to_string();
        if !self
            .storage
            .allow_list_contains(ctx.deps.storage, &sender_string_address)
            .map_err(|_| {
                StdError::generic_err(format!(
                    "Error checking if address is allowed in operation: {}",
                    operation
                ))
            })?
        {
            return Err(StdError::generic_err(format!(
                "{} {}",
                sender_string_address, operation
            )));
        };
        Ok(())
    }

    /// ASC contract instantiation
    ///
    /// The Application Smart Contract instantiation.
    ///
    /// # Arguments
    ///
    /// * `allow_list_conf` - an optional list of who can call crs-gen, insecure-key-gen, key-gen,
    /// key-gen preprocessing methods.
    /// Providing None will default to only the address of the sender.
    /// Providing `["*"]` will allow everyone to access the endpoints
    /// If the list is not the wild-card it should only contain valid addresses.
    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        debug_proof: Option<bool>,
        verify_proof_contract_addr: String,
        kms_core_conf: KmsCoreConf,
        allow_list_conf: Option<AllowListConf>,
    ) -> StdResult<Response> {
        if let KmsCoreConf::Threshold(conf) = &kms_core_conf {
            // centralized setting should be used if there is only one party
            if conf.parties.len() < 2 {
                return Err(cosmwasm_std::StdError::generic_err(
                    "conf.parties.len() !< 2, in this case please use the centralized version", // VerificationError::GenericErr,
                ));
            }

            // check that degree is at least 1
            if conf.degree_for_reconstruction < 1 {
                return Err(cosmwasm_std::StdError::generic_err(
                    "conf.degree_for_reconstruction !< 1",
                ));
            }

            // check that the number of shares needed for reconstruction is at least degree + 2
            // this is the minimum value such that error detection is possible
            if conf.response_count_for_reconstruction < conf.degree_for_reconstruction + 2 {
                return Err(cosmwasm_std::StdError::generic_err(
                    "conf.response_count_for_reconstruction !< conf.degree_for_reconstruction + 2",
                ));
            }

            // there can not be enough responses for reconstruction
            if conf.response_count_for_reconstruction > conf.parties.len() {
                return Err(cosmwasm_std::StdError::generic_err(
                    "conf.response_count_for_reconstruction !> conf.parties.len()",
                ));
            }

            // there can not be enough responses for majority vote
            if conf.response_count_for_majority_vote > conf.parties.len() {
                return Err(cosmwasm_std::StdError::generic_err(
                    "conf.response_count_for_majority_vote !> conf.parties.len()",
                ));
            }
        };

        // Inclusion proof debug configuration
        // While developing without a blockchain against which to verify we might need to skip the
        // call to a inclusion proof smart contract altogether. This allows that
        if let Some(debug_proof) = debug_proof {
            self.storage
                .set_debug_proof(ctx.deps.storage, debug_proof)?;
        } else {
            self.storage.set_debug_proof(ctx.deps.storage, false)?;
        }

        // Allow-list configuration
        if let Some(allow_list) = allow_list_conf {
            // Verify that they can be cast as addresses
            let all_valid_addresses = allow_list
                .allow_list
                .clone()
                .into_iter()
                .all(|addr| ctx.deps.api.addr_validate(&addr).is_ok());

            let wild_card = (allow_list.allow_list.len() == 1) && (allow_list.allow_list[0] == "*");
            if !(all_valid_addresses | wild_card) {
                return Err(cosmwasm_std::StdError::generic_err(
                    "allow_list contains invalid addresses",
                ));
            };

            self.storage
                .set_allow_list(ctx.deps.storage, allow_list.allow_list)?
        } else {
            self.storage
                .set_allow_list(ctx.deps.storage, vec![ctx.info.sender.to_string()])?
        }

        // Inclusion proof smart contract configuration
        self.storage
            .set_verify_proof_contract_address(ctx.deps.storage, verify_proof_contract_addr)?;

        // KMS Core configuration
        self.storage
            .update_core_conf(ctx.deps.storage, kms_core_conf)?;

        // Administrator configuration
        ADMIN.set(ctx.deps, Some(ctx.info.sender.clone()))?;

        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get_kms_core_conf(&self, ctx: QueryCtx) -> StdResult<KmsCoreConf> {
        self.storage.load_core_conf(ctx.deps.storage)
    }

    #[sv::msg(exec)]
    pub fn update_kms_core_conf(&self, ctx: ExecCtx, conf: KmsCoreConf) -> StdResult<Response> {
        ADMIN
            .assert_admin(ctx.deps.as_ref(), &ctx.info.sender)
            .map_err(|_| {
                StdError::generic_err("Only the admin can update the KMS core configuration")
            })?;
        self.storage.update_core_conf(ctx.deps.storage, conf)
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
    pub fn decrypt(&self, ctx: ExecCtx, decrypt: DecryptValues) -> StdResult<Response> {
        // decipher the size encoding and ensure the payment is included in the message
        let ciphertext_handles = decrypt.ciphertext_handles();

        let ctvecs: Vec<Vec<u8>> = ciphertext_handles.0.iter().map(|ct| ct.to_vec()).collect();

        self.verify_payment(&ctx, &ctvecs).map_err(|e| {
            StdError::generic_err(format!(
                "Error verifying payment for ciphertext storage - {}",
                e
            ))
        })?;
        let mut ctx = ctx;
        let response = self.process_request_transaction(&mut ctx, decrypt.clone().into())?;
        self.chain_verify_proof_contract_call(ctx, response, decrypt.proof().to_string())
    }

    #[sv::msg(exec)]
    pub fn decrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            decrypt_response.into(),
        )
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc(&self, ctx: ExecCtx) -> StdResult<Response> {
        let mut ctx = ctx;
        self.verify_allow_list(&ctx, "keygen_preproc")?;
        self.process_request_transaction(&mut ctx, KeyGenPreprocValues::default().into())
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            KeyGenPreprocResponseValues::default().into(),
        )
    }

    #[sv::msg(exec)]
    pub fn insecure_key_gen(
        &self,
        ctx: ExecCtx,
        insecure_key_gen: InsecureKeyGenValues,
    ) -> StdResult<Response> {
        let mut ctx = ctx;
        self.verify_allow_list(&ctx, "insecure_key_gen")?;
        self.process_request_transaction(&mut ctx, OperationValue::InsecureKeyGen(insecure_key_gen))
    }

    #[sv::msg(exec)]
    pub fn insecure_key_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            keygen_response.into(),
        )
    }

    #[sv::msg(exec)]
    pub fn keygen(&self, ctx: ExecCtx, keygen: KeyGenValues) -> StdResult<Response> {
        let mut ctx = ctx;
        self.verify_allow_list(&ctx, "keygen")?;
        self.process_request_transaction(&mut ctx, keygen.into())
    }

    #[sv::msg(exec)]
    pub fn keygen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            keygen_response.into(),
        )
    }

    #[sv::msg(exec)]
    pub fn reencrypt(&self, ctx: ExecCtx, reencrypt: ReencryptValues) -> StdResult<Response> {
        // decipher the size encoding and ensure the payment is included in the message
        let ciphertext_handle: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        self.verify_payment(&ctx, &[ciphertext_handle.clone()])?;
        let mut ctx = ctx;
        let response = self.process_request_transaction(&mut ctx, reencrypt.clone().into())?;
        self.chain_verify_proof_contract_call(ctx, response, reencrypt.proof().to_string())
    }

    #[sv::msg(exec)]
    pub fn reencrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            reencrypt_response.into(),
        )
    }

    #[sv::msg(exec)]
    pub fn verify_proven_ct(
        &self,
        ctx: ExecCtx,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> StdResult<Response> {
        let mut ctx = ctx;
        self.process_request_transaction(&mut ctx, verify_proven_ct.into())
    }

    #[sv::msg(exec)]
    pub fn verify_proven_ct_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            verify_proven_ct_response.into(),
        )
    }

    #[sv::msg(exec)]
    pub fn crs_gen(&self, ctx: ExecCtx, crs_gen: CrsGenValues) -> StdResult<Response> {
        let mut ctx = ctx;
        self.verify_allow_list(&ctx, "crs_gen")?;
        self.process_request_transaction(&mut ctx, OperationValue::CrsGen(crs_gen))
    }

    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    ) -> StdResult<Response> {
        self.process_transaction(
            ctx.deps.storage,
            &ctx.env,
            &txn_id.to_vec(),
            crs_gen_response.into(),
        )
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
    use cosmwasm_std::Event;
    use events::kms::AllowListConf;
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
    use events::kms::KmsCoreThresholdConf;
    use events::kms::KmsEvent;
    use events::kms::KmsOperation;
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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 2,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()]
                }),
            )
            .call(&owner)
            .is_err());

        // `response_count_for_majority_vote` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 5,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()]
                }),
            )
            .call(&owner)
            .is_err());

        // `response_count_for_reconstruction` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 5,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()]
                }),
            )
            .call(&owner)
            .is_err());

        // finally we make a successful attempt
        let contract = code_id
            .instantiate(
                Some(true),
                DUMMY_BECH32_ADDR.to_string(),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
            )
            .call(&owner)
            .unwrap();

        let value = KmsCoreConf::Threshold(KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 4],
            response_count_for_majority_vote: 3,
            response_count_for_reconstruction: 3,
            degree_for_reconstruction: 1,
            param_choice: FheParameter::Test,
        });

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
        // one event because there's always an execute event
        assert_eq!(response.events.len(), 1);

        let response = contract
            .verify_proven_ct_response(txn_id.clone(), proven_ct_response)
            .call(&owner)
            .unwrap();
        // two events because there's always an execute event
        // plus the verify ct request since it reached the threshold
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
        // one event because there's always an execute event
        assert_eq!(response.events.len(), 1);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();
        // two events because there's always an execute event
        // plus the decryption request since it reached the threshold
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
        // one event because there's always an execute event
        assert_eq!(response.events.len(), 1);

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response)
            .call(&owner)
            .unwrap();
        // two events because there's always an execute event
        // plus the decryption request since it reached the threshold
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
            )
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc().call(&owner).unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .keygen_preproc_response(txn_id.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
        assert_eq!(response.events.len(), 2);

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
        assert_eq!(response.events.len(), 1);

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        // one exec and two response events
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 1,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                None,
            )
            .call(&owner)
            .unwrap();

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
        assert_eq!(response.events.len(), 1);

        let response = contract
            .reencrypt_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 1);

        let response = contract
            .reencrypt_response(txn_id.clone(), response_values.clone())
            .call(&owner)
            .unwrap();
        // one exec and one response event since we hit the threshold of 3
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
        assert_eq!(response.events.len(), 2);

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
        assert_eq!(response.events.len(), 1);

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response)
            .call(&owner)
            .unwrap();
        // one exec and two response events
        assert_eq!(response.events.len(), 2);

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
                Some(AllowListConf {
                    allow_list: vec![owner.to_string()],
                }),
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
        assert_eq!(response.events.len(), 2);

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
        assert_eq!(response.events.len(), 1);

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

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
        assert_eq!(response.events.len(), 1);

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

    #[test]
    fn test_allow_list() {
        let owner = "owner".into_addr();
        let user = "user".into_addr();
        let another_user = "another_user".into_addr();
        let app = App::default();

        let crsgen_val = CrsGenValues::new(
            192,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap();
        for (allow_list, allowed, instantiation_ok) in [
            (None, vec![true, false, false], true), // Defaults to owner only
            (Some(vec![]), vec![false, false, false], true), // Empty -> no one can operate (not sure this is really useful)
            (Some(vec!["*".to_string()]), vec![true, true, true], true), // Wild-card, everyone can
            (Some(vec!["".to_string()]), vec![false, false, false], false), // Instantiation error -> not a valid address
            (
                Some(vec![user.to_string(), owner.to_string()]),
                vec![true, true, false],
                true,
            ), // Both user and
            // owner can
            (
                Some(vec![user.to_string(), owner.to_string(), "*".to_string()]),
                vec![false, false, false],
                false,
            ), // Instantiation
            // error -> invalid to use wild card with other addresses
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
                        KmsCoreConf::Threshold(KmsCoreThresholdConf {
                            parties: vec![KmsCoreParty::default(); 4],
                            response_count_for_majority_vote: 2,
                            response_count_for_reconstruction: 3,
                            degree_for_reconstruction: 1,
                            param_choice: FheParameter::Test,
                        }),
                        allow_list
                            .clone()
                            .map(|allow_list| AllowListConf { allow_list }),
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
                        assert_eq!(response.events.len(), 2);
                    } else {
                        // Failure
                        contract.crs_gen(crsgen_val.clone()).call(&wallet).expect_err(
                            format!(
                                "{} ({}) wasn't allowed to call CRS gen but somehow succeeded with allow_list: {:?}.",
                                wallet_name,
                                wallet,
                                allow_list,
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
                        KmsCoreConf::Threshold(KmsCoreThresholdConf {
                            parties: vec![KmsCoreParty::default(); 4],
                            response_count_for_majority_vote: 2,
                            response_count_for_reconstruction: 3,
                            degree_for_reconstruction: 1,
                            param_choice: FheParameter::Test,
                        }),
                        allow_list
                            .clone()
                            .map(|allow_list| AllowListConf { allow_list }),
                    )
                    .call(&owner)
                    .expect_err(
                        format!(
                            "Instantiation didn't fail as expected with allow-list: {:?}.",
                            allow_list
                        )
                        .as_str(),
                    );
            }
        }
    }
}
