use crate::events::EventEmitStrategy as _;
use crate::{
    proof::{ContractProofType, DebugProofStrategy, ProofStrategy},
    state::{KmsContractStorage, KmsCoreConf},
};
use core::cell::RefCell;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Response, StdError, StdResult, VerificationError};
use cw_controllers::Admin;
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues,
    KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues, KmsEvent,
    OperationValue, ReencryptResponseValues, ReencryptValues, Transaction, TransactionId,
};
use events::HexVector;
use sha3::{Digest, Sha3_256};
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, QueryCtx},
};

#[cw_serde]
pub struct SequenceResponse {
    pub sequence: u64,
}

#[cw_serde]
pub struct ConfigurationResponse {
    pub value: String,
}

pub(crate) const ADMIN: Admin = Admin::new("kms-conf-admin");

pub struct KmsContract {
    pub(crate) storage: KmsContractStorage,
    proof_strategy: RefCell<Box<dyn ProofStrategy>>,
}

impl Default for KmsContract {
    fn default() -> Self {
        Self {
            storage: KmsContractStorage::new(),
            proof_strategy: RefCell::new(Box::new(DebugProofStrategy {})),
        }
    }
}

#[entry_points]
#[contract]
impl KmsContract {
    pub fn new() -> Self {
        Self::default()
    }

    fn derive_transaction_id(&self, ctx: &ExecCtx) -> StdResult<Vec<u8>> {
        let block_height = ctx.env.block.height;
        let transaction_index = ctx
            .env
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
        result[..].to_vec()
    }

    fn process_transaction<T>(
        &self,
        ctx: ExecCtx,
        txn_id: &[u8],
        proof: HexVector,
        operation: T,
    ) -> StdResult<Response>
    where
        T: Into<OperationValue> + Clone,
    {
        let mut ctx = ctx;
        self.storage
            .update_transaction(&mut ctx, txn_id, &operation)?;
        let response = self.emit_event(&ctx, txn_id, proof, &operation)?;
        Ok(response)
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        proof_type: ContractProofType,
        kms_core_conf: KmsCoreConf,
    ) -> StdResult<Response> {
        match proof_type {
            ContractProofType::Debug => {
                *self.proof_strategy.borrow_mut() = Box::new(DebugProofStrategy {})
            }
            ContractProofType::Tendermint => {
                *self.proof_strategy.borrow_mut() = Box::new(DebugProofStrategy {})
            }
        }
        self.storage
            .update_core_conf(ctx.deps.storage, kms_core_conf)?;
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

    #[sv::msg(exec)]
    pub fn decrypt(
        &self,
        ctx: ExecCtx,
        decrypt: DecryptValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_request_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let txn_id = self.derive_transaction_id(&ctx)?;
        self.process_transaction(ctx, &txn_id, proof, decrypt)
    }

    #[sv::msg(exec)]
    pub fn decrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        decrypt_response: DecryptResponseValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_response_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        self.process_transaction(ctx, &txn_id.to_vec(), proof, decrypt_response)
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc(&self, ctx: ExecCtx, proof: HexVector) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_request_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let txn_id = self.derive_transaction_id(&ctx)?;
        self.process_transaction(ctx, &txn_id, proof, KeyGenPreprocValues::default())
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_response_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        self.process_transaction(
            ctx,
            &txn_id.to_vec(),
            proof,
            KeyGenPreprocResponseValues::default(),
        )
    }

    #[sv::msg(exec)]
    pub fn keygen(
        &self,
        ctx: ExecCtx,
        keygen: KeyGenValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_request_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let txn_id = self.derive_transaction_id(&ctx)?;
        self.process_transaction(ctx, &txn_id, proof, keygen)
    }

    #[sv::msg(exec)]
    pub fn keygen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_response_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        self.process_transaction(ctx, &txn_id.to_vec(), proof, keygen_response)
    }

    #[sv::msg(exec)]
    pub fn reencrypt(
        &self,
        ctx: ExecCtx,
        reencrypt: ReencryptValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_request_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let txn_id = self.derive_transaction_id(&ctx)?;
        self.process_transaction(ctx, &txn_id, proof, reencrypt)
    }

    #[sv::msg(exec)]
    pub fn reencrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_response_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }

        self.process_transaction(ctx, &txn_id.to_vec(), proof, reencrypt_response)
    }

    #[sv::msg(exec)]
    pub fn crs_gen(&self, ctx: ExecCtx, proof: HexVector) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_request_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let txn_id = self.derive_transaction_id(&ctx)?;
        self.process_transaction(ctx, &txn_id, proof, CrsGenValues::default())
    }

    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
        proof: HexVector,
    ) -> StdResult<Response> {
        if !self
            .proof_strategy
            .borrow()
            .verify_response_proof(proof.clone().into())
        {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        self.process_transaction(ctx, &txn_id.to_vec(), proof, crs_gen_response)
    }
}

#[cfg(test)]
mod tests {
    use super::sv::mt::KmsContractProxy;
    use crate::contract::sv::mt::CodeId;
    use crate::contract::KmsContract;
    use crate::proof::ContractProofType;
    use crate::state::KmsCoreConf;
    use crate::state::KmsCoreThresholdConf;
    use cosmwasm_std::Event;
    use events::kms::CrsGenResponseValues;
    use events::kms::DecryptResponseValues;
    use events::kms::DecryptValues;
    use events::kms::FheType;
    use events::kms::KeyGenPreprocResponseValues;
    use events::kms::KeyGenPreprocValues;
    use events::kms::KeyGenResponseValues;
    use events::kms::KeyGenValues;
    use events::kms::KmsEvent;
    use events::kms::KmsOperation;
    use events::kms::OperationValue;
    use events::kms::ReencryptResponseValues;
    use events::kms::ReencryptValues;
    use events::kms::TransactionId;
    use events::HexVector;
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;

    #[test]
    fn test_instantiate() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
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
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let value = KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] });

        contract
            .update_kms_core_conf(value.clone())
            .call(&owner)
            .unwrap();

        let result = contract.get_kms_core_conf().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_decrypt() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let decrypt = DecryptValues::builder()
            .key_id(vec![1, 2, 3])
            .version(1)
            .servers_needed(2)
            .ciphertext(vec![2, 3, 4])
            .randomness(vec![3, 4, 5])
            .fhe_type(FheType::Euint8)
            .build();
        let response = contract
            .decrypt(decrypt.clone(), proof.clone())
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let decrypt_response = DecryptResponseValues::builder()
            .signature(vec![4, 5, 6])
            .payload(vec![6, 7, 8])
            .build();

        let response = contract
            .decrypt_response(txn_id.clone(), decrypt_response, proof.clone())
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::DecryptResponse(
                DecryptResponseValues::builder()
                    .signature(vec![4, 5, 6])
                    .payload(vec![6, 7, 8])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_transaction(txn_id.clone()).unwrap();
        assert_eq!(response.block_height(), 12345);
        assert_eq!(response.transaction_index(), 0);
        assert_eq!(response.operations().len(), 2);
    }

    #[test]
    fn test_preproc() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc(proof.clone()).call(&owner).unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .keygen_preproc_response(txn_id.clone(), proof.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(OperationValue::KeyGenPreprocResponse(
                KeyGenPreprocResponseValues {},
            ))
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_keygen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let preproc_id = "preproc_id".as_bytes().to_vec().into();
        let keygen = KeyGenValues::builder().preproc_id(preproc_id).build();
        let response = contract
            .keygen(keygen.clone(), proof.clone())
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let keygen_response = KeyGenResponseValues::builder()
            .request_id(txn_id.to_vec())
            .public_key_digest("digest1".to_string())
            .public_key_signature(vec![4, 5, 6])
            .server_key_digest("digest2".to_string())
            .server_key_signature(vec![7, 8, 9])
            .build();

        let response = contract
            .keygen_response(txn_id.clone(), keygen_response.clone(), proof.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGenResponse)
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();
        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_reencrypt() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let reencrypt = ReencryptValues::builder()
            .signature(vec![1])
            .version(1)
            .servers_needed(2)
            .verification_key(vec![2])
            .randomness(vec![3])
            .enc_key(vec![4])
            .fhe_type(FheType::Euint8)
            .key_id(vec![5])
            .ciphertext(vec![6])
            .ciphertext_digest(vec![9])
            .eip712_name("name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![7])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![8])
            .build();

        let response = contract
            .reencrypt(reencrypt.clone(), proof.clone())
            .call(&owner)
            .unwrap();

        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Reencrypt)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response_values = ReencryptResponseValues::builder()
            .version(1)
            .servers_needed(2)
            .verification_key(vec![1])
            .digest(vec![2])
            .fhe_type(FheType::Ebool)
            .signcrypted_ciphertext(vec![3])
            .build();

        let response = contract
            .reencrypt_response(txn_id.clone(), response_values.clone(), proof.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 1);
    }

    #[test]
    fn test_crs_gen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let response = contract.crs_gen(proof.clone()).call(&owner).unwrap();

        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGen)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let crs_gen_response = CrsGenResponseValues::builder()
            .request_id(txn_id.to_hex())
            .digest("my digest".to_string())
            .signature(vec![4, 5, 6])
            .build();

        let response = contract
            .crs_gen_response(txn_id.clone(), crs_gen_response.clone(), proof.clone())
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGenResponse)
            .txn_id(txn_id.clone())
            .proof(proof)
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
    fn test_get_operations_value() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                ContractProofType::Debug,
                KmsCoreConf::Threshold(KmsCoreThresholdConf { parties: vec![] }),
            )
            .call(&owner)
            .unwrap();

        let decrypt = DecryptValues::builder()
            .key_id(vec![1, 2, 3])
            .version(1)
            .servers_needed(2)
            .ciphertext(vec![2, 3, 4])
            .randomness(vec![3, 4, 5])
            .fhe_type(FheType::Euint8)
            .build();
        let response = contract
            .decrypt(decrypt.clone(), proof.clone())
            .call(&owner)
            .unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_operations_value(expected_event).unwrap();
        assert_eq!(response.len(), 1);

        let not_expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        let response = contract.get_operations_value(not_expected_event);
        assert!(response.is_err());
    }
}
