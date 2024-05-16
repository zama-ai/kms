use crate::proof::ContractProofType;
use crate::proof::DebugProofStrategy;
use crate::proof::ProofStrategy;
use core::cell::RefCell;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::VerificationError;
use cosmwasm_std::{Response, StdResult};
use cw_storage_plus::Map;
use events::kms::{
    CrsGenResponseValues, DecryptResponseValues, DecryptValues, KeyGenPreprocResponseValues,
    KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues, ReencryptResponseValues,
    ReencryptValues, Transaction, TransactionId,
};
use events::kms::{CrsGenValues, KmsEvent};
use events::HexVector;
use sha2::Digest;
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::{contract, entry_points};

#[cw_serde]
pub struct SequenceResponse {
    pub sequence: u64,
}

#[cw_serde]
pub struct ConfigurationResponse {
    pub value: String,
}

pub struct KmsContract {
    pub(crate) config: Map<String, String>,
    pub(crate) transactions: Map<Vec<u8>, Transaction>,
    proof_strategy: RefCell<Box<dyn ProofStrategy>>,
}

impl Default for KmsContract {
    fn default() -> Self {
        Self {
            config: Map::new("config"),
            transactions: Map::new("transactions"),
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

    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        key: String,
        value: String,
        proof_type: ContractProofType,
    ) -> StdResult<Response> {
        self.config.save(ctx.deps.storage, key, &value)?;
        match proof_type {
            ContractProofType::Debug => {
                *self.proof_strategy.borrow_mut() = Box::new(DebugProofStrategy {})
            }
            ContractProofType::Tendermint => {
                *self.proof_strategy.borrow_mut() = Box::new(DebugProofStrategy {})
            }
        }
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get(&self, ctx: QueryCtx, key: String) -> StdResult<ConfigurationResponse> {
        let value = self.config.load(ctx.deps.storage, key)?;
        Ok(ConfigurationResponse { value })
    }

    #[sv::msg(exec)]
    pub fn set(&self, ctx: ExecCtx, key: String, value: String) -> StdResult<Response> {
        self.config
            .update(ctx.deps.storage, key, |_| -> StdResult<String> {
                Ok(value)
            })?;
        Ok(Response::default())
    }

    fn derive_transaction_id(&self, ctx: &ExecCtx) -> (Vec<u8>, Transaction) {
        let mut hasher = sha2::Sha256::new();
        let block_height = ctx.env.block.height;
        let transaction_index = ctx.env.transaction.clone().unwrap().index;
        hasher.update(block_height.to_string());
        hasher.update(transaction_index.to_string());
        let result = hasher.finalize();
        // truncate the result to 20 bytes
        let id = result[..20].to_vec();
        let transaction = Transaction {
            block_height,
            transaction_index,
        };
        (id, transaction)
    }

    #[sv::msg(query)]
    pub fn transactions(&self, ctx: QueryCtx, txn_id: TransactionId) -> StdResult<Transaction> {
        let value = self.transactions.load(ctx.deps.storage, txn_id.to_vec())?;
        Ok(value)
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
        let (txn_id, transaction) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(decrypt)
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions
            .save(ctx.deps.storage, txn_id, &transaction)?;
        Ok(response)
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
        if !self.transactions.has(ctx.deps.storage, txn_id.to_vec()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(decrypt_response)
            .txn_id(txn_id)
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());

        Ok(response)
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
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KeyGenPreprocValues {})
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
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
        if !self.transactions.has(ctx.deps.storage, txn_id.to_vec()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KeyGenPreprocResponseValues {})
            .proof(proof)
            .txn_id(txn_id)
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
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
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(keygen)
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
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
        if !self.transactions.has(ctx.deps.storage, txn_id.to_vec()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(keygen_response)
            .txn_id(txn_id)
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
    }

    // TODO find a way to simplfy this API
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
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(reencrypt)
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
    }

    // TODO find a way to simplfy this API
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

        if !self.transactions.has(ctx.deps.storage, txn_id.to_vec()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(reencrypt_response)
            .txn_id(txn_id)
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
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
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(CrsGenValues::default())
            .txn_id(txn_id.clone())
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
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
        if !self.transactions.has(ctx.deps.storage, txn_id.to_vec()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(crs_gen_response)
            .txn_id(txn_id)
            .proof(proof)
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::sv::mt::{CodeId, KmsContractProxy as _};
    use crate::proof::ContractProofType;
    use cosmwasm_std::Event;
    use events::kms::CrsGenResponseValues;
    use events::kms::CrsGenValues;
    use events::kms::DecryptResponseValues;
    use events::kms::DecryptValues;
    use events::kms::FheType;
    use events::kms::KeyGenPreprocResponseValues;
    use events::kms::KeyGenPreprocValues;
    use events::kms::KeyGenResponseValues;
    use events::kms::KeyGenValues;
    use events::kms::KmsEvent;
    use events::kms::KmsOperationAttribute;
    use events::kms::ReencryptResponseValues;
    use events::kms::ReencryptValues;
    use events::kms::TransactionId;
    use events::HexVector;
    use sha2::Digest;
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;

    fn expected_transaction_id(height: u64, txn_idx: u32) -> TransactionId {
        let mut hasher = sha2::Sha256::new();
        hasher.update(height.to_string());
        hasher.update(txn_idx.to_string());
        let result = hasher.finalize();
        result[..20].to_vec().into()
    }

    #[test]
    fn test_instantiate() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
            )
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "lodge");
    }

    #[test]
    fn test_increment_explicit() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
            )
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "lodge");

        contract
            .set("name".to_owned(), "juan".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "juan");
    }

    #[test]
    fn test_add_multiple_entries() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
            )
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "lodge");

        contract
            .set("name".to_owned(), "juan".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "juan");

        contract
            .set("name".to_owned(), "jose".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "jose");
    }

    #[test]
    fn test_decrypt() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
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
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(decrypt)
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
            .operation(KmsOperationAttribute::DecryptResponse(
                DecryptResponseValues::builder()
                    .signature(vec![4, 5, 6])
                    .payload(vec![6, 7, 8])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.transactions(txn_id.clone()).unwrap();
        assert_eq!(response.block_height, 12345);
        assert_eq!(response.transaction_index, 0);
    }

    #[test]
    fn test_preproc() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                "name".to_owned(),
                "kc1212".to_owned(),
                ContractProofType::Debug,
            )
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc(proof.clone()).call(&owner).unwrap();
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenPreproc(KeyGenPreprocValues {}))
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
            .operation(KmsOperationAttribute::KeyGenPreprocResponse(
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
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
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
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(keygen)
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
            .operation(keygen_response)
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
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
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

        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(reencrypt)
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
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(response_values)
            .txn_id(txn_id.clone())
            .proof(proof.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_crs_gen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let proof: HexVector = vec![1, 2, 3].into();

        let contract = code_id
            .instantiate(
                "name".to_owned(),
                "lodge".to_owned(),
                ContractProofType::Debug,
            )
            .call(&owner)
            .unwrap();

        let response = contract.crs_gen(proof.clone()).call(&owner).unwrap();

        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(CrsGenValues::default())
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
            .operation(crs_gen_response)
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
}
