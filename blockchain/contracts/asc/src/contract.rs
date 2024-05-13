#![allow(clippy::too_many_arguments)]

use cosmwasm_schema::cw_serde;
use cosmwasm_std::VerificationError;
use cosmwasm_std::{Response, StdResult};
use cw_storage_plus::Map;
use events::kms::{
    CrsGenResponseValues, DecryptResponseValues, DecryptValues, FheType,
    KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues,
    KmsOperationAttribute, ReencryptResponseValues, ReencryptValues, Transaction, TransactionId,
};
use events::kms::{CrsGenValues, KmsEvent};
use sha2::Digest;
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::{contract, entry_points};

pub struct KmsContract {
    pub(crate) config: Map<String, String>,
    pub(crate) transactions: Map<Vec<u8>, Transaction>,
}

impl Default for KmsContract {
    fn default() -> Self {
        Self {
            config: Map::new("config"),
            transactions: Map::new("transactions"),
        }
    }
}

#[cw_serde]
pub struct SequenceResponse {
    pub sequence: u64,
}

#[cw_serde]
pub struct ConfigurationResponse {
    pub value: String,
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
    ) -> StdResult<Response> {
        self.config.save(ctx.deps.storage, key, &value)?;
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
    pub fn transactions(&self, ctx: QueryCtx, txn_id: Vec<u8>) -> StdResult<Transaction> {
        let value = self.transactions.load(ctx.deps.storage, txn_id)?;
        Ok(value)
    }

    #[sv::msg(exec)]
    pub fn decrypt(
        &self,
        ctx: ExecCtx,
        version: u32,
        servers_needed: u32,
        key_id: Vec<u8>,
        ciphertext: Vec<u8>,
        randomness: Vec<u8>,
        fhe_type: FheType,
    ) -> StdResult<Response> {
        let (txn_id, transaction) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(
                DecryptValues::builder()
                    .version(version)
                    .servers_needed(servers_needed)
                    .key_id(TransactionId::from(key_id).to_hex())
                    .fhe_type(fhe_type)
                    .ciphertext(ciphertext)
                    .randomness(randomness)
                    .build(),
            ))
            .txn_id(txn_id.clone())
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
        txn_id: Vec<u8>,
        signature: Vec<u8>,
        payload: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::DecryptResponse(
                DecryptResponseValues::builder()
                    .signature(signature)
                    .payload(payload)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());

        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc(&self, ctx: ExecCtx) -> StdResult<Response> {
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc_response(&self, ctx: ExecCtx, txn_id: Vec<u8>) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenPreprocResponse(
                KeyGenPreprocResponseValues {},
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen(&self, ctx: ExecCtx, preproc_id: Vec<u8>) -> StdResult<Response> {
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGen(
                KeyGenValues::builder()
                    .preproc_id(TransactionId::from(preproc_id).to_hex())
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen_response(
        &self,
        ctx: ExecCtx,
        txn_id: Vec<u8>,
        public_key_digest: String,
        public_key_signature: Vec<u8>,
        server_key_digest: String,
        server_key_signature: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenResponse(
                KeyGenResponseValues::builder()
                    .request_id(TransactionId::from(txn_id.clone()).to_hex())
                    .public_key_digest(public_key_digest)
                    .public_key_signature(public_key_signature)
                    .server_key_digest(server_key_digest)
                    .server_key_signature(server_key_signature)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
    }

    // TODO find a way to simplfy this API
    #[sv::msg(exec)]
    pub fn reencrypt(
        &self,
        ctx: ExecCtx,
        signature: Vec<u8>,
        version: u32,
        servers_needed: u32,
        verification_key: Vec<u8>,
        randomness: Vec<u8>,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        key_id: Vec<u8>,
        ciphertext: Vec<u8>,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: Vec<u8>,
        eip712_verifying_contract: String,
        eip712_salt: Vec<u8>,
    ) -> StdResult<Response> {
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Reencrypt(
                ReencryptValues::builder()
                    .signature(signature)
                    .version(version)
                    .servers_needed(servers_needed)
                    .verification_key(verification_key)
                    .randomness(randomness)
                    .enc_key(enc_key)
                    .fhe_type(fhe_type)
                    .key_id(TransactionId::from(key_id).to_hex())
                    .ciphertext(ciphertext)
                    .eip712_name(eip712_name)
                    .eip712_version(eip712_version)
                    .eip712_chain_id(eip712_chain_id)
                    .eip712_verifying_contract(eip712_verifying_contract)
                    .eip712_salt(eip712_salt)
                    .build(),
            ))
            .txn_id(txn_id.clone())
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
        txn_id: Vec<u8>,
        version: u32,
        servers_needed: u32,
        verification_key: Vec<u8>,
        digest: Vec<u8>,
        fhe_type: FheType,
        signcrypted_ciphertext: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::ReencryptResponse(
                ReencryptResponseValues::builder()
                    .version(version)
                    .servers_needed(servers_needed)
                    .verification_key(verification_key)
                    .digest(digest)
                    .fhe_type(fhe_type)
                    .signcrypted_ciphertext(signcrypted_ciphertext)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn crs_gen(&self, ctx: ExecCtx) -> StdResult<Response> {
        let (txn_id, tx) = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CrsGen(CrsGenValues::default()))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.save(ctx.deps.storage, txn_id, &tx)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn crs_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: Vec<u8>,
        digest: String,
        signature: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }

        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CrsGenResponse(
                CrsGenResponseValues::builder()
                    .request_id(TransactionId::from(txn_id.clone()).to_hex())
                    .digest(digest)
                    .signature(signature)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::sv::mt::{CodeId, KmsContractProxy as _};
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
    use sha2::Digest;
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;

    fn expected_transaction_id(height: u64, txn_idx: u32) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(height.to_string());
        hasher.update(txn_idx.to_string());
        let result = hasher.finalize();
        result[..20].to_vec()
    }

    #[test]
    fn test_instantiate() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
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
            .instantiate("name".to_owned(), "lodge".to_owned())
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
            .instantiate("name".to_owned(), "lodge".to_owned())
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

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let response = contract
            .decrypt(
                1,
                2,
                vec![1, 2, 3],
                vec![2, 3, 4],
                vec![3, 4, 5],
                FheType::Euint8,
            )
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(
                DecryptValues::builder()
                    .key_id(TransactionId::from(vec![1, 2, 3]).to_hex())
                    .version(1)
                    .servers_needed(2)
                    .ciphertext(vec![2, 3, 4])
                    .randomness(vec![3, 4, 5])
                    .fhe_type(FheType::Euint8)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .decrypt_response(txn_id.clone(), vec![4, 5, 6], vec![6, 7, 8])
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

        let contract = code_id
            .instantiate("name".to_owned(), "kc1212".to_owned())
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc().call(&owner).unwrap();
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenPreproc(KeyGenPreprocValues {}))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .keygen_preproc_response(txn_id.clone())
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenPreprocResponse(
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
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let preproc_id = vec![2, 2, 2];
        let response = contract.keygen(preproc_id.clone()).call(&owner).unwrap();
        println!("response: {:#?}", response);
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGen(
                KeyGenValues::builder()
                    .preproc_id(TransactionId::from(preproc_id).to_hex())
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .keygen_response(
                txn_id.clone(),
                "digest1".to_string(),
                vec![4, 5, 6],
                "digest2".to_string(),
                vec![7, 8, 9],
            )
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenResponse(
                KeyGenResponseValues::builder()
                    .request_id(TransactionId::from(txn_id.clone()).to_hex())
                    .public_key_digest("digest1".to_string())
                    .public_key_signature(vec![4, 5, 6])
                    .server_key_digest("digest2".to_string())
                    .server_key_signature(vec![7, 8, 9])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_reencrypt() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let response = contract
            .reencrypt(
                vec![1],
                1,
                2,
                vec![2],
                vec![3],
                vec![4],
                FheType::Euint8,
                vec![5],
                vec![6],
                "name".to_string(),
                "version".to_string(),
                vec![7],
                "contract".to_string(),
                vec![8],
            )
            .call(&owner)
            .unwrap();

        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Reencrypt(
                ReencryptValues::builder()
                    .signature(vec![1])
                    .version(1)
                    .servers_needed(2)
                    .verification_key(vec![2])
                    .randomness(vec![3])
                    .enc_key(vec![4])
                    .fhe_type(FheType::Euint8)
                    .key_id(TransactionId::from(vec![5]).to_hex())
                    .ciphertext(vec![6])
                    .eip712_name("name".to_string())
                    .eip712_version("version".to_string())
                    .eip712_chain_id(vec![7])
                    .eip712_verifying_contract("contract".to_string())
                    .eip712_salt(vec![8])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .reencrypt_response(
                txn_id.clone(),
                1,
                2,
                vec![1],
                vec![2],
                FheType::Ebool,
                vec![3],
            )
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::ReencryptResponse(
                ReencryptResponseValues::builder()
                    .version(1)
                    .servers_needed(2)
                    .verification_key(vec![1])
                    .digest(vec![2])
                    .fhe_type(FheType::Ebool)
                    .signcrypted_ciphertext(vec![3])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_crs_gen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let response = contract.crs_gen().call(&owner).unwrap();

        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CrsGen(CrsGenValues::default()))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .crs_gen_response(txn_id.clone(), "my digest".to_string(), vec![4, 5, 6])
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CrsGenResponse(
                CrsGenResponseValues::builder()
                    .request_id(TransactionId::from(txn_id.clone()).to_hex())
                    .digest("my digest".to_string())
                    .signature(vec![4, 5, 6])
                    .build(),
            ))
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
}
