use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, VerificationError};
use cosmwasm_std::{Response, StdResult};
use cw_storage_plus::Map;
use events::kms::KmsEvent;
use events::kms::{
    CsrGenResponseValues, DecryptResponseValues, DecryptValues, FheType, KeyGenResponseValues,
    KmsOperationAttribute, ReencryptResponseValues, ReencryptValues,
};
use sha2::Digest;
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::{contract, entry_points};

pub struct KmsContract {
    pub(crate) config: Map<String, String>,
    pub(crate) transactions: Map<Vec<u8>, Vec<u8>>,
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
pub struct TransactionPayload {
    pub attributes: Vec<Attribute>,
}

#[cw_serde]
pub struct SequenceResponse {
    pub sequence: u64,
}

#[cw_serde]
pub struct ConfigurationResponse {
    pub value: String,
}

#[cw_serde]
pub struct TransactionResponse {
    pub value: TransactionPayload,
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

    fn derive_transaction_id(&self, ctx: &ExecCtx) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(ctx.env.block.height.to_string());
        hasher.update(ctx.env.transaction.clone().unwrap().index.to_string());
        let result = hasher.finalize();
        // truncate the result to 20 bytes
        result[..20].to_vec()
    }

    #[sv::msg(exec)]
    pub fn decrypt(
        &self,
        ctx: ExecCtx,
        ciphertext: Vec<u8>,
        fhe_type: FheType,
    ) -> StdResult<Response> {
        let txn_id = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(
                DecryptValues::builder()
                    .ciphertext(ciphertext)
                    .fhe_type(fhe_type)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions
            .save(ctx.deps.storage, txn_id.clone(), &txn_id)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn decrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::DecryptResponse(
                DecryptResponseValues::builder()
                    .plaintext(plaintext)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());

        self.transactions.remove(ctx.deps.storage, txn_id);
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen(&self, ctx: ExecCtx) -> StdResult<Response> {
        let txn_id = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGen)
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions
            .save(ctx.deps.storage, txn_id.clone(), &txn_id)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen_response(
        &self,
        ctx: ExecCtx,
        txn_id: Vec<u8>,
        key: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenResponse(
                KeyGenResponseValues::builder().key(key).build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.remove(ctx.deps.storage, txn_id);
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn reencrypt(
        &self,
        ctx: ExecCtx,
        ciphertext: Vec<u8>,
        fhe_type: FheType,
    ) -> StdResult<Response> {
        let txn_id = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Reencrypt(
                ReencryptValues::builder()
                    .ciphertext(ciphertext)
                    .fhe_type(fhe_type)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions
            .save(ctx.deps.storage, txn_id.clone(), &txn_id)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn reencrypt_response(
        &self,
        ctx: ExecCtx,
        txn_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::ReencryptResponse(
                ReencryptResponseValues::builder()
                    .cyphertext(ciphertext)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.remove(ctx.deps.storage, txn_id);
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn csr_gen(&self, ctx: ExecCtx) -> StdResult<Response> {
        let txn_id = self.derive_transaction_id(&ctx);
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CsrGen)
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions
            .save(ctx.deps.storage, txn_id.clone(), &txn_id)?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn csr_gen_response(
        &self,
        ctx: ExecCtx,
        txn_id: Vec<u8>,
        csr: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, txn_id.clone()) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CsrGenResponse(
                CsrGenResponseValues::builder().csr(csr).build(),
            ))
            .txn_id(txn_id.clone())
            .build();
        let response = Response::new().add_event(event.into());
        self.transactions.remove(ctx.deps.storage, txn_id);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::sv::mt::{CodeId, KmsContractProxy as _};
    use cosmwasm_std::Event;
    use events::kms::CsrGenResponseValues;
    use events::kms::DecryptResponseValues;
    use events::kms::DecryptValues;
    use events::kms::FheType;
    use events::kms::KeyGenResponseValues;
    use events::kms::KmsEvent;
    use events::kms::KmsOperationAttribute;
    use events::kms::ReencryptResponseValues;
    use events::kms::ReencryptValues;
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
            .decrypt(vec![1, 2, 3], FheType::Euint8)
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(
                DecryptValues::builder()
                    .ciphertext(vec![1, 2, 3])
                    .fhe_type(FheType::Euint8)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .decrypt_response(txn_id.clone(), vec![4, 5, 6])
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::DecryptResponse(
                DecryptResponseValues::builder()
                    .plaintext(vec![4, 5, 6])
                    .build(),
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

        let response = contract.keygen().call(&owner).unwrap();
        println!("response: {:#?}", response);
        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .keygen_response(txn_id.clone(), vec![4, 5, 6])
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenResponse(
                KeyGenResponseValues::builder().key(vec![4, 5, 6]).build(),
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
            .reencrypt(vec![1, 2, 3], FheType::Euint8)
            .call(&owner)
            .unwrap();

        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::Reencrypt(
                ReencryptValues::builder()
                    .ciphertext(vec![1, 2, 3])
                    .fhe_type(FheType::Euint8)
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .reencrypt_response(txn_id.clone(), vec![4, 5, 6])
            .call(&owner)
            .unwrap();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::ReencryptResponse(
                ReencryptResponseValues::builder()
                    .cyphertext(vec![4, 5, 6])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);
    }

    #[test]
    fn test_csr_gen() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let response = contract.csr_gen().call(&owner).unwrap();

        let txn_id = expected_transaction_id(12345, 0);
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CsrGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract
            .csr_gen_response(txn_id.clone(), vec![4, 5, 6])
            .call(&owner)
            .unwrap();

        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperationAttribute::CsrGenResponse(
                CsrGenResponseValues::builder().csr(vec![4, 5, 6]).build(),
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
