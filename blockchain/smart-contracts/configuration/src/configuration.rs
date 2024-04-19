use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, VerificationError};
use cosmwasm_std::{Response, StdResult};
use cw_storage_plus::Item;
use cw_storage_plus::Map;
use events::kms::KmsOperationAttributeValue;
use events::kms::{FheType, KmsOperationAttribute};
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::{contract, entry_points};

pub struct KmsContract {
    pub(crate) sequence: Item<u64>,
    pub(crate) config: Map<String, String>,
    pub(crate) transactions: Map<u64, TransactionPayload>,
}

impl Default for KmsContract {
    fn default() -> Self {
        Self {
            sequence: Item::new("sequence"),
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
        self.sequence.save(ctx.deps.storage, &0)?;
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get(&self, ctx: QueryCtx, key: String) -> StdResult<ConfigurationResponse> {
        let value = self.config.load(ctx.deps.storage, key)?;
        Ok(ConfigurationResponse { value })
    }

    #[sv::msg(query)]
    pub fn sequence(&self, ctx: QueryCtx) -> StdResult<SequenceResponse> {
        let sequence = self.sequence.load(ctx.deps.storage)?;
        Ok(SequenceResponse { sequence })
    }

    #[sv::msg(exec)]
    pub fn set(&self, ctx: ExecCtx, key: String, value: String) -> StdResult<Response> {
        self.config
            .update(ctx.deps.storage, key, |_| -> StdResult<String> {
                Ok(value)
            })?;
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get_transaction(&self, ctx: QueryCtx, seq_no: u64) -> StdResult<TransactionResponse> {
        Ok(TransactionResponse {
            value: self.transactions.load(ctx.deps.storage, seq_no)?,
        })
    }

    #[sv::msg(exec)]
    pub fn decrypt(
        &self,
        ctx: ExecCtx,
        ciphertext: Vec<u8>,
        fhe_type: FheType,
    ) -> StdResult<Response> {
        let current_sequence = self.sequence.load(ctx.deps.storage)?;
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::Decrypt)
            .seq_no(current_sequence)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new().add_attributes(attributes.clone());

        // transaction payload
        let mut transaction_payload = TransactionPayload { attributes };
        transaction_payload
            .attributes
            .push(Attribute::new("ciphertext", hex::encode(ciphertext)));
        transaction_payload
            .attributes
            .push(Attribute::new("fhetype", fhe_type.to_string()));
        self.transactions
            .save(ctx.deps.storage, current_sequence, &transaction_payload)?;

        self.sequence
            .update(ctx.deps.storage, |sequence| -> StdResult<u64> {
                Ok(sequence + 1)
            })?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn decrypt_response(
        &self,
        ctx: ExecCtx,
        seq_no: u64,
        plaintext: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, seq_no) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::DecryptResponse)
            .seq_no(seq_no)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new()
            .add_attributes(attributes)
            .add_attribute("plaintext", hex::encode(plaintext));
        self.transactions.remove(ctx.deps.storage, seq_no);
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen(&self, ctx: ExecCtx) -> StdResult<Response> {
        let current_sequence = self.sequence.load(ctx.deps.storage)?;
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::KeyGen)
            .seq_no(current_sequence)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new().add_attributes(attributes.clone());
        // transaction payload
        let transaction_payload = TransactionPayload { attributes };
        self.transactions
            .save(ctx.deps.storage, current_sequence, &transaction_payload)?;

        self.sequence
            .update(ctx.deps.storage, |sequence| -> StdResult<u64> {
                Ok(sequence + 1)
            })?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn keygen_response(&self, ctx: ExecCtx, seq_no: u64, key: Vec<u8>) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, seq_no) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::KeyGenResponse)
            .seq_no(seq_no)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new()
            .add_attributes(attributes)
            .add_attribute("key", hex::encode(key));
        self.transactions.remove(ctx.deps.storage, seq_no);
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn reencrypt(
        &self,
        ctx: ExecCtx,
        ciphertext: Vec<u8>,
        fhe_type: FheType,
    ) -> StdResult<Response> {
        let current_sequence = self.sequence.load(ctx.deps.storage)?;
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::Reencrypt)
            .seq_no(current_sequence)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new().add_attributes(attributes.clone());
        // transaction payload
        let mut transaction_payload = TransactionPayload { attributes };
        transaction_payload
            .attributes
            .push(Attribute::new("ciphertext", hex::encode(ciphertext)));
        transaction_payload
            .attributes
            .push(Attribute::new("fhetype", fhe_type.to_string()));
        self.transactions
            .save(ctx.deps.storage, current_sequence, &transaction_payload)?;
        self.sequence
            .update(ctx.deps.storage, |sequence| -> StdResult<u64> {
                Ok(sequence + 1)
            })?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn reencrypt_response(
        &self,
        ctx: ExecCtx,
        seq_no: u64,
        ciphertext: Vec<u8>,
    ) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, seq_no) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::ReencryptResponse)
            .seq_no(seq_no)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new()
            .add_attributes(attributes)
            .add_attribute("ciphertext", hex::encode(ciphertext));
        self.transactions.remove(ctx.deps.storage, seq_no);
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn csr_gen(&self, ctx: ExecCtx) -> StdResult<Response> {
        let current_sequence = self.sequence.load(ctx.deps.storage)?;
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::CsrGen)
            .seq_no(current_sequence)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new().add_attributes(attributes.clone());
        // transaction payload
        let transaction_payload = TransactionPayload { attributes };
        self.transactions
            .save(ctx.deps.storage, current_sequence, &transaction_payload)?;
        self.sequence
            .update(ctx.deps.storage, |sequence| -> StdResult<u64> {
                Ok(sequence + 1)
            })?;
        Ok(response)
    }

    #[sv::msg(exec)]
    pub fn csr_gen_response(&self, ctx: ExecCtx, seq_no: u64, csr: Vec<u8>) -> StdResult<Response> {
        if !self.transactions.has(ctx.deps.storage, seq_no) {
            return Err(cosmwasm_std::StdError::verification_err(
                VerificationError::GenericErr,
            ));
        }
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::CsrGenResponse)
            .seq_no(seq_no)
            .build();
        let attributes: Vec<Attribute> = operation.clone().into();
        let response = Response::new()
            .add_attributes(attributes)
            .add_attribute("csr", hex::encode(csr));
        self.transactions.remove(ctx.deps.storage, seq_no);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::sv::mt::{CodeId, KmsContractProxy as _};
    use events::kms::FheType;
    use events::kms::KmsEventAttributeKey;
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;

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
        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "decrypt");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "0");

        // query the transaction
        let transaction = contract.get_transaction(0).unwrap().value;
        println!("transaction: {:#?}", transaction);
        assert_eq!(
            transaction.attributes[0].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(transaction.attributes[0].value, "decrypt");
        assert_eq!(
            transaction.attributes[1].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(transaction.attributes[1].value, "0");
        assert_eq!(transaction.attributes[2].key, "ciphertext".to_string());
        assert_eq!(transaction.attributes[2].value, "010203");
        assert_eq!(transaction.attributes[3].key, "fhetype".to_string());
        assert_eq!(transaction.attributes[3].value, "euint8");

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 1);

        let response = contract
            .decrypt_response(0, vec![4, 5, 6])
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);

        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "decrypt-response");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "0");
        assert_eq!(
            response.events[1].attributes[3].key,
            "plaintext".to_string()
        );
        assert_eq!(response.events[1].attributes[3].value, "040506");

        let transaction = contract.get_transaction(0);
        assert!(transaction.is_err());

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 1);
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
        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "key-gen");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "0");

        let transaction = contract.get_transaction(0).unwrap().value;
        assert_eq!(
            transaction.attributes[0].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(transaction.attributes[0].value, "key-gen");
        assert_eq!(
            transaction.attributes[1].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(transaction.attributes[1].value, "0");

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 1);

        let response = contract
            .keygen_response(0, vec![4, 5, 6])
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);

        assert_eq!(response.events.len(), 2);

        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );

        assert_eq!(response.events[1].attributes[1].value, "key-gen-response");

        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );

        assert_eq!(response.events[1].attributes[2].value, "0");

        assert_eq!(response.events[1].attributes[3].key, "key".to_string());
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
        println!("response: {:#?}", response);
        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "reencrypt");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "0");

        let transaction = contract.get_transaction(0).unwrap().value;
        assert_eq!(
            transaction.attributes[0].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(transaction.attributes[0].value, "reencrypt");
        assert_eq!(
            transaction.attributes[1].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(transaction.attributes[1].value, "0");
        assert_eq!(transaction.attributes[2].key, "ciphertext".to_string());
        assert_eq!(transaction.attributes[2].value, "010203");
        assert_eq!(transaction.attributes[3].key, "fhetype".to_string());
        assert_eq!(transaction.attributes[3].value, "euint8");

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 1);

        let response = contract
            .reencrypt_response(0, vec![4, 5, 6])
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);

        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "reencrypt-response");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "0");
        assert_eq!(
            response.events[1].attributes[3].key,
            "ciphertext".to_string()
        );
        assert_eq!(response.events[1].attributes[3].value, "040506");

        let transaction = contract.get_transaction(0);
        assert!(transaction.is_err());

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 1);
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
        println!("response: {:#?}", response);
        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "csr-gen");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "0");

        let transaction = contract.get_transaction(0).unwrap().value;
        assert_eq!(
            transaction.attributes[0].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(transaction.attributes[0].value, "csr-gen");
        assert_eq!(
            transaction.attributes[1].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(transaction.attributes[1].value, "0");

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 1);

        let response = contract
            .csr_gen_response(0, vec![4, 5, 6])
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);

        assert_eq!(response.events.len(), 2);

        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );

        assert_eq!(response.events[1].attributes[1].value, "csr-gen-response");

        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );

        assert_eq!(response.events[1].attributes[2].value, "0");

        assert_eq!(response.events[1].attributes[3].key, "csr".to_string());

        assert_eq!(response.events[1].attributes[3].value, "040506");

        let transaction = contract.get_transaction(0);

        assert!(transaction.is_err());

        let sequence = contract.sequence().unwrap().sequence;

        assert_eq!(sequence, 1);

        let response = contract.csr_gen().call(&owner).unwrap();
        println!("response: {:#?}", response);
        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].attributes[1].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(response.events[1].attributes[1].value, "csr-gen");
        assert_eq!(
            response.events[1].attributes[2].key,
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(response.events[1].attributes[2].value, "1");

        let transaction = contract.get_transaction(1).unwrap().value;
        assert_eq!(
            transaction.attributes[0].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(transaction.attributes[0].value, "csr-gen");
        assert_eq!(
            transaction.attributes[1].key,
            KmsEventAttributeKey::Sequence.to_string()
        );

        let sequence = contract.sequence().unwrap().sequence;
        assert_eq!(sequence, 2);

        let response = contract
            .csr_gen_response(1, vec![7, 8, 9])
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);
    }
}
