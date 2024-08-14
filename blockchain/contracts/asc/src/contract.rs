use super::state::KmsContractStorage;
use crate::events::EventEmitStrategy as _;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    to_json_binary, Env, Reply, Response, StdError, StdResult, Storage, SubMsg, SubMsgResult,
    VerificationError, WasmMsg,
};
use cw_controllers::Admin;
use cw_utils::must_pay;
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues,
    KeyGenPreprocResponseValues, KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues,
    KmsCoreConf, KmsEvent, OperationValue, Proof, ReencryptResponseValues, ReencryptValues,
    Transaction, TransactionId,
};
use sha3::{Digest, Sha3_256};
use std::ops::Deref;
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, QueryCtx, ReplyCtx},
};

const UCOSM: &str = "ucosm";

pub(crate) const ADMIN: Admin = Admin::new("kms-conf-admin");

#[cw_serde]
pub struct ProofPayload {
    pub proof: Vec<u8>,
    pub value: Vec<u8>,
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

    fn process_transaction<T>(
        &self,
        storage: &mut dyn Storage,
        env: &Env,
        txn_id: &[u8],
        operation: T,
    ) -> StdResult<Response>
    where
        T: Into<OperationValue> + Clone,
    {
        self.storage
            .update_transaction(storage, env, txn_id, &operation)?;
        let response = self.emit_event(storage, txn_id, &operation)?;
        Ok(response)
    }

    fn verify_proof_call<T: Into<OperationValue> + Clone>(
        &self,
        ctx: ExecCtx,
        proof: Proof<Vec<u8>>,
        value: &[u8],
        operation: T,
    ) -> StdResult<Response> {
        if self.storage.get_debug_proof(ctx.deps.storage)? {
            let txn_id = self.derive_transaction_id(&ctx.env)?;
            self.process_transaction(ctx.deps.storage, &ctx.env, &txn_id, operation)
        } else {
            self.call_proof_contract(ctx, proof, value, operation)
        }
    }

    fn call_proof_contract<T: Into<OperationValue>>(
        &self,
        ctx: ExecCtx,
        proof: Proof<Vec<u8>>,
        value: &[u8],
        operation: T,
    ) -> StdResult<Response> {
        let msg = ProofMessage {
            verify_proof: ProofPayload {
                proof: proof.proof,
                value: value.to_vec(),
            },
        };
        let msg = WasmMsg::Execute {
            contract_addr: proof.contract_address,
            msg: to_json_binary(&msg)?,
            funds: vec![],
        };
        let reply_id = self.storage.next_id(ctx.deps.storage)?;
        self.storage
            .add_pending_transaction(ctx.deps.storage, reply_id, operation)?;
        let sub_msg = SubMsg::reply_on_success(msg, reply_id);
        let response = Response::new().add_submessage(sub_msg);
        Ok(response)
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        debug_proof: Option<bool>,
        kms_core_conf: KmsCoreConf,
    ) -> StdResult<Response> {
        if let KmsCoreConf::Threshold(conf) = &kms_core_conf {
            // centralized setting should be used if there is only one party
            if conf.parties.len() < 2 {
                return Err(cosmwasm_std::StdError::verification_err(
                    VerificationError::GenericErr,
                ));
            }

            // check that degree is at least 1
            if conf.degree_for_reconstruction < 1 {
                return Err(cosmwasm_std::StdError::verification_err(
                    VerificationError::GenericErr,
                ));
            }

            // check that the number of shares needed for reconstruction is at least degree + 2
            // this is the minimum value such that error detection is possible
            if conf.response_count_for_reconstruction < conf.degree_for_reconstruction + 2 {
                return Err(cosmwasm_std::StdError::verification_err(
                    VerificationError::GenericErr,
                ));
            }

            // there can not be enough responses for reconstruction
            if conf.response_count_for_reconstruction > conf.parties.len() {
                return Err(cosmwasm_std::StdError::verification_err(
                    VerificationError::GenericErr,
                ));
            }

            // there can not be enough responses for majority vote
            if conf.response_count_for_majority_vote > conf.parties.len() {
                return Err(cosmwasm_std::StdError::verification_err(
                    VerificationError::GenericErr,
                ));
            }
        };

        if let Some(debug_proof) = debug_proof {
            self.storage
                .set_debug_proof(ctx.deps.storage, debug_proof)?;
        } else {
            self.storage.set_debug_proof(ctx.deps.storage, false)?;
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

    /// return ciphertext size from handle. Size is encoded as u32 in the first 4 bytes of the handle
    fn parse_ciphertext_handle_size(ciphertext_handle: &[u8]) -> u32 {
        ((ciphertext_handle[0] as u32) << 24)
            | ((ciphertext_handle[1] as u32) << 16)
            | ((ciphertext_handle[2] as u32) << 8)
            | (ciphertext_handle[3] as u32)
    }

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
    pub fn decrypt(
        &self,
        ctx: ExecCtx,
        decrypt: DecryptValues,
        proof: Proof<Vec<u8>>,
    ) -> StdResult<Response> {
        // decipher the size encoding and ensure the payment is included in the message
        let ciphertext_handles = decrypt.ciphertext_handles();

        let ctvecs: Vec<Vec<u8>> = ciphertext_handles.0.iter().map(|ct| ct.to_vec()).collect();

        self.verify_payment(&ctx, &ctvecs).map_err(|e| {
            StdError::generic_err(format!(
                "Error verifying payment for ciphertext storage - {}",
                e
            ))
        })?;
        let value = ctvecs.into_iter().flatten().collect::<Vec<u8>>();
        self.verify_proof_call(ctx, proof, &value, decrypt)
            .map_err(|e| {
                StdError::generic_err(format!("Error verifying proof for decryption - {}", e))
            })
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
            decrypt_response,
        )
    }

    #[sv::msg(exec)]
    pub fn keygen_preproc(&self, ctx: ExecCtx, proof: Proof<Vec<u8>>) -> StdResult<Response> {
        self.verify_proof_call(ctx, proof, &[], KeyGenPreprocValues::default())
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
            KeyGenPreprocResponseValues::default(),
        )
    }

    #[sv::msg(exec)]
    pub fn keygen(
        &self,
        ctx: ExecCtx,
        keygen: KeyGenValues,
        proof: Proof<Vec<u8>>,
    ) -> StdResult<Response> {
        let value = keygen.preproc_id().deref().to_vec();
        self.verify_proof_call(ctx, proof, &value, keygen)
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
            keygen_response,
        )
    }

    #[sv::msg(exec)]
    pub fn reencrypt(
        &self,
        ctx: ExecCtx,
        reencrypt: ReencryptValues,
        proof: Proof<Vec<u8>>,
    ) -> StdResult<Response> {
        // decipher the size encoding and ensure the payment is included in the message
        let ciphertext_handle: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        self.verify_payment(&ctx, &[ciphertext_handle.clone()])?;

        self.verify_proof_call(ctx, proof, &ciphertext_handle, reencrypt)
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
            reencrypt_response,
        )
    }

    #[sv::msg(exec)]
    pub fn crs_gen(&self, ctx: ExecCtx, proof: Proof<Vec<u8>>) -> StdResult<Response> {
        self.verify_proof_call(ctx, proof, &[], CrsGenValues::default())
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
            crs_gen_response,
        )
    }

    #[allow(dead_code)]
    #[sv::msg(reply)]
    pub fn reply(&self, ctx: ReplyCtx, reply: Reply) -> StdResult<Response> {
        let reply_id = reply.id;
        let result = reply.result;
        let response = match result {
            SubMsgResult::Ok(_) => {
                let pending_txn = self
                    .storage
                    .get_pending_transaction(ctx.deps.storage, reply_id)?;
                let txn_id = self.derive_transaction_id(&ctx.env)?;
                self.process_transaction(ctx.deps.storage, &ctx.env, &txn_id, pending_txn)
            }
            SubMsgResult::Err(e) => Err(StdError::generic_err(format!("Reply failed - {}", e))),
        };
        self.storage
            .remove_pending_transaction(ctx.deps.storage, reply_id)?;
        response
    }
}

#[cfg(test)]
mod tests {
    use super::sv::mt::KmsContractProxy;
    use crate::contract::sv::mt::CodeId;
    use crate::contract::KmsContract;
    use crate::contract::Proof;
    use aipsc::contract::sv::mt::InclusionProofContractProxy;
    use cosmwasm_std::coin;
    use cosmwasm_std::coins;
    use cosmwasm_std::Addr;
    use cosmwasm_std::Event;
    use ed25519_consensus::SigningKey;
    use ed25519_consensus::VerificationKey;
    use events::kms::CrsGenResponseValues;
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
    use rand::thread_rng;
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;
    use tendermint::merkle::proof::ProofOp;
    use tendermint::merkle::proof::ProofOps;
    use tendermint_ipsc::contract::sv::mt::CodeId as ProofCodeId;
    use tendermint_ipsc::contract::NewHeader;
    use tendermint_ipsc::contract::TendermintUpdateHeader;

    const UCOSM: &str = "ucosm";

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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 2,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .is_err());

        // `response_count_for_majority_vote` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                Some(true),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 5,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .is_err());

        // `response_count_for_reconstruction` is greater than the no. of parties
        assert!(code_id
            .instantiate(
                Some(true),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 5,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .is_err());

        // finally we make a successful attempt
        let contract = code_id
            .instantiate(
                Some(true),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 3,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
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
        let proof = Proof::default();

        let contract = code_id
            .instantiate(
                Some(true),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
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

        let decrypt = DecryptValues::builder()
            .key_id(vec![1, 2, 3])
            .version(1)
            .ciphertext_handles(vec![ciphertext_handle; batch_size])
            .fhe_types(vec![FheType::Euint8; batch_size])
            .build();

        // test insufficient funds
        let _failed_response = contract
            .decrypt(decrypt.clone(), proof.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&gateway)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decrypt(decrypt.clone(), proof)
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

        let decrypt_response = DecryptResponseValues::builder()
            .signature(vec![4, 5, 6])
            .payload(vec![6, 7, 8])
            .build();

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
            .operation(OperationValue::DecryptResponse(
                DecryptResponseValues::builder()
                    .signature(vec![4, 5, 6])
                    .payload(vec![6, 7, 8])
                    .build(),
            ))
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_transaction(txn_id.clone()).unwrap();
        assert_eq!(response.block_height(), 12345);
        assert_eq!(response.transaction_index(), 0);
        // three operations: one decrypt and two decrypt response
        assert_eq!(response.operations().len(), 3);
    }

    #[ignore = "impleming proof contract"]
    #[test]
    fn test_decrypt_with_proof() {
        let test = Addr::unchecked("test");
        let proof_address = Addr::unchecked("wasm19dnevk6vtv3y48lsksh452mv9x6endmxh4zzdf");

        let app = cw_multi_test::App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(storage, &test, coins(5000000, UCOSM))
                .unwrap();
        });

        let app = App::new(app);
        let proof_app = App::default();
        let code_id = CodeId::store_code(&app);
        let proof_code_id = ProofCodeId::store_code(&proof_app);
        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate(
                None,
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .unwrap();

        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();

        let batch_size = 2_usize;

        let sk = SigningKey::new(thread_rng());
        let sig = sk.sign([1, 2, 3].as_ref());
        let sig_bytes: [u8; 64] = sig.into();
        let vk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

        let validator_set = vec![vk_bytes.to_vec().into()];
        let signature = sig_bytes.to_vec().into();

        let contract_proof = proof_code_id
            .instantiate(validator_set)
            .call(&owner)
            .unwrap();

        let proof_op = ProofOp {
            key: vec![1, 2, 3],
            field_type: "u8".to_string(),
            data: vec![1, 2, 3],
        };
        let proof_ops = ProofOps {
            ops: vec![proof_op],
        };

        let proof = Proof::builder()
            .contract_address(proof_address.to_string())
            .proof(bincode::serialize(&proof_ops).unwrap())
            .build();
        let tendermint_header = TendermintUpdateHeader {
            new_validator_set: None,
            new_header: NewHeader {
                root_hash: vec![1, 2, 3].into(),
                signatures: vec![signature],
            },
        };

        contract_proof
            .update_header(tendermint_header)
            .call(&proof_address)
            .unwrap();

        let data_size = extract_ciphertext_size(&ciphertext_handle) * batch_size as u32;
        assert_eq!(data_size, 661448 * batch_size as u32);

        let decrypt = DecryptValues::builder()
            .key_id(vec![1, 2, 3])
            .version(1)
            .ciphertext_handles(vec![ciphertext_handle; batch_size])
            .fhe_types(vec![FheType::Euint8; batch_size])
            .build();

        // test insufficient funds
        let _failed_response = contract
            .decrypt(decrypt.clone(), proof.clone())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&test)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .decrypt(decrypt.clone(), proof)
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&test)
            .unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let decrypt_response = DecryptResponseValues::builder()
            .signature(vec![4, 5, 6])
            .payload(vec![6, 7, 8])
            .build();

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
            .operation(OperationValue::DecryptResponse(
                DecryptResponseValues::builder()
                    .signature(vec![4, 5, 6])
                    .payload(vec![6, 7, 8])
                    .build(),
            ))
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
        let proof = Proof::default();

        let contract = code_id
            .instantiate(
                Some(true),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .unwrap();

        let response = contract.keygen_preproc(proof).call(&owner).unwrap();
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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .unwrap();

        let preproc_id = "preproc_id".as_bytes().to_vec().into();
        let keygen = KeyGenValues::builder().preproc_id(preproc_id).build();
        let response = contract
            .keygen(keygen.clone(), Proof::default())
            .call(&owner)
            .unwrap();
        println!("response: {:#?}", response);
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 1,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .unwrap();

        let ciphertext_handle =
            hex::decode("000a17c82f8cd9fe41c871f12b391a2afaf5b640ea4fdd0420a109aa14c674d3e385b955")
                .unwrap();
        let data_size = extract_ciphertext_size(&ciphertext_handle);
        assert_eq!(data_size, 661448);

        let reencrypt = ReencryptValues::builder()
            .signature(vec![1])
            .version(1)
            .client_address("0x1234".to_string())
            .enc_key(vec![4])
            .fhe_type(FheType::Euint8)
            .key_id(vec![5])
            .ciphertext_handle(ciphertext_handle.clone())
            .ciphertext_digest(vec![9])
            .eip712_name("name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![7])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![8])
            .build();

        let _failed_response = contract
            .reencrypt(reencrypt.clone(), Proof::default())
            .with_funds(&[coin(42_u128, UCOSM)])
            .call(&owner)
            .expect_err("Insufficient funds sent to cover the data size");

        let response = contract
            .reencrypt(reencrypt.clone(), Proof::default())
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

        let response_values = ReencryptResponseValues::builder()
            .signature(vec![4, 5, 6])
            .payload(vec![6, 7, 8])
            .build();

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

        let contract = code_id
            .instantiate(
                Some(true),
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
                }),
            )
            .call(&owner)
            .unwrap();

        let response = contract.crs_gen(Proof::default()).call(&owner).unwrap();

        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::CrsGen)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let crs_gen_response = CrsGenResponseValues::builder()
            .request_id(txn_id.to_hex())
            .digest("my digest".to_string())
            .signature(vec![4, 5, 6])
            .build();

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
    fn test_get_operations_value() {
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
                KmsCoreConf::Threshold(KmsCoreThresholdConf {
                    parties: vec![KmsCoreParty::default(); 4],
                    response_count_for_majority_vote: 2,
                    response_count_for_reconstruction: 3,
                    degree_for_reconstruction: 1,
                    param_choice: FheParameter::Test,
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

        let decrypt = DecryptValues::builder()
            .key_id(vec![1, 2, 3])
            .version(1)
            .ciphertext_handles(vec![ciphertext_handle; batch_size])
            .fhe_types(vec![FheType::Euint8; batch_size])
            .build();
        let response = contract
            .decrypt(decrypt.clone(), Proof::default())
            .with_funds(&[coin(data_size.into(), UCOSM)])
            .call(&caller)
            .unwrap();
        let txn_id: TransactionId = KmsContract::hash_transaction_id(12345, 0).into();
        assert_eq!(response.events.len(), 2);

        let expected_event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(txn_id.clone())
            .build();

        assert_event(&response.events, &expected_event);

        let response = contract.get_operations_value(expected_event).unwrap();
        assert_eq!(response.len(), 1);

        let not_expected_event = KmsEvent::builder()
            .operation(KmsOperation::KeyGen)
            .txn_id(txn_id.clone())
            .build();

        let response = contract.get_operations_value(not_expected_event);
        assert!(response.is_err());
    }
}
