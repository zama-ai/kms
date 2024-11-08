// Static configuration: URL, ACL Contract Address, Slot Number for Decryption, Encryption
// Per request Cipher Text Handle, Permission Type
// Output: Cipher Text Handle, Proof Ops, Block Height, Root Hash
//
// For verification: Output
//

#[cfg(feature = "default")]
pub mod proof_handler {
    use crate::types::{
        biguint_to_bytes32, bytes32_to_biguint, EVMProofParams, EthGetProofRequest,
        EthGetProofResult, EthResponse, EthereumConfig, EvmPermissionProof, Permission,
        ACL_DECRYPT_MAPPING_SLOT, ACL_REENCRYPT_MAPPING_SLOT, TRUE_SOLIDITY_STR,
    };

    use ethereum_triedb::{
        keccak::{keccak_256, KeccakHasher},
        EIP1186Layout, StorageProof,
    };
    use rlp::{Decodable, Rlp};
    use trie_db::{Trie, TrieDBBuilder};

    use reqwest::Client;

    use hex_literal::hex;
    use primitive_types::H256;
    use sha3::{Digest, Keccak256};

    use anyhow::{anyhow, Error};

    pub struct EthereumProofHandler {
        pub config: EthereumConfig,
        pub client: Client,
    }

    impl EthereumProofHandler {
        pub fn new(config: EthereumConfig) -> Result<Self, Error> {
            Ok(Self {
                config,
                client: Client::new(),
            })
        }

        pub async fn fetch_proof(
            &self,
            params: EVMProofParams,
        ) -> Result<EvmPermissionProof, Error> {
            let mut proofs = vec![];

            let permission: Permission;
            let ciphertext_handles: Vec<Vec<u8>>;
            let accounts: Vec<Vec<u8>>;

            match params {
                EVMProofParams::Decrypt(params) => {
                    permission = Permission::Decrypt;
                    ciphertext_handles = params.ciphertext_handles;
                    accounts = vec![];

                    for handle in ciphertext_handles.clone() {
                        let evm_storage_key: &str = &Self::compute_storage_key_decrypt(
                            &handle,
                            &hex!(
                                "a688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00"
                            ),
                        )?;

                        match self.fetch_proof_for_storage_key(evm_storage_key).await {
                            Ok(proof) => proofs.push(proof),
                            Err(e) => return Err(e),
                        }
                    }
                }
                EVMProofParams::Reencrypt(params) => {
                    permission = Permission::Reencrypt;
                    ciphertext_handles = params.ciphertext_handles;
                    accounts = params.accounts;

                    if accounts.len() == ciphertext_handles.len() {
                        for (h, acc) in ciphertext_handles.iter().zip(accounts.iter()) {
                            let evm_storage_key: &str = &Self::compute_storage_key_reencrypt(
                                    h,
                                    acc,
                                    &hex!(
                                        "a688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00"
                                    ),
                                )?;

                            match self.fetch_proof_for_storage_key(evm_storage_key).await {
                                Ok(proof) => proofs.push(proof),
                                Err(e) => return Err(e),
                            }
                        }
                    } else {
                        return Err(anyhow!("account length does not match cipher text handles"));
                    }
                }
            }

            let proof = EvmPermissionProof {
                ciphertext_handles,
                accounts,
                block_height: 0,    // TODO
                root_hash: vec![0], // TODO
                contract_address: hex::decode(&self.config.acl_contract_address[2..]).unwrap(),
                permission: permission.into(),
                proof: proofs,
            };

            match Self::verify_proof(self, proof.clone()) {
                Ok(true) => Ok(proof),
                Ok(false) => Err(anyhow!("Proof is not valid")),
                Err(e) => Err(e),
            }
        }

        async fn fetch_proof_for_storage_key(
            &self,
            evm_storage_key: &str,
        ) -> Result<Vec<u8>, Error> {
            let req_params = [
                &serde_json::Value::String(self.config.acl_contract_address.clone()),
                &serde_json::Value::Array(vec![serde_json::Value::String(
                    evm_storage_key.to_string(),
                )]),
                &serde_json::Value::String("latest".to_string()),
            ];
            let request = EthGetProofRequest {
                jsonrpc: "2.0",
                method: "eth_getProof",
                params: req_params,
                id: 1,
            };
            let response = self
                .client
                .post(&self.config.json_rpc_url)
                .json(&request)
                .send()
                .await?
                .json::<EthResponse>()
                .await?;
            Ok(match response {
                EthResponse::Success(proof_response) => {
                    let mut result = proof_response.result.clone();
                    if result.storageProof.len() != 1 {
                        return Err(anyhow!("Length of storage proof must be 1"));
                    }
                    if result.storageProof[0].value != TRUE_SOLIDITY_STR {
                        return Err(anyhow!(
                            "Incorrect value for permission {}",
                            result.storageProof[0].value
                        ));
                    }
                    result.storageLocation =
                        hex!("a688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00")
                            .to_vec();

                    let proof_response = serde_json::to_string(&result).unwrap();
                    proof_response.into_bytes()
                }
                EthResponse::Error { error } => {
                    return Err(anyhow!(
                        "Error from server: {} (code: {})",
                        error.message,
                        error.code
                    ));
                }
            })
        }

        pub fn verify_proof(&self, params: EvmPermissionProof) -> Result<bool, Error> {
            if params.ciphertext_handles.len() != params.proof.len() {
                return Err(anyhow!(
                    "count of ciphertext handles should be equal to count of proofs"
                ));
            }

            match Permission::try_from(params.permission)? {
                Permission::Decrypt => {
                    for (handle, proof) in params.ciphertext_handles.iter().zip(params.proof.iter())
                    {
                        let proof = String::from_utf8(proof.clone()).unwrap();
                        let proof: EthGetProofResult = serde_json::from_str(&proof).unwrap();

                        let evm_storage_key =
                            Self::compute_storage_key_decrypt(handle, &proof.storageLocation)?;

                        if let Some(value) = evaluate_merkle_proof(proof, evm_storage_key) {
                            return value;
                        }
                    }
                }
                Permission::Reencrypt => {
                    if params.accounts.len() == params.ciphertext_handles.len()
                        && params.accounts.len() == params.proof.len()
                    {
                        for ((handle, account), proof) in params
                            .ciphertext_handles
                            .iter()
                            .zip(params.accounts.iter())
                            .zip(params.proof.iter())
                        {
                            let proof = String::from_utf8(proof.clone()).unwrap();
                            let proof: EthGetProofResult = serde_json::from_str(&proof).unwrap();

                            let evm_storage_key = Self::compute_storage_key_reencrypt(
                                    handle,
                                    account,
                                    &hex!(
                                        "a688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00"
                                    ),
                                )?;

                            if let Some(value) = evaluate_merkle_proof(proof, evm_storage_key) {
                                return value;
                            }
                        }
                    } else {
                        return Err(anyhow!("lengths of account {}, handles {} and ciphertext handles {} do not match",
                            params.accounts.len(), params.ciphertext_handles.len(), params.proof.len()));
                    }
                }
            }
            Ok(true)
        }

        fn compute_storage_key_reencrypt(
            handle: &[u8],
            account: &[u8],
            storage_location: &[u8],
        ) -> Result<String, Error> {
            let intermediate_slot =
                Self::compute_storage_key(&[ACL_REENCRYPT_MAPPING_SLOT], handle, storage_location)?;
            let intermediate_slot_bytes = hex::decode(intermediate_slot.trim_start_matches("0x"))?;

            // Step 2: Compute the final storage key for persistedAllowedPairs[handle][account]
            let account_padded = {
                let mut padded = [0u8; 32];
                padded[12..].copy_from_slice(account); // Left-pad the account address
                padded
            };

            Self::compute_storage_key(&[], &account_padded, &intermediate_slot_bytes)
        }

        fn compute_storage_key_decrypt(
            handle: &[u8],
            storage_location: &[u8],
        ) -> Result<String, Error> {
            // Compute the storage key for allowedForDecryption[handle]
            Self::compute_storage_key(&[ACL_DECRYPT_MAPPING_SLOT], handle, storage_location)
        }
        fn compute_storage_key(
            base_slot_bytes: &[u8],
            key_in_mapping: &[u8],
            storage_location: &[u8],
        ) -> Result<String, Error> {
            let key_in_mapping: [u8; 32] = {
                let mut padded = [0u8; 32];
                let start = 32 - key_in_mapping.len().min(32);
                padded[start..]
                    .copy_from_slice(&key_in_mapping[key_in_mapping.len().saturating_sub(32)..]);
                padded
            };

            let storage_location: [u8; 32] = {
                let mut padded = [0u8; 32];
                let start = 32 - storage_location.len().min(32);
                padded[start..].copy_from_slice(
                    &storage_location[storage_location.len().saturating_sub(32)..],
                );
                padded
            };

            let base_slot: [u8; 32] = {
                let mut padded = [0u8; 32];
                let start = 32 - base_slot_bytes.len().min(32);
                padded[start..]
                    .copy_from_slice(&base_slot_bytes[base_slot_bytes.len().saturating_sub(32)..]);
                padded
            };

            let base_slot = bytes32_to_biguint(&base_slot);
            let storage_location = bytes32_to_biguint(&storage_location);
            let slot = storage_location + base_slot;
            let slot = biguint_to_bytes32(&slot);

            let mut concatenated = Vec::with_capacity(64);
            concatenated.extend_from_slice(&key_in_mapping);
            concatenated.extend_from_slice(&slot);

            let mut hasher = Keccak256::new();
            hasher.update(&concatenated);

            Ok(format!(
                "0x{:x}",
                H256::from_slice(hasher.finalize().as_slice())
            ))
        }
    }

    fn evaluate_merkle_proof(
        proof: EthGetProofResult,
        evm_storage_key: String,
    ) -> Option<Result<bool, Error>> {
        let storage_hash_str = &proof.storageHash;
        let storage_hash = H256::from_slice(&hex::decode(&storage_hash_str[2..]).unwrap());
        let mut extracted_key = H256::zero();
        let mut extracted_proof_nodes: Vec<Vec<u8>> = Vec::new();
        if let Some(proof) = proof.storageProof.first() {
            extracted_key = H256::from_slice(&hex::decode(&proof.key[2..]).unwrap());
            // extracted_value = U256::from_str_radix(&proof.value[2..], 16).unwrap();
            extracted_proof_nodes = proof
                .proof
                .iter()
                .map(|p| hex::decode(&p[2..]).unwrap())
                .collect();
        }
        if hex::decode(&evm_storage_key[2..]).unwrap() != extracted_key.as_bytes() {
            return Some(Err(anyhow!("Keys do not match")));
        }
        let key_retrieval = keccak_256(extracted_key.as_bytes());
        let db = StorageProof::new(extracted_proof_nodes).into_memory_db::<KeccakHasher>();
        let trie = TrieDBBuilder::<EIP1186Layout<KeccakHasher>>::new(&db, &storage_hash).build();
        let storage_result = trie.get(&key_retrieval).unwrap().unwrap();
        let storage_value = <bool as Decodable>::decode(&Rlp::new(&storage_result)).unwrap();

        // let mut extracted_value = U256::zero();

        // Decode the retrieved data (assuming it's a bool for this example)
        if !storage_value {
            return Some(Ok(false));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::std_proof_handler::EthereumProofHandler;
    use crate::types::{DecryptProofParams, EVMProofParams, EthereumConfig, ReencryptProofParams};
    use tokio::test;

    #[test]
    async fn test_check_permission_on_acl() {
        let config = EthereumConfig {
            json_rpc_url: "http://127.0.0.1:8645".to_string(),
            acl_contract_address: "0x2C411273C34e8629f9c01233723D19A6ae8D6afb".to_string(),
        };

        let proof_handler = EthereumProofHandler::new(config).unwrap();

        let test_cases = [
            (
                "decrypt",
                EVMProofParams::Decrypt(DecryptProofParams {
                    ciphertext_handles: vec![hex::decode(
                        "0000000000000000000000000000000000000001",
                    )
                    .unwrap()],
                }),
                true,
            ),
            (
                "reencrypt",
                EVMProofParams::Reencrypt(ReencryptProofParams {
                    ciphertext_handles: vec![hex::decode(
                        "0000000000000000000000000000000000000001",
                    )
                    .unwrap()],
                    accounts: vec![hex::decode("00000000000000000000000000000000000000A1").unwrap()],
                }),
                true,
            ),
        ];

        for (name, params, should_succeed) in &test_cases {
            let result = proof_handler.fetch_proof(params.clone()).await;
            assert_eq!(
                result.is_ok(),
                *should_succeed,
                "Test case {} failed for handle",
                *name,
            );
        }
    }
}
