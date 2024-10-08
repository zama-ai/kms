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
        ACL_DECRYPT_MAPPING_SLOT, TRUE_SOLIDITY_STR,
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
            // MANO: Introduce error handling.
            Ok(Self {
                config,
                client: Client::new(),
            })
        }
        pub async fn fetch_proof(
            &self,
            params: EVMProofParams,
        ) -> Result<EvmPermissionProof, Error> {
            let evm_storage_key: &str = match params.permission {
                Permission::Decrypt => &Self::compute_storage_key(
                    [ACL_DECRYPT_MAPPING_SLOT].as_ref(),
                    &params.cipher_text_handle,
                    &hex!("a688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00"),
                )?,
                Permission::Reencrypt => "TODO", // TODO: Implement
            };

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

            match response {
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
                    let proof_response = proof_response.into_bytes();
                    let proof_reponse = vec![proof_response];

                    let proof = EvmPermissionProof {
                        ciphertext_handles: vec![params.cipher_text_handle],
                        block_height: 0,    // TODO
                        root_hash: vec![0], // TODO
                        contract_address: hex::decode(&self.config.acl_contract_address[2..])
                            .unwrap(),
                        permission: params.permission.into(),
                        proof: proof_reponse,
                    };

                    match Self::verify_proof(self, proof.clone()) {
                        Ok(true) => Ok(proof),
                        Ok(false) => Err(anyhow!("Proof is not valid")),
                        Err(e) => Err(e),
                    }
                }
                EthResponse::Error { error } => Err(anyhow!(
                    "Error from server: {} (code: {})",
                    error.message,
                    error.code
                )),
            }
        }

        // fn verify_proof(&self, params: EvmPermissionProof) -> Result<bool, Error> {
        pub fn verify_proof(&self, params: EvmPermissionProof) -> Result<bool, Error> {
            if params.ciphertext_handles.len() != 1 || params.proof.len() != 1 {
                return Err(anyhow!(
                    "Proof should contain exactly one proof op and one ciphertext handle"
                ));
            }

            let proof_response = params.proof[0].clone();
            let proof_response = String::from_utf8(proof_response).unwrap();
            let proof_response: EthGetProofResult = serde_json::from_str(&proof_response).unwrap();

            let evm_storage_key = match Permission::try_from(params.permission)? {
                Permission::Decrypt => Self::compute_storage_key(
                    [ACL_DECRYPT_MAPPING_SLOT].as_ref(),
                    &params.ciphertext_handles[0],
                    &proof_response.storageLocation,
                )?,
                Permission::Reencrypt => String::from("TODO"),
            };

            let storage_hash_str = &proof_response.storageHash;
            let storage_hash = H256::from_slice(&hex::decode(&storage_hash_str[2..]).unwrap());

            let mut extracted_key = H256::zero();
            // let mut extracted_value = U256::zero();
            let mut extracted_proof_nodes: Vec<Vec<u8>> = Vec::new();

            if let Some(proof) = proof_response.storageProof.first() {
                extracted_key = H256::from_slice(&hex::decode(&proof.key[2..]).unwrap());
                // extracted_value = U256::from_str_radix(&proof.value[2..], 16).unwrap();
                extracted_proof_nodes = proof
                    .proof
                    .iter()
                    .map(|p| hex::decode(&p[2..]).unwrap())
                    .collect();
            }
            if hex::decode(&evm_storage_key[2..]).unwrap() != extracted_key.as_bytes() {
                return Err(anyhow!("Keys do not match"));
            }

            let key_retrieval = keccak_256(extracted_key.as_bytes());

            let db = StorageProof::new(extracted_proof_nodes).into_memory_db::<KeccakHasher>();
            let trie =
                TrieDBBuilder::<EIP1186Layout<KeccakHasher>>::new(&db, &storage_hash).build();

            let storage_result = trie.get(&key_retrieval).unwrap().unwrap();

            // Decode the retrieved data (assuming it's a bool for this example)
            let storage_value = <bool as Decodable>::decode(&Rlp::new(&storage_result)).unwrap();
            Ok(storage_value)
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
}
