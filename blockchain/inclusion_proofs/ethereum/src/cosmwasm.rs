// Static configuration: URL, ACL Contract Address, Slot Number for Decryption, Encryption
// Per request Cipher Text Handle, Permission Type
// Output: Cipher Text Handle, Proof Ops, Block Height, Root Hash
//
// For verification: Output

#[cfg(feature = "cosmwasm")]
pub mod proof_handler {
    use crate::types::{
        biguint_to_bytes32, bytes32_to_biguint, EthGetProofResult, EvmPermissionProof, Permission,
        ACL_DECRYPT_MAPPING_SLOT, ACL_REENCRYPT_MAPPING_SLOT,
    };

    use crate::cosmwasm_nodecodec::nodecodec::{keccak_256, EIP1186Layout, KeccakHasher};
    use ethereum_triedb_local::StorageProof;
    use hex_literal::hex;
    use primitive_types::H256;
    use rlp::{Decodable, Rlp};
    use sha3::{Digest, Keccak256};
    use trie_db::{Trie, TrieDBBuilder};

    use anyhow::{anyhow, Error};

    pub struct EthereumProofHandler {}

    impl EthereumProofHandler {
        pub fn verify_proof(
            params: EvmPermissionProof,
            ciphertext_handles: Vec<Vec<u8>>,
        ) -> Result<bool, Error> {
            if params.ciphertext_handles.len() != params.proof.len() {
                return Err(anyhow!(
                    "count of ciphertext handles should be equal to count of proofs {}, {}",
                    params.ciphertext_handles.len(),
                    params.proof.len()
                ));
            }

            if params.ciphertext_handles != ciphertext_handles {
                return Err(anyhow!(
                    "proof does not correspond to the given set of ciphertext handles {} {}",
                    hex::encode(&params.ciphertext_handles[0]),
                    hex::encode(&ciphertext_handles[0])
                ));
            }

            match Permission::try_from(params.permission)? {
                Permission::Decrypt => {
                    for (handle, proof) in params.ciphertext_handles.iter().zip(params.proof.iter())
                    {
                        let proof = String::from_utf8(proof.clone())?;
                        let proof: EthGetProofResult = serde_json::from_str(&proof)?;

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
                            let proof = String::from_utf8(proof.clone())?;
                            let proof: EthGetProofResult = serde_json::from_str(&proof)?;

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
        pub fn compute_storage_key(
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
        let storage_hash = match hex::decode(&proof.storageHash) {
            Ok(hash) => H256::from_slice(&hash),
            Err(_) => return Some(Err(anyhow!("invalid storage hash"))),
        };
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
        let key_retrieval = key_retrieval.as_bytes().to_vec();
        let db = StorageProof::new(extracted_proof_nodes).into_memory_db::<KeccakHasher>();
        let trie = TrieDBBuilder::<EIP1186Layout<KeccakHasher>>::new(&db, &storage_hash).build();
        let storage_result = trie.get(&key_retrieval).unwrap().unwrap();
        let storage_value = <bool as Decodable>::decode(&Rlp::new(&storage_result))
            .map_err(|e| anyhow!("Error decoding storage value from RLP: {}", e))
            .ok()?;

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
    use crate::cosmwasm_proof_handler::EthereumProofHandler;
    use hex_literal::hex;

    #[test]
    fn test_compute_storage_key() {
        // Define input values
        let base_slot_bytes =
            hex!("0000000000000000000000000000000000000000000000000000000000000001").to_vec();
        let key_in_mapping =
            hex!("f2eac20e8f2385a14094f424c3adb8ee0a713bfcbb9b4dd6071824013ba60200").to_vec();
        let storage_location =
            hex!("a688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00").to_vec();

        // Call the function
        let result = EthereumProofHandler::compute_storage_key(
            &base_slot_bytes,
            &key_in_mapping,
            &storage_location,
        );

        // Define the expected output
        let expected_output = "0xadd5658dbf7dce2c0f05b5f0d307477a8dcb3a717c9d5d1b330481a463d56c9d"; // Replace with the actual expected output

        // Assert the result
        assert_eq!(result.unwrap(), expected_output);
    }
}
