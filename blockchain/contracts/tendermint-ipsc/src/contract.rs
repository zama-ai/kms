use crate::proof::strategy::TendermintProofStrategy;
use aipsc::contract::InclusionProofContract;
use anyhow::{anyhow, Error};
use contracts_common::migrations::Migration;
use cosmwasm_std::{Response, StdError, StdResult};
use cw2::set_contract_version;
use prost::Message;
use sha3::{Digest, Keccak256};
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx},
};

// Info for migration
const CONTRACT_NAME: &str = "kms-tendermint-ipsc";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct ProofContract {}

/// Implement the `Migration` trait
///
/// This allows to migrate the contract's state from an old version to a new version, without
/// changing its address. This will automatically use versioning to ensure compatibility between
/// versions
impl Migration for ProofContract {}

#[entry_points]
#[contract]
#[sv::messages(aipsc::contract as InclusionProofContract)]
impl ProofContract {
    pub fn new() -> Self {
        Self {}
    }
    #[sv::msg(instantiate)]
    pub fn instantiate(&self, ctx: InstantiateCtx) -> StdResult<Response> {
        // Set contract name and version in the storage
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        Ok(Response::default())
    }

    /// Function to migrate from old version to new version
    ///
    /// As there is only one version of the contract for now, this function has no real use. Future
    /// versions of the contract will be required to provide this function, with additional migration
    /// logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> StdResult<Response> {
        self.apply_migration(ctx.deps.storage)
    }
}

impl InclusionProofContract for ProofContract {
    type Error = StdError;

    fn verify_proof(&self, _ctx: ExecCtx, proof: String, _handles: String) -> StdResult<Response> {
        let proof = hex::decode(proof).unwrap();
        let proof = EthermintPermissionProof::decode(&*proof).unwrap();

        let evm_storage_key = match Permission::try_from(proof.permission).unwrap() {
            Permission::Decrypt => compute_storage_key(
                [ACL_DECRYPT_MAPPING_SLOT].as_ref(),
                &proof.ciphertext_handles[0],
            )
            .unwrap(),
            Permission::Reencrypt => vec![1, 2, 3, 4],
        };

        let result = TendermintProofStrategy::verify_storage_proof(
            &proof.proof[0],
            &proof.contract_address.clone(),
            &proof.root_hash,
            &evm_storage_key,
            &TRUE_SOLIDITY,
        )
        .unwrap();

        Ok(Response::new()
            .add_attribute("method", "verify tendermint proof")
            .add_attribute("result", result.to_string())) // Convert bool to string for the attribute
    }
}

fn compute_storage_key(base_slot_bytes: &[u8], key_in_mapping: &[u8]) -> Result<Vec<u8>, Error> {
    if key_in_mapping.len() != 32 {
        return Err(anyhow!("Key in mapping should be 32 bytes"));
    }

    let base_slot: [u8; 32] = {
        let mut padded = [0u8; 32];
        let start = 32 - base_slot_bytes.len().min(32);
        padded[start..]
            .copy_from_slice(&base_slot_bytes[base_slot_bytes.len().saturating_sub(32)..]);
        padded
    };

    let mut concatenated = Vec::with_capacity(64);
    concatenated.extend_from_slice(key_in_mapping);
    concatenated.extend_from_slice(&base_slot);

    let mut hasher = Keccak256::new();
    hasher.update(&concatenated);
    Ok(hasher.finalize().to_vec())
}

// Constant defining handle number
const ACL_DECRYPT_MAPPING_SLOT: u8 = 0;
// const ACL_REENCRYPT_MAPPING_SLOT: u8 = 1;

const VEC_SIZE: usize = 31;
const TRUE_SOLIDITY: [u8; VEC_SIZE + 1] = {
    let mut vec = [0u8; VEC_SIZE + 1];
    vec[VEC_SIZE] = 1; // Set the last element to 1
    vec
};

/// Represents the operations allowed for a cipher text handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Permission {
    Decrypt = 0,
    Reencrypt = 1,
}
impl Permission {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Permission::Decrypt => "Decrypt",
            Permission::Reencrypt => "Reencrypt",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "Decrypt" => Some(Self::Decrypt),
            "Reencrypt" => Some(Self::Reencrypt),
            _ => None,
        }
    }
}

/// Ethermint specific proof of a perrmission granted for a list of cipher text handles
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthermintPermissionProof {
    /// Ordered list of cipher text handles.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub ciphertext_handles: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(enumeration = "Permission", tag = "2")]
    pub permission: i32,
    /// Block height at which the proof was generated.
    #[prost(uint64, tag = "3")]
    pub block_height: u64,
    /// Root hash for merkle proofs.
    #[prost(bytes = "vec", tag = "4")]
    pub root_hash: ::prost::alloc::vec::Vec<u8>,
    /// Address on ACL contract on ethermint.
    #[prost(bytes = "vec", tag = "5")]
    pub contract_address: ::prost::alloc::vec::Vec<u8>,
    /// Ordered list of encoded proof ops for each cipher text handle in cipher text handles.
    /// See cometbft/proto/cometbft/crypto/v1/proof.proto.
    #[prost(bytes = "vec", repeated, tag = "6")]
    pub proof: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
