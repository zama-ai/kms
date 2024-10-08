use super::operator::default_proof_runtime;

use super::operator::KeyEncoding;
use super::operator::KeyPath;
use super::serde_ops::raw_to_proof_ops;
use anyhow::{anyhow, Error};
use tendermint_proto::v0_38::crypto::ProofOps as RawProofOps;

pub(crate) struct TendermintProofStrategy {}

impl TendermintProofStrategy {
    pub fn verify_storage_proof(
        proof_raw: &[u8],
        contract_address: &[u8],
        app_hash: &[u8],
        storage_key: &[u8],
        value: &[u8],
    ) -> Result<bool, Error> {
        let decoded_raw: RawProofOps = prost::Message::decode(proof_raw).unwrap();
        let proof = raw_to_proof_ops(decoded_raw);
        verify(app_hash, 32)?;
        verify(contract_address, 20)?;
        let padded_storage_key = verify_or_pad(storage_key, 32)?;

        let key = state_key_for_proof(contract_address, &padded_storage_key);
        let pr = default_proof_runtime();
        let verfied = pr.verify_value(&proof, app_hash, &key, value);
        if let Err(e) = verfied {
            return Err(anyhow!("Error verifying proof: {:?}", e));
        }
        Ok(true)
    }
}

const STORAGE_PREFIX: u8 = 0x02;

macro_rules! state_key {
    ($contract_address:expr, $storage_key:expr) => {{
        let mut key = Vec::new();
        key.push(STORAGE_PREFIX);
        key.extend_from_slice($contract_address);
        key.extend_from_slice($storage_key);
        key
    }};
}

/// Constructs a state key for proof verification, formatted as a string.
///
/// This function builds a path suitable for proof verification, encoding the contract address
/// and storage key within the path.
///
/// # Arguments
///
/// * `contract_address` - The address of the contract.
/// * `storage_key` - The storage key, potentially padded to a specific length.
///
/// # Returns
///
/// The state key path as a string, or an error if the path construction fails.
fn state_key_for_proof(contract_address: &[u8], storage_key: &[u8]) -> String {
    let mut path = KeyPath::default();
    path.append_key("evm".into(), KeyEncoding::Url);
    path.append_key(state_key!(contract_address, storage_key), KeyEncoding::Hex);
    path.to_string()
        .expect("Error creating state key for proof")
}

/// Verifies or pads a hexadecimal representation to ensure it matches an expected length.
///
/// # Arguments
///
/// * `hex` - The hexadecimal data to verify or pad.
/// * `expected_length` - The expected length of the data.
///
/// # Returns
///
/// The verified or padded data as a vector of bytes, or an error if verification fails.
pub fn verify_or_pad(hex: &[u8], expected_length: usize) -> Result<Vec<u8>, Error> {
    if hex.len() == expected_length {
        return Ok(hex.to_owned());
    }
    if hex.len() < expected_length {
        let mut padded = vec![0; expected_length - hex.len()];
        padded.extend_from_slice(hex);
        return Ok(padded);
    }
    Err(anyhow!(
        "Error: expected hex length: {}, got: {}",
        expected_length,
        hex.len()
    ))
}

/// Verifies the length of a hexadecimal representation.
///
/// # Arguments
///
/// * `hex` - The hexadecimal data to verify.
/// * `expected_length` - The expected length of the data.
///
/// # Returns
///
/// A result indicating success if the data length matches the expected length, or an error.
fn verify(hex: &[u8], expected_length: usize) -> Result<(), Error> {
    if hex.len() != expected_length {
        return Err(anyhow!(
            "Error: expected hex length: {}, got: {}",
            expected_length,
            hex.len()
        ));
    }
    Ok(())
}
