//! Fixtures for the Solana linker sensitivity suite.
//!
//! A single canonical request, mutated one field at a time. Tests read as "this request, except
//! for X", which is what makes a sensitivity suite reviewable: the reader can see that exactly one
//! thing changed.

use alloy_primitives::{U256, address};
use alloy_sol_types::Eip712Domain;
use kms_grpc::solana_binding::{SolanaUserDecryptBinding, SolanaUserDecryptBindingError};

/// A Solana-kind host chain id: type byte `0x01`, as every embedded handle chain id must be.
pub const CHAIN_ID: u64 = kms_grpc::solana_binding::solana_host_chain_id(12_345);

pub const PROGRAM_ID: [u8; 32] = [0x22; 32];
pub const RECEIVER: [u8; 32] = [0x33; 32];

/// In production the request carries the 869-byte safe-serialized `UnifiedPublicEncKey::MlKem512`
/// container (the 800-byte encapsulation key plus its framing), though the binding does not
/// enforce a width — that rule lives in the wallet permit and the connector.
pub const TRANSPORT_KEY_LEN: usize = 869;

/// The Gateway `Decryption` contract's EIP-712 domain the fixtures are hashed under: the
/// contract's name and version, a gateway chain id, a fixed contract address, no salt. One domain
/// for every suite in this directory, so a test that changes it changes exactly one thing.
pub fn gateway_domain() -> Eip712Domain {
    Eip712Domain::new(
        Some("Decryption".into()),
        Some("1".into()),
        Some(U256::from(54_321u64)),
        Some(address!("66f9664f97F2b50F62D13eA064982f936dE76657")),
        None,
    )
}

/// A ciphertext handle embedding `chain_id`, with `discriminator` filling every other byte so
/// handles of one request stay distinguishable.
pub fn handle_for_chain(chain_id: u64, discriminator: u8) -> [u8; 32] {
    let mut handle = [discriminator; 32];
    handle[22..30].copy_from_slice(&chain_id.to_be_bytes());
    handle
}

/// A ciphertext handle on the canonical chain.
pub fn handle(discriminator: u8) -> [u8; 32] {
    handle_for_chain(CHAIN_ID, discriminator)
}

/// A deterministic transport key of the usual width.
pub fn transport_key() -> Vec<u8> {
    (0..TRANSPORT_KEY_LEN).map(|byte| byte as u8).collect()
}

/// The inputs of a Solana user-decryption request, as fields, so a test can change exactly one.
///
/// `extra_data` is not among them: it is not a linker input, and its authentication belongs to the
/// response signature, tested where that signature is verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub verifying_program_id: Vec<u8>,
    pub receiver_id: Vec<u8>,
    pub handles: Vec<[u8; 32]>,
    pub transport_key: Vec<u8>,
    pub domain: Eip712Domain,
}

impl Request {
    /// The canonical two-handle request every variant deviates from.
    pub fn canonical() -> Self {
        Self {
            verifying_program_id: PROGRAM_ID.to_vec(),
            receiver_id: RECEIVER.to_vec(),
            handles: vec![handle(1), handle(2)],
            transport_key: transport_key(),
            domain: gateway_domain(),
        }
    }

    pub fn with_handles(mut self, handles: Vec<[u8; 32]>) -> Self {
        self.handles = handles;
        self
    }

    pub fn try_build(&self) -> Result<SolanaUserDecryptBinding, SolanaUserDecryptBindingError> {
        SolanaUserDecryptBinding::new(
            &self.verifying_program_id,
            &self.receiver_id,
            self.handles.iter().map(|handle| handle.as_slice()),
            &self.transport_key,
        )
    }

    pub fn build(&self) -> SolanaUserDecryptBinding {
        self.try_build().expect("a canonical Solana request")
    }

    pub fn link(&self) -> Vec<u8> {
        self.build().compute_link(&self.domain)
    }
}
