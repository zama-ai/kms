//! Shared fixtures for the Solana linker v1 test binaries.
//!
//! A single canonical request, mutated one field at a time. Tests read as "this request, except
//! for X", which is what makes a sensitivity suite reviewable: the reader can see that exactly one
//! thing changed.

// Each test binary compiles this module and uses a subset of it.
#![allow(dead_code)]

use kms_grpc::solana_binding::{SolanaUserDecryptBinding, SolanaUserDecryptBindingError};

/// A Solana-kind host chain id: bit 63 set, as every embedded handle chain id must be.
pub const CHAIN_ID: u64 = (1 << 63) | 12_345;

pub const PROGRAM_ID: [u8; 32] = [0x22; 32];
pub const RECEIVER: [u8; 32] = [0x33; 32];
pub const CONTEXT_ID: [u8; 32] = [0x44; 32];
pub const EPOCH_ID: [u8; 32] = [0x55; 32];

/// In production the request carries the 869-byte serialized `UnifiedPublicEncKey::MlKem512`
/// container (the 800-byte encapsulation key plus its framing), though the binding does not
/// enforce a width — that rule lives in the wallet permit and the connector.
pub const TRANSPORT_KEY_LEN: usize = 869;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub verifying_program_id: Vec<u8>,
    pub receiver_id: Vec<u8>,
    pub kms_context_id: Vec<u8>,
    pub kms_epoch_id: Vec<u8>,
    pub handles: Vec<[u8; 32]>,
    pub transport_key: Vec<u8>,
}

impl Request {
    /// The canonical two-handle request every variant deviates from.
    pub fn canonical() -> Self {
        Self {
            verifying_program_id: PROGRAM_ID.to_vec(),
            receiver_id: RECEIVER.to_vec(),
            kms_context_id: CONTEXT_ID.to_vec(),
            kms_epoch_id: EPOCH_ID.to_vec(),
            handles: vec![handle(1), handle(2)],
            transport_key: transport_key(),
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
            &self.kms_context_id,
            &self.kms_epoch_id,
            self.handles.iter().map(|handle| handle.as_slice()),
            &self.transport_key,
        )
    }

    pub fn build(&self) -> SolanaUserDecryptBinding {
        self.try_build().expect("a canonical Solana request")
    }

    pub fn link(&self) -> Vec<u8> {
        self.build().compute_link()
    }
}
