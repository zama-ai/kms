use crate::execution::endpoints::decryption::DecryptionMode;
use crate::execution::tfhe_internals::parameters::{Ciphertext64, DKGParams};
use crate::session_id::SessionId;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::grpc::SupportedRing;

#[derive(Debug, Serialize, Deserialize, Clone, ValueEnum)]
pub enum SessionType {
    Small,
    Large,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrssInitParams {
    pub session_id: SessionId,
    pub ring: SupportedRing,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreprocKeyGenParams {
    pub session_type: SessionType,
    pub session_id: SessionId,
    pub dkg_params: DKGParams,
    pub num_sessions: u32,
    pub percentage_offline: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdKeyGenParams {
    pub session_id: SessionId,
    pub dkg_params: DKGParams,
    pub session_id_preproc: Option<SessionId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdKeyGenResultParams {
    pub session_id: SessionId,
    pub dkg_params: Option<DKGParams>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreprocDecryptParams {
    pub session_id: SessionId,
    pub key_sid: SessionId,
    pub decryption_mode: DecryptionMode,
    pub num_ctxts: u128,
    pub ctxt_type: TfheType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughtputParams {
    /// Defines the num of copies of each ctxt we will decrypt
    pub num_copies: usize,
    /// Defines the num of sessions to run in parallel
    pub num_sessions: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdDecryptParams {
    pub session_id: SessionId,
    pub decryption_mode: DecryptionMode,
    pub key_sid: SessionId,
    pub preproc_sid: Option<SessionId>,
    pub ctxts: Vec<Ciphertext64>,
    pub tfhe_type: TfheType,
    // If Some, copies each ctxts the given
    // number of times and spawns
    pub throughput: Option<ThroughtputParams>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrsGenParams {
    pub session_id: SessionId,
    pub witness_dim: u128,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ongoing,
    Finished,
    Missing,
}

#[derive(Clone, Debug, Serialize, Deserialize, ValueEnum)]
pub enum TfheType {
    Bool,
    U4,
    U8,
    U16,
    U32,
    U64,
    U128,
    U160,
    U256,
    U2048,
}

impl TfheType {
    pub fn get_num_bits_rep(&self) -> usize {
        match self {
            TfheType::Bool => 1,
            TfheType::U4 => 4,
            TfheType::U8 => 8,
            TfheType::U16 => 16,
            TfheType::U32 => 32,
            TfheType::U64 => 64,
            TfheType::U128 => 128,
            TfheType::U160 => 160,
            TfheType::U256 => 256,
            TfheType::U2048 => 2048,
        }
    }
}
