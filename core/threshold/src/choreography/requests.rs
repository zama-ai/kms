use crate::execution::runtime::session::DecryptionMode;
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
    pub decryption_mode: DecryptionMode,
    pub num_blocks: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdDecryptParams {
    pub session_id: SessionId,
    pub decryption_mode: DecryptionMode,
    pub key_sid: SessionId,
    pub preproc_sid: Option<SessionId>,
    pub ctxts: Vec<Ciphertext64>,
    pub tfhe_type: TfheType,
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
