use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{experimental::bgv::basics::LevelEllCiphertext, session_id::SessionId};

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SupportedRing {
    LevelOne,
    LevelKsw,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrssInitParams {
    pub session_id: SessionId,
    pub ring: SupportedRing,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreprocKeyGenParams {
    pub session_id: SessionId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdKeyGenParams {
    pub session_id: SessionId,
    pub session_id_preproc: Option<SessionId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdKeyGenResultParams {
    pub session_id: SessionId,
    pub gen_params: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdDecryptParams {
    pub session_id: SessionId,
    pub key_sid: SessionId,
    pub ctxts: Vec<LevelEllCiphertext>,
}
