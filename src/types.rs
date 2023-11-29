use serde::Deserialize;
use tendermint::block::signed_header::SignedHeader;

use crate::kms::{DecryptionResponse, ReencryptionResponse};

pub type Signature = Vec<u8>;

/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms {
    fn decrypt(&self, ct: &[u8]) -> DecryptionResponse;
    fn reencrypt(&self, ct: &[u8]) -> ReencryptionResponse;
}

#[derive(Debug, Deserialize)]
pub struct LightClientCommitResponse {
    _jsonrpc: String,
    _id: i32,
    pub result: SignedHeaderWrapper,
}

#[derive(Debug, Deserialize)]
pub struct SignedHeaderWrapper {
    pub signed_header: SignedHeader,
}
