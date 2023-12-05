use serde::Deserialize;
use tendermint::block::signed_header::SignedHeader;

use crate::{
    core::der_types::ClientRequest,
    kms::{
        DecryptionRequest, DecryptionResponse, FheType, ReencryptionRequest, ReencryptionResponse,
    },
};

/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms {
    fn validate_and_decrypt(
        &self,
        request: &DecryptionRequest,
    ) -> anyhow::Result<Option<DecryptionResponse>>;
    fn validate_and_reencrypt(
        &self,
        request: &ReencryptionRequest,
    ) -> anyhow::Result<Option<ReencryptionResponse>>;
    /// Decrypt directly without validation
    fn decrypt(&self, ct: &[u8], ct_type: FheType) -> anyhow::Result<DecryptionResponse>;
    fn reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        client_req: &ClientRequest,
    ) -> anyhow::Result<Option<ReencryptionResponse>>;
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
