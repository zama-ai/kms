use serde::Deserialize;
use tendermint::block::signed_header::SignedHeader;

use crate::{core::request::ClientRequest, kms::FheType};

/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms {
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<(Vec<u8>, u32)>;
    fn validate_and_reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        client_req: &ClientRequest,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    fn reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        client_req: &ClientRequest,
    ) -> anyhow::Result<Option<Vec<u8>>>;
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
