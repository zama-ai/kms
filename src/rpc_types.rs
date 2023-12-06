use serde::Deserialize;
use tendermint::block::signed_header::SignedHeader;

use crate::{
    core::der_types::{KeyAddress, PublicEncKey},
    kms::FheType,
};

/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms {
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<(Vec<u8>, u32)>;
    fn validate_and_reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        enc_key: &PublicEncKey,
        address: &KeyAddress,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    // TODO add digest of decrypted cipher
    fn reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        enc_key: &PublicEncKey,
        address: &KeyAddress,
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
