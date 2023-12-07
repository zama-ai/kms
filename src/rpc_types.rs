use serde::{ser::Error, Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::fmt;
use tendermint::block::signed_header::SignedHeader;

use crate::{
    core::der_types::{KeyAddress, PublicEncKey, PublicSigKey, Signature},
    kms::{
        DecryptionRequest, DecryptionRequestPayload, DecryptionResponsePayload, FheType, Proof,
        ReencryptionRequest, ReencryptionRequestPayload,
    },
};

/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms {
    fn verify_sig<T: fmt::Debug + Serialize>(
        &self,
        payload: &T,
        signature: &Signature,
        address: &KeyAddress,
    ) -> bool;
    fn sign<T: fmt::Debug + Serialize>(&self, msg: &T) -> anyhow::Result<Signature>;
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<u32>;
    // TODO add digest of decrypted cipher
    fn reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        enc_key: &PublicEncKey,
        address: &KeyAddress,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    fn digest<T: fmt::Debug + Serialize>(&self, msg: &T) -> anyhow::Result<Vec<u8>>;
    fn get_verf_key(&self) -> PublicSigKey;
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

impl serde::Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.height.to_be_bytes().to_vec());
        to_ser.append(&mut self.merkle_patricia_proof.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for ReencryptionRequestPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.address.to_vec());
        to_ser.append(&mut self.enc_key.to_vec());
        to_ser.append(&mut self.fhe_type.to_be_bytes().to_vec());
        to_ser.append(&mut self.ciphertext.to_vec());
        let mut proof = to_vec(&self.proof).map_err(Error::custom)?;
        to_ser.append(&mut proof);
        to_ser.append(&mut self.randomness.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for ReencryptionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.signature.to_vec());
        to_ser.append(&mut to_vec(&self.payload).map_err(Error::custom)?);
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for DecryptionRequestPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.address.to_vec());
        to_ser.append(&mut self.fhe_type.to_be_bytes().to_vec());
        to_ser.append(&mut self.ciphertext.to_vec());
        let mut proof = to_vec(&self.proof).map_err(Error::custom)?;
        to_ser.append(&mut proof);
        to_ser.append(&mut self.randomness.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for DecryptionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.signature.to_vec());
        to_ser.append(&mut to_vec(&self.payload).map_err(Error::custom)?);
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for DecryptionResponsePayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.address.to_vec());
        to_ser.append(&mut self.fhe_type.to_be_bytes().to_vec());
        to_ser.append(&mut self.plaintext.to_be_bytes().to_vec());
        to_ser.append(&mut self.digest.to_vec());
        to_ser.append(&mut self.randomness.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}
