use kms_grpc::kms::v1::CiphertextFormat;
use kms_grpc::kms::v1::TypedPlaintext;
use rand::CryptoRng;
use rand::RngCore;
use serde::Serialize;
use tfhe::FheTypes;
use threshold_fhe::hashing::DomainSep;

use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::cryptography::internal_crypto_types::PublicSigKey;
use crate::cryptography::internal_crypto_types::Signature;
use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;

use super::base::KmsFheKeyHandles;

pub trait BaseKms {
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        dsep: &DomainSep,
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()>;
    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<Signature>;
    fn get_serialized_verf_key(&self) -> Vec<u8>;
    fn digest<T: ?Sized + AsRef<[u8]>>(
        domain_separator: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<Vec<u8>>;
}
/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms: BaseKms {
    fn public_decrypt(
        keys: &KmsFheKeyHandles,
        ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
    ) -> anyhow::Result<TypedPlaintext>;
    #[allow(clippy::too_many_arguments)]
    fn user_decrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        ct_type: FheTypes,
        ct_format: CiphertextFormat,
        digest_link: &[u8],
        enc_key: &UnifiedPublicEncKey,
        client_address: &alloy_primitives::Address,
    ) -> anyhow::Result<Vec<u8>>;
}
