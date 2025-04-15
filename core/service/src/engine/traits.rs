use kms_grpc::kms::v1::CiphertextFormat;
use kms_grpc::kms::v1::TypedPlaintext;
use rand::CryptoRng;
use rand::RngCore;
use serde::Serialize;
use tfhe::FheTypes;

use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::cryptography::internal_crypto_types::PublicEncKey;
use crate::cryptography::internal_crypto_types::PublicSigKey;
use crate::cryptography::internal_crypto_types::Signature;

use super::base::KmsFheKeyHandles;

pub trait BaseKms {
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()>;
    fn sign<T: Serialize + AsRef<[u8]>>(&self, msg: &T) -> anyhow::Result<Signature>;
    fn get_serialized_verf_key(&self) -> Vec<u8>;
    fn digest<T: ?Sized + AsRef<[u8]>>(msg: &T) -> anyhow::Result<Vec<u8>>;
}
/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms: BaseKms {
    fn decrypt(
        keys: &KmsFheKeyHandles,
        ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
    ) -> anyhow::Result<TypedPlaintext>;
    #[allow(clippy::too_many_arguments)]
    fn reencrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        ct_type: FheTypes,
        ct_format: CiphertextFormat,
        digest_link: &[u8],
        enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
    ) -> anyhow::Result<Vec<u8>>;
}
