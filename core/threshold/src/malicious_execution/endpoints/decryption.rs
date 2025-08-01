use crate::{
    algebra::{
        base_ring::Z128,
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Solve},
    },
    execution::{
        endpoints::{
            decryption::{
                OnlineNoiseFloodDecryption, SnsDecryptionKeyType, SnsRadixOrBoolCiphertext,
            },
            keygen::PrivateKeySet,
        },
        online::preprocessing::NoiseFloodPreprocessing,
        runtime::session::BaseSessionHandles,
    },
};

pub struct DroppingOnlineNoiseFloodDecryption;

#[tonic::async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineNoiseFloodDecryption<EXTENSION_DEGREE>
    for DroppingOnlineNoiseFloodDecryption
{
    async fn decrypt<
        S: BaseSessionHandles,
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + ?Sized,
        T,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
        _ciphertext: &SnsRadixOrBoolCiphertext,
        _ddec_key_type: SnsDecryptionKeyType,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
    {
        // No messages are sent in the online phase
        Ok(T::ZERO)
    }
}
