use std::sync::{Arc, Mutex};

use crate::{
    algebra::{
        base_ring::Z128,
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Solve},
    },
    execution::{
        endpoints::decryption::{
            OnlineNoiseFloodDecryption, SnsDecryptionKeyType, SnsRadixOrBoolCiphertext,
        },
        online::preprocessing::NoiseFloodPreprocessing,
        runtime::sessions::base_session::BaseSessionHandles,
        tfhe_internals::private_keysets::PrivateKeySet,
    },
};

pub struct DroppingOnlineNoiseFloodDecryption;

#[tonic::async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineNoiseFloodDecryption<EXTENSION_DEGREE>
    for DroppingOnlineNoiseFloodDecryption
{
    async fn decrypt<
        S: BaseSessionHandles,
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + 'static,
        T,
    >(
        _session: &mut S,
        _preprocessing: Arc<Mutex<P>>,
        _keyshares: Arc<PrivateKeySet<EXTENSION_DEGREE>>,
        _ciphertext: Arc<SnsRadixOrBoolCiphertext>,
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
