use std::{collections::HashMap, time::Duration};

use tfhe::core_crypto::prelude::LweKeyswitchKey;
use threshold_fhe::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Ring, Solve},
    },
    execution::{
        endpoints::{
            decryption::{LowLevelCiphertext, NoiseFloodPreparation, RadixOrBoolCiphertext},
            keygen::{FhePubKeySet, PrivateKeySet},
        },
        online::preprocessing::DKGPreprocessing,
        runtime::session::{
            BaseSession, BaseSessionHandles, ParameterHandles, SessionParameters, SmallSession,
        },
        tfhe_internals::parameters::DKGParams,
        zk::ceremony::{
            Ceremony, FinalizedInternalPublicParameter, InternalPublicParameter, SecureCeremony,
        },
    },
};

#[tonic::async_trait]
pub(crate) trait ThresholdCrsProtocol {
    async fn execute(
        session: &mut BaseSession,
        witness_dim: usize,
        max_num_pt_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter>;
}

pub(crate) struct RealThresholdCrsProtocol;

#[tonic::async_trait]
impl ThresholdCrsProtocol for RealThresholdCrsProtocol {
    async fn execute(
        session: &mut BaseSession,
        witness_dim: usize,
        max_num_pt_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter> {
        let real_ceremony = SecureCeremony::default();
        real_ceremony
            .execute::<Z64, _>(session, witness_dim, max_num_pt_bits)
            .await
    }
}

pub(crate) struct DummyThresholdCrsProtocol;

#[tonic::async_trait]
impl ThresholdCrsProtocol for DummyThresholdCrsProtocol {
    async fn execute(
        session: &mut BaseSession,
        _witness_dim: usize,
        _max_num_pt_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter> {
        // Dummy implementation, replace with actual logic
        Ok(FinalizedInternalPublicParameter {
            inner: InternalPublicParameter::default(),
            sid: session.session_id(),
        })
    }
}

trait ThresholdPublicDecryption {
    async fn decrypt_using_noiseflooding<P, T>(
        noiseflood_session: &mut P,
        server_key: &tfhe::integer::ServerKey,
        ck: &tfhe::integer::noise_squashing::NoiseSquashingKey,
        ct: LowLevelCiphertext,
        secret_key_share: &PrivateKeySet<4>,
    ) -> anyhow::Result<(HashMap<String, T>, std::time::Duration)>
    where
        P: NoiseFloodPreparation<4>,
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, 4>: ErrorCorrect + Invert + Solve;

    async fn secure_decrypt_using_bitdec<T>(
        session: &mut SmallSession<ResiduePoly<Z64, 4>>,
        ct: &RadixOrBoolCiphertext,
        secret_key_share: &PrivateKeySet<4>,
        ksk: &LweKeyswitchKey<Vec<u64>>,
    ) -> anyhow::Result<(HashMap<String, T>, Duration)>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, 4>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, 4>: ErrorCorrect + Invert + Solve;
}

trait ThresholdUserDecryption {
    async fn partial_decrypt_using_noiseflooding<P>(
        noiseflood_session: &mut P,
        server_key: &tfhe::integer::ServerKey,
        ck: &tfhe::integer::noise_squashing::NoiseSquashingKey,
        ct: LowLevelCiphertext,
        secret_key_share: &PrivateKeySet<4>,
    ) -> anyhow::Result<(HashMap<String, Vec<ResiduePoly<Z128, 4>>>, u32, Duration)>
    where
        P: NoiseFloodPreparation<4>,
        ResiduePoly<Z128, 4>: ErrorCorrect + Invert + Solve;

    async fn secure_partial_decrypt_using_bitdec(
        session: &mut SmallSession<ResiduePoly<Z64, 4>>,
        ct: &RadixOrBoolCiphertext,
        secret_key_share: &PrivateKeySet<4>,
        ksk: &LweKeyswitchKey<Vec<u64>>,
    ) -> anyhow::Result<(HashMap<String, Vec<ResiduePoly<Z64, 4>>>, Duration)>
    where
        ResiduePoly<Z128, 4>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, 4>: ErrorCorrect + Invert + Solve;
}

/*
trait ThresholdKeygen {
    async fn distributed_keygen_z128<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, 4>> + Send + ?Sized,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<4>)>
    where
        ResiduePoly<Z128, 4>: ErrorCorrect,
        ResiduePoly<Z64, 4>: Ring;

    async fn distributed_sns_compression_keygen_z128<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, 4>> + Send + ?Sized,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        glwe_secret_key_share_sns_as_lwe: &LweSecretKeyShare<Z128, 4>,
    ) -> anyhow::Result<(
        SnsCompressionPrivateKeyShares<Z128, 4>,
        NoiseSquashingCompressionKey,
    )>
    where
        ResiduePoly<Z128, 4>: ErrorCorrect;
}

*/
