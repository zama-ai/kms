use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect},
    },
    execution::{
        online::preprocessing::DKGPreprocessing,
        runtime::sessions::base_session::BaseSessionHandles,
        tfhe_internals::{
            lwe_key::LweSecretKeyShare,
            lwe_packing_keyswitch_key::LwePackingKeyswitchKeyShares,
            lwe_packing_keyswitch_key_generation::allocate_and_generate_lwe_packing_keyswitch_key,
            parameters::{DistributedSnsCompressionParameters, EncryptionType},
            randomness::MPCEncryptionRandomGenerator,
            sns_compression_key::SnsCompressionPrivateKeyShares,
        },
    },
};

use itertools::Itertools;
use tfhe::{
    core_crypto::prelude::ParallelByteRandomGenerator,
    shortint::list_compression::{
        CompressedNoiseSquashingCompressionKey, NoiseSquashingCompressionKey,
    },
};
use tracing::instrument;

async fn generate_sns_compression_key_shares<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    Gen: ParallelByteRandomGenerator,
    S: BaseSessionHandles,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share_sns_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &DistributedSnsCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    preprocessing: &mut P,
    session: &mut S,
) -> anyhow::Result<(
    SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    LwePackingKeyswitchKeyShares<Z, EXTENSION_DEGREE>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let private_sns_compression_key_shares =
        SnsCompressionPrivateKeyShares::new_from_preprocessing(
            params.raw_compression_parameters,
            preprocessing,
            params.pmax,
            session,
        )
        .await
        .inspect_err(|e| {
            tracing::error!("failed to generate private sns compression shares: {e}")
        })?;

    let noise_vec = preprocessing
        .next_noise_vec(params.ksk_num_noise, params.ksk_noisebound)
        .inspect_err(|e| {
            tracing::error!("failed to get noise vec for sns compression shares: {e}")
        })?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(noise_vec);

    let packing_key_switching_key_shares = allocate_and_generate_lwe_packing_keyswitch_key(
        glwe_secret_key_share_sns_as_lwe,
        &private_sns_compression_key_shares.post_packing_ks_key,
        params.raw_compression_parameters.packing_ks_base_log,
        params.raw_compression_parameters.packing_ks_level,
        EncryptionType::Bits128,
        mpc_encryption_rng,
    );

    Ok((
        private_sns_compression_key_shares,
        packing_key_switching_key_shares,
    ))
}

#[instrument(name="Gen Sns Compression Key", skip(glwe_secret_key_share_sns_as_lwe, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub(crate) async fn generate_sns_compression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share_sns_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: DistributedSnsCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(
    SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    NoiseSquashingCompressionKey,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let (private_sns_compression_key_shares, packing_key_switching_key_shares) =
        generate_sns_compression_key_shares(
            glwe_secret_key_share_sns_as_lwe,
            &params,
            mpc_encryption_rng,
            preprocessing,
            session,
        )
        .await?;

    let packing_key_switching_key = packing_key_switching_key_shares
        .open_to_tfhers_type::<u128, _>(session)
        .await
        .inspect_err(|e| tracing::error!("failed to open tfhers type u128: {e}"))?;

    let compression_key = NoiseSquashingCompressionKey::from_raw_parts(
        packing_key_switching_key,
        params.raw_compression_parameters.lwe_per_glwe,
    );
    Ok((private_sns_compression_key_shares, compression_key))
}

#[instrument(name="Gen compressed Sns Compression Key", skip(glwe_secret_key_share_sns_as_lwe, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub(crate) async fn generate_compressed_sns_compression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share_sns_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: DistributedSnsCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<(
    SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    CompressedNoiseSquashingCompressionKey,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let (private_sns_compression_key_shares, packing_key_switching_key_shares) =
        generate_sns_compression_key_shares(
            glwe_secret_key_share_sns_as_lwe,
            &params,
            mpc_encryption_rng,
            preprocessing,
            session,
        )
        .await?;

    let packing_key_switching_key = packing_key_switching_key_shares
        .open_to_tfhers_seeded_type::<u128, _>(seed, session)
        .await
        .inspect_err(|e| tracing::error!("failed to open tfhers type u128: {e}"))?;

    let compression_key = CompressedNoiseSquashingCompressionKey::from_raw_parts(
        packing_key_switching_key,
        params.raw_compression_parameters.lwe_per_glwe,
    );

    Ok((private_sns_compression_key_shares, compression_key))
}
