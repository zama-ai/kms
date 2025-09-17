use itertools::Itertools;
use tfhe::{
    core_crypto::prelude::ParallelByteRandomGenerator,
    shortint::server_key::{
        CompressedModulusSwitchNoiseReductionKey, ModulusSwitchNoiseReductionKey,
    },
};
use tracing::instrument;

use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect, Zero},
    },
    execution::{
        online::preprocessing::DKGPreprocessing,
        runtime::session::BaseSessionHandles,
        tfhe_internals::{
            lwe_ciphertext::{self, encrypt_lwe_ciphertext_list, LweCiphertextShare},
            lwe_key::LweSecretKeyShare,
            parameters::MSNRKParams,
            randomness::MPCEncryptionRandomGenerator,
        },
    },
};

/// Generate the modulus switching noise reduction key from the small LWE key.
/// This key is essentially encryptions of zeros, and it's used as a part of
/// the bootstrap algorithm if it exists, right before modulus switching.
#[instrument(name="Gen MSNRK",skip(input_lwe_sk, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub(crate) async fn generate_mod_switch_noise_reduction_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &MSNRKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<ModulusSwitchNoiseReductionKey<u64>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let output = generate_encrypted_zeros(
        input_lwe_sk,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )?;

    let opened_ciphertext_list = lwe_ciphertext::open_to_tfhers_type(output, session).await?;

    Ok(ModulusSwitchNoiseReductionKey {
        modulus_switch_zeros: opened_ciphertext_list,
        ms_bound: params.params.ms_bound,
        ms_r_sigma_factor: params.params.ms_r_sigma_factor,
        ms_input_variance: params.params.ms_input_variance,
    })
}

#[instrument(name="Gen Compressed MSNRK",skip(input_lwe_sk, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub(crate) async fn generate_compressed_mod_switch_noise_reduction_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &MSNRKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<CompressedModulusSwitchNoiseReductionKey<u64>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let output = generate_encrypted_zeros(
        input_lwe_sk,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )?;

    let opened_ciphertext_list =
        lwe_ciphertext::open_to_tfhers_seeded_type(output, seed, session).await?;

    Ok(CompressedModulusSwitchNoiseReductionKey {
        modulus_switch_zeros: opened_ciphertext_list,
        ms_bound: params.params.ms_bound,
        ms_r_sigma_factor: params.params.ms_r_sigma_factor,
        ms_input_variance: params.params.ms_input_variance,
    })
}

fn generate_encrypted_zeros<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &MSNRKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<Vec<LweCiphertextShare<Z, EXTENSION_DEGREE>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let my_role = session.my_role();
    tracing::info!("(Party {my_role}) Generating MSNRK...Start");
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(params.num_needed_noise, params.noise_bound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    let zeros_count = params.params.modulus_switch_zeros_count.0;
    let lwe_size = input_lwe_sk.lwe_dimension().to_lwe_size();
    let mut output = vec![LweCiphertextShare::new(lwe_size); zeros_count];
    let encoded = vec![ResiduePoly::<Z, EXTENSION_DEGREE>::ZERO; zeros_count];
    encrypt_lwe_ciphertext_list(input_lwe_sk, &mut output, &encoded, mpc_encryption_rng)?;

    Ok(output)
}
