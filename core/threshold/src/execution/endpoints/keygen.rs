use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::structure_traits::Zero;
use crate::execution::online::preprocessing::{DKGPreprocessing, RandomPreprocessing};
use crate::execution::tfhe_internals::compression_decompression_key::{
    CompressionPrivateKeyShares, SnsCompressionPrivateKeyShares,
};
use crate::execution::tfhe_internals::lwe_bootstrap_key::par_decompress_into_lwe_bootstrap_key_generated_from_xof;
use crate::execution::tfhe_internals::lwe_ciphertext::{
    self, encrypt_lwe_ciphertext_list, LweCiphertextShare,
};
use crate::execution::tfhe_internals::lwe_key::LweCompactPublicKeyShare;
use crate::execution::tfhe_internals::lwe_keyswitch_key::LweKeySwitchKeyShare;
use crate::execution::tfhe_internals::lwe_packing_keyswitch_key_generation::allocate_and_generate_lwe_packing_keyswitch_key;
use crate::execution::tfhe_internals::parameters::{
    BKParams, DKGParams, DistributedCompressionParameters, DistributedSnsCompressionParameters,
    EncryptionType, KSKParams, MSNRKConfiguration, MSNRKParams, NoiseInfo,
};
use crate::execution::tfhe_internals::private_keysets::{GenericPrivateKeySet, PrivateKeySet};
use crate::execution::tfhe_internals::public_keysets::{
    CompressedFhePubKeySet, FhePubKeySet, RawCompressedPubKeySet, RawPubKeySet,
};
use crate::hashing::DomainSep;
use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect, Ring},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::triple::open_list,
        runtime::session::BaseSessionHandles,
        tfhe_internals::{
            glwe_key::GlweSecretKeyShare,
            lwe_bootstrap_key_generation::allocate_and_generate_lwe_bootstrap_key,
            lwe_key::{allocate_and_generate_new_lwe_compact_public_key, LweSecretKeyShare},
            lwe_keyswitch_key_generation::allocate_and_generate_new_lwe_keyswitch_key,
            lwe_packing_keyswitch_key::LwePackingKeyswitchKeyShares,
            randomness::MPCEncryptionRandomGenerator,
        },
    },
};
use itertools::Itertools;
use num_integer::div_ceil;
use tfhe::core_crypto::commons::traits::UnsignedInteger;
use tfhe::core_crypto::prelude::{
    SeededLweBootstrapKey, SeededLweCompactPublicKey, SeededLweKeyswitchKey,
};
use tfhe::core_crypto::{
    algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier,
    entities::{FourierLweBootstrapKey, LweBootstrapKey, LweCompactPublicKey, LweKeyswitchKey},
    prelude::ByteRandomGenerator,
};
use tfhe::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressedNoiseSquashingCompressionKey,
    CompressionKey, DecompressionKey, NoiseSquashingCompressionKey,
};
use tfhe::shortint::parameters::LweCiphertextCount;
use tfhe::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey, ShortintBootstrappingKey,
};
use tfhe::shortint::ClassicPBSParameters;
use tfhe_csprng::generators::SoftwareRandomGenerator;
use tfhe_csprng::seeders::XofSeed;
use tracing::instrument;

pub(crate) const DSEP_KG: DomainSep = *b"TFHE_GEN";

///Sample the random but public seed
async fn sample_seed<
    Z: Ring + ErrorCorrect,
    P: RandomPreprocessing<Z> + ?Sized,
    S: BaseSessionHandles,
>(
    sec: u64,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<u128> {
    //NOTE: next_random_vec samples uniformly from Z[X]/F(X)
    //(as required by the ideal functional Fig.94).
    let num_seeds = div_ceil(sec, Z::BIT_LENGTH as u64) as usize;
    let shared_seeds = preprocessing.next_random_vec(num_seeds)?;
    let seeds = open_list(&shared_seeds, session).await?;
    //Turn the random element in Z[X]/F(X) to random params.sec bits
    Ok(seeds
        .iter()
        .flat_map(Z::to_byte_vec)
        .take((sec as usize) >> 3)
        .fold(0_u128, |acc, x| (acc << 8) + (x as u128)))
}

///Generates the lwe private key share and associated public key
fn generate_lwe_key_shares<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(
    LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    LweCompactPublicKeyShare<Z, EXTENSION_DEGREE>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params = params.get_params_basics_handle();
    let my_role = session.my_role();
    //Init the shared LWE secret key
    tracing::info!("(Party {my_role}) Generating LWE Secret key...Start");
    let lwe_secret_key_share =
        LweSecretKeyShare::new_from_preprocessing(params.lwe_hat_dimension(), preprocessing)?;
    tracing::info!("(Party {my_role}) Generating corresponding public key...Start");
    let NoiseInfo { amount, bound } = params.num_needed_noise_pk();
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(amount, bound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    //and fill the noise generator with noise generated above
    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    //Then actually generate the public key
    let lwe_public_key_shared =
        allocate_and_generate_new_lwe_compact_public_key(&lwe_secret_key_share, mpc_encryption_rng);

    Ok((lwe_secret_key_share, lwe_public_key_shared))
}

///Generates the lwe private key share and associated public key
#[instrument(name="Gen Lwe keys",skip( mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_lwe_private_public_key_pair<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(
    LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    LweCompactPublicKey<Vec<u64>>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let (lwe_secret_key_share, lwe_public_key_shared) =
        generate_lwe_key_shares(params, mpc_encryption_rng, session, preprocessing)?;

    //Open the public key and cast it to TFHE-RS type
    Ok((
        lwe_secret_key_share,
        lwe_public_key_shared.open_to_tfhers_type(session).await?,
    ))
}

///Generates the lwe private key share and associated public key
#[instrument(name="Gen Lwe keys",skip( mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_lwe_private_compressed_public_key_pair<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<(
    LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    SeededLweCompactPublicKey<Vec<u64>>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let (lwe_secret_key_share, lwe_public_key_shared) =
        generate_lwe_key_shares(params, mpc_encryption_rng, session, preprocessing)?;

    //Open the public key and cast it to TFHE-RS type
    Ok((
        lwe_secret_key_share,
        lwe_public_key_shared
            .open_to_tfhers_seeded_type(seed, session)
            .await?,
    ))
}

/// Generate the modulus switching noise reduction key from the small LWE key.
/// This key is essentially encryptions of zeros, and it's used as a part of
/// the bootstrap algorithm if it exists, right before modulus switching.
#[instrument(name="Gen MSNRK",skip(input_lwe_sk, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_mod_switch_noise_reduction_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
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

#[instrument(name="Gen Compressed MSNRK",skip(input_lwe_sk, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compressed_mod_switch_noise_reduction_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
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
    Gen: ByteRandomGenerator,
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

/// Generate KSK shares using MPC encryption
fn generate_ksk_share<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &KSKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweKeySwitchKeyShare<Z, EXTENSION_DEGREE>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let my_role = session.my_role();
    tracing::info!("(Party {my_role}) Generating KSK...Start");
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(params.num_needed_noise, params.noise_bound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    //Then compute the KSK
    allocate_and_generate_new_lwe_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        params.decomposition_base_log,
        params.decomposition_level_count,
        mpc_encryption_rng,
    )
}

///Generate the Key Switch Key from a Glwe key given in Lwe format,
///and an actual Lwe key
#[instrument(name="Gen KSK",skip(input_lwe_sk, output_lwe_sk, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_key_switch_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &KSKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweKeyswitchKey<Vec<u64>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let ksk_share = generate_ksk_share(
        input_lwe_sk,
        output_lwe_sk,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )?;

    //Open the KSK and cast it to TFHE-RS type
    ksk_share.open_to_tfhers_type(session).await
}

///Generate the Key Switch Key from a Glwe key given in Lwe format,
///and an actual Lwe key
#[instrument(name="Gen compressed KSK",skip(input_lwe_sk, output_lwe_sk, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compressed_key_switch_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &KSKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<SeededLweKeyswitchKey<Vec<u64>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let ksk_share = generate_ksk_share(
        input_lwe_sk,
        output_lwe_sk,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )?;

    //Open the KSK and cast it to TFHE-RS seeded type
    ksk_share.open_to_tfhers_seeded_type(seed, session).await
}

///Helper function to generate bootstrap key share
async fn generate_bootstrap_key_share<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    lwe_secret_key_share: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &BKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<
    crate::execution::tfhe_internals::lwe_bootstrap_key::LweBootstrapKeyShare<Z, EXTENSION_DEGREE>,
>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let my_role = session.my_role();
    //First sample the noise
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(params.num_needed_noise, params.noise_bound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    tracing::info!("(Party {my_role}) Generating BK for {:?} ...Start", params);

    let bk_share = allocate_and_generate_lwe_bootstrap_key(
        lwe_secret_key_share,
        glwe_secret_key_share,
        params.decomposition_base_log,
        params.decomposition_level_count,
        mpc_encryption_rng,
        params.enc_type,
        session,
        preprocessing,
    )
    .await?;

    tracing::info!("(Party {my_role}) Generating BK {:?} ...Done", params);
    Ok(bk_share)
}

///Generates a Bootstrapping Key given a Glwe key in Glwe format
///, a Lwe key and the params for the BK generation
#[instrument(name="Gen BK", skip(glwe_secret_key_share, lwe_secret_key_share, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_bootstrap_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    Scalar: UnsignedInteger,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    lwe_secret_key_share: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: BKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweBootstrapKey<Vec<Scalar>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let my_role = session.my_role();
    let bk_share = generate_bootstrap_key_share(
        glwe_secret_key_share,
        lwe_secret_key_share,
        &params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    tracing::info!("(Party {my_role}) Opening BK {:?} ...Start", params);
    //Open the bk and cast it to TFHE-rs type
    let bk = bk_share.open_to_tfhers_type::<Scalar, _>(session).await?;
    tracing::info!("(Party {my_role}) Opening BK {:?} ...Done", params);
    Ok(bk)
}

///Generates a Bootstrapping Key given a Glwe key in Glwe format
///, a Lwe key and the params for the BK generation
#[instrument(name="Gen compressed BK", skip(glwe_secret_key_share, lwe_secret_key_share, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compressed_bootstrap_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    Scalar: UnsignedInteger,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    lwe_secret_key_share: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: BKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<SeededLweBootstrapKey<Vec<Scalar>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let my_role = session.my_role();
    let bk_share = generate_bootstrap_key_share(
        glwe_secret_key_share,
        lwe_secret_key_share,
        &params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    tracing::info!("(Party {my_role}) Opening BK {:?} ...Start", params);
    //Open the bk and cast it to TFHE-rs type
    let bk = bk_share
        .open_to_tfhers_seeded_type::<Scalar, _>(seed, session)
        .await?;
    tracing::info!("(Party {my_role}) Opening BK {:?} ...Done", params);
    Ok(bk)
}

#[instrument(name="Gen Decompression Key", skip(private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<DecompressionKey>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let blind_rotate_key: LweBootstrapKey<Vec<u64>> = generate_bootstrap_key(
        private_glwe_compute_key,
        &private_compression_key.clone().into_lwe_secret_key(),
        params.bk_params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    // Creation of the bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        blind_rotate_key.input_lwe_dimension(),
        blind_rotate_key.glwe_size(),
        blind_rotate_key.polynomial_size(),
        blind_rotate_key.decomposition_base_log(),
        blind_rotate_key.decomposition_level_count(),
    );

    // Conversion to fourier domain
    par_convert_standard_lwe_bootstrap_key_to_fourier(&blind_rotate_key, &mut fourier_bsk);

    // TODO implement `modulus_switch_noise_reduction_key` keygen
    let blind_rotate_key = ShortintBootstrappingKey::Classic {
        bsk: fourier_bsk,
        // NOTE: Not sure if it should be standard or CenteredMean
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration::Standard,
    };

    Ok(DecompressionKey {
        blind_rotate_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
    })
}

#[instrument(name="Gen compressed Decompression Key", skip(private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compressed_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<CompressedDecompressionKey>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let blind_rotate_key: SeededLweBootstrapKey<Vec<u64>> = generate_compressed_bootstrap_key(
        private_glwe_compute_key,
        &private_compression_key.clone().into_lwe_secret_key(),
        params.bk_params,
        mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await?;

    Ok(CompressedDecompressionKey {
        blind_rotate_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
    })
}

fn generate_sns_compression_key_shares<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share_sns_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &DistributedSnsCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    preprocessing: &mut P,
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
        )
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

async fn generate_sns_compression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
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
        )?;

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

async fn generate_compressed_sns_compression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
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
        )?;

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

/// Helper function to generate packing key switching key shares
/// for use in Compression key.
fn generate_packing_key_switching_key_shares<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: &DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    preprocessing: &mut P,
) -> anyhow::Result<LwePackingKeyswitchKeyShares<Z, EXTENSION_DEGREE>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let noise_vec = preprocessing
        .next_noise_vec(params.ksk_num_noise, params.ksk_noisebound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(noise_vec);

    Ok(allocate_and_generate_lwe_packing_keyswitch_key(
        private_glwe_compute_key_as_lwe,
        &private_compression_key.post_packing_ks_key,
        params.raw_compression_parameters.packing_ks_base_log,
        params.raw_compression_parameters.packing_ks_level,
        EncryptionType::Bits64,
        mpc_encryption_rng,
    ))
}

#[instrument(name="Gen Compression and Decompression Key", skip(private_glwe_compute_key_as_lwe, private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compression_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_glwe_compute_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(CompressionKey, DecompressionKey)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let packing_key_switching_key_shares = generate_packing_key_switching_key_shares(
        private_glwe_compute_key_as_lwe,
        private_compression_key,
        &params,
        mpc_encryption_rng,
        preprocessing,
    )?;

    let packing_key_switching_key = packing_key_switching_key_shares
        .open_to_tfhers_type::<u64, _>(session)
        .await?;

    let compression_key = CompressionKey {
        packing_key_switching_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
        storage_log_modulus: params.raw_compression_parameters.storage_log_modulus,
    };

    let decompression_key = generate_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    Ok((compression_key, decompression_key))
}

/// Note that in the return value, it is possible for [CompressionPrivateKeyShares] to be None
/// while [CompressionKey], [DecompressionKey] exists because we do not copy the secret shares again.
async fn distributed_keygen_compression_material<
    Z: BaseRing,
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >,
    glwe_sk_share_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    glwe_secret_key_share_compression: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<(
    Option<CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    Option<(CompressionKey, DecompressionKey)>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();

    let compression_material = if let Some(comp_params) =
        params_basics_handle.get_compression_decompression_params()
    {
        match glwe_secret_key_share_compression {
            Some(inner) => {
                let compression_keys = generate_compression_decompression_keys(
                    glwe_sk_share_as_lwe,
                    glwe_secret_key_share,
                    inner,
                    comp_params,
                    mpc_encryption_rng,
                    session,
                    preprocessing,
                )
                .await?;
                (None, Some(compression_keys))
            }
            None => {
                let private_compression_key = CompressionPrivateKeyShares::new_from_preprocessing(
                    comp_params.raw_compression_parameters,
                    preprocessing,
                )?;

                let compression_keys = generate_compression_decompression_keys(
                    glwe_sk_share_as_lwe,
                    glwe_secret_key_share,
                    &private_compression_key,
                    comp_params,
                    mpc_encryption_rng,
                    session,
                    preprocessing,
                )
                .await?;
                (Some(private_compression_key), Some(compression_keys))
            }
        }
    } else {
        (None, None)
    };
    Ok(compression_material)
}

#[allow(clippy::too_many_arguments)]
#[instrument(name="Gen compressed Compression and Decompression Key", skip(private_glwe_compute_key_as_lwe, private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compressed_compression_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_glwe_compute_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
    seed: u128,
) -> anyhow::Result<(CompressedCompressionKey, CompressedDecompressionKey)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let packing_key_switching_key_shares = generate_packing_key_switching_key_shares(
        private_glwe_compute_key_as_lwe,
        private_compression_key,
        &params,
        mpc_encryption_rng,
        preprocessing,
    )?;

    let packing_key_switching_key = packing_key_switching_key_shares
        .open_to_tfhers_seeded_type::<u64, _>(seed, session)
        .await?;

    let compression_key = CompressedCompressionKey {
        packing_key_switching_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
        storage_log_modulus: params.raw_compression_parameters.storage_log_modulus,
    };

    let decompression_key = generate_compressed_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await?;

    Ok((compression_key, decompression_key))
}

#[allow(clippy::too_many_arguments)]
/// Note that in the return value, it is possible for [CompressionPrivateKeyShares] to be None
/// while [CompressionKey], [DecompressionKey] exists because we do not copy the secret shares again.
async fn distributed_keygen_compressed_compression_material<
    Z: BaseRing,
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >,
    glwe_sk_share_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    glwe_secret_key_share_compression: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    seed: u128,
) -> anyhow::Result<(
    Option<CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    Option<(CompressedCompressionKey, CompressedDecompressionKey)>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();

    let compression_material = if let Some(comp_params) =
        params_basics_handle.get_compression_decompression_params()
    {
        match glwe_secret_key_share_compression {
            Some(inner) => {
                let compression_keys = generate_compressed_compression_decompression_keys(
                    glwe_sk_share_as_lwe,
                    glwe_secret_key_share,
                    inner,
                    comp_params,
                    mpc_encryption_rng,
                    session,
                    preprocessing,
                    seed,
                )
                .await?;
                (None, Some(compression_keys))
            }
            None => {
                let private_compression_key = CompressionPrivateKeyShares::new_from_preprocessing(
                    comp_params.raw_compression_parameters,
                    preprocessing,
                )?;

                let compression_keys = generate_compressed_compression_decompression_keys(
                    glwe_sk_share_as_lwe,
                    glwe_secret_key_share,
                    &private_compression_key,
                    comp_params,
                    mpc_encryption_rng,
                    session,
                    preprocessing,
                    seed,
                )
                .await?;
                (Some(private_compression_key), Some(compression_keys))
            }
        }
    } else {
        (None, None)
    };
    Ok(compression_material)
}

trait Finalizable<const EXTENSION_DEGREE: usize> {
    /// Finalizes the keyset by converting it to a `PrivateKeySet`.
    ///
    /// This method is used to convert the generic private key set into a concrete
    /// `PrivateKeySet` with the given parameters.
    ///
    /// Inputs:
    /// - `self`: The generic private key set to finalize.
    /// - `parameters`: The parameters for the classic PBS.
    ///
    /// Outputs:
    /// - A finalized `PrivateKeySet`.
    fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet<EXTENSION_DEGREE>;
}

impl<const EXTENSION_DEGREE: usize> Finalizable<EXTENSION_DEGREE>
    for GenericPrivateKeySet<Z128, EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet<EXTENSION_DEGREE> {
        self.finalize_keyset(parameters)
    }
}

impl<const EXTENSION_DEGREE: usize> Finalizable<EXTENSION_DEGREE>
    for GenericPrivateKeySet<Z64, EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet<EXTENSION_DEGREE> {
        self.finalize_keyset(parameters)
    }
}

/// Trait for generic online distributed key generation.
/// It is used for testing since the return types are generic private types.
/// For public use, the [OnlineDistributedKeyGen128] trait should be used instead.
#[tonic::async_trait]
pub trait OnlineDistributedKeyGen<Z>: Send + Sync {
    /// Runs the distributed key generation protocol.
    ///
    /// We have a private trait bound here to ensure that the
    /// an internal type implements a private trait Finalizable.
    #[allow(private_bounds)]
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
        const EXTENSION_DEGREE: usize,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        Z: BaseRing,
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>;

    // NOTE: This can not be used or tested yet as we are waiting for tfhe-rs
    // next release to be able to decompress the keys generated here.
    // see https://github.com/zama-ai/kms/pull/40

    /// Runs the distributed key generation protocol.
    ///
    /// We have a private trait bound here to ensure that the
    /// an internal type implements a private trait Finalizable.
    #[allow(private_bounds)]
    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
        const EXTENSION_DEGREE: usize,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(CompressedFhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        Z: BaseRing,
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>;
}

pub type SecureOnlineDistributedKeyGen128 = SecureOnlineDistributedKeyGen<Z128>;

pub struct SecureOnlineDistributedKeyGen<Z: BaseRing>(std::marker::PhantomData<Z>);

#[tonic::async_trait]
impl<Z: BaseRing> OnlineDistributedKeyGen<Z> for SecureOnlineDistributedKeyGen<Z> {
    /// Runs the distributed key generation protocol.
    ///
    /// Inputs:
    /// - `session`: the session that holds necessary information for networking
    /// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
    /// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
    ///
    /// Outputs:
    /// - A [`RawPubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
    /// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
    ///
    /// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
    /// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
    #[instrument(name="TFHE.Threshold-KeyGen", skip(session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
    #[allow(private_bounds)]
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
        const EXTENSION_DEGREE: usize,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>,
    {
        if Z::BIT_LENGTH == 64 {
            if let DKGParams::WithSnS(_) = params {
                return Err(anyhow_error_and_log(
                    "Can not generate Switch and Squash key with ResiduePolyF8Z64".to_string(),
                ));
            }
        }

        let (pub_key_set, priv_key_set) = distributed_keygen_from_optional_compression_sk(
            session,
            preprocessing,
            params,
            existing_compression_sk,
        )
        .await?;
        Ok((
            pub_key_set.to_pubkeyset(params),
            priv_key_set.finalize_keyset(
                params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
            ),
        ))
    }

    #[instrument(name="TFHE.Threshold-CompressedKeyGen", skip(session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
    #[allow(private_bounds)]
    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
        const EXTENSION_DEGREE: usize,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(CompressedFhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>,
    {
        if Z::BIT_LENGTH == 64 {
            if let DKGParams::WithSnS(_) = params {
                return Err(anyhow_error_and_log(
                    "Can not generate Switch and Squash key with ResiduePolyF8Z64".to_string(),
                ));
            }
        }

        let (pub_key_set, priv_key_set) =
            distributed_keygen_compressed_from_optional_compression_sk(
                session,
                preprocessing,
                params,
                existing_compression_sk,
            )
            .await?;
        Ok((
            pub_key_set.to_compressed_pubkeyset(params),
            priv_key_set.finalize_keyset(
                params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
            ),
        ))
    }
}

/// Runs the distributed key generation protocol but optionally
/// uses an existing compression secret key.
///
/// Inputs:
/// - `session`: the session that holds necessary information for networking
/// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
/// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
/// - `existing_compression_sk`: an optional compression secret key,
///   a new one is generated if this argument is None.
///
/// Outputs:
/// - A [`RawPubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
/// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
///
/// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
/// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
async fn distributed_keygen_from_optional_compression_sk<
    Z: BaseRing,
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<(RawPubKeySet, GenericPrivateKeySet<Z, EXTENSION_DEGREE>)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let my_role = session.my_role();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    //Generate the shared LWE hat secret key and corresponding public key
    let (lwe_hat_secret_key_share, lwe_public_key) = generate_lwe_private_public_key_pair(
        &params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    //Generate the LWE (no hat) secret key if it should exist
    let lwe_secret_key_share = if params_basics_handle.has_dedicated_compact_pk_params() {
        LweSecretKeyShare::new_from_preprocessing(
            params_basics_handle.lwe_dimension(),
            preprocessing,
        )?
    } else {
        lwe_hat_secret_key_share.clone()
    };

    tracing::info!("(Party {my_role}) Generating corresponding public key...Done");

    //Generate the GLWE secret key
    tracing::info!("(Party {my_role}) Generating GLWE secret key...Start");
    let glwe_secret_key_share = GlweSecretKeyShare::new_from_preprocessing(
        params_basics_handle.glwe_sk_num_bits(),
        params_basics_handle.polynomial_size(),
        preprocessing,
    )?;

    let glwe_sk_share_as_lwe = glwe_secret_key_share.clone().into_lwe_secret_key();

    tracing::info!("(Party {my_role}) Generating GLWE secret key...Done");

    //Generate the compression keys if needed
    //Generate the compression keys, we'll have None if there are no
    //compression materials to generate
    let compression_material = distributed_keygen_compression_material(
        session,
        preprocessing,
        params,
        &mut mpc_encryption_rng,
        &glwe_sk_share_as_lwe,
        &glwe_secret_key_share,
        existing_compression_sk,
    )
    .await?;

    //Generate the KSK
    let ksk_params = params_basics_handle.get_ksk_params();

    let ksk = generate_key_switch_key(
        &glwe_sk_share_as_lwe,
        &lwe_secret_key_share,
        &ksk_params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;
    tracing::info!("(Party {my_role}) Generating KSK...Done");

    //Computing and opening BK can take a while, so we increase the timeout
    session.network().set_timeout_for_bk()?;
    //Compute the bootstrapping keys
    let bk = generate_bootstrap_key(
        &glwe_secret_key_share,
        &lwe_secret_key_share,
        params_basics_handle.get_bk_params(),
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    //If needed, compute the SnS BK
    let (glwe_secret_key_share_sns, bk_sns, msnrk_sns) = match params {
        DKGParams::WithSnS(sns_params) => {
            tracing::info!("(Party {my_role}) Generating SnS GLWE...Start");
            //compute the SnS GLWE key
            let glwe_secret_key_share_sns = GlweSecretKeyShare::new_from_preprocessing(
                sns_params.glwe_sk_num_bits_sns(),
                sns_params.polynomial_size_sns(),
                preprocessing,
            )?;

            //Computing and opening BK SNS can take a while, so we increase the timeout
            session.network().set_timeout_for_bk_sns()?;

            tracing::info!("(Party {my_role}) Generating SnS GLWE...Done");
            let bk_sns = generate_bootstrap_key(
                &glwe_secret_key_share_sns,
                &lwe_secret_key_share,
                sns_params.get_bk_sns_params(),
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?;

            let msnrk_sns = match sns_params.get_msnrk_configuration_sns() {
                MSNRKConfiguration::Standard => ModulusSwitchConfiguration::Standard,
                MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        generate_mod_switch_noise_reduction_key(
                            &lwe_secret_key_share,
                            &msnrkparams,
                            &mut mpc_encryption_rng,
                            session,
                            preprocessing,
                        )
                        .await?,
                    )
                }
                MSNRKConfiguration::CenteredMeanNoiseReduction => {
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction
                }
            };

            tracing::info!("(Party {my_role}) Opening SnS BK...Done");
            (
                Some(glwe_secret_key_share_sns),
                Some(bk_sns),
                Some(msnrk_sns),
            )
        }
        DKGParams::WithoutSnS(_) => (None, None, None),
    };

    //Compute the PKSK
    let pksk = match (
        params_basics_handle.get_pksk_destination(),
        params_basics_handle.get_pksk_params(),
    ) {
        //Corresponds to type = F-GLWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Big), Some(pksk_params)) => Some(
            generate_key_switch_key(
                &lwe_hat_secret_key_share,
                &glwe_sk_share_as_lwe,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?,
        ),

        //Corresponds to type = LWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Small), Some(pksk_params)) => Some(
            generate_key_switch_key(
                &lwe_hat_secret_key_share,
                &lwe_secret_key_share,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?,
        ),
        (None, None) => None,
        _ => {
            tracing::error!("Incompatible parameters regarding pksk, can not generate it.");
            None
        }
    };

    // If needed, compute the mod switch noise reduction key
    let msnrk = match params_basics_handle.get_msnrk_configuration() {
        MSNRKConfiguration::Standard => ModulusSwitchConfiguration::Standard,
        MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                generate_mod_switch_noise_reduction_key(
                    &lwe_secret_key_share,
                    &msnrkparams,
                    &mut mpc_encryption_rng,
                    session,
                    preprocessing,
                )
                .await?,
            )
        }
        MSNRKConfiguration::CenteredMeanNoiseReduction => {
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
    };

    // note that glwe_secret_key_share_compression may be None even if compression_keys is Some
    // this is because we might have generated the compression keys from an existing compression sk share
    let (glwe_secret_key_share_compression, compression_keys) = compression_material;

    // If needed, compute the sns compression keys
    let sns_compression_materials =
        match (params, params_basics_handle.get_sns_compression_params()) {
            (DKGParams::WithSnS(_), Some(comp_params)) => {
                let (private_sns_compression_key, sns_compression_key) =
                    generate_sns_compression_keys(
                        &glwe_secret_key_share_sns
                            .clone()
                            .map(|key| key.into_lwe_secret_key())
                            .unwrap(),
                        comp_params,
                        &mut mpc_encryption_rng,
                        session,
                        preprocessing,
                    )
                    .await?;

                Some((private_sns_compression_key, sns_compression_key))
            }
            _ => None,
        };

    let (glwe_secret_key_share_sns_compression, sns_compression_key) =
        match sns_compression_materials {
            Some((private_sns_compression_key, sns_compression_key)) => {
                (Some(private_sns_compression_key), Some(sns_compression_key))
            }
            None => (None, None),
        };

    let pub_key_set = RawPubKeySet {
        lwe_public_key,
        ksk,
        pksk,
        bk,
        bk_sns,
        compression_keys,
        msnrk,
        msnrk_sns,
        seed,
        sns_compression_key,
    };

    let priv_key_set = GenericPrivateKeySet {
        lwe_encryption_secret_key_share: lwe_hat_secret_key_share,
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns,
        glwe_secret_key_share_compression,
        glwe_secret_key_share_sns_compression,
    };

    Ok((pub_key_set, priv_key_set))
}

/// Runs the distributed key generation protocol but optionally
/// uses an existing compression secret key.
///
/// Inputs:
/// - `session`: the session that holds necessary information for networking
/// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
/// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
/// - `existing_compression_sk`: an optional compression secret key,
///   a new one is generated if this argument is None.
///
/// Outputs:
/// - A [`RawPubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
/// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
///
/// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
/// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
async fn distributed_keygen_compressed_from_optional_compression_sk<
    Z: BaseRing,
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<(
    RawCompressedPubKeySet,
    GenericPrivateKeySet<Z, EXTENSION_DEGREE>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let my_role = session.my_role();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    //Generate the shared LWE hat secret key and corresponding public key
    let (lwe_hat_secret_key_share, lwe_public_key) =
        generate_lwe_private_compressed_public_key_pair(
            &params,
            &mut mpc_encryption_rng,
            session,
            preprocessing,
            seed,
        )
        .await?;

    //Generate the LWE (no hat) secret key if it should exist
    let lwe_secret_key_share = if params_basics_handle.has_dedicated_compact_pk_params() {
        LweSecretKeyShare::new_from_preprocessing(
            params_basics_handle.lwe_dimension(),
            preprocessing,
        )?
    } else {
        lwe_hat_secret_key_share.clone()
    };

    tracing::info!("(Party {my_role}) Generating corresponding public key...Done");

    //Generate the GLWE secret key
    tracing::info!("(Party {my_role}) Generating GLWE secret key...Start");
    let glwe_secret_key_share = GlweSecretKeyShare::new_from_preprocessing(
        params_basics_handle.glwe_sk_num_bits(),
        params_basics_handle.polynomial_size(),
        preprocessing,
    )?;

    let glwe_sk_share_as_lwe = glwe_secret_key_share.clone().into_lwe_secret_key();

    tracing::info!("(Party {my_role}) Generating GLWE secret key...Done");

    //Generate the compression keys if needed
    //Generate the compression keys, we'll have None if there are no
    //compression materials to generate
    let compression_material = distributed_keygen_compressed_compression_material(
        session,
        preprocessing,
        params,
        &mut mpc_encryption_rng,
        &glwe_sk_share_as_lwe,
        &glwe_secret_key_share,
        existing_compression_sk,
        seed,
    )
    .await?;

    //Generate the KSK
    let ksk_params = params_basics_handle.get_ksk_params();

    let ksk = generate_compressed_key_switch_key(
        &glwe_sk_share_as_lwe,
        &lwe_secret_key_share,
        &ksk_params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await?;
    tracing::info!("(Party {my_role}) Generating KSK...Done");

    //Computing and opening BK can take a while, so we increase the timeout
    session.network().set_timeout_for_bk()?;
    //Compute the bootstrapping keys
    let bk = generate_compressed_bootstrap_key(
        &glwe_secret_key_share,
        &lwe_secret_key_share,
        params_basics_handle.get_bk_params(),
        &mut mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await?;

    //If needed, compute the SnS BK
    let (glwe_secret_key_share_sns, bk_sns, msnrk_sns) = match params {
        DKGParams::WithSnS(sns_params) => {
            tracing::info!("(Party {my_role}) Generating SnS GLWE...Start");
            //compute the SnS GLWE key
            let glwe_secret_key_share_sns = GlweSecretKeyShare::new_from_preprocessing(
                sns_params.glwe_sk_num_bits_sns(),
                sns_params.polynomial_size_sns(),
                preprocessing,
            )?;

            //Computing and opening BK SNS can take a while, so we increase the timeout
            session.network().set_timeout_for_bk_sns()?;

            tracing::info!("(Party {my_role}) Generating SnS GLWE...Done");
            let bk_sns = generate_compressed_bootstrap_key(
                &glwe_secret_key_share_sns,
                &lwe_secret_key_share,
                sns_params.get_bk_sns_params(),
                &mut mpc_encryption_rng,
                session,
                preprocessing,
                seed,
            )
            .await?;

            let msnrk_sns = match sns_params.get_msnrk_configuration_sns() {
                MSNRKConfiguration::Standard => CompressedModulusSwitchConfiguration::Standard,
                MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
                    CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        generate_compressed_mod_switch_noise_reduction_key(
                            &lwe_secret_key_share,
                            &msnrkparams,
                            &mut mpc_encryption_rng,
                            session,
                            preprocessing,
                            seed,
                        )
                        .await?,
                    )
                }
                MSNRKConfiguration::CenteredMeanNoiseReduction => {
                    CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction
                }
            };

            tracing::info!("(Party {my_role}) Opening SnS BK...Done");
            (
                Some(glwe_secret_key_share_sns),
                Some(bk_sns),
                Some(msnrk_sns),
            )
        }
        DKGParams::WithoutSnS(_) => (None, None, None),
    };

    //Compute the PKSK
    let pksk = match (
        params_basics_handle.get_pksk_destination(),
        params_basics_handle.get_pksk_params(),
    ) {
        //Corresponds to type = F-GLWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Big), Some(pksk_params)) => Some(
            generate_compressed_key_switch_key(
                &lwe_hat_secret_key_share,
                &glwe_sk_share_as_lwe,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
                seed,
            )
            .await?,
        ),

        //Corresponds to type = LWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Small), Some(pksk_params)) => Some(
            generate_compressed_key_switch_key(
                &lwe_hat_secret_key_share,
                &lwe_secret_key_share,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
                seed,
            )
            .await?,
        ),
        (None, None) => None,
        _ => {
            tracing::error!("Incompatible parameters regarding pksk, can not generate it.");
            None
        }
    };

    // If needed, compute the mod switch noise reduction key
    let msnrk = match params_basics_handle.get_msnrk_configuration() {
        MSNRKConfiguration::Standard => CompressedModulusSwitchConfiguration::Standard,
        MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
            CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                generate_compressed_mod_switch_noise_reduction_key(
                    &lwe_secret_key_share,
                    &msnrkparams,
                    &mut mpc_encryption_rng,
                    session,
                    preprocessing,
                    seed,
                )
                .await?,
            )
        }
        MSNRKConfiguration::CenteredMeanNoiseReduction => {
            CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
    };

    // note that glwe_secret_key_share_compression may be None even if compression_keys is Some
    // this is because we might have generated the compression keys from an existing compression sk share
    let (glwe_secret_key_share_compression, compression_keys) = compression_material;

    // If needed, compute the sns compression keys
    let sns_compression_materials =
        match (params, params_basics_handle.get_sns_compression_params()) {
            (DKGParams::WithSnS(_), Some(comp_params)) => {
                let (private_sns_compression_key, sns_compression_key) =
                    generate_compressed_sns_compression_keys(
                        &glwe_secret_key_share_sns
                            .clone()
                            .map(|key| key.into_lwe_secret_key())
                            .unwrap(),
                        comp_params,
                        &mut mpc_encryption_rng,
                        session,
                        preprocessing,
                        seed,
                    )
                    .await?;

                Some((private_sns_compression_key, sns_compression_key))
            }
            _ => None,
        };

    let (glwe_secret_key_share_sns_compression, sns_compression_key) =
        match sns_compression_materials {
            Some((private_sns_compression_key, sns_compression_key)) => {
                (Some(private_sns_compression_key), Some(sns_compression_key))
            }
            None => (None, None),
        };

    let pub_key_set = RawCompressedPubKeySet {
        lwe_public_key,
        ksk,
        pksk,
        bk,
        bk_sns,
        compression_keys,
        msnrk,
        msnrk_sns,
        seed,
        sns_compression_key,
    };

    let priv_key_set = GenericPrivateKeySet {
        lwe_encryption_secret_key_share: lwe_hat_secret_key_share,
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns,
        glwe_secret_key_share_compression,
        glwe_secret_key_share_sns_compression,
    };

    Ok((pub_key_set, priv_key_set))
}

#[instrument(name="Gen Decompression Key Z128", skip(private_glwe_compute_key, private_compression_key, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn distributed_decompression_keygen_z128<
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    private_glwe_compute_key: &GlweSecretKeyShare<Z128, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>,
) -> anyhow::Result<DecompressionKey>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let params_basics_handle = params.get_params_basics_handle();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    // QU: Do we want to use the same DSEP as in the regualr KG?
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z128,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    let params = params_basics_handle
        .get_compression_decompression_params()
        .ok_or_else(|| anyhow::anyhow!("missing (de)compression parameters"))?;

    generate_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await
}

/// NOTE: When we generate a standalone CompressedDecompressionKey via this fn, it needs to be decompressed
/// using the decompression function WE provide [`decompressed_compressed_standalone_decompression_key_from_xof`], not the one from the TFHE-rs library.
#[instrument(name="Gen compressed Decompression Key Z128", skip(private_glwe_compute_key, private_compression_key, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn distributed_compressed_decompression_keygen_z128<
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    private_glwe_compute_key: &GlweSecretKeyShare<Z128, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>,
) -> anyhow::Result<CompressedDecompressionKey>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let params_basics_handle = params.get_params_basics_handle();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    // QU: Do we want to use the same DSEP as in the regualr KG?
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z128,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    let params = params_basics_handle
        .get_compression_decompression_params()
        .ok_or_else(|| anyhow::anyhow!("missing (de)compression parameters"))?;

    generate_compressed_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await
}

/// Correctly decompresses a CompressedDecompressionKey standalone generated from the XOF
/// and outputs a the raw elements of a [`DecompressionKey`] __BEFORE__ the fourrier transform.
pub fn decompressed_compressed_standalone_decompression_key_from_xof(
    compressed_decompression_key: CompressedDecompressionKey,
) -> (LweBootstrapKey<Vec<u64>>, LweCiphertextCount) {
    let CompressedDecompressionKey {
        blind_rotate_key: key,
        lwe_per_glwe: count,
    } = compressed_decompression_key;

    let decompressed_key = par_decompress_into_lwe_bootstrap_key_generated_from_xof::<
        _,
        SoftwareRandomGenerator,
    >(key, DSEP_KG);
    (decompressed_key, count)
}

#[instrument(name="Gen sns compression Key Z128", skip(glwe_secret_key_share_sns_as_lwe, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn distributed_sns_compression_keygen_z128<
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    glwe_secret_key_share_sns_as_lwe: &LweSecretKeyShare<Z128, EXTENSION_DEGREE>,
) -> anyhow::Result<(
    SnsCompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>,
    NoiseSquashingCompressionKey,
)>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    // QU: Do we want to use the same DSEP as in the regualr KG?
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z128,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    let params = params_basics_handle
        .get_sns_compression_params()
        .ok_or_else(|| anyhow::anyhow!("missing sns compression parameters"))?;

    generate_sns_compression_keys(
        glwe_secret_key_share_sns_as_lwe,
        params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await
}

#[cfg(test)]
pub mod tests {
    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::common::ResiduePoly,
            structure_traits::{ErrorCorrect, Invert, Ring, Solve},
        },
        execution::{
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::{
                parameters::{DKGParamsBasics, DKGParamsRegular, DKGParamsSnS},
                utils::expanded_encrypt,
            },
        },
        file_handling::tests::read_element,
        tests::helper::tests_and_benches::execute_protocol_large,
    };
    use crate::{
        execution::{
            endpoints::keygen::RawPubKeySet,
            tfhe_internals::utils::tests::reconstruct_lwe_secret_key_from_file,
        },
        networking::NetworkMode,
    };
    use crate::{
        execution::{
            random::{get_rng, seed_from_rng},
            tfhe_internals::{
                parameters::{
                    DKGParams, BC_PARAMS_NO_SNS, NIST_PARAMS_P32_NO_SNS_FGLWE,
                    NIST_PARAMS_P32_NO_SNS_LWE, NIST_PARAMS_P32_SNS_FGLWE,
                    NIST_PARAMS_P8_NO_SNS_FGLWE, NIST_PARAMS_P8_NO_SNS_LWE,
                    NIST_PARAMS_P8_SNS_FGLWE, OLD_PARAMS_P32_REAL_WITH_SNS, PARAMS_TEST_BK_SNS,
                },
                test_feature::to_hl_client_key,
                utils::tests::reconstruct_glwe_secret_key_from_file,
            },
        },
        file_handling::tests::write_element,
    };
    use itertools::Itertools;
    use std::path::Path;
    use tfhe::{
        core_crypto::{
            algorithms::{
                convert_standard_lwe_bootstrap_key_to_fourier_128, par_generate_lwe_bootstrap_key,
            },
            commons::{
                generators::{DeterministicSeeder, EncryptionRandomGenerator},
                math::random::{DefaultRandomGenerator, TUniform},
                traits::CastInto,
            },
            entities::{Fourier128LweBootstrapKey, GlweSecretKey, LweBootstrapKey, LweSecretKey},
        },
        integer::parameters::DynamicDistribution,
        prelude::{CiphertextList, FheDecrypt, FheMin, FheTryEncrypt},
        set_server_key,
        shortint::{
            client_key::atomic_pattern::{AtomicPatternClientKey, StandardAtomicPatternClientKey},
            noise_squashing::NoiseSquashingKey,
            parameters::CoreCiphertextModulus,
            PBSParameters,
        },
        CompressedCiphertextListBuilder, FheUint32, FheUint64, FheUint8,
    };
    use tfhe_csprng::seeders::Seeder;

    #[cfg(feature = "slow_tests")]
    use super::distributed_keygen_from_optional_compression_sk;

    #[cfg(feature = "slow_tests")]
    use tokio::time::Duration;

    #[cfg(feature = "slow_tests")]
    use crate::{
        execution::{
            config::BatchParams,
            keyset_config::KeySetConfig,
            online::preprocessing::create_memory_factory,
            runtime::session::{BaseSessionHandles, SmallSession, ToBaseSession},
            small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
            tfhe_internals::test_feature::run_decompression_test,
        },
        tests::helper::tests_and_benches::execute_protocol_small,
    };

    const DUMMY_PREPROC_SEED: u64 = 42;

    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn pure_tfhers_test() {
        let params = crate::execution::tfhe_internals::parameters::NIST_PARAMS_P32_INTERNAL_FGLWE;
        let classic_pbs = params.ciphertext_parameters;
        let dedicated_cpk_params = params.dedicated_compact_public_key_parameters.unwrap();

        let config = tfhe::ConfigBuilder::with_custom_parameters(classic_pbs)
            .use_dedicated_compact_public_key_parameters(dedicated_cpk_params);

        let client_key = tfhe::ClientKey::generate(config.clone());
        let server_key = tfhe::ServerKey::new(&client_key);
        let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

        try_tfhe_pk_compactlist_computation(&client_key, &server_key, &public_key);
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns_f8() {
        old_keygen_params32_with_sns::<8>()
    }

    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns_f4() {
        old_keygen_params32_with_sns::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns_f3() {
        old_keygen_params32_with_sns::<3>()
    }

    fn old_keygen_params32_with_sns<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = OLD_PARAMS_P32_REAL_WITH_SNS;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_switch_and_squash(
            temp_dir.path(),
            params.try_into().unwrap(),
            num_parties,
            threshold,
        );

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            false,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe_f8() {
        keygen_params32_no_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe_f4() {
        keygen_params32_no_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe_f3() {
        keygen_params32_no_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_FGLWE`]
    fn keygen_params32_no_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P32_NO_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe_f8() {
        keygen_params8_no_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe_f4() {
        keygen_params8_no_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe_f3() {
        keygen_params8_no_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_FGLWE`]
    fn keygen_params8_no_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P8_NO_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe_f8() {
        keygen_params32_no_sns_lwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe_f4() {
        keygen_params32_no_sns_lwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe_f3() {
        keygen_params32_no_sns_lwe::<3>()
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_LWE`]
    fn keygen_params32_no_sns_lwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P32_NO_SNS_LWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe_f8() {
        keygen_params8_no_sns_lwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe_f4() {
        keygen_params8_no_sns_lwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe_f3() {
        keygen_params8_no_sns_lwe::<3>()
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_LWE`]
    fn keygen_params8_no_sns_lwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P8_NO_SNS_LWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params_bk_sns_f8() {
        keygen_params_bk_sns::<8>()
    }

    #[test]
    fn keygen_params_bk_sns_f4() {
        keygen_params_bk_sns::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params_bk_sns_f3() {
        keygen_params_bk_sns::<3>()
    }

    ///Tests related to [`PARAMS_TEST_BK_SNS`]
    fn keygen_params_bk_sns<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_switch_and_squash(
            temp_dir.path(),
            params.try_into().unwrap(),
            num_parties,
            threshold,
        );

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_f8() {
        integration_keygen_params_bk_sns::<8>(KeySetConfig::default())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_f4() {
        integration_keygen_params_bk_sns::<4>(KeySetConfig::default())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_f3() {
        integration_keygen_params_bk_sns::<3>(KeySetConfig::default())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_existing_compression_sk_f4() {
        integration_keygen_params_bk_sns::<4>(KeySetConfig::use_existing_compression_sk())
    }

    #[cfg(feature = "slow_tests")]
    ///Tests related to [`PARAMS_TEST_BK_SNS`] using _less fake_ preprocessing
    fn integration_keygen_params_bk_sns<const EXTENSION_DEGREE: usize>(keyset_config: KeySetConfig)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_real_dkg_and_save(
            params,
            num_parties,
            threshold,
            temp_dir.path(),
            keyset_config,
            false,
        );

        run_switch_and_squash(
            temp_dir.path(),
            params.try_into().unwrap(),
            num_parties,
            threshold,
        );

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe_f8() {
        keygen_params32_with_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe_f4() {
        keygen_params32_with_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe_f3() {
        keygen_params32_with_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P32_SNS_FGLWE`]
    fn keygen_params32_with_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P32_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_switch_and_squash(
            temp_dir.path(),
            params.try_into().unwrap(),
            num_parties,
            threshold,
        );

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe_f8() {
        keygen_params8_with_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe_f4() {
        keygen_params8_with_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe_f3() {
        keygen_params8_with_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P8_REAL_WITH_SNS`]
    fn keygen_params8_with_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P8_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_switch_and_squash(
            temp_dir.path(),
            params.try_into().unwrap(),
            num_parties,
            threshold,
        );

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params_blockchain_without_sns_f8() {
        keygen_params_blockchain_without_sns::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params_blockchain_without_sns_f4() {
        keygen_params_blockchain_without_sns::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params_blockchain_without_sns_f3() {
        keygen_params_blockchain_without_sns::<3>()
    }

    ///Tests related to [`BC_PARAMS_NO_SNS`]
    fn keygen_params_blockchain_without_sns<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = BC_PARAMS_NO_SNS;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path(), false);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );
    }

    // taken from https://stackoverflow.com/questions/64498617/how-to-transpose-a-vector-of-vectors-in-rust
    #[cfg(feature = "slow_tests")]
    fn transpose2<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
        assert!(!v.is_empty());
        let len = v[0].len();
        let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
        (0..len)
            .map(|_| {
                iters
                    .iter_mut()
                    .map(|n| n.next().unwrap())
                    .collect::<Vec<T>>()
            })
            .collect()
    }

    #[cfg(feature = "slow_tests")]
    fn binary_vec64_to_shares128<R: rand::Rng + rand::CryptoRng, const EXTENSION_DEGREE: usize>(
        v: Vec<u64>,
        n: usize,
        t: usize,
        rng: &mut R,
    ) -> Vec<Vec<crate::execution::sharing::share::Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        use crate::execution::sharing::shamir::{InputOp, ShamirSharings};
        use std::num::Wrapping;
        transpose2(
            v.into_iter()
                .map(|s| {
                    assert!(s == 0 || s == 1);
                    let s = ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(
                        s as u128,
                    ));
                    ShamirSharings::share(rng, s, n, t).unwrap().shares
                })
                .collect::<Vec<Vec<_>>>(),
        )
    }

    #[cfg(feature = "slow_tests")]
    fn binary_vec128_to_shares128<R: rand::Rng + rand::CryptoRng, const EXTENSION_DEGREE: usize>(
        v: Vec<u128>,
        n: usize,
        t: usize,
        rng: &mut R,
    ) -> Vec<Vec<crate::execution::sharing::share::Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        use crate::execution::sharing::shamir::{InputOp, ShamirSharings};
        use std::num::Wrapping;
        transpose2(
            v.into_iter()
                .map(|s| {
                    assert!(s == 0 || s == 1);
                    let s = ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(s));
                    ShamirSharings::share(rng, s, n, t).unwrap().shares
                })
                .collect::<Vec<Vec<_>>>(),
        )
    }

    #[cfg(feature = "slow_tests")]
    fn run_real_decompression_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        // first we need to generate two server keys
        use crate::{
            execution::{
                endpoints::keygen::distributed_decompression_keygen_z128,
                sharing::share::Share,
                tfhe_internals::{
                    compression_decompression_key::CompressionPrivateKeyShares,
                    glwe_key::GlweSecretKeyShare, test_feature::gen_key_set,
                },
            },
            file_handling::tests::{read_element, write_element},
        };

        let keyset_config = KeySetConfig::DecompressionOnly;
        let mut rng = aes_prng::AesRng::from_random_seed();
        let keyset1 = gen_key_set(params, &mut rng);
        let keyset2 = gen_key_set(params, &mut rng);

        let compression_key_1_poly_size = keyset1
            .get_raw_compression_client_key()
            .unwrap()
            .polynomial_size();
        let compression_key_1 = keyset1
            .get_raw_compression_client_key()
            .unwrap()
            .into_container();
        let glwe_key_2_poly_size = keyset2.get_raw_glwe_client_key().polynomial_size();
        let glwe_key_2 = keyset2.get_raw_glwe_client_key().into_container();

        // and then secret share the secret keys
        let compression_key_shares_1 =
            binary_vec64_to_shares128(compression_key_1, num_parties, threshold, &mut rng);
        assert_eq!(compression_key_shares_1.len(), num_parties);
        let glwe_key_shares_2 =
            binary_vec64_to_shares128(glwe_key_2, num_parties, threshold, &mut rng);
        assert_eq!(glwe_key_shares_2.len(), num_parties);

        // We need to pass these shares into the FnMut,
        // but FnMut doesn't allow us to move a reference
        // so write these two shares into the temporary storage
        // and then we'll read it in the task.
        write_element(
            prefix_path.join("compression_key_shares_1"),
            &compression_key_shares_1,
        )
        .unwrap();
        write_element(prefix_path.join("glwe_key_shares_2"), &glwe_key_shares_2).unwrap();

        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        prefix: Option<String>| async move {
            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(240))
                .unwrap();
            let batch_size = BatchParams {
                triples: params
                    .get_params_basics_handle()
                    .total_triples_required(keyset_config),
                randoms: params
                    .get_params_basics_handle()
                    .total_randomness_required(keyset_config),
            };

            let mut small_preproc = SecureSmallPreprocessing::default()
                .execute(&mut session, batch_size)
                .await
                .unwrap();

            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    keyset_config,
                    session.get_mut_base_session(),
                    &mut small_preproc,
                )
                .await
                .unwrap();

            let my_role = session.my_role();
            let prefix = prefix.unwrap();
            let path_compression_key_shares_1 = Path::new(&prefix).join("compression_key_shares_1");
            let path_glwe_key_shares_2 = Path::new(&prefix).join("glwe_key_shares_2");
            let compression_key_shares_1 = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_compression_key_shares_1)
            .unwrap()[&my_role];
            let glwe_key_shares_2 = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_glwe_key_shares_2)
            .unwrap()[&my_role];

            let params_handle = params.get_params_basics_handle();
            let private_glwe_compute_key = GlweSecretKeyShare {
                data: glwe_key_shares_2.to_vec(),
                polynomial_size: glwe_key_2_poly_size,
            };
            let private_compression_key = CompressionPrivateKeyShares {
                post_packing_ks_key: GlweSecretKeyShare {
                    data: compression_key_shares_1.to_vec(),
                    polynomial_size: compression_key_1_poly_size,
                },
                params: params_handle
                    .get_compression_decompression_params()
                    .unwrap()
                    .raw_compression_parameters,
            };
            let decompression_key = distributed_decompression_keygen_z128(
                &mut session,
                dkg_preproc.as_mut(),
                params,
                &private_glwe_compute_key,
                &private_compression_key,
            )
            .await
            .unwrap();

            // make sure we used up all the preprocessing materials
            assert_eq!(0, dkg_preproc.bits_len());
            assert_eq!(0, dkg_preproc.triples_len());
            assert_eq!(0, dkg_preproc.randoms_len());

            use strum::IntoEnumIterator;
            for bound in crate::execution::tfhe_internals::parameters::NoiseBounds::iter() {
                assert_eq!(0, dkg_preproc.noise_len(bound));
            }

            (my_role, decompression_key)
        };

        // Sync network because we also init the PRSS in the task
        let mut results =
            execute_protocol_small::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                num_parties,
                threshold as u8,
                None,
                NetworkMode::Sync,
                None,
                &mut task,
                Some(prefix_path.to_str().unwrap().to_string()),
            );

        // check that the decompression keys are the same
        let decompression_key = results.pop().unwrap().1;
        let decompression_key_bytes = bc2wrap::serialize(&decompression_key).unwrap();
        for (_role, key) in results {
            let buf = bc2wrap::serialize(&key).unwrap();
            assert_eq!(buf, decompression_key_bytes);
        }
        // check that we can do the decompression
        run_decompression_test(
            &keyset1.client_key,
            &keyset2.client_key,
            None,
            decompression_key,
        );
    }

    #[cfg(feature = "slow_tests")]
    fn run_real_sns_compression_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        use std::collections::HashMap;

        use tfhe::{
            core_crypto::prelude::GlweSecretKeyOwned,
            shortint::list_compression::NoiseSquashingCompressionPrivateKey,
        };

        // first we need to generate two server keys
        use crate::{
            execution::{
                endpoints::keygen::distributed_sns_compression_keygen_z128,
                sharing::share::Share,
                tfhe_internals::{
                    glwe_key::GlweSecretKeyShare,
                    test_feature::{combine_and_run_sns_compression_test, gen_key_set},
                },
            },
            file_handling::tests::{read_element, write_element},
        };

        let keyset_config = KeySetConfig::AddSnsCompressionKey;
        let mut rng = aes_prng::AesRng::from_random_seed();

        // here we need to remove the private sns compression key
        let keyset = {
            let mut tmp = gen_key_set(params, &mut rng);
            let ck_parts = tmp.client_key.into_raw_parts();
            tmp.client_key = tfhe::ClientKey::from_raw_parts(
                ck_parts.0, ck_parts.1, ck_parts.2, ck_parts.3, None, ck_parts.5,
            );
            tmp
        };

        let (glwe_sns_key_poly_size, glwe_sns_key) = {
            let k = keyset.get_raw_glwe_client_sns_key().unwrap();
            (k.polynomial_size(), k.into_container())
        };

        // and then secret share the secret keys
        let glwe_sns_key_shares =
            binary_vec128_to_shares128(glwe_sns_key, num_parties, threshold, &mut rng);
        assert_eq!(glwe_sns_key_shares.len(), num_parties);

        // We need to pass these shares into the FnMut,
        // but FnMut doesn't allow us to move a reference
        // so write these two shares into the temporary storage
        // and then we'll read it in the task.
        const GLWE_SNS_KEY_SHARES: &str = "glwe_sns_key_shares";
        write_element(prefix_path.join(GLWE_SNS_KEY_SHARES), &glwe_sns_key_shares).unwrap();

        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        prefix: Option<String>| async move {
            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(240))
                .unwrap();
            let batch_size = BatchParams {
                triples: params
                    .get_params_basics_handle()
                    .total_triples_required(keyset_config),
                randoms: params
                    .get_params_basics_handle()
                    .total_randomness_required(keyset_config),
            };

            let mut small_preproc = SecureSmallPreprocessing::default()
                .execute(&mut session, batch_size)
                .await
                .unwrap();

            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    keyset_config,
                    session.get_mut_base_session(),
                    &mut small_preproc,
                )
                .await
                .unwrap();

            let my_role = session.my_role();
            let prefix = prefix.unwrap();
            let path_glwe_sns_key_shares = Path::new(&prefix).join(GLWE_SNS_KEY_SHARES);
            let glwe_key_sns_shares = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_glwe_sns_key_shares)
            .unwrap()[&my_role];

            let private_glwe_sns_key_share = GlweSecretKeyShare {
                data: glwe_key_sns_shares.to_vec(),
                polynomial_size: glwe_sns_key_poly_size,
            };
            let (sns_compression_shares, sns_compression_key) =
                distributed_sns_compression_keygen_z128(
                    &mut session,
                    dkg_preproc.as_mut(),
                    params,
                    &private_glwe_sns_key_share.into_lwe_secret_key(),
                )
                .await
                .unwrap();

            // make sure we used up all the preprocessing materials
            assert_eq!(0, dkg_preproc.bits_len());
            assert_eq!(0, dkg_preproc.triples_len());
            assert_eq!(0, dkg_preproc.randoms_len());

            use strum::IntoEnumIterator;

            for bound in crate::execution::tfhe_internals::parameters::NoiseBounds::iter() {
                assert_eq!(0, dkg_preproc.noise_len(bound));
            }

            (my_role, (sns_compression_shares, sns_compression_key))
        };

        // Sync network because we also init the PRSS in the task
        let mut results =
            execute_protocol_small::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                num_parties,
                threshold as u8,
                None,
                NetworkMode::Sync,
                None,
                &mut task,
                Some(prefix_path.to_str().unwrap().to_string()),
            );

        // reconstruct the shares
        let all_shares = results
            .iter()
            .map(|(role, (share, _))| (*role, share.post_packing_ks_key.clone().data))
            .collect::<HashMap<_, _>>();
        let sns_compression_glwe_sk_bits =
            crate::execution::tfhe_internals::utils::reconstruct_bit_vec::<_, EXTENSION_DEGREE>(
                all_shares,
                match params {
                    DKGParams::WithoutSnS(_) => panic!("expected sns compression params"),
                    DKGParams::WithSnS(dkgparams_sn_s) => {
                        dkgparams_sn_s.sns_compression_sk_num_bits()
                    }
                },
                threshold,
            )
            .into_iter()
            .map(|x| x as u128)
            .collect::<Vec<_>>();

        let sns_compression_params = match params {
            DKGParams::WithoutSnS(_) => panic!("expected sns compression params"),
            DKGParams::WithSnS(dkgparams_sn_s) => dkgparams_sn_s.sns_compression_params.unwrap(),
        };
        let sns_compression_private_key = NoiseSquashingCompressionPrivateKey::from_raw_parts(
            GlweSecretKeyOwned::from_container(
                sns_compression_glwe_sk_bits,
                glwe_sns_key_poly_size,
            ),
            sns_compression_params,
        );

        // check that the compression keys are the same
        let sns_compression_key = results.pop().unwrap().1 .1;
        let decompression_key_bytes = bc2wrap::serialize(&sns_compression_key).unwrap();
        for (_role, key) in results {
            let buf = bc2wrap::serialize(&key.1).unwrap();
            assert_eq!(buf, decompression_key_bytes);
        }

        // check that we can do the sns compression test
        combine_and_run_sns_compression_test(
            params,
            &keyset.client_key,
            sns_compression_key,
            sns_compression_private_key,
            None,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn decompression_keygen_f4() {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();
        run_real_decompression_dkg_and_save::<4>(params, num_parties, threshold, temp_dir.path())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn sns_compression_keygen_f4() {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();
        run_real_sns_compression_dkg_and_save::<4>(params, num_parties, threshold, temp_dir.path())
    }

    #[cfg(feature = "slow_tests")]
    fn run_real_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
        keyset_config: KeySetConfig,
        run_compressed: bool,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        _bot: Option<String>| async move {
            use crate::execution::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
            let compression_sk_skares = if keyset_config.is_standard_using_existing_compression_sk()
            {
                // we use dummy preprocessing to generate the existing compression sk
                // because it won't consume our preprocessing materials
                let mut dummy_preproc =
                    DummyPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(
                        DUMMY_PREPROC_SEED,
                        &session,
                    );
                let params_basics_handles = params.get_params_basics_handle();
                Some(
                    CompressionPrivateKeyShares::new_from_preprocessing(
                        params_basics_handles
                            .get_compression_decompression_params()
                            .unwrap()
                            .raw_compression_parameters,
                        &mut dummy_preproc,
                    )
                    .unwrap(),
                )
            } else {
                None
            };

            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(240))
                .unwrap();
            let batch_size = BatchParams {
                triples: params
                    .get_params_basics_handle()
                    .total_triples_required(keyset_config),
                randoms: params
                    .get_params_basics_handle()
                    .total_randomness_required(keyset_config),
            };

            let mut small_preproc = SecureSmallPreprocessing::default()
                .execute(&mut session, batch_size)
                .await
                .unwrap();

            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    keyset_config,
                    session.get_mut_base_session(),
                    &mut small_preproc,
                )
                .await
                .unwrap();

            assert_ne!(0, dkg_preproc.bits_len());
            assert_ne!(0, dkg_preproc.triples_len());
            assert_ne!(0, dkg_preproc.randoms_len());

            let my_role = session.my_role();
            let (pk, sk) = if run_compressed {
                let (compressed_pk, sk) =
                    super::distributed_keygen_compressed_from_optional_compression_sk::<
                        Z64,
                        _,
                        _,
                        EXTENSION_DEGREE,
                    >(&mut session, &mut large_preproc, params, None)
                    .await
                    .unwrap();
                (compressed_pk.decompress(), sk)
            } else {
                super::distributed_keygen_from_optional_compression_sk::<
                Z128,
                _,
                _,
                EXTENSION_DEGREE,
            >(&mut session, &mut large_preproc, params, None)
            .await
            .unwrap()
            };

            // make sure we used up all the preprocessing materials
            assert_eq!(0, dkg_preproc.bits_len());
            assert_eq!(0, dkg_preproc.triples_len());
            assert_eq!(0, dkg_preproc.randoms_len());

            use strum::IntoEnumIterator;
            for bound in crate::execution::tfhe_internals::parameters::NoiseBounds::iter() {
                assert_eq!(0, dkg_preproc.noise_len(bound));
            }

            (
                my_role,
                pk,
                sk.finalize_keyset(
                    params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                ),
            )
        };

        // Sync network because we also init the PRSS in the task
        let results =
            execute_protocol_small::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                num_parties,
                threshold as u8,
                None,
                NetworkMode::Sync,
                None,
                &mut task,
                None,
            );

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            write_element(
                prefix_path.join(format!("sk_p{}.der", role.one_based())),
                &sk,
            )
            .unwrap();
        }

        write_element(prefix_path.join("pk.der"), &pk_ref).unwrap();
    }

    ///Runs the DKG protocol with [`DummyPreprocessing`]
    /// and [`FakeBitGenEven`]. Saves the results to file.
    fn run_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
        run_compressed: bool,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    {
        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role();
            let mut large_preproc = DummyPreprocessing::new(DUMMY_PREPROC_SEED, &session);

            let (pk, sk) = if run_compressed {
                let (compressed_pk, sk) =
                    super::distributed_keygen_compressed_from_optional_compression_sk::<
                        Z64,
                        _,
                        _,
                        EXTENSION_DEGREE,
                    >(&mut session, &mut large_preproc, params, None)
                    .await
                    .unwrap();
                (compressed_pk.decompress(), sk)
            } else {
                super::distributed_keygen_from_optional_compression_sk::<
                Z128,
                _,
                _,
                EXTENSION_DEGREE,
            >(&mut session, &mut large_preproc, params, None)
            .await
            .unwrap()
            };

            (
                my_role,
                pk,
                sk.finalize_keyset(
                    params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                ),
            )
        };

        //Async because the preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results =
            execute_protocol_large::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                num_parties,
                threshold,
                None,
                NetworkMode::Async,
                Some(delay_vec),
                &mut task,
            );

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            write_element(
                prefix_path.join(format!("sk_p{}.der", role.one_based())),
                &sk,
            )
            .unwrap();
        }

        write_element(prefix_path.join("pk.der"), &pk_ref).unwrap();
    }

    fn run_switch_and_squash<const EXTENSION_DEGREE: usize>(
        prefix_path: &Path,
        params: DKGParamsSnS,
        num_parties: usize,
        threshold: usize,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let message = (params.get_message_modulus().0 - 1) as u8;

        let sk_lwe = reconstruct_lwe_secret_key_from_file::<EXTENSION_DEGREE, _>(
            num_parties,
            threshold,
            &params,
            prefix_path,
        );
        let (sk_glwe, big_sk_glwe, sns_compression_sk) =
            reconstruct_glwe_secret_key_from_file::<EXTENSION_DEGREE>(
                num_parties,
                threshold,
                DKGParams::WithSnS(params),
                prefix_path,
            );

        let sns_raw_private_key = GlweSecretKey::from_container(
            big_sk_glwe.clone().unwrap().into_container(),
            params.sns_params.polynomial_size,
        );

        let pk: RawPubKeySet = read_element(prefix_path.join("pk.der")).unwrap();
        let pub_key_set = pk.to_pubkeyset(DKGParams::WithSnS(params));
        let (integer_server_key, _, _, _, ck, _, _) =
            pub_key_set.server_key.clone().into_raw_parts();
        let ck = ck.unwrap();

        set_server_key(pub_key_set.server_key);

        let ddec_pk = pk.compute_tfhe_hl_api_compact_public_key(DKGParams::WithSnS(params));
        let ddec_sk = to_hl_client_key(
            &DKGParams::WithSnS(params),
            sk_lwe.clone(),
            sk_glwe,
            None,
            None,
            Some(sns_raw_private_key),
            sns_compression_sk,
        )
        .unwrap();

        //Try and generate the bk_sns directly from the private keys
        let sk_lwe_lifted_128 = LweSecretKey::from_container(
            sk_lwe
                .into_container()
                .iter()
                .map(|bit| *bit as u128)
                .collect_vec(),
        );

        let mut bsk_out = LweBootstrapKey::new(
            0_u128,
            params.glwe_dimension_sns().to_glwe_size(),
            params.polynomial_size_sns(),
            params.decomposition_base_log_bk_sns(),
            params.decomposition_level_count_bk_sns(),
            params.lwe_dimension(),
            CoreCiphertextModulus::<u128>::new_native(),
        );
        let mut rng = get_rng();
        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(seed_from_rng(&mut rng));
        let mut enc_rng = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );

        let big_sk_glwe = GlweSecretKey::from_container(
            big_sk_glwe.unwrap().into_container(),
            params.polynomial_size_sns(),
        );

        par_generate_lwe_bootstrap_key(
            &sk_lwe_lifted_128,
            &big_sk_glwe,
            &mut bsk_out,
            DynamicDistribution::TUniform(TUniform::new(params.glwe_tuniform_bound_sns().0 as u32)),
            &mut enc_rng,
        );
        let mut fbsk_out = Fourier128LweBootstrapKey::new(
            params.lwe_dimension(),
            params.glwe_dimension_sns().to_glwe_size(),
            params.polynomial_size_sns(),
            params.decomposition_base_log_bk_sns(),
            params.decomposition_level_count_bk_sns(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk_out, &mut fbsk_out);
        drop(bsk_out);

        let ck_bis = {
            let (_, mod_switch, pt_modulus, pt_carry, ct_modulus) =
                ck.clone().into_raw_parts().into_raw_parts();
            tfhe::integer::noise_squashing::NoiseSquashingKey::from_raw_parts(
                NoiseSquashingKey::from_raw_parts(
                    fbsk_out, mod_switch, pt_modulus, pt_carry, ct_modulus,
                ),
            )
        };

        let small_ct: FheUint64 = expanded_encrypt(&ddec_pk, message as u64, 64).unwrap();
        let (raw_ct, _id, _tag) = small_ct.clone().into_raw_parts();
        let large_ct = ck
            .squash_radix_ciphertext_noise(&integer_server_key, &raw_ct)
            .unwrap();
        let large_ct_bis = ck_bis
            .squash_radix_ciphertext_noise(&integer_server_key, &raw_ct)
            .unwrap();

        let res_small: u8 = small_ct.decrypt(&ddec_sk);
        let sns_private_key = ddec_sk.clone().into_raw_parts().3.unwrap();
        let res_large = sns_private_key.decrypt_radix(&large_ct).unwrap();
        let res_large_bis = sns_private_key.decrypt_radix(&large_ct_bis).unwrap();

        assert_eq!(message, res_small);
        assert_eq!(message as u128, res_large_bis);
        assert_eq!(message as u128, res_large);
    }

    ///Runs only the shortint computation
    pub fn run_tfhe_computation_shortint<const EXTENSION_DEGREE: usize, Params: DKGParamsBasics>(
        prefix_path: &Path,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        with_compact: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );
        let pub_key_set = pk.to_pubkeyset(params);

        set_server_key(pub_key_set.server_key);
        let shortint_pk = pk.compute_tfhe_shortint_server_key(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        if with_compact {
            let tfhe_sk = tfhe::ClientKey::from_raw_parts(
                shortint_sk.into(),
                None,
                None,
                None,
                None,
                tfhe::Tag::default(),
            );
            let pub_key_set = pk.to_pubkeyset(params);
            try_tfhe_pk_compactlist_computation(
                &tfhe_sk,
                &pub_key_set.server_key,
                &pub_key_set.public_key,
            );
        }
    }

    ///Runs both shortint and fheuint computation
    fn run_tfhe_computation_fheuint<const EXTENSION_DEGREE: usize>(
        prefix_path: &Path,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        do_compression_test: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );

        let pub_key_set = pk.to_pubkeyset(params);

        set_server_key(pub_key_set.server_key);

        let shortint_pk = pk.compute_tfhe_shortint_server_key(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        // Note that there is no `compression_key` because this key is never used to
        // encrypt/decrypt. We only compress and decompress which doesn't require this key.
        let tfhe_sk = tfhe::ClientKey::from_raw_parts(
            shortint_sk.into(),
            None,
            None,
            None,
            None,
            tfhe::Tag::default(),
        );

        try_tfhe_fheuint_computation(&tfhe_sk);
        if do_compression_test {
            try_tfhe_compression_computation(&tfhe_sk);
        }
    }

    ///Read files created by [`run_dkg_and_save`] and reconstruct the secret keys
    ///from the parties' shares
    fn retrieve_keys_from_files<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) -> (tfhe::shortint::ClientKey, RawPubKeySet)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let params_tfhe_rs = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let lwe_secret_key = reconstruct_lwe_secret_key_from_file::<EXTENSION_DEGREE, _>(
            num_parties,
            threshold,
            params.get_params_basics_handle(),
            prefix_path,
        );
        let (glwe_secret_key, _, _) = reconstruct_glwe_secret_key_from_file::<EXTENSION_DEGREE>(
            num_parties,
            threshold,
            params,
            prefix_path,
        );
        let pk: RawPubKeySet = read_element(prefix_path.join("pk.der")).unwrap();

        let sck = StandardAtomicPatternClientKey::from_raw_parts(
            glwe_secret_key,
            lwe_secret_key,
            PBSParameters::PBS(params_tfhe_rs),
            None,
        );
        let shortint_client_key = tfhe::shortint::ClientKey {
            atomic_pattern: AtomicPatternClientKey::Standard(sck),
        };

        (shortint_client_key, pk)
    }

    //TFHE-rs doctest for shortint
    fn try_tfhe_shortint_computation(
        shortint_client_key: &tfhe::shortint::ClientKey,
        shortint_server_key: &tfhe::shortint::ServerKey,
    ) {
        let clear_a = 3u64;
        let clear_b = 3u64;
        let scalar = 4u8;

        let mut ct_1 = shortint_client_key.encrypt(clear_a);
        let mut ct_2 = shortint_client_key.encrypt(clear_b);

        shortint_server_key.smart_scalar_mul_assign(&mut ct_1, scalar);
        shortint_server_key.smart_sub_assign(&mut ct_1, &mut ct_2);
        shortint_server_key.smart_mul_lsb_assign(&mut ct_1, &mut ct_2);

        let clear_res: u64 = shortint_client_key.decrypt(&ct_1);

        let modulus = shortint_client_key.parameters().message_modulus().0;

        let expected_res = ((clear_a * scalar as u64 - clear_b) * clear_b) % modulus;
        assert_eq!(clear_res, expected_res);
    }

    fn try_tfhe_pk_compactlist_computation(
        client_key: &tfhe::ClientKey,
        server_keys: &tfhe::ServerKey,
        pk: &tfhe::CompactPublicKey,
    ) {
        let clear_a = 3u64;
        let clear_b = 5u64;

        let compact_ctxt_list = tfhe::CompactCiphertextList::builder(pk)
            .push(clear_a)
            .push(clear_b)
            .build_packed();

        let result = {
            set_server_key(server_keys.clone());
            let all_keys = server_keys.clone().into_raw_parts();
            let cpk_ksk = all_keys.1;
            assert!(cpk_ksk.is_some());
            // Verify the ciphertexts
            let expander = compact_ctxt_list.expand().unwrap();
            let a: tfhe::FheUint64 = expander.get(0).unwrap().unwrap();
            let b: tfhe::FheUint64 = expander.get(1).unwrap().unwrap();

            a + b
        };

        let a_plus_b: u64 = result.decrypt(client_key);
        assert_eq!(a_plus_b, clear_a.wrapping_add(clear_b));
    }

    //TFHE-rs doctest for fheuint
    fn try_tfhe_fheuint_computation(client_key: &tfhe::ClientKey) {
        //// Key generation
        let clear_a = 1344u32;
        let clear_b = 5u32;
        let clear_c = 7u8;

        // Encrypting the input data using the (private) client_key
        // FheUint32: Encrypted equivalent to u32
        let mut encrypted_a = FheUint32::try_encrypt(clear_a, client_key).unwrap();
        let encrypted_b = FheUint32::try_encrypt(clear_b, client_key).unwrap();

        // FheUint8: Encrypted equivalent to u8
        let encrypted_c = FheUint8::try_encrypt(clear_c, client_key).unwrap();

        // Clear equivalent computations: 1344 * 5 = 6720
        let encrypted_res_mul = &encrypted_a * &encrypted_b;

        let clear_mult: u32 = encrypted_res_mul.decrypt(client_key);
        assert_eq!(clear_mult, 6720);

        // Clear equivalent computations: 6720 >> 5 = 210
        encrypted_a = &encrypted_res_mul >> &encrypted_b;

        let clear_after_shift: u16 = encrypted_a.decrypt(client_key);
        assert_eq!(clear_after_shift, 210);

        // Clear equivalent computations: let casted_a = a as u8;
        let casted_a: FheUint8 = encrypted_a.cast_into();

        // Clear equivalent computations: min(42, 7) = 7
        let encrypted_res_min = &casted_a.min(&encrypted_c);

        let clear_after_min: u8 = encrypted_res_min.decrypt(client_key);
        assert_eq!(clear_after_min, 7);

        // Operation between clear and encrypted data:
        // Clear equivalent computations: 7 & 1 = 1
        let encrypted_res = encrypted_res_min & 1_u8;

        let clear_res: u8 = encrypted_res.decrypt(client_key);
        assert_eq!(clear_res, 1);
    }

    fn try_tfhe_compression_computation(client_key: &tfhe::ClientKey) {
        let clear_a = 1344u32;
        let clear_b = 5u32;
        let clear_c = 7u8;

        // Encrypting the input data using the (private) client_key
        // FheUint32: Encrypted equivalent to u32
        let encrypted_a = FheUint32::try_encrypt(clear_a, client_key).unwrap();
        let encrypted_b = FheUint32::try_encrypt(clear_b, client_key).unwrap();

        // FheUint8: Encrypted equivalent to u8
        let encrypted_c = FheUint8::try_encrypt(clear_c, client_key).unwrap();

        // note that the server key is set in the caller of this function
        let compressed = CompressedCiphertextListBuilder::new()
            .push(encrypted_a)
            .push(encrypted_b)
            .push(encrypted_c)
            .build()
            .unwrap();

        let decompressed: FheUint32 = compressed.get(0).unwrap().unwrap();
        let decrypted: u32 = decompressed.decrypt(client_key);
        assert_eq!(decrypted, clear_a);

        let decompressed: FheUint32 = compressed.get(1).unwrap().unwrap();
        let decrypted: u32 = decompressed.decrypt(client_key);
        assert_eq!(decrypted, clear_b);

        let decompressed: FheUint8 = compressed.get(2).unwrap().unwrap();
        let decrypted: u8 = decompressed.decrypt(client_key);
        assert_eq!(decrypted, clear_c);
    }
}
