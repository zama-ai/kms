use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect},
    },
    execution::{
        online::preprocessing::DKGPreprocessing,
        runtime::session::BaseSessionHandles,
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares,
            glwe_key::GlweSecretKeyShare,
            lwe_bootstrap_key_generation::{
                generate_bootstrap_key, generate_compressed_bootstrap_key,
            },
            lwe_key::LweSecretKeyShare,
            lwe_packing_keyswitch_key::LwePackingKeyswitchKeyShares,
            lwe_packing_keyswitch_key_generation::allocate_and_generate_lwe_packing_keyswitch_key,
            parameters::{DKGParams, DistributedCompressionParameters, EncryptionType},
            randomness::MPCEncryptionRandomGenerator,
        },
    },
};

use itertools::Itertools;
use tfhe::{
    core_crypto::prelude::{
        par_convert_standard_lwe_bootstrap_key_to_fourier, FourierLweBootstrapKey, LweBootstrapKey,
        ParallelByteRandomGenerator, SeededLweBootstrapKey,
    },
    shortint::list_compression::{
        CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, DecompressionKey,
    },
};
use tfhe_csprng::generators::SoftwareRandomGenerator;
use tracing::instrument;

#[instrument(name="Gen Decompression Key", skip(private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub(crate) async fn generate_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
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

    Ok(DecompressionKey {
        blind_rotate_key: fourier_bsk,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
    })
}

#[instrument(name="Gen compressed Decompression Key", skip(private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub(crate) async fn generate_compressed_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
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

/// helper function to generate packing key switching key shares
/// for use in compression key.
/// Helper function to generate packing key switching key shares
/// for use in Compression key.
fn generate_packing_key_switching_key_shares_for_compression<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    Gen: ParallelByteRandomGenerator,
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

#[instrument(name="Gen Compression and Decompression Key", skip(private_glwe_compute_key_as_lwe, private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
async fn generate_compression_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
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
    let packing_key_switching_key_shares =
        generate_packing_key_switching_key_shares_for_compression(
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

#[allow(clippy::too_many_arguments)]
#[instrument(name="Gen compressed Compression and Decompression Key", skip(private_glwe_compute_key_as_lwe, private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
async fn generate_compressed_compression_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    S: BaseSessionHandles,
    Gen: ParallelByteRandomGenerator,
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
    let packing_key_switching_key_shares =
        generate_packing_key_switching_key_shares_for_compression(
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

    let decompression_key: CompressedDecompressionKey = generate_compressed_decompression_keys(
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

/// Note that in the return value, it is possible for [CompressionPrivateKeyShares] to be None
/// while [CompressionKey], [DecompressionKey] exists because we do not copy the secret shares again.
pub(crate) async fn distributed_keygen_compression_material<
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
/// Note that in the return value, it is possible for [CompressionPrivateKeyShares] to be None
/// while [CompressionKey], [DecompressionKey] exists because we do not copy the secret shares again.
pub(crate) async fn distributed_keygen_compressed_compression_material<
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
