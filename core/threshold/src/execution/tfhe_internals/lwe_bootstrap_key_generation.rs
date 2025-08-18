use itertools::{EitherOrBoth, Itertools};
use tfhe::{
    core_crypto::prelude::{
        ByteRandomGenerator, LweBootstrapKey, SeededLweBootstrapKey, UnsignedInteger,
    },
    shortint::parameters::{DecompositionBaseLog, DecompositionLevelCount},
};
use tracing::instrument;

use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::preprocessing::{DKGPreprocessing, TriplePreprocessing},
        runtime::session::BaseSessionHandles,
        tfhe_internals::parameters::BKParams,
    },
};

use super::{
    ggsw_ciphertext::{encrypt_constant_ggsw_ciphertext, ggsw_encode_messages},
    glwe_key::GlweSecretKeyShare,
    lwe_bootstrap_key::LweBootstrapKeyShare,
    lwe_key::LweSecretKeyShare,
    parameters::EncryptionType,
    randomness::MPCEncryptionRandomGenerator,
};

pub async fn generate_lwe_bootstrap_key<Z, Gen, S, P, const EXTENSION_DEGREE: usize>(
    input_lwe_secret_key: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_glwe_secret_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output: &mut LweBootstrapKeyShare<Z, EXTENSION_DEGREE>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preproc: &mut P,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
    S: BaseSessionHandles,
    P: TriplePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let encryption_type = output.encryption_type();
    let gen_iter = generator.fork_bsk_to_ggsw(
        output.input_lwe_dimension(),
        output.decomposition_level_count(),
        output.glwe_size(),
        output.polynomial_size(),
        encryption_type,
    )?;

    let encoded_input_key_elements = ggsw_encode_messages(
        &input_lwe_secret_key.data,
        output_glwe_secret_key,
        session,
        preproc,
    )
    .await?;

    for ggsw_encoded_generator in output
        .ggsw_list
        .iter_mut()
        .zip_longest(encoded_input_key_elements.into_iter())
        .zip_longest(gen_iter)
    {
        if let EitherOrBoth::Both(EitherOrBoth::Both(ggsw, encoded), mut generator) =
            ggsw_encoded_generator
        {
            encrypt_constant_ggsw_ciphertext(
                output_glwe_secret_key,
                ggsw,
                encoded,
                &mut generator,
                encryption_type,
            );
        } else {
            return Err(anyhow_error_and_log("zip error"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn allocate_and_generate_lwe_bootstrap_key<Z, Gen, S, P, const EXTENSION_DEGREE: usize>(
    input_lwe_secret_key: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_glwe_secret_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    encryption_type: EncryptionType,
    session: &mut S,
    preproc: &mut P,
) -> anyhow::Result<LweBootstrapKeyShare<Z, EXTENSION_DEGREE>>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
    S: BaseSessionHandles,
    P: TriplePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let mut bsk = LweBootstrapKeyShare::new(
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        encryption_type,
    );

    generate_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        generator,
        session,
        preproc,
    )
    .await?;

    Ok(bsk)
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

/// Generates a Bootstrapping Key given a Glwe key in Glwe format
/// , a Lwe key and the params for the BK generation
#[instrument(name="Gen BK", skip(glwe_secret_key_share, lwe_secret_key_share, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub(crate) async fn generate_bootstrap_key<
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

/// Generates a compressed Bootstrapping Key given a Glwe key in Glwe format
/// , a Lwe key and the params for the BK generation
#[instrument(name="Gen compressed BK", skip(glwe_secret_key_share, lwe_secret_key_share, mpc_encryption_rng, session, preprocessing, seed), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub(crate) async fn generate_compressed_bootstrap_key<
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ops::Deref};

    use itertools::Itertools;
    use tfhe::{
        boolean::prelude::LweDimension,
        core_crypto::{
            algorithms::{
                allocate_and_generate_new_lwe_bootstrap_key, decrypt_constant_ggsw_ciphertext,
                decrypt_glwe_ciphertext,
            },
            commons::{
                generators::{DeterministicSeeder, EncryptionRandomGenerator},
                math::{
                    decomposition::SignedDecomposer,
                    random::{DefaultRandomGenerator, TUniform},
                },
                traits::{ContiguousEntityContainer, ContiguousEntityContainerMut},
            },
            entities::{GlweSecretKeyOwned, LweSecretKeyOwned, PlaintextList},
            prelude::PlaintextCount,
        },
        integer::parameters::DynamicDistribution,
        shortint::parameters::{
            CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, PolynomialSize,
        },
    };
    use tfhe_csprng::{
        generators::SoftwareRandomGenerator,
        seeders::{Seeder, XofSeed},
    };

    use crate::{
        algebra::{
            base_ring::Z128, galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring,
        },
        execution::{
            online::{
                preprocessing::dummy::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            random::{get_rng, seed_from_rng},
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::{
                glwe_key::GlweSecretKeyShare,
                lwe_bootstrap_key::par_decompress_into_lwe_bootstrap_key_generated_from_xof,
                lwe_key::LweSecretKeyShare,
                parameters::{EncryptionType, TUniformBound},
                randomness::{
                    MPCEncryptionRandomGenerator, MPCMaskRandomGenerator, MPCNoiseRandomGenerator,
                },
                utils::reconstruct_bit_vec,
            },
        },
        networking::NetworkMode,
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::allocate_and_generate_lwe_bootstrap_key;

    #[test]
    #[ignore] //Ignore for now, might be able to run on CI with bigger timeout though
    fn test_lwe_bootstrap_key() {
        //Testing with small parameters, as NIST params take too long
        let lwe_dimension = 32_usize;
        let polynomial_size = 128_usize;
        let glwe_dimension = 2_usize;
        let t_uniform_bound_glwe = 5_usize;
        let bk_base_log = 18_usize;
        let bk_level_count = 3_usize;
        let seed = 42;

        let num_key_bits_lwe = lwe_dimension;
        let num_key_bits_glwe = glwe_dimension * polynomial_size;

        let mut task = |mut session: LargeSession| async move {
            let xof_seed = XofSeed::new_u128(seed, *b"TEST_GEN");
            let mut dummy_preproc = DummyPreprocessing::new(seed as u64, &session);

            //Generate the Lwe key
            let lwe_secret_key_share = LweSecretKeyShare::<Z128, 4>::new_from_preprocessing(
                LweDimension(lwe_dimension),
                &mut dummy_preproc,
            )
            .unwrap();

            //Generate the Glwe key
            let glwe_secret_key_share = GlweSecretKeyShare::<Z128, 4>::new_from_preprocessing(
                num_key_bits_glwe,
                PolynomialSize(polynomial_size),
                &mut dummy_preproc,
            )
            .unwrap();

            //Prepare enough noise for the bk
            let t_uniform_amount =
                lwe_dimension * (glwe_dimension + 1) * bk_level_count * polynomial_size;
            let vec_tuniform_noise = RealSecretDistributions::t_uniform(
                t_uniform_amount,
                TUniformBound(t_uniform_bound_glwe),
                &mut dummy_preproc,
            )
            .unwrap()
            .iter()
            .map(|share| share.value())
            .collect_vec();

            let mut mpc_encryption_rng = MPCEncryptionRandomGenerator {
                mask: MPCMaskRandomGenerator::<SoftwareRandomGenerator>::new_from_seed(
                    xof_seed.clone(),
                ),
                noise: MPCNoiseRandomGenerator {
                    vec: vec_tuniform_noise,
                },
            };

            //Generate the bk
            let bk_share = allocate_and_generate_lwe_bootstrap_key(
                &lwe_secret_key_share,
                &glwe_secret_key_share,
                DecompositionBaseLog(bk_base_log),
                DecompositionLevelCount(bk_level_count),
                &mut mpc_encryption_rng,
                EncryptionType::Bits128,
                &mut session,
                &mut dummy_preproc,
            )
            .await
            .unwrap();

            let bk = bk_share
                .clone()
                .open_to_tfhers_type::<u128, _>(&session)
                .await
                .unwrap();
            let bk_compressed = bk_share
                .open_to_tfhers_seeded_type(seed, &session)
                .await
                .unwrap();

            assert_eq!(
                bk,
                par_decompress_into_lwe_bootstrap_key_generated_from_xof::<
                    _,
                    SoftwareRandomGenerator,
                >(bk_compressed.clone(), xof_seed.domain_separator())
            );

            (
                session.my_role(),
                lwe_secret_key_share,
                glwe_secret_key_share,
                bk,
            )
        };

        let parties = 5;
        let threshold = 1;

        //This is Async because triples are generated from dummy preprocessing
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        let mut lwe_key_shares = HashMap::new();
        let mut glwe_key_shares = HashMap::new();
        let bk_ref = results[0].3.clone();
        for (role, lwe_share, glwe_share, bk) in results.into_iter() {
            assert_eq!(bk_ref, bk);

            lwe_key_shares.insert(role, Vec::new());
            let lwe_key_shares = lwe_key_shares.get_mut(&role).unwrap();
            for key_share in lwe_share.data.into_iter() {
                (*lwe_key_shares).push(key_share);
            }

            glwe_key_shares.insert(role, Vec::new());
            let glwe_key_shares = glwe_key_shares.get_mut(&role).unwrap();
            for key_share in glwe_share.data.into_iter() {
                (*glwe_key_shares).push(key_share)
            }
        }
        //Try and reconstruct the keys
        let lwe_key = reconstruct_bit_vec(lwe_key_shares, num_key_bits_lwe, threshold);

        let glwe_key = reconstruct_bit_vec(glwe_key_shares, num_key_bits_glwe, threshold);

        //Cast both secret keys to tfhe-rs
        let lwe_secret_key = LweSecretKeyOwned::from_container(lwe_key.clone());

        let lwe_secret_key_lifted_128 =
            LweSecretKeyOwned::from_container(lwe_key.iter().map(|b| *b as u128).collect_vec());

        let glwe_secret_key = GlweSecretKeyOwned::from_container(
            glwe_key.iter().map(|bit| *bit as u128).collect_vec(),
            PolynomialSize(polynomial_size),
        );

        let mut rng = get_rng();
        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(seed_from_rng(&mut rng));
        let mut enc_rng = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );

        //We want to make sure tfhers and our bk are encryptions of the same thing
        let bk_tfhers = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_secret_key_lifted_128,
            &glwe_secret_key,
            DecompositionBaseLog(bk_base_log),
            DecompositionLevelCount(bk_level_count),
            DynamicDistribution::TUniform(TUniform::new(t_uniform_bound_glwe.try_into().unwrap())),
            CoreCiphertextModulus::<u128>::new_native(),
            &mut enc_rng,
        );

        //Decrypt all the underlying glwe ctxt and check they are all correct
        //the BK is a list of lwe_dimension GGSW ciphertext (one GGSW ctxt for each lwe key bit)
        assert_eq!(
            bk_ref.deref().ggsw_ciphertext_count().0,
            lwe_secret_key.lwe_dimension().0
        );
        for ((ggsw_1, ggsw_2), &input_key_bit) in bk_ref
            .iter()
            .zip_eq(bk_tfhers.iter())
            .zip_eq(lwe_secret_key.as_ref())
        {
            //Here ggsw is a ggsw encryption of the keybit input_key_bit
            let decrypted_ggsw_1 = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw_1);
            let decrypted_ggsw_2 = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw_1);
            assert_eq!(decrypted_ggsw_1.0, input_key_bit as u128);
            assert_eq!(decrypted_ggsw_1, decrypted_ggsw_2);

            //A GGSW ciphertext is a list of GgswLevelMatrix (one GgswLevelMatrix for each level)
            for (level_idx, (ggsw_matrix_1, ggsw_matrix_2)) in
                ggsw_1.iter().zip_eq(ggsw_2.iter()).enumerate()
            {
                //A GgswLevelMatrix is a list of GlweCiphertext (one GlweCiphertext for each glwe key bit-poly)
                //Except the last row which is the plain message
                for (glwe_ctxt_1, glwe_ctxt_2) in ggsw_matrix_1
                    .as_glwe_list()
                    .iter()
                    .zip_eq(ggsw_matrix_2.as_glwe_list().iter())
                {
                    let mut decrypted_plaintext_list_1 =
                        PlaintextList::new(0_u128, PlaintextCount(polynomial_size));
                    decrypt_glwe_ciphertext(
                        &glwe_secret_key,
                        &glwe_ctxt_1,
                        &mut decrypted_plaintext_list_1,
                    );

                    let mut decrypted_plaintext_list_2 =
                        PlaintextList::new(0_u128, PlaintextCount(polynomial_size));
                    decrypt_glwe_ciphertext(
                        &glwe_secret_key,
                        &glwe_ctxt_2,
                        &mut decrypted_plaintext_list_2,
                    );

                    let decomposer = SignedDecomposer::new(
                        DecompositionBaseLog(bk_base_log * (level_idx + 1)),
                        DecompositionLevelCount(1),
                    );

                    decrypted_plaintext_list_1
                        .iter_mut()
                        .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));

                    decrypted_plaintext_list_2
                        .iter_mut()
                        .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
                    assert_eq!(decrypted_plaintext_list_1, decrypted_plaintext_list_2);
                }
            }
        }
    }
}
