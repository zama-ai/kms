use itertools::EitherOrBoth;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tfhe::{
    core_crypto::prelude::ByteRandomGenerator,
    shortint::parameters::{DecompositionBaseLog, DecompositionLevelCount},
};

use crate::{
    algebra::{
        residue_poly::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{online::preprocessing::TriplePreprocessing, runtime::session::BaseSessionHandles},
};

use super::{
    ggsw_ciphertext::{encrypt_constant_ggsw_ciphertext, ggsw_encode_messages},
    glwe_key::GlweSecretKeyShare,
    lwe_bootstrap_key::LweBootstrapKeyShare,
    lwe_key::LweSecretKeyShare,
    parameters::EncryptionType,
    randomness::MPCEncryptionRandomGenerator,
};

pub async fn generate_lwe_bootstrap_key<Z, Gen, Rnd, S, P>(
    input_lwe_secret_key: &LweSecretKeyShare<Z>,
    output_glwe_secret_key: &GlweSecretKeyShare<Z>,
    output: &mut LweBootstrapKeyShare<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preproc: &mut P,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
    Rnd: Rng + CryptoRng,
    S: BaseSessionHandles<Rnd>,
    P: TriplePreprocessing<ResiduePoly<Z>> + ?Sized,
    ResiduePoly<Z>: ErrorCorrect,
{
    let encryption_type = output.encryption_type();
    let gen_iter = generator.fork_bsk_to_ggsw(
        output.input_lwe_dimension(),
        output.decomposition_level_count(),
        output.glwe_size(),
        output.polynomial_size(),
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
            )?;
        } else {
            return Err(anyhow_error_and_log("zip error"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn allocate_and_generate_lwe_bootstrap_key<Z, Gen, Rnd, S, P>(
    input_lwe_secret_key: &LweSecretKeyShare<Z>,
    output_glwe_secret_key: &GlweSecretKeyShare<Z>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    encryption_type: EncryptionType,
    session: &mut S,
    preproc: &mut P,
) -> anyhow::Result<LweBootstrapKeyShare<Z>>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
    Rnd: Rng + CryptoRng,
    S: BaseSessionHandles<Rnd>,
    P: TriplePreprocessing<ResiduePoly<Z>> + ?Sized,
    ResiduePoly<Z>: ErrorCorrect,
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ops::Deref};

    use concrete_csprng::{generators::SoftwareRandomGenerator, seeders::Seeder};
    use itertools::Itertools;
    use tfhe::{
        core_crypto::{
            algorithms::{
                allocate_and_generate_new_lwe_bootstrap_key, decrypt_constant_ggsw_ciphertext,
                decrypt_glwe_ciphertext,
            },
            commons::{
                generators::{DeterministicSeeder, EncryptionRandomGenerator},
                math::{
                    decomposition::SignedDecomposer,
                    random::{ActivatedRandomGenerator, TUniform},
                },
                traits::{ContiguousEntityContainer, ContiguousEntityContainerMut},
            },
            entities::{GlweSecretKeyOwned, LweSecretKeyOwned, PlaintextList},
        },
        integer::parameters::DynamicDistribution,
        shortint::{
            parameters::{
                CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
                PolynomialSize,
            },
            wopbs::PlaintextCount,
        },
    };

    use crate::{
        algebra::{base_ring::Z128, residue_poly::ResiduePoly128},
        execution::{
            online::{
                gen_bits::{BitGenEven, RealBitGenEven},
                preprocessing::dummy::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            random::{get_rng, seed_from_rng},
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::{
                glwe_key::GlweSecretKeyShare,
                lwe_key::LweSecretKeyShare,
                parameters::EncryptionType,
                parameters::TUniformBound,
                randomness::{
                    MPCEncryptionRandomGenerator, MPCMaskRandomGenerator, MPCNoiseRandomGenerator,
                },
                utils::tests::reconstruct_bit_vec,
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
        let seed = 0;

        let num_key_bits_lwe = lwe_dimension;
        let num_key_bits_glwe = glwe_dimension * polynomial_size;

        let mut task = |mut session: LargeSession| async move {
            let mut large_preproc = DummyPreprocessing::new(seed as u64, session.clone());

            //Generate the Lwe key
            let lwe_secret_key_share = LweSecretKeyShare::<Z128> {
                data: RealBitGenEven::gen_bits_even(
                    num_key_bits_lwe,
                    &mut large_preproc,
                    &mut session,
                )
                .await
                .unwrap(),
            };

            //Generate the Glwe key
            let glwe_secret_key_share = GlweSecretKeyShare::<Z128> {
                data: RealBitGenEven::gen_bits_even(
                    num_key_bits_glwe,
                    &mut large_preproc,
                    &mut session,
                )
                .await
                .unwrap(),
                polynomial_size: PolynomialSize(polynomial_size),
            };

            //Prepare enough noise for the bk
            let t_uniform_amount =
                lwe_dimension * (glwe_dimension + 1) * bk_level_count * polynomial_size;
            let vec_tuniform_noise = RealSecretDistributions::t_uniform(
                t_uniform_amount,
                TUniformBound(t_uniform_bound_glwe),
                &mut large_preproc,
            )
            .unwrap()
            .iter()
            .map(|share| share.value())
            .collect_vec();

            let mut mpc_encryption_rng = MPCEncryptionRandomGenerator {
                mask: MPCMaskRandomGenerator::<SoftwareRandomGenerator>::new_from_seed(seed),
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
                &mut large_preproc,
            )
            .await
            .unwrap();

            let bk = bk_share
                .open_to_tfhers_type::<u128, _, _>(&session)
                .await
                .unwrap();

            (
                session.my_role().unwrap(),
                lwe_secret_key_share,
                glwe_secret_key_share,
                bk,
            )
        };

        let parties = 5;
        let threshold = 1;

        //This is Async because triples are generated from dummy preprocessing
        //Delay P1 by 1s every round
        let delay_vec = vec![std::time::Duration::from_secs(1)];
        let results = execute_protocol_large::<ResiduePoly128, _, _>(
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
            DeterministicSeeder::<ActivatedRandomGenerator>::new(seed_from_rng(&mut rng));
        let mut enc_rng = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
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
            .zip(bk_tfhers.iter())
            .zip(lwe_secret_key.as_ref())
        {
            //Here ggsw is a ggsw encryption of the keybit input_key_bit
            let decrypted_ggsw_1 = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw_1);
            let decrypted_ggsw_2 = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw_1);
            assert_eq!(decrypted_ggsw_1.0, input_key_bit as u128);
            assert_eq!(decrypted_ggsw_1, decrypted_ggsw_2);

            //A GGSW ciphertext is a list of GgswLevelMatrix (one GgswLevelMatrix for each level)
            for (level_idx, (ggsw_matrix_1, ggsw_matrix_2)) in
                ggsw_1.iter().zip(ggsw_2.iter()).enumerate()
            {
                //A GgswLevelMatrix is a list of GlweCiphertext (one GlweCiphertext for each glwe key bit-poly)
                //Except the last row which is the plain message
                for (glwe_ctxt_1, glwe_ctxt_2) in ggsw_matrix_1
                    .as_glwe_list()
                    .iter()
                    .zip(ggsw_matrix_2.as_glwe_list().iter())
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
