//! NOTE: To keep it closer to tfhe-rs, we do not implement GLev, but have it implicitly inside GGSW
//! (i.e. slightly differs from NIST api)
//
//! Went with the non-parallel version for now,
//! but it shouldn't be too hard to go with
//! parallel as that seems to be mainly related
//! to being able to parallelize randomness sampling.
//
//! Also, dealt with the fact that we have
//! an MPC multiplication inside the GGSW encryption
//! by asking the result of the mults to be input as part of the plaintext.
//! See [`ggsw_encode_message`]
use std::ops::Neg;

use crate::{
    algebra::{
        residue_poly::ResiduePoly,
        structure_traits::{BaseRing, Zero},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{preprocessing::Preprocessing, triple::mult_list},
        runtime::session::BaseSessionHandles,
        sharing::{shamir::ErrorCorrect, share::Share},
        tfhe_internals::utils::slice_wrapping_scalar_mul_assign,
    },
};

use super::{
    glwe_ciphertext::{
        encrypt_glwe_ciphertext_assign, get_batch_param_glwe_enc, GlweCiphertextShare,
    },
    glwe_key::GlweSecretKeyShare,
    randomness::{EncryptionType, MPCEncryptionRandomGenerator},
};
use itertools::{EitherOrBoth, Itertools};
use rand::{CryptoRng, Rng};
use tfhe::{
    core_crypto::{
        commons::{
            math::decomposition::DecompositionLevel, parameters::GlweSize,
            traits::ByteRandomGenerator,
        },
        entities::ggsw_level_matrix_size,
    },
    shortint::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    },
};

#[derive(Clone)]
pub struct GgswLevelMatrixShare<Z: BaseRing> {
    pub data: Vec<GlweCiphertextShare<Z>>,
    glwe_size: GlweSize,
    //polynomial_size: PolynomialSize,
}

impl<Z: BaseRing> GgswLevelMatrixShare<Z> {
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }
}

impl<Z: BaseRing> GgswLevelMatrixShare<Z> {
    pub fn new(
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        encryption_type: EncryptionType,
    ) -> Self {
        Self {
            data: (0..glwe_size.0)
                .map(|_| {
                    GlweCiphertextShare::<Z>::new_from_encoded_message(
                        vec![ResiduePoly::ZERO; polynomial_size.0],
                        polynomial_size,
                        glwe_size.to_glwe_dimension().0,
                        encryption_type,
                    )
                })
                .collect_vec(),
            glwe_size,
        }
    }
}

impl<Z: BaseRing> GgswLevelMatrixShare<Z> {
    pub fn as_mut_glwe_list(&mut self) -> &mut Vec<GlweCiphertextShare<Z>> {
        &mut self.data
    }
}

#[derive(Clone)]
pub struct GgswCiphertextShare<Z: BaseRing> {
    pub data: Vec<GgswLevelMatrixShare<Z>>,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
}

impl<Z: BaseRing> GgswCiphertextShare<Z> {
    //Allocate new empty GgswCiphertextShare
    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        encryption_type: EncryptionType,
    ) -> Self {
        let data = (0..decomp_level_count.0)
            .map(|_| GgswLevelMatrixShare::new(polynomial_size, glwe_size, encryption_type))
            .collect_vec();
        Self {
            data,
            glwe_size,
            polynomial_size,
            decomp_base_log,
        }
    }

    pub fn ggsw_level_matrix_size(&self) -> usize {
        ggsw_level_matrix_size(self.glwe_size, self.polynomial_size)
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.len())
    }
}

pub async fn ggsw_encode_messages<
    Rnd: Rng + CryptoRng + Sync,
    Z: BaseRing,
    S: BaseSessionHandles<Rnd>,
    P: Preprocessing<ResiduePoly<Z>>,
>(
    messages: &[Share<ResiduePoly<Z>>],
    key_bits: &GlweSecretKeyShare<Z>,
    session: &mut S,
    preproc: &mut P,
) -> anyhow::Result<Vec<Vec<Vec<ResiduePoly<Z>>>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let num_messages = messages.len();
    let size_mult = num_messages * key_bits.data.len();
    let triples = preproc.next_triple_vec(size_mult)?;
    let vectorized_message = messages
        .iter()
        .flat_map(|message| (0..key_bits.data.len()).map(|_| *message))
        .collect_vec();
    let vectorized_key_bits = (0..num_messages)
        .flat_map(|_| key_bits.data.clone())
        .collect_vec();
    let prods = mult_list(&vectorized_key_bits, &vectorized_message, triples, session).await?;

    let glwe_dimension = key_bits.glwe_dimension().0;
    let polynomial_size = key_bits.polynomial_size().0;
    let mut res = Vec::with_capacity(num_messages);
    for (idx, message) in messages.iter().enumerate() {
        let start_index = idx * glwe_dimension * polynomial_size;
        let end_index = (idx + 1) * glwe_dimension * polynomial_size;
        res.push(repack_single_message(
            prods.get(start_index..end_index).ok_or_else(|| anyhow_error_and_log(format!("prods of unexpected length, can not take slice with start_idx {start_index} and end_idx {end_index}")))?,
            polynomial_size,
            message,
        ))
    }
    Ok(res)
}

fn repack_single_message<Z>(
    prods: &[Share<ResiduePoly<Z>>],
    polynomial_size: usize,
    message: &Share<ResiduePoly<Z>>,
) -> Vec<Vec<ResiduePoly<Z>>>
where
    Z: BaseRing,
{
    let mut res = prods
        .iter()
        .chunks(polynomial_size)
        .into_iter()
        //We take negation wrt to Ciphertext domain,
        //which is big enough to also work as a negation
        //wrt to the respective plaintext domains after shifting
        .map(|chunk| chunk.map(|elem| elem.value().neg()).collect_vec())
        .collect_vec();
    res.push([message.value()].to_vec());
    res
}

///This functions compute the necessary encoding required for GGSW
///In particular this does the MPC multiplication between the shared key bits and the secret message
pub async fn ggsw_encode_message<
    Rnd: Rng + CryptoRng + Sync,
    Z: BaseRing,
    S: BaseSessionHandles<Rnd>,
    P: Preprocessing<ResiduePoly<Z>>,
>(
    message: &Share<ResiduePoly<Z>>,
    key_bits: &GlweSecretKeyShare<Z>,
    session: &mut S,
    preproc: &mut P,
) -> anyhow::Result<Vec<Vec<ResiduePoly<Z>>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    Ok(
        ggsw_encode_messages(&[*message], key_bits, session, preproc)
            .await?
            .remove(0),
    )
}

///Expect encoded to contain the the glwe_dimension + 1 plaintext that will be glev encoded.
///This is because we want to avoid having to do MPC multiplication here
///(as it'd require access to the session) and would make the function async
///
///Note that this means we have to move away a bit form tfhe-rs logic
///i.e. here encoded is s.t.
///- encoded\[i\] returns sharing of the ith polynomial to be GLev encrypted (len polynomial_size)
///- encoded\[-1\] returns sharing of the actual bit message message (len 1)
pub fn encrypt_constant_ggsw_ciphertext<Z, Gen>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
    output: &mut GgswCiphertextShare<Z>,
    encoded: Vec<Vec<ResiduePoly<Z>>>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    encryption_type: EncryptionType,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
{
    let gen_iter = generator
        .fork_ggsw_to_ggsw_levels(
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .expect("Failed to split generator into ggsw levels");

    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();

    for (level_index, level_matrix_generator) in
        output.data.iter_mut().zip_longest(gen_iter).enumerate()
    {
        if let EitherOrBoth::Both(level_matrix, mut generator) = level_matrix_generator {
            let decomp_level = DecompositionLevel(level_index + 1);

            //Note that here tfhe-rs still only works on the msg and
            // lets [`encrypt_constant_ggsw_level_matrix_row`] deal with with mult the proper key component)
            //but we cant do that as its a secret-secret mult (so ask for it as input, cf ggsw_encode_message)

            let factor = match encryption_type {
                EncryptionType::Bits64 => Z::ONE << (64 - (decomp_base_log.0 * decomp_level.0)),
                EncryptionType::Bits128 => Z::ONE << (128 - (decomp_base_log.0 * decomp_level.0)),
            };

            let gen_iter = generator
                .fork_ggsw_level_to_glwe(output_glwe_size, output_polynomial_size)
                .expect("Failed to split generator into glwe");

            let last_row_index = level_matrix.glwe_size().0 - 1;

            for row_index_row_as_glwe_generator in level_matrix
                .as_mut_glwe_list()
                .iter_mut()
                .enumerate()
                .zip_longest(gen_iter)
            {
                if let EitherOrBoth::Both((row_index, row_as_glwe), mut generator) =
                    row_index_row_as_glwe_generator
                {
                    ecnrypt_constant_ggsw_level_matrix_row(
                        glwe_secret_key_share,
                        (row_index, last_row_index),
                        factor,
                        row_as_glwe,
                        encoded
                            .get(row_index)
                            .ok_or_else(|| {
                                anyhow_error_and_log(format!(
                                    "Can't access encoded at index {row_index}"
                                ))
                            })?
                            .clone(),
                        &mut generator,
                    )?;
                } else {
                    return Err(anyhow_error_and_log("zip error.".to_string()));
                }
            }
        } else {
            return Err(anyhow_error_and_log("zip error.".to_string()));
        }
    }

    Ok(())
}

fn ecnrypt_constant_ggsw_level_matrix_row<Z, Gen>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
    (row_index, last_row_index): (usize, usize),
    factor: Z,
    row_as_glwe: &mut GlweCiphertextShare<Z>,
    encoded_row: Vec<ResiduePoly<Z>>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
{
    //Do proper scaling using the provided list of secret shared plaintexts
    if row_index < last_row_index {
        let body = row_as_glwe.get_mut_body();
        debug_assert_eq!(encoded_row.len(), body.len());
        *body = encoded_row;

        slice_wrapping_scalar_mul_assign(body, factor);
    } else {
        let body = row_as_glwe.get_mut_body();
        body.iter_mut().for_each(|e| *e = ResiduePoly::ZERO);
        body[0] = encoded_row[0] * factor;
    }

    encrypt_glwe_ciphertext_assign(glwe_secret_key_share, row_as_glwe, generator)
}

///Returns a tuple (number_of_triples,number_of_random) required for mpc ggsw encryption
pub fn get_batch_param_ggsw_encryption(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    decomp_level_count: DecompositionLevelCount,
    t_uniform_bound: usize,
) -> (usize, usize) {
    let num_mults = polynomial_size.0 * glwe_dimension.0;
    let num_glwe_encryptions = (glwe_dimension.0 + 1) * decomp_level_count.0;
    let glwe_batch_params =
        get_batch_param_glwe_enc(num_glwe_encryptions, polynomial_size, t_uniform_bound);
    (num_mults + glwe_batch_params.0, glwe_batch_params.1)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::Wrapping};

    use aes_prng::AesRng;
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use itertools::Itertools;
    use rand::SeedableRng;
    use tfhe::{
        core_crypto::{
            algorithms::decrypt_constant_ggsw_ciphertext,
            commons::traits::ContiguousEntityContainerMut,
            entities::{GgswCiphertext, GlweSecretKeyOwned},
        },
        shortint::{
            parameters::{
                DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
            },
            CiphertextModulus,
        },
    };

    use crate::execution::sharing::shamir::InputOp;
    use crate::{
        algebra::residue_poly::ResiduePoly64,
        execution::{
            online::{
                gen_bits::{BitGenEven, FakeBitGenEven, RealBitGenEven},
                preprocessing::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            runtime::{
                party::Role,
                session::{LargeSession, ParameterHandles},
            },
            sharing::{shamir::ShamirSharings, share::Share},
            tfhe_internals::{
                glwe_key::GlweSecretKeyShare,
                randomness::{
                    EncryptionType, MPCEncryptionRandomGenerator, MPCMaskRandomGenerator,
                    MPCNoiseRandomGenerator,
                },
                utils::tests::{reconstruct_bit_vec, reconstruct_glwe_body_vec},
            },
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::{encrypt_constant_ggsw_ciphertext, ggsw_encode_message, GgswCiphertextShare};

    //Test encryption with our code, decryption with tfhe-rs
    //Note that this does not really test the whole ggsw encryption, as decryption
    //only cares about the last row of the encryption matrix
    #[test]
    fn test_ggsw_encryption() {
        //Testing with NIST params in P=8
        let polynomial_size = 512_usize;
        let polynomial_size = PolynomialSize(polynomial_size);
        let glwe_dimension = GlweDimension(3_usize);
        let decomp_base_log = DecompositionBaseLog(18_usize);
        let decomp_level_count = DecompositionLevelCount(2_usize);
        let t_uniform_bound = 27_usize;

        let seed = 0;
        let msg = 3_u64;

        let num_key_bits = glwe_dimension.0 * polynomial_size.0;

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let shared_message = ShamirSharings::share(
                &mut AesRng::seed_from_u64(0),
                ResiduePoly64::from_scalar(Wrapping(msg)),
                session.num_parties(),
                session.threshold() as usize,
            )
            .unwrap()
            .shares[my_role.zero_based()];

            let t_uniform_amount =
                polynomial_size.0 * glwe_dimension.to_glwe_size().0 * decomp_level_count.0;

            let mut large_preproc = DummyPreprocessing::new(seed as u64, session.clone());

            let glwe_secret_key_share = GlweSecretKeyShare {
                data: RealBitGenEven::gen_bits_even(num_key_bits, &mut large_preproc, &mut session)
                    .await
                    .unwrap(),
                polynomial_size,
            };

            let encoded_message = ggsw_encode_message(
                &shared_message,
                &glwe_secret_key_share,
                &mut session,
                &mut large_preproc,
            )
            .await
            .unwrap();

            let vec_tuniform_noise =
                RealSecretDistributions::t_uniform::<_, _, _, _, FakeBitGenEven>(
                    t_uniform_amount,
                    t_uniform_bound,
                    &mut large_preproc,
                    &mut session,
                )
                .await
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

            let mut output: GgswCiphertextShare<_> = GgswCiphertextShare::new(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                EncryptionType::Bits64,
            );

            encrypt_constant_ggsw_ciphertext(
                &glwe_secret_key_share,
                &mut output,
                encoded_message,
                &mut mpc_encryption_rng,
                EncryptionType::Bits64,
            )
            .unwrap();

            (my_role, glwe_secret_key_share, output)
        };

        let parties = 5;
        let threshold = 1;

        let results =
            execute_protocol_large::<ResiduePoly64, _, _>(parties, threshold, None, &mut task);

        let mut glwe_key_shares: HashMap<Role, Vec<Share<_>>> = HashMap::new();
        let mut ggsw_ctxt_shares: HashMap<Role, Vec<Share<_>>> = HashMap::new();
        let mut ref_masks = Vec::new();
        for (role, key_shares, ctxt_shares) in results.iter() {
            glwe_key_shares.insert(*role, Vec::new());
            ggsw_ctxt_shares.insert(*role, Vec::new());
            let glwe_key_shares = glwe_key_shares.get_mut(role).unwrap();
            let ggsw_ctxt_shares = ggsw_ctxt_shares.get_mut(role).unwrap();
            for key_share in key_shares.data.iter() {
                (*glwe_key_shares).push(*key_share);
            }

            for (lvl_idx, level_matrix_share) in ctxt_shares.data.iter().enumerate() {
                for (idx, glwe_ctxt_share) in level_matrix_share.data.iter().enumerate() {
                    for ctxt_share in glwe_ctxt_share.body.iter() {
                        (*ggsw_ctxt_shares).push(Share::new(*role, *ctxt_share));
                    }

                    //Make sure the mask is the same for all parties for all underlying glwe ctxt
                    let ref_mask = results.first().unwrap().2.data[lvl_idx].data[idx]
                        .mask
                        .clone();
                    assert_eq!(glwe_ctxt_share.mask, ref_mask);
                    ref_masks.push(ref_mask);
                }
            }
        }

        //Try and reconstruct the key
        let key = reconstruct_bit_vec(glwe_key_shares, num_key_bits, threshold);

        //Try and reconstruct all the glwe ctxt
        let num_glwe_ctxt = (glwe_dimension.0 + 1) * decomp_level_count.0;
        let bodies = reconstruct_glwe_body_vec(
            ggsw_ctxt_shares,
            num_glwe_ctxt,
            polynomial_size.0,
            threshold,
        );

        //Cast everything into tfhe-rs types
        let glwe_secret_key = GlweSecretKeyOwned::from_container(key, polynomial_size);

        let mut ggsw = GgswCiphertext::new(
            0_u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            CiphertextModulus::new_native(),
        );
        let mut glwe_list = ggsw.as_mut_glwe_list();
        for (glwe_idx, mut glwe_ctxt) in glwe_list.iter_mut().enumerate() {
            let mut glwe_ctxt_mut_mask = glwe_ctxt.get_mut_mask();
            let underlying_container = glwe_ctxt_mut_mask.as_mut();
            assert_eq!(underlying_container.len(), ref_masks[glwe_idx].len());
            for (c, m) in underlying_container
                .iter_mut()
                .zip(ref_masks[glwe_idx].clone())
            {
                *c = m.0;
            }

            let mut glwe_ctxt_mut_body = glwe_ctxt.get_mut_body();
            let underlying_container = glwe_ctxt_mut_body.as_mut();
            assert_eq!(underlying_container.len(), bodies[glwe_idx].len());
            for (c, m) in underlying_container
                .iter_mut()
                .zip(bodies[glwe_idx].clone())
            {
                *c = m.0;
            }
        }

        let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
        assert_eq!(decrypted.0, msg);
    }
}
