use itertools::{EitherOrBoth, Itertools};
use tfhe::core_crypto::commons::{
    parameters::{LweCiphertextCount, LweSize},
    traits::ByteRandomGenerator,
};

use crate::{
    algebra::{residue_poly::ResiduePoly, structure_traits::BaseRing},
    error::error_handler::anyhow_error_and_log,
};

use super::{
    lwe_key::LweSecretKeyShare,
    randomness::{EncryptionType, MPCEncryptionRandomGenerator},
    utils::slice_wrapping_dot_product,
};

#[derive(Clone, Debug, PartialEq, Eq)]
///Structure that holds a share of a LWE ctxt
/// - mask holds the mask composed of [`BaseRing`] elements
/// - body is the b part, in it's shared domain so a [`ResiduePoly`]
pub struct LweCiphertextShare<Z: BaseRing> {
    pub mask: Vec<Z>,
    pub body: ResiduePoly<Z>,
}

impl<Z: BaseRing> LweCiphertextShare<Z> {
    pub fn new(lwe_size: LweSize) -> Self {
        Self {
            mask: vec![Z::default(); lwe_size.to_lwe_dimension().0],
            body: ResiduePoly::default(),
        }
    }
    pub fn get_mut_mask_and_body(&mut self) -> (&mut Vec<Z>, &mut ResiduePoly<Z>) {
        (&mut self.mask, &mut self.body)
    }

    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.mask.len() + 1)
    }
}

pub fn encrypt_lwe_ciphertext<Gen, Z>(
    lwe_secret_key_share: &LweSecretKeyShare<Z>,
    output: &mut LweCiphertextShare<Z>,
    encoded: ResiduePoly<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Gen: ByteRandomGenerator,
    Z: BaseRing,
{
    let (mask, body) = output.get_mut_mask_and_body();

    fill_lwe_mask_and_body_for_encryption(lwe_secret_key_share, mask, body, encoded, generator)
}

pub fn encrypt_lwe_ciphertext_list<Gen, Z>(
    lwe_secret_key_share: &LweSecretKeyShare<Z>,
    output: &mut [LweCiphertextShare<Z>],
    encoded: &[ResiduePoly<Z>],
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Gen: ByteRandomGenerator,
    Z: BaseRing,
{
    let gen_iter =
        generator.fork_lwe_list_to_lwe(LweCiphertextCount(output.len()), output[0].lwe_size())?;

    for encoded_plaintext_ciphertext_loop_generator in encoded
        .iter()
        .zip_longest(output.iter_mut())
        .zip_longest(gen_iter)
    {
        if let EitherOrBoth::Both(
            EitherOrBoth::Both(encoded_plaintext, ciphertext),
            mut loop_generator,
        ) = encoded_plaintext_ciphertext_loop_generator
        {
            encrypt_lwe_ciphertext(
                lwe_secret_key_share,
                ciphertext,
                *encoded_plaintext,
                &mut loop_generator,
            )?;
        } else {
            return Err(anyhow_error_and_log("zip error".to_string()));
        }
    }
    Ok(())
}

fn fill_lwe_mask_and_body_for_encryption<Z, Gen>(
    lwe_secret_key_share: &LweSecretKeyShare<Z>,
    output_mask: &mut [Z],
    output_body: &mut ResiduePoly<Z>,
    encoded: ResiduePoly<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Gen: ByteRandomGenerator,
    Z: BaseRing,
{
    //Sample the mask, the only LWE encryptions we need are in the small domain
    generator.fill_slice_with_random_mask_custom_mod(output_mask, EncryptionType::Bits64);

    //Pop one noise from rng
    let noise = generator.random_noise_custom_mod();

    //Compute the multisum betweem sk and mask
    let mask_key_dot_product =
        slice_wrapping_dot_product(output_mask, &lwe_secret_key_share.data_as_raw_vec())?;

    //Finish computing the body
    *output_body = mask_key_dot_product + noise + encoded;
    Ok(())
}

///Returns a tuple (number_of_triples, number_of_bits) required for mpc lwe encryption
pub fn get_batch_param_lwe_enc(num_encryptions: usize, t_uniform_bound: usize) -> (usize, usize) {
    (
        (t_uniform_bound + 2) * num_encryptions,
        (t_uniform_bound + 2) * num_encryptions,
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::Wrapping};

    use aes_prng::AesRng;
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use itertools::Itertools;
    use rand_core::SeedableRng;
    use tfhe::{
        core_crypto::{
            algorithms::decrypt_lwe_ciphertext,
            commons::math::decomposition::SignedDecomposer,
            entities::{LweCiphertextOwned, LweSecretKeyOwned},
        },
        shortint::{
            parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension},
            CiphertextModulus,
        },
    };

    use crate::{
        algebra::residue_poly::ResiduePoly64,
        execution::{
            online::{
                gen_bits::{BitGenEven, FakeBitGenEven, RealBitGenEven},
                preprocessing::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            runtime::session::{LargeSession, ParameterHandles},
            sharing::{shamir::ShamirSharing, share::Share},
            tfhe_internals::{
                randomness::{
                    MPCEncryptionRandomGenerator, MPCMaskRandomGenerator, MPCNoiseRandomGenerator,
                },
                utils::tests::reconstruct_bit_vec,
            },
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::{encrypt_lwe_ciphertext, LweCiphertextShare, LweSecretKeyShare};

    #[test]
    fn test_lwe_encryption() {
        //Testing with NIST params P=8
        let lwe_dimension = 1024_usize;
        let message_log_modulus = 3_usize;
        let ctxt_log_modulus = 64_usize;
        let scaling = ctxt_log_modulus - message_log_modulus;
        let t_uniform_bound = 41_usize;
        let msg = 3;
        let seed = 0;
        let num_key_bits = lwe_dimension;

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let encoded_message = ShamirSharing::share(
                &mut AesRng::seed_from_u64(0),
                ResiduePoly64::from_scalar(Wrapping(msg << scaling)),
                session.amount_of_parties(),
                session.threshold() as usize,
            )
            .unwrap()
            .shares[my_role.zero_based()]
            .value();

            let mut large_preproc = DummyPreprocessing::new(seed as u64, session.clone());

            let lwe_secret_key_share = LweSecretKeyShare {
                data: RealBitGenEven::gen_bits_even(num_key_bits, &mut large_preproc, &mut session)
                    .await
                    .unwrap(),
            };

            let vec_tuniform_noise =
                RealSecretDistributions::t_uniform::<_, _, _, _, FakeBitGenEven>(
                    1,
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

            let mut lwe_ctxt = LweCiphertextShare::new(LweDimension(lwe_dimension).to_lwe_size());
            encrypt_lwe_ciphertext(
                &lwe_secret_key_share,
                &mut lwe_ctxt,
                encoded_message,
                &mut mpc_encryption_rng,
            )
            .unwrap();
            (my_role, lwe_secret_key_share, lwe_ctxt)
        };

        let parties = 5;
        let threshold = 1;
        let results =
            execute_protocol_large::<ResiduePoly64, _, _>(parties, threshold, None, &mut task);

        //Reconstruct everything and decrypt using tfhe-rs

        let mut lwe_ctxt_shares = HashMap::new();
        let mut lwe_key_shares = HashMap::new();
        let mask_ref = results[0].2.mask.clone();
        for (role, key_shares, ctxt_share) in results {
            lwe_key_shares.insert(role, Vec::new());
            let lwe_key_shares = lwe_key_shares.get_mut(&role).unwrap();
            for key_share in key_shares.data {
                (*lwe_key_shares).push(key_share);
            }
            lwe_ctxt_shares.insert(role, Share::new(role, ctxt_share.body));

            //Make sure all parties have same mask
            assert_eq!(mask_ref, ctxt_share.mask);
        }

        //Try and reconstruct the key
        let key = reconstruct_bit_vec(lwe_key_shares, num_key_bits, threshold);

        //Try and reconstruct the body
        let body = {
            let vec_shares = lwe_ctxt_shares.into_values().collect_vec();
            ShamirSharing::create(vec_shares)
                .reconstruct(threshold)
                .unwrap()
                .to_scalar()
                .unwrap()
                .0
        };

        //Cast everything to tfhe-rs
        let lwe_dimension = LweDimension(lwe_dimension);
        let lwe_secret_key = LweSecretKeyOwned::from_container(key);

        let ctxt_modulus = CiphertextModulus::new_native();
        let mut lwe_ctxt =
            LweCiphertextOwned::new(0_u64, lwe_dimension.to_lwe_size(), ctxt_modulus);

        let mut lwe_ctxt_mut_mask = lwe_ctxt.get_mut_mask();
        let underlying_container = lwe_ctxt_mut_mask.as_mut();
        assert_eq!(underlying_container.len(), mask_ref.len());
        for (c, m) in underlying_container.iter_mut().zip(mask_ref) {
            *c = m.0;
        }

        let lwe_ctxt_mut_body = lwe_ctxt.get_mut_body();
        *lwe_ctxt_mut_body.data = body;

        let decrypted_plaintenxt = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ctxt);

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(message_log_modulus),
            DecompositionLevelCount(1),
        );

        let rounded = decomposer.closest_representable(decrypted_plaintenxt.0);

        let cleartext = rounded >> scaling;

        assert_eq!(msg, cleartext);
    }
}
