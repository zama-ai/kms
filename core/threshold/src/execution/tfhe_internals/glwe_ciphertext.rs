use tfhe::{
    core_crypto::commons::traits::ByteRandomGenerator, shortint::parameters::PolynomialSize,
};

use crate::algebra::{
    residue_poly::ResiduePoly,
    structure_traits::{BaseRing, Zero},
};

use super::{
    glwe_key::GlweSecretKeyShare,
    randomness::{EncryptionType, MPCEncryptionRandomGenerator},
    utils::polynomial_wrapping_add_multisum_assign,
};

#[derive(Clone, Debug, PartialEq, Eq)]
///Structure that holds a share of a  Glwe ctxt
/// - mask holds the masks in a "flatten" way.
/// Each mask is a polynomial, so the Vec holds
/// multiple polynomials, each as a list of coefs
/// - body is the B part, also a polynomial held as a list of coefs
pub struct GlweCiphertextShare<Z: BaseRing> {
    //Integration note: if it's easier,
    //we can probably have both the mask and body of the same type
    //Just then need to be carefull how we handle mask sampling
    pub mask: Vec<Z>,
    pub body: Vec<ResiduePoly<Z>>,
    pub polynomial_size: PolynomialSize,
    pub encryption_type: EncryptionType,
}

impl<Z: BaseRing> GlweCiphertextShare<Z> {
    pub fn new(
        polynomial_size: PolynomialSize,
        glwe_dimension: usize,
        encryption_type: EncryptionType,
    ) -> Self {
        Self {
            mask: vec![Z::default(); polynomial_size.0 * glwe_dimension],
            body: vec![ResiduePoly::ZERO; polynomial_size.0],
            polynomial_size,
            encryption_type,
        }
    }
    ///Properly allocate the mask space and put the encoded_message into the body
    /// for in-place encryption.
    ///
    /// encoded_message means the message should already be scaled with the desired scaling factor
    pub fn new_from_encoded_message(
        encoded_message: Vec<ResiduePoly<Z>>,
        polynomial_size: PolynomialSize,
        glwe_dimension: usize,
        encryption_type: EncryptionType,
    ) -> Self {
        GlweCiphertextShare {
            mask: vec![Z::default(); polynomial_size.0 * glwe_dimension],
            body: encoded_message,
            polynomial_size,
            encryption_type,
        }
    }
    //Get mutable handles over the mask and body of a share of a glwe ctxt
    pub fn get_mut_mask_and_body(&mut self) -> (&mut Vec<Z>, &mut Vec<ResiduePoly<Z>>) {
        (&mut self.mask, &mut self.body)
    }

    pub fn get_mut_body(&mut self) -> &mut Vec<ResiduePoly<Z>> {
        &mut self.body
    }
}

///Encrypt a message contained in the output
/// e.g. output should be the output of a [`GlweCiphertextShare::new_from_encoded_message`] call
pub fn encrypt_glwe_ciphertext_assign<Gen, Z>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
    output: &mut GlweCiphertextShare<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Gen: ByteRandomGenerator,
    Z: BaseRing,
{
    let encryption_type = output.encryption_type;
    let (mask, body) = output.get_mut_mask_and_body();

    fill_glwe_mask_and_body_for_encryption_assign(
        glwe_secret_key_share,
        mask,
        body,
        generator,
        encryption_type,
    )
}

fn fill_glwe_mask_and_body_for_encryption_assign<Z, Gen>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
    output_mask: &mut [Z],
    output_body: &mut [ResiduePoly<Z>],
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    encryption_type: EncryptionType,
) -> anyhow::Result<()>
where
    Gen: ByteRandomGenerator,
    Z: BaseRing,
{
    //Sample the mask
    generator.fill_slice_with_random_mask_custom_mod(output_mask, encryption_type);
    //Put the noise in the body
    generator.unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign(output_body)?;

    //Do the inner product between mask and key and add it to the body
    polynomial_wrapping_add_multisum_assign(output_body, output_mask, glwe_secret_key_share)
}

///Returns a tuple (number_of_triples,number_of_random) required for mpc glwe encrpytion
pub fn get_batch_param_glwe_enc(
    num_encryptions: usize,
    polynomial_size: PolynomialSize,
    t_uniform_bound: usize,
) -> (usize, usize) {
    (
        polynomial_size.0 * (t_uniform_bound + 2) * num_encryptions,
        polynomial_size.0 * (t_uniform_bound + 2) * num_encryptions,
    )
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
            algorithms::decrypt_glwe_ciphertext,
            commons::{
                math::decomposition::SignedDecomposer, parameters::GlweSize,
                traits::ContiguousEntityContainerMut,
            },
            entities::{GlweCiphertextOwned, GlweSecretKeyOwned, PlaintextList},
        },
        shortint::{
            parameters::{
                DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
            },
            wopbs::PlaintextCount,
            CiphertextModulus,
        },
    };

    use crate::{
        algebra::residue_poly::ResiduePoly64,
        execution::{
            online::{
                gen_bits::{BitGenEven, RealBitGenEven},
                preprocessing::dummy::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            runtime::{
                party::Role,
                session::{LargeSession, ParameterHandles},
            },
            sharing::{shamir::ShamirSharings, share::Share},
            tfhe_internals::{
                parameters::TUniformBound,
                randomness::{EncryptionType, MPCMaskRandomGenerator, MPCNoiseRandomGenerator},
                utils::tests::{reconstruct_bit_vec, reconstruct_glwe_body_vec},
            },
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::{
        encrypt_glwe_ciphertext_assign, GlweCiphertextShare, GlweSecretKeyShare,
        MPCEncryptionRandomGenerator,
    };
    use crate::execution::sharing::shamir::InputOp;

    //Test that we can encrypt with our code and decrypt with TFHE-rs
    #[test]
    #[ignore] //Fails on CI due to timeout
    fn test_glwe_encryption() {
        //Testing with NIST params P=8
        let polynomial_size = 512_usize;
        let polynomial_size = PolynomialSize(polynomial_size);
        let glwe_dimension = 3_usize;
        let message_log_modulus = 3_usize;
        let ctxt_log_modulus = 64_usize;
        let scaling = ctxt_log_modulus - message_log_modulus;
        let t_uniform_bound = 27;
        let seed = 0;
        let msg = 3;

        let num_key_bits = glwe_dimension * polynomial_size.0;

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let encoded_message = (0..polynomial_size.0)
                .map(|idx| {
                    ShamirSharings::share(
                        &mut AesRng::seed_from_u64(idx as u64),
                        ResiduePoly64::from_scalar(Wrapping(msg << scaling)),
                        session.num_parties(),
                        session.threshold() as usize,
                    )
                    .unwrap()
                    .shares[my_role.zero_based()]
                    .value()
                })
                .collect_vec();

            let t_uniform_amount = polynomial_size.0;

            let mut large_preproc = DummyPreprocessing::new(seed as u64, session.clone());

            let glwe_secret_key_share = GlweSecretKeyShare {
                data: RealBitGenEven::gen_bits_even(num_key_bits, &mut large_preproc, &mut session)
                    .await
                    .unwrap(),
                polynomial_size,
            };

            let vec_tuniform_noise = RealSecretDistributions::t_uniform(
                t_uniform_amount,
                TUniformBound(t_uniform_bound),
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

            let mut glwe_ctxt = GlweCiphertextShare::new_from_encoded_message(
                encoded_message,
                polynomial_size,
                glwe_dimension,
                EncryptionType::Bits64,
            );
            encrypt_glwe_ciphertext_assign(
                &glwe_secret_key_share,
                &mut glwe_ctxt,
                &mut mpc_encryption_rng,
            )
            .unwrap();

            (session.my_role().unwrap(), glwe_secret_key_share, glwe_ctxt)
        };
        let parties = 5;
        let threshold = 1;
        //Hopefully we should be able to reconstruct everything and decrypt using tfhe-rs ?
        let results =
            execute_protocol_large::<ResiduePoly64, _, _>(parties, threshold, None, &mut task);

        let mut glwe_ctxt_shares: HashMap<Role, Vec<Share<_>>> = HashMap::new();
        let mut glwe_key_shares: HashMap<Role, Vec<Share<_>>> = HashMap::new();
        let mask_ref = results[0].2.mask.clone();
        for (role, key_shares, ctxt_shares) in results {
            glwe_ctxt_shares.insert(role, Vec::new());
            glwe_key_shares.insert(role, Vec::new());
            let glwe_key_shares = glwe_key_shares.get_mut(&role).unwrap();
            let glwe_ctxt_shares = glwe_ctxt_shares.get_mut(&role).unwrap();
            for key_share in key_shares.data {
                (*glwe_key_shares).push(key_share);
            }
            for ctxt_share in ctxt_shares.body {
                (*glwe_ctxt_shares).push(Share::new(role, ctxt_share));
            }

            //Make sure all parties have the same mask
            assert_eq!(mask_ref, ctxt_shares.mask);
        }

        //Try and reconstruct the key
        let key = reconstruct_bit_vec(glwe_key_shares, num_key_bits, threshold);

        //Try and reconstruct the body
        let body = &reconstruct_glwe_body_vec(glwe_ctxt_shares, 1, polynomial_size.0, threshold)[0];

        //Cast everything into tfhe-rs types
        let glwe_dimension = GlweDimension(glwe_dimension);
        let glwe_secret_key = GlweSecretKeyOwned::from_container(key, polynomial_size);

        let ctxt_modulus = CiphertextModulus::new_native();
        let mut glwe_ctxt = GlweCiphertextOwned::new(
            0_u64,
            GlweSize(glwe_dimension.0 + 1),
            polynomial_size,
            ctxt_modulus,
        );
        let mut glwe_ctxt_mut_mask = glwe_ctxt.get_mut_mask();
        let underlying_container = glwe_ctxt_mut_mask.as_mut();
        assert_eq!(underlying_container.len(), mask_ref.len());
        for (c, m) in underlying_container.iter_mut().zip(mask_ref) {
            *c = m.0;
        }

        let mut glwe_ctxt_mut_body = glwe_ctxt.get_mut_body();
        let underlying_container = glwe_ctxt_mut_body.as_mut();
        assert_eq!(underlying_container.len(), body.len());
        for (c, m) in underlying_container.iter_mut().zip(body) {
            *c = m.0;
        }

        //Decrypt
        let mut decrypted_plaintext_list =
            PlaintextList::new(0_u64, PlaintextCount(polynomial_size.0));

        decrypt_glwe_ciphertext(&glwe_secret_key, &glwe_ctxt, &mut decrypted_plaintext_list);

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(message_log_modulus),
            DecompositionLevelCount(1),
        );

        decrypted_plaintext_list
            .iter_mut()
            .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));

        let mut cleartext_list = decrypted_plaintext_list.into_container();
        cleartext_list.iter_mut().for_each(|elt| *elt >>= scaling);

        cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
    }
}
