use itertools::{EitherOrBoth, Itertools};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::{commons::traits::ByteRandomGenerator, entities::LweCompactPublicKeyOwned},
    shortint::{
        parameters::{LweDimension, PolynomialSize},
        CiphertextModulus,
    },
};

use crate::{
    algebra::{residue_poly::ResiduePoly, structure_traits::BaseRing},
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::triple::open_list, runtime::session::BaseSessionHandles, sharing::share::Share,
    },
};

use super::{
    glwe_ciphertext::GlweCiphertextShare,
    randomness::{EncryptionType, MPCEncryptionRandomGenerator},
    utils::slice_semi_reverse_negacyclic_convolution,
};

///Structure that holds a share of the LWE key
/// - data contains shares of the key components
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LweSecretKeyShare<Z> {
    pub data: Vec<Share<ResiduePoly<Z>>>,
}

#[derive(Clone)]
pub struct LweCompactPublicKeyShare<Z: BaseRing> {
    pub glwe_ciphertext_share: GlweCiphertextShare<Z>,
}

impl<Z: BaseRing> LweCompactPublicKeyShare<Z> {
    pub fn new(lwe_dimension: LweDimension) -> Self {
        Self {
            glwe_ciphertext_share: GlweCiphertextShare::new(
                PolynomialSize(lwe_dimension.0),
                1,
                //The only Lwe public key we need is in the smaller domain
                EncryptionType::Bits64,
            ),
        }
    }

    pub fn get_mut_mask_and_body(&mut self) -> (&mut Vec<Z>, &mut Vec<ResiduePoly<Z>>) {
        self.glwe_ciphertext_share.get_mut_mask_and_body()
    }

    pub async fn open_to_tfhers_type<R: CryptoRngCore + Send + Sync, S: BaseSessionHandles<R>>(
        self,
        session: &S,
    ) -> anyhow::Result<LweCompactPublicKeyOwned<u64>> {
        let lwe_dimension = LweDimension(self.glwe_ciphertext_share.polynomial_size.0);
        let my_role = session.my_role()?;
        let shared_body = self
            .glwe_ciphertext_share
            .body
            .into_iter()
            .map(|value| Share::new(my_role, value))
            .collect_vec();
        let body: Vec<Z> = open_list(&shared_body, session)
            .await?
            .iter()
            .map(|value| value.to_scalar())
            .try_collect()?;

        let mut pk =
            LweCompactPublicKeyOwned::new(0_u64, lwe_dimension, CiphertextModulus::new_native());
        let (mut pk_mask, mut pk_body) = pk.get_mut_mask_and_body();
        let underlying_container = pk_mask.as_mut();
        for c_m in underlying_container
            .iter_mut()
            .zip_longest(self.glwe_ciphertext_share.mask)
        {
            if let EitherOrBoth::Both(c, m) = c_m {
                let m_byte_vec = m.to_byte_vec();
                let m = m_byte_vec.iter().rev().fold(0_u64, |acc, byte| {
                    acc.wrapping_shl(8).wrapping_add(*byte as u64)
                });
                *c = m;
            } else {
                return Err(anyhow_error_and_log("zip error".to_string()));
            }
        }

        let underlying_container = pk_body.as_mut();
        for c_m in underlying_container.iter_mut().zip_longest(body) {
            if let EitherOrBoth::Both(c, m) = c_m {
                let m_byte_vec = m.to_byte_vec();
                let m = m_byte_vec.iter().rev().fold(0_u64, |acc, byte| {
                    acc.wrapping_shl(8).wrapping_add(*byte as u64)
                });
                *c = m;
            } else {
                return Err(anyhow_error_and_log("zip error".to_string()));
            }
        }

        Ok(pk)
    }
}

impl<Z: BaseRing> LweSecretKeyShare<Z> {
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.len())
    }

    pub fn data_as_raw_vec(&self) -> Vec<ResiduePoly<Z>> {
        self.data.iter().map(|share| share.value()).collect_vec()
    }
}

pub fn allocate_and_generate_new_lwe_compact_public_key<Z, Gen>(
    lwe_secret_key: &LweSecretKeyShare<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<LweCompactPublicKeyShare<Z>>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
{
    let mut pk = LweCompactPublicKeyShare::new(lwe_secret_key.lwe_dimension());

    generate_lwe_compact_public_key(lwe_secret_key, &mut pk, generator)?;

    Ok(pk)
}

pub fn generate_lwe_compact_public_key<Z, Gen>(
    lwe_secret_key_share: &LweSecretKeyShare<Z>,
    output: &mut LweCompactPublicKeyShare<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
{
    let encryption_type = output.glwe_ciphertext_share.encryption_type;
    let (mask, body) = output.get_mut_mask_and_body();
    generator.fill_slice_with_random_mask_custom_mod(mask, encryption_type);

    slice_semi_reverse_negacyclic_convolution(body, mask, &lwe_secret_key_share.data_as_raw_vec())?;

    generator.unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign(body)
}

///Returns a tuple (number_of_triples, number_of_randomness) required for generating a lwe key
pub fn get_batch_param_lwe_key_gen(lwe_dimension: LweDimension) -> (usize, usize) {
    (lwe_dimension.0, lwe_dimension.0)
}

#[cfg(test)]
mod tests {
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use itertools::Itertools;
    use std::collections::HashMap;
    use tfhe::{
        core_crypto::{
            algorithms::{
                decrypt_lwe_ciphertext, encrypt_lwe_ciphertext_with_compact_public_key,
                misc::divide_round,
            },
            commons::{
                generators::{EncryptionRandomGenerator, SecretRandomGenerator},
                math::random::{ActivatedRandomGenerator, RandomGenerator},
            },
            entities::{LweCiphertext, LweSecretKeyOwned, Plaintext},
            seeders::new_seeder,
        },
        shortint::{
            parameters::{LweDimension, StandardDev},
            CiphertextModulus,
        },
        Seed,
    };

    use crate::{
        algebra::{base_ring::Z64, residue_poly::ResiduePoly64},
        execution::{
            online::{
                gen_bits::{BitGenEven, FakeBitGenEven, RealBitGenEven},
                preprocessing::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::{
                randomness::{
                    MPCEncryptionRandomGenerator, MPCMaskRandomGenerator, MPCNoiseRandomGenerator,
                },
                utils::tests::reconstruct_bit_vec,
            },
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::{allocate_and_generate_new_lwe_compact_public_key, LweSecretKeyShare};

    #[test]
    #[ignore] //This test requires a seeder which corresponds to a different feature depending on the architecture
    fn test_pk_generation() {
        let lwe_dimension = 1024_usize;
        let message_log_modulus = 3_usize;
        let ctxt_log_modulus = 64_usize;
        let t_uniform_bound = 41_usize;

        let num_key_bits = lwe_dimension;

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();

            let seed = 0;

            let mut large_preproc = DummyPreprocessing::new(seed as u64, session.clone());

            let vec_shared_bits =
                RealBitGenEven::gen_bits_even(num_key_bits, &mut large_preproc, &mut session)
                    .await
                    .unwrap();

            //Generate secret key
            let lwe_secret_key_share: LweSecretKeyShare<Z64> = LweSecretKeyShare {
                data: vec_shared_bits,
            };

            let mpc_mask_generator = MPCMaskRandomGenerator {
                gen: RandomGenerator::<SoftwareRandomGenerator>::new(Seed(seed)),
            };

            let vec_tuniform_noise =
                RealSecretDistributions::t_uniform::<_, _, _, _, FakeBitGenEven>(
                    lwe_dimension,
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
                mask: mpc_mask_generator,
                noise: MPCNoiseRandomGenerator {
                    vec: vec_tuniform_noise,
                },
            };

            //Generate public key
            let pk = allocate_and_generate_new_lwe_compact_public_key(
                &lwe_secret_key_share,
                &mut mpc_encryption_rng,
            )
            .unwrap();

            let opened_pk = pk.clone().open_to_tfhers_type(&session).await.unwrap();

            (my_role, lwe_secret_key_share, opened_pk)
        };

        let parties = 5;
        let threshold = 1;
        let results =
            execute_protocol_large::<ResiduePoly64, _, _>(parties, threshold, None, &mut task);

        let mut lwe_key_shares = HashMap::new();
        let opened_pk_ref = results[0].2.clone();
        for (role, key_shares, opened_pk) in results {
            lwe_key_shares.insert(role, Vec::new());
            let lwe_key_shares = lwe_key_shares.get_mut(&role).unwrap();
            for key_share in key_shares.data {
                (*lwe_key_shares).push(key_share);
            }
            assert_eq!(opened_pk_ref, opened_pk);
        }
        //Try and reconstruct the key
        let key = reconstruct_bit_vec(lwe_key_shares, num_key_bits, threshold);

        //Cast everything to tfhe-rs
        let lwe_secret_key = LweSecretKeyOwned::from_container(key);

        let ciphertext_modulus = CiphertextModulus::new_native();

        //Encrypt using public key
        let scaling = ctxt_log_modulus - message_log_modulus;
        let msg = 3_u64;
        let mut ct = LweCiphertext::new(
            0_u64,
            LweDimension(lwe_dimension).to_lwe_size(),
            ciphertext_modulus,
        );
        let plaintext = Plaintext(msg << scaling);

        //Using parameters from the config files in temp/default_params.json
        let mut seeder = new_seeder();
        let mut encryption_random_generator: EncryptionRandomGenerator<ActivatedRandomGenerator> =
            EncryptionRandomGenerator::new(seeder.seed(), seeder.as_mut());
        let mut secret_random_generator: SecretRandomGenerator<ActivatedRandomGenerator> =
            SecretRandomGenerator::new(seeder.seed());

        encrypt_lwe_ciphertext_with_compact_public_key(
            &opened_pk_ref,
            &mut ct,
            plaintext,
            StandardDev(3.15283466779972e-16),
            StandardDev(3.15283466779972e-16),
            &mut secret_random_generator,
            &mut encryption_random_generator,
        );
        //Decrypt using secret key
        let decrypted = decrypt_lwe_ciphertext(&lwe_secret_key, &ct);

        let decoded = divide_round(decrypted.0, 1 << scaling) % (1 << message_log_modulus);

        assert_eq!(msg, decoded);
    }
}
