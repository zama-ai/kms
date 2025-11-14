use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tfhe::{
    shortint::parameters::{GlweDimension, PolynomialSize},
    Versionize,
};
use tfhe_versionable::VersionsDispatch;

use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect},
    },
    execution::{
        online::preprocessing::BitPreprocessing,
        runtime::session::BaseSessionHandles,
        sharing::share::Share,
        tfhe_internals::{parameters::compute_min_max_hw, utils::compute_hamming_weight_glwe_sk},
    },
};

use super::lwe_key::LweSecretKeyShare;

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum GlweSecretKeyShareVersioned<Z: Clone, const EXTENSION_DEGREE: usize> {
    V0(GlweSecretKeyShare<Z, EXTENSION_DEGREE>),
}

/// Structure that holds a share of a GLWE secret key
///
/// - data contains share of the key (i.e. shares of w polynomial with binary coefficients each of degree polynomial_size-1)
///   shares are in the galois extension domain but the underlying secret is really a bit in the underlying [`BaseRing`]
/// - polynomial_size is the total number of coefficients in the above polynomials
#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(GlweSecretKeyShareVersioned)]
pub struct GlweSecretKeyShare<Z: Clone, const EXTENSION_DEGREE: usize> {
    pub data: Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>,
    pub polynomial_size: PolynomialSize,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> GlweSecretKeyShare<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    pub async fn new_from_preprocessing<
        P: BitPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
        S: BaseSessionHandles,
    >(
        total_size: usize,
        polynomial_size: PolynomialSize,
        preprocessing: &mut P,
        pmax: Option<f64>,
        session: &mut S,
    ) -> anyhow::Result<Self> {
        let data = if let Some(pmax) = pmax {
            // We need to consider GLWE keys as GlweDim keys of size polynomial_size
            let (min_hw, max_hw) = compute_min_max_hw(pmax, polynomial_size.0 as u64);
            let max_hw = Z::from_u128(max_hw as u128);
            let min_hw = Z::from_u128(min_hw as u128);

            let mut total_size = total_size;
            let mut data = Vec::with_capacity(total_size);
            loop {
                let local_data = preprocessing.next_bit_vec(total_size)?;

                // Safety check, should never happen as next_bit_vec should already error out if
                // that's the case
                if local_data.len() < total_size {
                    anyhow::bail!("Not enough data in preprocessing to sample a GLWE key");
                }

                let hws: Vec<Z> =
                    compute_hamming_weight_glwe_sk(&local_data, session, polynomial_size)
                        .await?
                        .into_iter()
                        .map(|x| x.to_scalar())
                        .try_collect()?;

                for (index, hw) in hws.into_iter().enumerate() {
                    if hw <= max_hw && hw >= min_hw {
                        tracing::info!("Hamming weight within bounds: {hw}, keeping this key.");
                        total_size -= polynomial_size.0;
                        data.extend_from_slice(
                            // Direct indexing here is safe we just checked the size
                            &local_data[index * polynomial_size.0..(index + 1) * polynomial_size.0],
                        );
                    } else {
                        tracing::info!(
                            "Hamming weight out of bounds: {hw}. Expected min : {min_hw}, max : {max_hw}"
                        );
                    }
                }

                if total_size == 0 {
                    tracing::info!("Sampled all necessary keys with correct hw");
                    break;
                }
            }
            data
        } else {
            preprocessing.next_bit_vec(total_size)?
        };

        Ok(Self {
            data,
            polynomial_size,
        })
    }

    pub fn data_as_raw_vec(&self) -> Vec<ResiduePoly<Z, EXTENSION_DEGREE>> {
        self.data.iter().map(|share| share.value()).collect_vec()
    }

    pub fn into_lwe_secret_key(self) -> LweSecretKeyShare<Z, EXTENSION_DEGREE> {
        LweSecretKeyShare { data: self.data }
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.data.len() / self.polynomial_size.0)
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }
}

///Returns a tuple (number_of_triples,number_of_random) required for generating a glwe key
pub fn get_batch_param_glwe_key_gen(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
) -> (usize, usize) {
    (
        polynomial_size.0 * glwe_dimension.0,
        polynomial_size.0 * glwe_dimension.0,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aes_prng::AesRng;
    use itertools::Itertools;
    use num_integer::Integer;
    use rand::SeedableRng;
    use tfhe::shortint::parameters::{GlweDimension, PolynomialSize};

    use crate::{
        algebra::{
            galois_rings::degree_4::ResiduePolyF4Z64,
            structure_traits::{One, Ring, Zero},
        },
        execution::{
            online::preprocessing::{dummy::DummyPreprocessing, memory::InMemoryBitPreprocessing},
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::utils::reconstruct_bit_vec,
        },
        networking::NetworkMode,
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::GlweSecretKeyShare;

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_forced_hw_keygen_glwe() {
        // Params such that we need each of the 3 keys with HW between 4 and 6
        let pmax = 0.6;
        let glwe_dim = GlweDimension(3);
        let key_size = 10;
        let polynomial_size = PolynomialSize(key_size);
        let total_size = glwe_dim.0 * polynomial_size.0;

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role();
            let mut rng = AesRng::seed_from_u64(42);

            let my_share_of_zero = DummyPreprocessing::share(
                session.num_parties(),
                session.threshold(),
                ResiduePolyF4Z64::ZERO,
                &mut rng,
            )
            .unwrap()[&my_role];

            let my_share_of_one = DummyPreprocessing::share(
                session.num_parties(),
                session.threshold(),
                ResiduePolyF4Z64::ONE,
                &mut rng,
            )
            .unwrap()[&my_role];

            // Create a vector of shares of zero and one to be used in preprocessing
            let available_bits = (0..2 * glwe_dim.0 * key_size)
                .map(|i| {
                    // Vector with a first chunk of  HW = 2
                    // and a second chunk of HW = 5
                    // for all keys
                    if i % (2 * key_size) <= key_size {
                        if i % (key_size / 2) == 0 {
                            my_share_of_one
                        } else {
                            my_share_of_zero
                        }
                    } else if i.is_even() {
                        my_share_of_one
                    } else {
                        my_share_of_zero
                    }
                })
                .collect_vec();

            let mut preprocessing = InMemoryBitPreprocessing { available_bits };

            let lwe_key = GlweSecretKeyShare::new_from_preprocessing(
                total_size,
                polynomial_size,
                &mut preprocessing,
                Some(pmax),
                &mut session,
            )
            .await
            .unwrap();
            (my_role, lwe_key)
        };

        let parties = 5;
        let threshold = 1;
        let results = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            None,
            NetworkMode::Async,
            None,
            &mut task,
        )
        .await;

        let mut glwe_key_shares = HashMap::new();
        for (role, key_shares) in results {
            glwe_key_shares.insert(role, Vec::new());
            let glwe_key_shares = glwe_key_shares.get_mut(&role).unwrap();
            for key_share in key_shares.data {
                (*glwe_key_shares).push(key_share);
            }
        }
        //Try and reconstruct the key
        let glwe_key = reconstruct_bit_vec(glwe_key_shares, total_size, threshold);

        for key in glwe_key.chunks(polynomial_size.0) {
            // Assert correct HW of the key
            let hw = key.iter().filter(|b| **b == 1).count();
            assert_eq!(hw, 5);
        }

        //Assert tracing contains "Hamming weight out of bounds"
        assert!(logs_contain(
            "Hamming weight out of bounds: 2. Expected min : 4, max : 6"
        ));
    }
}
