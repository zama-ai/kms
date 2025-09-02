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
        tfhe_internals::{
            parameters::compute_min_max_hw, utils::compute_hamming_weight_secret_vector_by_chunks,
        },
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

                let hws: Vec<Z> = compute_hamming_weight_secret_vector_by_chunks(
                    &local_data,
                    session,
                    polynomial_size.0,
                )
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
