use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tfhe::{
    shortint::parameters::{GlweDimension, PolynomialSize},
    Versionize,
};
use tfhe_versionable::VersionsDispatch;

use crate::{
    algebra::{galois_rings::degree_8::ResiduePolyF8, structure_traits::BaseRing},
    execution::{online::preprocessing::BitPreprocessing, sharing::share::Share},
};

use super::lwe_key::LweSecretKeyShare;

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum GlweSecretKeyShareVersioned<Z: Clone> {
    V0(GlweSecretKeyShare<Z>),
}

/// Structure that holds a share of a GLWE secret key
///
/// - data contains share of the key (i.e. shares of w polynomial with binary coefficients each of degree polynomial_size-1)
///   shares are in the galois extension domain but the underlying secret is really a bit in the underlying [`BaseRing`]
/// - polynomial_size is the total number of coefficients in the above polynomials
#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(GlweSecretKeyShareVersioned)]
pub struct GlweSecretKeyShare<Z: Clone> {
    pub data: Vec<Share<ResiduePolyF8<Z>>>,
    pub polynomial_size: PolynomialSize,
}

impl<Z: BaseRing> GlweSecretKeyShare<Z> {
    pub fn new_from_preprocessing<P: BitPreprocessing<ResiduePolyF8<Z>> + ?Sized>(
        total_size: usize,
        polynomial_size: PolynomialSize,
        preprocessing: &mut P,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            data: preprocessing.next_bit_vec(total_size)?,
            polynomial_size,
        })
    }

    pub fn data_as_raw_vec(&self) -> Vec<ResiduePolyF8<Z>> {
        self.data.iter().map(|share| share.value()).collect_vec()
    }

    pub fn into_lwe_secret_key(self) -> LweSecretKeyShare<Z> {
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
