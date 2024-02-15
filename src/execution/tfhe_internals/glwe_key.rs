use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tfhe::shortint::parameters::{GlweDimension, PolynomialSize};

use crate::{
    algebra::{residue_poly::ResiduePoly, structure_traits::BaseRing},
    execution::sharing::share::Share,
};

use super::lwe_key::LweSecretKeyShare;

///Structure that holds a share of a GLWE secret key
///- data contains share of the key (i.e. shares of w polynomial with binary coefficients each of degree polynomial_size-1)
/// shares are in the galois extension domain but the underlying secret is really a bit in the underlyin [`BaseRing`]
///- polynomial_size is the total number of coefficients in the above polynomials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlweSecretKeyShare<Z> {
    pub data: Vec<Share<ResiduePoly<Z>>>,
    pub polynomial_size: PolynomialSize,
}

impl<Z: BaseRing> GlweSecretKeyShare<Z> {
    pub fn data_as_raw_vec(&self) -> Vec<ResiduePoly<Z>> {
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
