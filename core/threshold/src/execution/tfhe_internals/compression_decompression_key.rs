use serde::{Deserialize, Serialize};
use tfhe::{
    boolean::prelude::{GlweDimension, PolynomialSize},
    shortint::parameters::CompressionParameters,
    Versionize,
};
use tfhe_versionable::VersionsDispatch;

use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, Ring},
    },
    execution::online::preprocessing::BitPreprocessing,
};

use super::{glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare};

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CompressionPrivateKeySharesVersioned<Z: Clone, const EXTENSION_DEGREE: usize> {
    V0(CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>),
}

///Structure that holds a share of the LWE key
/// - data contains shares of the key components
#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(CompressionPrivateKeySharesVersioned)]
pub struct CompressionPrivateKeyShares<Z: Clone, const EXTENSION_DEGREE: usize> {
    pub post_packing_ks_key: GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub params: CompressionParameters,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    pub fn new_from_preprocessing<
        P: BitPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    >(
        params: CompressionParameters,
        preprocessing: &mut P,
    ) -> anyhow::Result<Self> {
        let total_size = params.packing_ks_glwe_dimension.0 * params.packing_ks_polynomial_size.0;
        Ok(Self {
            post_packing_ks_key: GlweSecretKeyShare::new_from_preprocessing(
                total_size,
                params.packing_ks_polynomial_size,
                preprocessing,
            )?,
            params,
        })
    }

    pub fn data_as_raw_vec(&self) -> Vec<ResiduePoly<Z, EXTENSION_DEGREE>> {
        self.post_packing_ks_key.data_as_raw_vec()
    }

    pub fn into_lwe_secret_key(self) -> LweSecretKeyShare<Z, EXTENSION_DEGREE> {
        self.post_packing_ks_key.into_lwe_secret_key()
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.post_packing_ks_key.glwe_dimension()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.post_packing_ks_key.polynomial_size()
    }
}
