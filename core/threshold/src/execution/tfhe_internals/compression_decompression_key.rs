use serde::{Deserialize, Serialize};
use tfhe::{
    boolean::prelude::{GlweDimension, PolynomialSize},
    shortint::parameters::CompressionParameters,
    Versionize,
};
use tfhe_versionable::VersionsDispatch;

use crate::{
    algebra::{galois_rings::degree_8::ResiduePolyF8, structure_traits::BaseRing},
    execution::online::preprocessing::BitPreprocessing,
};

use super::{glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare};

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CompressionPrivateKeySharesVersioned<Z: Clone> {
    V0(CompressionPrivateKeyShares<Z>),
}

///Structure that holds a share of the LWE key
/// - data contains shares of the key components
#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(CompressionPrivateKeySharesVersioned)]
pub struct CompressionPrivateKeyShares<Z: Clone> {
    pub post_packing_ks_key: GlweSecretKeyShare<Z>,
    pub params: CompressionParameters,
}

impl<Z: BaseRing> CompressionPrivateKeyShares<Z> {
    pub fn new_from_preprocessing<P: BitPreprocessing<ResiduePolyF8<Z>> + ?Sized>(
        params: CompressionParameters,
        preprocessing: &mut P,
    ) -> anyhow::Result<Self> {
        let total_size = params.packing_ks_glwe_dimension.0 * params.packing_ks_polynomial_size.0;
        let post_packing_ks_key = GlweSecretKeyShare::new_from_preprocessing(
            total_size,
            params.packing_ks_polynomial_size,
            preprocessing,
        )?;
        Ok(Self {
            post_packing_ks_key,
            params,
        })
    }

    pub fn data_as_raw_vec(&self) -> Vec<ResiduePolyF8<Z>> {
        self.post_packing_ks_key.data_as_raw_vec()
    }

    pub fn into_lwe_secret_key(self) -> LweSecretKeyShare<Z> {
        self.post_packing_ks_key.into_lwe_secret_key()
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.post_packing_ks_key.glwe_dimension()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.post_packing_ks_key.polynomial_size()
    }
}
