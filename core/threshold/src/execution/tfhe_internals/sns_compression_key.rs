use serde::{Deserialize, Serialize};
use tfhe::{
    boolean::prelude::{GlweDimension, PolynomialSize},
    shortint::parameters::NoiseSquashingCompressionParameters,
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
        runtime::sessions::base_session::BaseSessionHandles,
    },
};

use super::{glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare};

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum SnsCompressionPrivateKeySharesVersioned<Z: Clone, const EXTENSION_DEGREE: usize> {
    V0(SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(SnsCompressionPrivateKeySharesVersioned)]
pub struct SnsCompressionPrivateKeyShares<Z: Clone, const EXTENSION_DEGREE: usize> {
    pub post_packing_ks_key: GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub params: NoiseSquashingCompressionParameters,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    pub async fn new_from_preprocessing<
        P: BitPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
        S: BaseSessionHandles,
    >(
        params: NoiseSquashingCompressionParameters,
        preprocessing: &mut P,
        pmax: Option<f64>,
        session: &mut S,
    ) -> anyhow::Result<Self> {
        let total_size = params.packing_ks_glwe_dimension.0 * params.packing_ks_polynomial_size.0;
        Ok(Self {
            post_packing_ks_key: GlweSecretKeyShare::new_from_preprocessing(
                total_size,
                params.packing_ks_polynomial_size,
                preprocessing,
                pmax,
                session,
            )
            .await?,
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
