use serde::{Deserialize, Serialize};
use tfhe::{
    boolean::prelude::{GlweDimension, PolynomialSize},
    shortint::parameters::{CompressionParameters, NoiseSquashingCompressionParameters},
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

trait CombinedCompressionParam<Z: Clone, const EXTENSION_DEGREE: usize> {
    fn packing_ks_glwe_dimension(&self) -> GlweDimension;
    fn packing_ks_polynomial_size(&self) -> PolynomialSize;
}

impl<Z: Clone, const EXTENSION_DEGREE: usize> CombinedCompressionParam<Z, EXTENSION_DEGREE>
    for CompressionParameters
{
    fn packing_ks_glwe_dimension(&self) -> GlweDimension {
        self.packing_ks_glwe_dimension
    }

    fn packing_ks_polynomial_size(&self) -> PolynomialSize {
        self.packing_ks_polynomial_size
    }
}

impl<Z: Clone, const EXTENSION_DEGREE: usize> CombinedCompressionParam<Z, EXTENSION_DEGREE>
    for NoiseSquashingCompressionParameters
{
    fn packing_ks_glwe_dimension(&self) -> GlweDimension {
        self.packing_ks_glwe_dimension
    }

    fn packing_ks_polynomial_size(&self) -> PolynomialSize {
        self.packing_ks_polynomial_size
    }
}

fn new_from_preprocessing<
    Z: BaseRing,
    const EXTENSION_DEGREE: usize,
    Param: CombinedCompressionParam<Z, EXTENSION_DEGREE>,
    P: BitPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
>(
    params: Param,
    preprocessing: &mut P,
) -> anyhow::Result<GlweSecretKeyShare<Z, EXTENSION_DEGREE>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    let total_size = params.packing_ks_glwe_dimension().0 * params.packing_ks_polynomial_size().0;
    GlweSecretKeyShare::new_from_preprocessing(
        total_size,
        params.packing_ks_polynomial_size(),
        preprocessing,
    )
}

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
        Ok(Self {
            post_packing_ks_key: new_from_preprocessing(params, preprocessing)?,
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
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    pub fn new_from_preprocessing<
        P: BitPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    >(
        params: NoiseSquashingCompressionParameters,
        preprocessing: &mut P,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            post_packing_ks_key: new_from_preprocessing(params, preprocessing)?,
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
