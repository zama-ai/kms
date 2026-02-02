use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::structure_traits::ErrorCorrect;
use crate::execution::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
#[cfg(feature = "testing")]
use crate::execution::tfhe_internals::parameters::DKGParams;
use crate::execution::tfhe_internals::sns_compression_key::SnsCompressionPrivateKeyShares;
use crate::{
    algebra::galois_rings::common::ResiduePoly,
    execution::tfhe_internals::{glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare},
};
use serde::{Deserialize, Serialize};

use tfhe::shortint::ClassicPBSParameters;
use tfhe::Versionize;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

pub(crate) struct GenericPrivateKeySet<Z: Clone, const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub lwe_secret_key_share: LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub glwe_secret_key_share: GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns: Option<GlweSecretKeyShare<Z, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_compression: Option<CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_sns_compression:
        Option<SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PrivateKeySetVersioned<const EXTENSION_DEGREE: usize> {
    /// V0 is the original private key set
    V0(PrivateKeySetV0<EXTENSION_DEGREE>),
    // V1 is the same as V0 with the addition of glwe_sns_compression_key
    V1(PrivateKeySetV1<EXTENSION_DEGREE>),
    V2(PrivateKeySet<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Versionize)]
#[versionize(PrivateKeySetVersioned)]
/// The private key set structure holding the secret key shares for each party
/// of the DKG. The keys can be either Z64 or Z128 depending on the DKG parameters.
/// But all keys in the set are of the same type after a DKG.
///
/// The only reason why type might differ is if the [`PrivateKeySet`] has just
/// been upgraded from a [`PrivateKeySetV1`] where the keys were still Z64.
/// In this case, one __must__ call `PrivateKeySet::lift` to make the [`PrivateKeySet`] conformant.
pub struct PrivateKeySet<const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub lwe_compute_secret_key_share: LweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub glwe_secret_key_share: GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_compression:
        Option<CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>>,
    pub glwe_sns_compression_key_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    pub parameters: ClassicPBSParameters,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Version)]
pub struct PrivateKeySetV1<const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z64, EXTENSION_DEGREE>,
    pub lwe_compute_secret_key_share: LweSecretKeyShare<Z64, EXTENSION_DEGREE>,
    // eventually we'll remove the enum here when we support more Z64+Z128 preproc
    pub glwe_secret_key_share: GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    // eventually we'll remove the enum here when we support more Z64+Z128 preproc
    pub glwe_secret_key_share_compression:
        Option<CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>>,
    pub glwe_sns_compression_key_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    pub parameters: ClassicPBSParameters,
}

#[cfg(feature = "testing")]
impl<const EXTENSION_DEGREE: usize> PrivateKeySet<EXTENSION_DEGREE> {
    pub fn init_dummy(param: DKGParams) -> Self {
        let params_basic_handle = param.get_params_basics_handle();
        Self {
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vec![],
            }),
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vec![],
            }),
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                data: vec![],
                polynomial_size: params_basic_handle.polynomial_size(),
            }),
            glwe_secret_key_share_sns_as_lwe: None,
            parameters: params_basic_handle.to_classic_pbs_parameters(),
            glwe_secret_key_share_compression: None,
            glwe_sns_compression_key_as_lwe: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Version)]
pub struct PrivateKeySetV0<const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z64, EXTENSION_DEGREE>,
    pub lwe_compute_secret_key_share: LweSecretKeyShare<Z64, EXTENSION_DEGREE>,
    pub glwe_secret_key_share: GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_compression:
        Option<CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>>,
    pub parameters: ClassicPBSParameters,
}

impl<const EXTENSION_DEGREE: usize> Upgrade<PrivateKeySetV1<EXTENSION_DEGREE>>
    for PrivateKeySetV0<EXTENSION_DEGREE>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<PrivateKeySetV1<EXTENSION_DEGREE>, Self::Error> {
        Ok(PrivateKeySetV1 {
            lwe_encryption_secret_key_share: self.lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share: self.lwe_compute_secret_key_share,
            glwe_secret_key_share: self.glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe: self.glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression: self.glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe: None,
            parameters: self.parameters,
        })
    }
}

impl<const EXTENSION_DEGREE: usize> Upgrade<PrivateKeySet<EXTENSION_DEGREE>>
    for PrivateKeySetV1<EXTENSION_DEGREE>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<PrivateKeySet<EXTENSION_DEGREE>, Self::Error> {
        Ok(PrivateKeySet {
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z64(
                self.lwe_encryption_secret_key_share,
            ),
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z64(
                self.lwe_compute_secret_key_share,
            ),
            glwe_secret_key_share: self.glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe: self.glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression: self.glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe: self.glwe_sns_compression_key_as_lwe,
            parameters: self.parameters,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum CompressionPrivateKeySharesEnumVersioned<const EXTENSION_DEGREE: usize> {
    V0(CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(CompressionPrivateKeySharesEnumVersioned)]
pub enum CompressionPrivateKeySharesEnum<const EXTENSION_DEGREE: usize> {
    Z64(CompressionPrivateKeyShares<Z64, EXTENSION_DEGREE>),
    Z128(CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>),
}

impl<const EXTENSION_DEGREE: usize> CompressionPrivateKeySharesEnum<EXTENSION_DEGREE> {
    pub fn try_cast_mut_to_z64(
        &mut self,
    ) -> anyhow::Result<&mut CompressionPrivateKeyShares<Z64, EXTENSION_DEGREE>> {
        match self {
            CompressionPrivateKeySharesEnum::Z64(inner) => Ok(inner),
            CompressionPrivateKeySharesEnum::Z128(_) => anyhow::bail!("not z64"),
        }
    }

    pub fn try_cast_mut_to_z128(
        &mut self,
    ) -> anyhow::Result<&mut CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>> {
        match self {
            CompressionPrivateKeySharesEnum::Z64(_) => anyhow::bail!("not z128"),
            CompressionPrivateKeySharesEnum::Z128(inner) => Ok(inner),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum LweSecretKeyShareEnumVersioned<const EXTENSION_DEGREE: usize> {
    V0(LweSecretKeyShareEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(LweSecretKeyShareEnumVersioned)]
pub enum LweSecretKeyShareEnum<const EXTENSION_DEGREE: usize> {
    Z64(LweSecretKeyShare<Z64, EXTENSION_DEGREE>),
    Z128(LweSecretKeyShare<Z128, EXTENSION_DEGREE>),
}

#[cfg(test)]
impl<const EXTENSION_DEGREE: usize> LweSecretKeyShareEnum<EXTENSION_DEGREE> {
    pub(crate) fn unsafe_cast_to_z64(self) -> LweSecretKeyShare<Z64, EXTENSION_DEGREE> {
        match self {
            LweSecretKeyShareEnum::Z64(inner) => inner,
            LweSecretKeyShareEnum::Z128(_) => panic!("not z64"),
        }
    }

    pub(crate) fn unsafe_cast_to_z128(self) -> LweSecretKeyShare<Z128, EXTENSION_DEGREE> {
        match self {
            LweSecretKeyShareEnum::Z64(_) => panic!("not z128"),
            LweSecretKeyShareEnum::Z128(inner) => inner,
        }
    }
    pub(crate) fn len(&self) -> usize {
        match self {
            LweSecretKeyShareEnum::Z64(inner) => inner.data.len(),
            LweSecretKeyShareEnum::Z128(inner) => inner.data.len(),
        }
    }
}

impl<const EXTENSION_DEGREE: usize> LweSecretKeyShareEnum<EXTENSION_DEGREE> {
    pub fn try_cast_mut_to_z64(
        &mut self,
    ) -> anyhow::Result<&mut LweSecretKeyShare<Z64, EXTENSION_DEGREE>> {
        match self {
            LweSecretKeyShareEnum::Z64(inner) => Ok(inner),
            LweSecretKeyShareEnum::Z128(_) => anyhow::bail!("not z64"),
        }
    }

    pub fn try_cast_mut_to_z128(
        &mut self,
    ) -> anyhow::Result<&mut LweSecretKeyShare<Z128, EXTENSION_DEGREE>> {
        match self {
            LweSecretKeyShareEnum::Z64(_) => anyhow::bail!("not z128"),
            LweSecretKeyShareEnum::Z128(inner) => Ok(inner),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum GlweSecretKeyShareEnumVersioned<const EXTENSION_DEGREE: usize> {
    V0(GlweSecretKeyShareEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(GlweSecretKeyShareEnumVersioned)]
pub enum GlweSecretKeyShareEnum<const EXTENSION_DEGREE: usize> {
    Z64(GlweSecretKeyShare<Z64, EXTENSION_DEGREE>),
    Z128(GlweSecretKeyShare<Z128, EXTENSION_DEGREE>),
}

impl<const EXTENSION_DEGREE: usize> GlweSecretKeyShareEnum<EXTENSION_DEGREE> {
    pub fn try_cast_mut_to_z64(
        &mut self,
    ) -> anyhow::Result<&mut GlweSecretKeyShare<Z64, EXTENSION_DEGREE>> {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => Ok(inner),
            GlweSecretKeyShareEnum::Z128(_) => anyhow::bail!("not z64"),
        }
    }

    pub fn try_cast_mut_to_z128(
        &mut self,
    ) -> anyhow::Result<&mut GlweSecretKeyShare<Z128, EXTENSION_DEGREE>> {
        match self {
            GlweSecretKeyShareEnum::Z64(_) => anyhow::bail!("not z128"),
            GlweSecretKeyShareEnum::Z128(inner) => Ok(inner),
        }
    }
}

#[cfg(test)]
impl<const EXTENSION_DEGREE: usize> GlweSecretKeyShareEnum<EXTENSION_DEGREE> {
    pub(crate) fn unsafe_cast_to_z64(self) -> GlweSecretKeyShare<Z64, EXTENSION_DEGREE> {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner,
            GlweSecretKeyShareEnum::Z128(_) => panic!("not z64"),
        }
    }

    pub(crate) fn unsafe_cast_to_z128(self) -> GlweSecretKeyShare<Z128, EXTENSION_DEGREE> {
        match self {
            GlweSecretKeyShareEnum::Z64(_) => panic!("not z128"),
            GlweSecretKeyShareEnum::Z128(inner) => inner,
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner.data.len(),
            GlweSecretKeyShareEnum::Z128(inner) => inner.data.len(),
        }
    }

    pub(crate) fn polynomial_size(&self) -> tfhe::boolean::prelude::PolynomialSize {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner.polynomial_size,
            GlweSecretKeyShareEnum::Z128(inner) => inner.polynomial_size,
        }
    }
}

impl<const EXTENSION_DEGREE: usize> GenericPrivateKeySet<Z128, EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    // When finalizing we keep everything mod Z128
    pub fn finalize_keyset(
        self,
        parameters: ClassicPBSParameters,
    ) -> PrivateKeySet<EXTENSION_DEGREE> {
        let glwe_secret_key_share_sns_as_lwe = self
            .glwe_secret_key_share_sns
            .map(|key| key.into_lwe_secret_key());

        let glwe_sns_compression_key_as_lwe = self
            .glwe_secret_key_share_sns_compression
            .map(|share| share.into_lwe_secret_key());

        PrivateKeySet {
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z128(
                self.lwe_encryption_secret_key_share,
            ),
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z128(self.lwe_secret_key_share),
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(self.glwe_secret_key_share),
            glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression: self
                .glwe_secret_key_share_compression
                .map(CompressionPrivateKeySharesEnum::Z128),
            glwe_sns_compression_key_as_lwe,
            parameters,
        }
    }
}

impl<const EXTENSION_DEGREE: usize> GenericPrivateKeySet<Z64, EXTENSION_DEGREE> {
    // This version of finalize_keyset is used when we have Z64 preprocessing,
    // which does not involve generating sns keys.
    pub fn finalize_keyset(
        self,
        parameters: ClassicPBSParameters,
    ) -> PrivateKeySet<EXTENSION_DEGREE> {
        PrivateKeySet {
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z64(
                self.lwe_encryption_secret_key_share,
            ),
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z64(self.lwe_secret_key_share),
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z64(self.glwe_secret_key_share),
            glwe_secret_key_share_sns_as_lwe: None,
            glwe_secret_key_share_compression: self
                .glwe_secret_key_share_compression
                .map(CompressionPrivateKeySharesEnum::Z64),
            glwe_sns_compression_key_as_lwe: None,
            parameters,
        }
    }
}
