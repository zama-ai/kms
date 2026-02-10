use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::Monomials;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Ring, Solve};
use crate::execution::config::BatchParams;
use crate::execution::online::bit_lift::{BitLift, SecureBitLift};
use crate::execution::online::gen_bits::{BitGenEven, SecureBitGenEven};
use crate::execution::online::preprocessing::memory::bit_lift::InMemoryBitLiftPreprocessing;
use crate::execution::online::preprocessing::{BasePreprocessing, BitPreprocessing};
use crate::execution::runtime::sessions::base_session::BaseSessionHandles;
use crate::execution::runtime::sessions::small_session::SmallSessionHandles;
use crate::execution::sharing::share::Share;
use crate::execution::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
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

impl<const EXTENSION_DEGREE: usize> PrivateKeySet<EXTENSION_DEGREE> {
    fn num_bits_to_lift(&self) -> usize {
        let mut count = 0;
        if let LweSecretKeyShareEnum::Z64(key) = &self.lwe_encryption_secret_key_share {
            count += key.data.len();
        }

        if let LweSecretKeyShareEnum::Z64(key) = &self.lwe_compute_secret_key_share {
            count += key.data.len();
        }

        if let GlweSecretKeyShareEnum::Z64(key) = &self.glwe_secret_key_share {
            count += key.data.len();
        }

        if let Some(CompressionPrivateKeySharesEnum::Z64(key)) =
            &self.glwe_secret_key_share_compression
        {
            count += key.post_packing_ks_key.data.len();
        }

        count
    }

    pub fn lift_to_z64(self) -> Self
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        PrivateKeySet {
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z64(
                self.lwe_encryption_secret_key_share.convert_to_z64(),
            ),
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z64(
                self.lwe_compute_secret_key_share.convert_to_z64(),
            ),
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z64(
                self.glwe_secret_key_share.convert_to_z64(),
            ),
            glwe_secret_key_share_sns_as_lwe: self.glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression: self.glwe_secret_key_share_compression.map(
                |compression| CompressionPrivateKeySharesEnum::Z64(compression.convert_to_z64()),
            ),
            glwe_sns_compression_key_as_lwe: self.glwe_sns_compression_key_as_lwe,
            parameters: self.parameters,
        }
    }

    /// Perform the required offline phase to lift the keys from Z64 to Z128,
    /// and then calls [`Self::lift_to_z128_online`] to perform the online phase of the lifting.
    pub async fn lift_to_z128_integrated<
        Ses64: SmallSessionHandles<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        Ses128: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>>,
    >(
        self,
        session_z64: &mut Ses64,
        session_z128: &mut Ses128,
    ) -> anyhow::Result<Self>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let num_bits_to_lift = self.num_bits_to_lift();

        let triples_z64 = SecureSmallPreprocessing::default()
            .execute(
                session_z64,
                BatchParams {
                    triples: num_bits_to_lift,
                    randoms: 0,
                },
            )
            .await?;

        let mut triples_randoms_z128 = SecureSmallPreprocessing::default()
            .execute(
                session_z128,
                BatchParams {
                    triples: num_bits_to_lift,
                    randoms: num_bits_to_lift,
                },
            )
            .await?;

        let bits_z128 = SecureBitGenEven::gen_bits_even(
            num_bits_to_lift,
            &mut triples_randoms_z128,
            session_z128,
        )
        .await?;

        let mut preproc = InMemoryBitLiftPreprocessing::new(bits_z128, triples_z64);

        Self::lift_to_z128_online(self, session_z128, &mut preproc).await
    }

    /// Lift the keys from Z64 to Z128 by performing secure bit lifting using the provided correlated randomness.
    async fn lift_to_z128_online<
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        mut self,
        session: &mut Ses,
        preproc: &mut P,
    ) -> anyhow::Result<Self>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        if let LweSecretKeyShareEnum::Z64(key) = self.lwe_encryption_secret_key_share {
            self.lwe_encryption_secret_key_share = LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: SecureBitLift::execute(key.data, preproc, session).await?,
            });
        }

        if let LweSecretKeyShareEnum::Z64(key) = self.lwe_compute_secret_key_share {
            self.lwe_compute_secret_key_share = LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: SecureBitLift::execute(key.data, preproc, session).await?,
            });
        }

        if let GlweSecretKeyShareEnum::Z64(key) = self.glwe_secret_key_share {
            self.glwe_secret_key_share = GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                data: SecureBitLift::execute(key.data, preproc, session).await?,
                polynomial_size: key.polynomial_size,
            });
        }

        if let Some(CompressionPrivateKeySharesEnum::Z64(key)) =
            self.glwe_secret_key_share_compression
        {
            self.glwe_secret_key_share_compression = Some(CompressionPrivateKeySharesEnum::Z128(
                CompressionPrivateKeyShares {
                    post_packing_ks_key: GlweSecretKeyShare {
                        data: SecureBitLift::execute(
                            key.post_packing_ks_key.data,
                            preproc,
                            session,
                        )
                        .await?,
                        polynomial_size: key.post_packing_ks_key.polynomial_size,
                    },
                    params: key.params,
                },
            ));
        }

        Ok(self)
    }
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

    // It's always possible to convert a Z128 key to Z64 by locally reducing mod 2^64
    pub fn convert_to_z64(self) -> CompressionPrivateKeyShares<Z64, EXTENSION_DEGREE>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        match self {
            CompressionPrivateKeySharesEnum::Z64(inner) => inner,
            CompressionPrivateKeySharesEnum::Z128(inner) => {
                let (data, polynomial_size) = {
                    let GlweSecretKeyShare {
                        data,
                        polynomial_size,
                    } = inner.post_packing_ks_key;
                    let data = data
                        .into_iter()
                        .map(|x| Share::new(x.owner(), x.value().to_residuepoly64()))
                        .collect();
                    (data, polynomial_size)
                };
                CompressionPrivateKeyShares {
                    post_packing_ks_key: GlweSecretKeyShare {
                        data,
                        polynomial_size,
                    },
                    params: inner.params,
                }
            }
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
    ) -> anyhow::Result<&mut LweSecretKeyShare<Z64, EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        match self {
            LweSecretKeyShareEnum::Z64(inner) => Ok(inner),
            LweSecretKeyShareEnum::Z128(_) => {
                anyhow::bail!("not z64")
            }
        }
    }

    // It's always possible to convert a Z128 key to Z64 by locally reducing mod 2^64
    pub fn convert_to_z64(self) -> LweSecretKeyShare<Z64, EXTENSION_DEGREE>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        match self {
            LweSecretKeyShareEnum::Z64(inner) => inner,
            LweSecretKeyShareEnum::Z128(inner) => {
                let data = inner
                    .data
                    .into_iter()
                    .map(|x| Share::new(x.owner(), x.value().to_residuepoly64()))
                    .collect();
                LweSecretKeyShare { data }
            }
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

    // It's always possible to convert a Z128 key to Z64 by locally reducing mod 2^64
    pub fn convert_to_z64(self) -> GlweSecretKeyShare<Z64, EXTENSION_DEGREE>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner,
            GlweSecretKeyShareEnum::Z128(inner) => {
                let data = inner
                    .data
                    .into_iter()
                    .map(|x| Share::new(x.owner(), x.value().to_residuepoly64()))
                    .collect();
                GlweSecretKeyShare {
                    data,
                    polynomial_size: inner.polynomial_size,
                }
            }
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

#[cfg(test)]
mod test {
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tokio::task::JoinSet;

    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::{
                common::ResiduePoly,
                degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
            },
            structure_traits::Ring,
        },
        execution::{
            online::triple::open_list,
            runtime::{
                sessions::small_session::{SmallSession128, SmallSession64},
                test_runtime::{generate_fixed_roles, DistributedTestRuntime},
            },
            sharing::share::Share,
            tfhe_internals::{
                parameters::BC_PARAMS_SNS,
                private_keysets::{
                    CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, LweSecretKeyShareEnum,
                    PrivateKeySet,
                },
                test_feature::initialize_key_material,
            },
        },
        networking::NetworkMode,
        session_id::SessionId,
    };

    // Note this fn is very much tailored for the test below
    // We first push all the Z64 keys in the same vector and all the Z128 keys in another vector, then we open them separately and concatenate the results.
    // This way when we open before and after and concatenate the result, we should have equality
    // because the test first switch all the keys that can live in Z64 to Z64, then lift all of them to Z128, so the order of the keys in the vectors is the same before and after lifting.
    #[allow(clippy::type_complexity)]
    fn private_key_to_vecs<const EXTENSION_DEGREE: usize>(
        key: PrivateKeySet<EXTENSION_DEGREE>,
    ) -> (
        Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>,
    ) {
        let mut z64_vec = Vec::new();
        let mut z128_vec = Vec::new();

        let PrivateKeySet {
            lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share,
            glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe,
            parameters: _,
        } = key;

        if let LweSecretKeyShareEnum::Z64(lwe_enc_key) = lwe_encryption_secret_key_share {
            z64_vec.extend(lwe_enc_key.data);
        } else if let LweSecretKeyShareEnum::Z128(lwe_enc_key) = lwe_encryption_secret_key_share {
            z128_vec.extend(lwe_enc_key.data);
        }

        if let LweSecretKeyShareEnum::Z64(lwe_comp_key) = lwe_compute_secret_key_share {
            z64_vec.extend(lwe_comp_key.data);
        } else if let LweSecretKeyShareEnum::Z128(lwe_comp_key) = lwe_compute_secret_key_share {
            z128_vec.extend(lwe_comp_key.data);
        }

        if let GlweSecretKeyShareEnum::Z64(glwe_key) = glwe_secret_key_share {
            z64_vec.extend(glwe_key.data);
        } else if let GlweSecretKeyShareEnum::Z128(glwe_key) = glwe_secret_key_share {
            z128_vec.extend(glwe_key.data);
        }

        if let Some(compression) = glwe_secret_key_share_compression {
            if let CompressionPrivateKeySharesEnum::Z64(compression) = compression {
                z64_vec.extend(compression.post_packing_ks_key.data);
            } else if let CompressionPrivateKeySharesEnum::Z128(compression) = compression {
                z128_vec.extend(compression.post_packing_ks_key.data);
            }
        };

        if let Some(k) = glwe_secret_key_share_sns_as_lwe {
            z128_vec.extend(k.data)
        }

        if let Some(k) = glwe_sns_compression_key_as_lwe {
            z128_vec.extend(k.data)
        }
        (z64_vec, z128_vec)
    }

    #[tokio::test]
    async fn lift_private_keyset() {
        let task = |mut session_z64: SmallSession64<4>, mut session_z128: SmallSession128<4>| async move {
            let (_, my_keys) = initialize_key_material::<_, 4>(
                &mut session_z64,
                BC_PARAMS_SNS,
                tfhe::Tag::default(),
            )
            .await
            .unwrap();

            let my_keys_z64 = my_keys.lift_to_z64();

            let (z64_vec_before, z128_vec_before) = private_key_to_vecs(my_keys_z64.clone());

            let my_keys_lifted = my_keys_z64
                .lift_to_z128_integrated(&mut session_z64, &mut session_z128)
                .await
                .unwrap();

            let (z64_vec_after, z128_vec_after) = private_key_to_vecs(my_keys_lifted);

            assert_eq!(z64_vec_after.len(), 0);

            let mut vec_before = open_list(&z64_vec_before, &session_z64)
                .await
                .unwrap()
                .into_iter()
                .map(|v| v.to_scalar().unwrap().0 as u128)
                .collect::<Vec<_>>();

            vec_before.extend(
                open_list(&z128_vec_before, &session_z128)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|v| v.to_scalar().unwrap().0),
            );

            let vec_after = open_list(&z128_vec_after, &session_z128)
                .await
                .unwrap()
                .into_iter()
                .map(|v| v.to_scalar().unwrap().0)
                .collect::<Vec<_>>();

            println!(
                "Total length of key vectors: before = {}, after = {}",
                vec_before.len(),
                vec_after.len()
            );
            // Need to reconstruct both the old and new keyset and check they are indeed the same
            assert_eq!(vec_before, vec_after);
            assert!(vec_after.iter().all(|x| *x == 0 || *x == 1));
            true
        };

        let num_parties = 4;
        let threshold = 1;

        // Creating a test runtime with sessions in extension ring Z64 and Z128
        // Note: Could be moved to helper.rs if we ever need such a setting in other tests
        let roles = generate_fixed_roles(num_parties);

        let test_runtime_z64 = DistributedTestRuntime::<
            ResiduePolyF4Z64,
            _,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >::new(roles.clone(), threshold, NetworkMode::Sync, None);

        let test_runtime_z128 = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            _,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(roles.clone(), threshold, NetworkMode::Sync, None);

        let session_id_z64 = SessionId::from(1);
        let session_id_z128 = SessionId::from(2);

        let mut tasks = JoinSet::new();
        for party in roles {
            let session_z64 = test_runtime_z64
                .small_session_for_party(
                    session_id_z64,
                    party,
                    Some(AesRng::seed_from_u64(party.one_based() as u64 + 64)),
                )
                .await;
            let session_z128 = test_runtime_z128
                .small_session_for_party(
                    session_id_z128,
                    party,
                    Some(AesRng::seed_from_u64(party.one_based() as u64 + 128)),
                )
                .await;
            tasks.spawn(task(session_z64, session_z128));
        }

        let mut res = Vec::new();
        while let Some(out) = tasks.join_next().await {
            res.push(out.unwrap());
        }

        assert_eq!(res.len(), num_parties);
        assert!(res.into_iter().all(|x| x));
    }
}
