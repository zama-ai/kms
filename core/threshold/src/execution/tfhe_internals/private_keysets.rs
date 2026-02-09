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

    /// NOTE: Requires at least 2 sessions
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

    // Note, could be done in one round, but it's a bit nicer written
    // this way (do we care ?)
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
