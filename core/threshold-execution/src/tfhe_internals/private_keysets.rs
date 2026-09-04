use crate::config::BatchParams;
use crate::online::bit_lift::{BitLift, SecureBitLift};
use crate::online::gen_bits::{BitGenEven, SecureBitGenEven};
use crate::online::preprocessing::memory::bit_lift::InMemoryBitLiftPreprocessing;
use crate::online::preprocessing::{BasePreprocessing, BitPreprocessing};
use crate::runtime::sessions::base_session::{BaseSessionHandles, synchronize_sessions};
use crate::runtime::sessions::small_session::SmallSessionHandles;
use crate::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
use crate::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
use crate::tfhe_internals::parameters::DKGParams;
use crate::tfhe_internals::sns_compression_key::SnsCompressionPrivateKeyShares;
use crate::tfhe_internals::{glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare};
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::{Monomials, ResiduePoly},
    sharing::share::Share,
    structure_traits::{ErrorCorrect, Invert, Ring, Solve},
};
use serde::{Deserialize, Serialize};
use tfhe::shortint::ClassicPBSParameters;
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

pub(crate) struct GenericPrivateKeySet<Z: Clone, const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub lwe_secret_key_share: LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub oprf_secret_key_share: Option<LweSecretKeyShare<Z, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share: GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns: Option<GlweSecretKeyShare<Z, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_compression: Option<CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_sns_compression:
        Option<SnsCompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PrivateKeySetVersions<const EXTENSION_DEGREE: usize> {
    /// V0 is the original private key set
    V0(PrivateKeySetV0<EXTENSION_DEGREE>),
    // V1 is the same as V0 with the addition of glwe_sns_compression_key
    V1(PrivateKeySetV1<EXTENSION_DEGREE>),
    V2(PrivateKeySetV2<EXTENSION_DEGREE>),
    V3(PrivateKeySet<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Versionize)]
#[versionize(PrivateKeySetVersions)]
/// The private key set structure holding the secret key shares for each party
/// of the DKG. The keys can be either Z64 or Z128 depending on the DKG parameters.
/// But all keys in the set are of the same type after a DKG.
///
/// The only reason why type might differ is if the [`PrivateKeySet`] has just
/// been upgraded from a [`PrivateKeySetV1`] where the keys were still Z64.
/// In this case, one __must__ call `PrivateKeySet::lift` to make the [`PrivateKeySet`] conformant.
///
/// # Why this type deliberately does not implement `Zeroize`
///
/// We do not impl `Zeroize` because these key shares stay in memory while the
/// kms is running as they're needed for decryption.
pub struct PrivateKeySet<const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub lwe_compute_secret_key_share: LweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub oprf_secret_key_share: Option<LweSecretKeyShareEnum<EXTENSION_DEGREE>>,
    pub glwe_secret_key_share: GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_compression:
        Option<CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>>,
    pub glwe_sns_compression_key_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    pub parameters: ClassicPBSParameters,
}

impl<const EXTENSION_DEGREE: usize> PrivateKeySet<EXTENSION_DEGREE> {
    fn num_bits_to_lift(&self) -> usize {
        let PrivateKeySet {
            lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share,
            oprf_secret_key_share,
            glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe: _,
            glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe: _,
            parameters: _,
        } = self;

        let mut count = 0;

        if let LweSecretKeyShareEnum::Z64(key) = lwe_encryption_secret_key_share {
            count += key.data.len();
        }

        if let LweSecretKeyShareEnum::Z64(key) = lwe_compute_secret_key_share {
            count += key.data.len();
        }

        if let Some(LweSecretKeyShareEnum::Z64(key)) = oprf_secret_key_share {
            count += key.data.len();
        }

        if let GlweSecretKeyShareEnum::Z64(key) = glwe_secret_key_share {
            count += key.data.len();
        }

        if let Some(CompressionPrivateKeySharesEnum::Z64(key)) = glwe_secret_key_share_compression {
            count += key.post_packing_ks_key.data.len();
        }

        count
    }

    /// Worst-case number of Z64 sub-keys a [`Self::lift_to_z128_integrated`] would
    /// bit-lift for a keyset with the given `parameters`.
    pub fn num_liftable_subkeys(parameters: DKGParams) -> usize {
        // LWE-encryption, LWE-compute and GLWE are always present. The SnS
        // keys are always shared over Z128 and are never bit-lifted.
        let base = 3;
        let compression = usize::from(parameters.compression().is_some());
        // Counted conservatively: OPRF presence is not encoded in `parameters`.
        let oprf_upper_bound = 1;
        base + compression + oprf_upper_bound
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
            oprf_secret_key_share: self
                .oprf_secret_key_share
                .map(|key| LweSecretKeyShareEnum::Z64(key.convert_to_z64())),
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

    /// Worst-case number of synchronous network rounds
    /// [`Self::lift_to_z128_integrated`] takes on a session of `num_parties`
    /// parties with the given `threshold`, summed across the z64 and z128 sessions
    /// (they run sequentially): two triple-preprocessing batches, one even-bit
    /// generation, and one bit-lift per liftable sub-key. Each sub-protocol
    /// contributes its own [`num_rounds`](SecureBitLift::num_rounds).
    ///
    /// Exposed so sessions that run *after* the lift can budget their first-round
    /// timeout (see resharing session advancement). `num_liftable_subkeys` is an
    /// upper bound on the Z64 sub-keys that get bit-lifted.
    pub fn lift_to_z128_num_rounds(
        num_parties: usize,
        threshold: usize,
        num_liftable_subkeys: usize,
    ) -> usize {
        // Nothing to lift (`num_liftable_subkeys == 0`, e.g. a Z64-mode keyset,
        // which is converted with the local `lift_to_z64`): the preprocessing
        // batches are empty and no bit-lift runs, so the whole interactive lift is
        // 0 rounds. Guard here so the budget is exact rather than counting the
        // (never-run) preprocessing/bit-gen.
        if num_liftable_subkeys == 0 {
            return 0;
        }
        // Both preprocessing batches request triples, so each is interactive.
        let triple_batch = BatchParams {
            triples: 1, // Note: `num_rounds` is independent of the batch size, so 1 suffices to count rounds.
            randoms: 0,
        };
        2 * SecureSmallPreprocessing::num_rounds(triple_batch, num_parties, threshold)
            + SecureBitGenEven::num_rounds()
            + num_liftable_subkeys * SecureBitLift::num_rounds()
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

        // The z64 preprocessing above ran on session_z64 while session_z128 sat
        // idle. Synchronize the z128 session's round clock to the z64 one so this
        // (first) z128 round budgets its timeout for that gap instead of starting a
        // fresh clock.
        synchronize_sessions(session_z128, session_z64).await;

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

        let lifted = Self::lift_to_z128_online(self, session_z128, &mut preproc).await?;

        // All of the z128 work above (preprocessing, bit generation, bit lift) ran
        // on session_z128 while session_z64 sat idle, so z128 now leads z64. Bring
        // z64 back up to z128 so both sessions are returned at the same round. The
        // lift sessions are reused across keys, and the next key's z128 catch-up
        // synchronizes z128 *to* z64 — which would move z128 backwards (colliding
        // with already-sent round tags) if z64 were left behind here.
        synchronize_sessions(session_z64, session_z128).await;

        Ok(lifted)
    }

    /// Lift the keys from Z64 to Z128 by performing secure bit lifting using the provided correlated randomness.
    ///
    /// NOTE: Could be batched to avoid spending so many rounds
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

        if let Some(LweSecretKeyShareEnum::Z64(key)) = self.oprf_secret_key_share {
            self.oprf_secret_key_share = Some(LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: SecureBitLift::execute(key.data, preproc, session).await?,
            }));
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

/// V2: private key set before adding the dedicated OPRF secret-key share.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Version)]
pub struct PrivateKeySetV2<const EXTENSION_DEGREE: usize> {
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

#[cfg(any(test, feature = "testing"))]
impl<const EXTENSION_DEGREE: usize> PrivateKeySet<EXTENSION_DEGREE> {
    pub fn init_dummy(param: DKGParams) -> Self {
        Self {
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vec![],
            }),
            oprf_secret_key_share: Some(LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vec![],
            })),
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vec![],
            }),
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                data: vec![],
                polynomial_size: param.polynomial_size(),
            }),
            glwe_secret_key_share_sns_as_lwe: None,
            parameters: param.classic_pbs(),
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

impl<const EXTENSION_DEGREE: usize> Upgrade<PrivateKeySetV2<EXTENSION_DEGREE>>
    for PrivateKeySetV1<EXTENSION_DEGREE>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<PrivateKeySetV2<EXTENSION_DEGREE>, Self::Error> {
        Ok(PrivateKeySetV2 {
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

impl<const EXTENSION_DEGREE: usize> Upgrade<PrivateKeySet<EXTENSION_DEGREE>>
    for PrivateKeySetV2<EXTENSION_DEGREE>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<PrivateKeySet<EXTENSION_DEGREE>, Self::Error> {
        Ok(PrivateKeySet {
            lwe_encryption_secret_key_share: self.lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share: self.lwe_compute_secret_key_share,
            oprf_secret_key_share: None,
            glwe_secret_key_share: self.glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe: self.glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression: self.glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe: self.glwe_sns_compression_key_as_lwe,
            parameters: self.parameters,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum CompressionPrivateKeySharesEnumVersions<const EXTENSION_DEGREE: usize> {
    V0(CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(CompressionPrivateKeySharesEnumVersions)]
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
pub enum LweSecretKeyShareEnumVersions<const EXTENSION_DEGREE: usize> {
    V0(LweSecretKeyShareEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(LweSecretKeyShareEnumVersions)]
pub enum LweSecretKeyShareEnum<const EXTENSION_DEGREE: usize> {
    Z64(LweSecretKeyShare<Z64, EXTENSION_DEGREE>),
    Z128(LweSecretKeyShare<Z128, EXTENSION_DEGREE>),
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
pub enum GlweSecretKeyShareEnumVersions<const EXTENSION_DEGREE: usize> {
    V0(GlweSecretKeyShareEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(GlweSecretKeyShareEnumVersions)]
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
}

pub(crate) trait Definalizable<Z: Clone, const EXTENSION_DEGREE: usize> {
    /// This is the opposite of the Finalizable trait, where we attempt to convert
    /// a finalized keyset to a non-finalized one.
    fn to_generic(
        &self,
        params: DKGParams,
    ) -> anyhow::Result<GenericPrivateKeySet<Z, EXTENSION_DEGREE>>;
}

impl<const EXTENSION_DEGREE: usize> Definalizable<Z128, EXTENSION_DEGREE>
    for PrivateKeySet<EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    fn to_generic(
        &self,
        params: DKGParams,
    ) -> anyhow::Result<GenericPrivateKeySet<Z128, EXTENSION_DEGREE>> {
        let lwe_encryption_secret_key_share = match &self.lwe_encryption_secret_key_share {
            LweSecretKeyShareEnum::Z128(key) => key.clone(),
            LweSecretKeyShareEnum::Z64(_) => {
                anyhow::bail!(
                    "Expected Z128 lwe_encryption_secret_key_share, got Z64. Keys must be lifted to Z128 before calling to_generic."
                )
            }
        };

        let lwe_secret_key_share = match &self.lwe_compute_secret_key_share {
            LweSecretKeyShareEnum::Z128(key) => key.clone(),
            LweSecretKeyShareEnum::Z64(_) => {
                anyhow::bail!(
                    "Expected Z128 lwe_compute_secret_key_share, got Z64. Keys must be lifted to Z128 before calling to_generic."
                )
            }
        };

        let oprf_secret_key_share = self
            .oprf_secret_key_share
            .as_ref()
            .map(|key| -> anyhow::Result<_> {
                match key {
                    LweSecretKeyShareEnum::Z128(key) => Ok(key.clone()),
                    LweSecretKeyShareEnum::Z64(_) => {
                        anyhow::bail!(
                            "Expected Z128 oprf_secret_key_share, got Z64. Keys must be lifted to Z128 before calling to_generic."
                        )
                    }
                }
            })
            .transpose()?;

        let glwe_secret_key_share = match &self.glwe_secret_key_share {
            GlweSecretKeyShareEnum::Z128(key) => key.clone(),
            GlweSecretKeyShareEnum::Z64(_) => {
                anyhow::bail!(
                    "Expected Z128 glwe_secret_key_share, got Z64. Keys must be lifted to Z128 before calling to_generic."
                )
            }
        };

        let glwe_secret_key_share_sns = self
            .glwe_secret_key_share_sns_as_lwe
            .as_ref()
            .map(|lwe_key| -> anyhow::Result<_> {
                let sns_params = match params.sns() {
                    Some(sns) => sns,
                    None => {
                        anyhow::bail!("PrivateKeySet has SNS key but DKGParams is WithoutSnS")
                    }
                };
                Ok(GlweSecretKeyShare::from_lwe_secret_key(
                    lwe_key.clone(),
                    sns_params.polynomial_size_sns(),
                ))
            })
            .transpose()?;

        let glwe_secret_key_share_compression = match &self.glwe_secret_key_share_compression {
            Some(CompressionPrivateKeySharesEnum::Z128(comp)) => Some(comp.clone()),
            Some(CompressionPrivateKeySharesEnum::Z64(_)) => {
                anyhow::bail!(
                    "Expected Z128 glwe_secret_key_share_compression, got Z64. Keys must be lifted to Z128 before calling to_generic."
                )
            }
            None => None,
        };

        let glwe_secret_key_share_sns_compression = self
            .glwe_sns_compression_key_as_lwe
            .as_ref()
            .map(|lwe_key| -> anyhow::Result<_> {
                let sns_comp_params = params.sns()
                .and_then(|sns| sns.sns_compression_params())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "PrivateKeySet has SNS compression key but DKGParams has no SNS compression params"
                        )
                    })?;
                Ok(SnsCompressionPrivateKeyShares::from_lwe_secret_key(
                    lwe_key.clone(),
                    sns_comp_params.packing_ks_polynomial_size,
                    sns_comp_params,
                ))
            })
            .transpose()?;

        Ok(GenericPrivateKeySet {
            lwe_encryption_secret_key_share,
            lwe_secret_key_share,
            oprf_secret_key_share,
            glwe_secret_key_share,
            glwe_secret_key_share_sns,
            glwe_secret_key_share_compression,
            glwe_secret_key_share_sns_compression,
        })
    }
}

impl<const EXTENSION_DEGREE: usize> Definalizable<Z64, EXTENSION_DEGREE>
    for PrivateKeySet<EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    fn to_generic(
        &self,
        _params: DKGParams,
    ) -> anyhow::Result<GenericPrivateKeySet<Z64, EXTENSION_DEGREE>> {
        let lifted = self.clone().lift_to_z64();

        let lwe_encryption_secret_key_share = match lifted.lwe_encryption_secret_key_share {
            LweSecretKeyShareEnum::Z64(key) => key,
            _ => unreachable!("lift_to_z64 should have converted to Z64"),
        };

        let lwe_secret_key_share = match lifted.lwe_compute_secret_key_share {
            LweSecretKeyShareEnum::Z64(key) => key,
            _ => unreachable!("lift_to_z64 should have converted to Z64"),
        };

        let oprf_secret_key_share = match lifted.oprf_secret_key_share {
            Some(LweSecretKeyShareEnum::Z64(key)) => Some(key),
            Some(_) => unreachable!("lift_to_z64 should have converted OPRF key to Z64"),
            None => None,
        };

        let glwe_secret_key_share = match lifted.glwe_secret_key_share {
            GlweSecretKeyShareEnum::Z64(key) => key,
            _ => unreachable!("lift_to_z64 should have converted to Z64"),
        };

        if lifted.glwe_secret_key_share_sns_as_lwe.is_some() {
            anyhow::bail!("Z64 keyset should not have SNS keys");
        }

        let glwe_secret_key_share_compression = match lifted.glwe_secret_key_share_compression {
            Some(CompressionPrivateKeySharesEnum::Z64(comp)) => Some(comp),
            Some(_) => unreachable!("lift_to_z64 should have converted compression key to Z64"),
            None => None,
        };

        if lifted.glwe_sns_compression_key_as_lwe.is_some() {
            anyhow::bail!("Z64 keyset should not have SNS compression keys");
        }

        Ok(GenericPrivateKeySet {
            lwe_encryption_secret_key_share,
            lwe_secret_key_share,
            oprf_secret_key_share,
            glwe_secret_key_share,
            glwe_secret_key_share_sns: None,
            glwe_secret_key_share_compression,
            glwe_secret_key_share_sns_compression: None,
        })
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
            oprf_secret_key_share: self.oprf_secret_key_share.map(LweSecretKeyShareEnum::Z128),
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
            oprf_secret_key_share: self.oprf_secret_key_share.map(LweSecretKeyShareEnum::Z64),
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
        online::triple::open_list,
        runtime::{
            sessions::small_session::{SmallSession64, SmallSession128},
            test_runtime::{DistributedTestRuntime, generate_fixed_roles},
        },
        tfhe_internals::{
            parameters::{BC_PARAMS_SNS, DkgMode, PARAMS_TEST_RESHARE},
            private_keysets::{
                CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, LweSecretKeyShareEnum,
                PrivateKeySet,
            },
            test_feature::insecure_initialize_key_material,
        },
    };
    use algebra::{
        base_ring::{Z64, Z128},
        galois_rings::{
            common::ResiduePoly,
            degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        },
        sharing::share::Share,
        structure_traits::Ring,
    };
    use threshold_types::network::NetworkMode;
    use threshold_types::session_id::SessionId;

    // The resharing round-budget is degree-independent; F4 is what resharing uses.
    const E: usize = ResiduePolyF4Z128::EXTENSION_DEGREE;

    /// [`PrivateKeySet::num_liftable_subkeys`] must be derivable from the public
    /// parameters alone (every party, including new-committee ones, computes the
    /// same value) and must be a safe upper bound on the sub-keys actually lifted.
    #[test]
    fn num_liftable_subkeys_from_params() {
        // Every shipped parameter set is Z128. A Z128 keyset may still carry Z64
        // sub-key shares if it was upgraded from a Z64 keyset, and Set-2 parties
        // can't tell — so they budget for the worst case: every present sub-key.
        for params in [BC_PARAMS_SNS, PARAMS_TEST_RESHARE] {
            assert_eq!(params.dkg_mode(), DkgMode::Z128);
            let n = PrivateKeySet::<E>::num_liftable_subkeys(params);
            // 3 always-present base sub-keys + optional compression + conservative OPRF.
            assert_eq!(n, 3 + usize::from(params.compression_sk_num_bits() > 0) + 1);
            assert!(
                (4..=5).contains(&n),
                "a Z128 keyset lifts at most 4-5 sub-keys, got {n}"
            );
        }
    }

    /// [`PrivateKeySet::lift_to_z128_num_rounds`] composes the preprocessing,
    /// even-bit-gen and per-sub-key bit-lift round counts, and is exactly 0 when
    /// there is nothing to lift.
    #[test]
    fn lift_to_z128_num_rounds_composition() {
        // Nothing to lift (Z128 keyset) — no preprocessing/bit-gen runs either.
        assert_eq!(PrivateKeySet::<E>::lift_to_z128_num_rounds(4, 1, 0), 0);
        assert_eq!(PrivateKeySet::<E>::lift_to_z128_num_rounds(7, 2, 0), 0);

        // 2 * preproc + gen_bits(2) + k * bit_lift(2), with
        // preproc = (t+1) * broadcast(t) = (t+1) * (3 + t).
        // (4,1): preproc = 2*4 = 8 -> 2*8 + 2 + 3*2 = 24.
        assert_eq!(PrivateKeySet::<E>::lift_to_z128_num_rounds(4, 1, 3), 24);
        // (7,2): preproc = 3*5 = 15 -> 2*15 + 2 + 5*2 = 42.
        assert_eq!(PrivateKeySet::<E>::lift_to_z128_num_rounds(7, 2, 5), 42);
    }

    // Note this fn is very much tailored for the test below
    // We first push all the Z64 keys in the same vector and all the Z128 keys in another vector, then we open them separately and concatenate the results.
    // This way when we open before and after and concatenate the result, we should have equality
    // because the test first switch all the keys that can live in Z64 to Z64, then lift all of them to Z128, so the order of the keys in the vectors is the same before and after lifting.
    #[expect(clippy::type_complexity)]
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
            oprf_secret_key_share,
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

        if let Some(oprf_key) = oprf_secret_key_share {
            if let LweSecretKeyShareEnum::Z64(oprf_key) = oprf_key {
                z64_vec.extend(oprf_key.data);
            } else if let LweSecretKeyShareEnum::Z128(oprf_key) = oprf_key {
                z128_vec.extend(oprf_key.data);
            }
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
            let (_, my_keys) = insecure_initialize_key_material::<_, 4>(
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

    /// Number of sub-keys of `key` that [`PrivateKeySet::lift_to_z128_integrated`]
    /// bit-lifts, i.e. the ones shared over Z64.
    fn count_z64_subkeys<const EXTENSION_DEGREE: usize>(
        key: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> usize {
        usize::from(matches!(
            key.lwe_encryption_secret_key_share,
            LweSecretKeyShareEnum::Z64(_)
        )) + usize::from(matches!(
            key.lwe_compute_secret_key_share,
            LweSecretKeyShareEnum::Z64(_)
        )) + usize::from(matches!(
            key.oprf_secret_key_share,
            Some(LweSecretKeyShareEnum::Z64(_))
        )) + usize::from(matches!(
            key.glwe_secret_key_share,
            GlweSecretKeyShareEnum::Z64(_)
        )) + usize::from(matches!(
            key.glwe_secret_key_share_compression,
            Some(CompressionPrivateKeySharesEnum::Z64(_))
        ))
    }

    /// The round budget of the lift is consistent with the lift itself:
    /// - `num_liftable_subkeys` bounds the sub-keys a keyset bit-lifts, and a
    ///   keyset with nothing to lift spends no network round;
    /// - a fault-free lift spends exactly two preprocessing broadcasts, one bit
    ///   generation and one bit lift per Z64 sub-key, which stays within
    ///   [`PrivateKeySet::lift_to_z128_num_rounds`] for the bound derived from the
    ///   public parameters;
    /// - both sessions are returned at the same round, so a later lift on the same
    ///   session pair (the next key) starts from a consistent clock.
    #[tokio::test]
    async fn lift_to_z128_round_accounting() {
        use crate::communication::broadcast::{Broadcast, SyncReliableBroadcast};
        use crate::online::bit_lift::{BitLift, SecureBitLift};
        use crate::online::gen_bits::{BitGenEven, SecureBitGenEven};
        use crate::runtime::sessions::base_session::GenericBaseSessionHandles;
        use crate::runtime::sessions::session_parameters::GenericParameterHandles;

        // Small keys: the round accounting does not depend on the key sizes, and
        // three lifts of a production-size keyset would be slow.
        let params = PARAMS_TEST_RESHARE;
        let task = move |mut session_z64: SmallSession64<4>,
                         mut session_z128: SmallSession128<4>| async move {
            let (_, my_keys) = insecure_initialize_key_material::<_, 4>(
                &mut session_z64,
                params,
                tfhe::Tag::default(),
            )
            .await
            .unwrap();
            let num_parties = session_z64.num_parties();
            let threshold = session_z64.threshold() as usize;
            let liftable_bound = PrivateKeySet::<4>::num_liftable_subkeys(params);
            let declared =
                PrivateKeySet::<4>::lift_to_z128_num_rounds(num_parties, threshold, liftable_bound);
            let broadcast_rounds = SyncReliableBroadcast::num_rounds(num_parties, threshold);
            // Rounds of a fault-free lift of `liftable` Z64 sub-keys: two
            // preprocessing broadcasts, one bit generation and one bit lift per
            // sub-key; none at all when there is nothing to lift.
            let fault_free_rounds = |liftable: usize| {
                if liftable == 0 {
                    0
                } else {
                    2 * broadcast_rounds
                        + SecureBitGenEven::num_rounds()
                        + liftable * SecureBitLift::num_rounds()
                }
            };

            // Lifts, in turn: the keyset as the DKG produced it, the lifted keyset
            // (nothing left to lift) and the keyset with every sub-key over Z64.
            let mut keys = my_keys;
            let mut rounds = std::cmp::max(
                session_z64.network().get_current_round().await,
                session_z128.network().get_current_round().await,
            );
            let mut liftable_seen = Vec::new();
            for step in 0..3 {
                if step == 2 {
                    keys = keys.lift_to_z64();
                }
                let liftable = count_z64_subkeys(&keys);
                liftable_seen.push(liftable);
                assert!(
                    liftable <= liftable_bound,
                    "{liftable} Z64 sub-keys exceed the bound {liftable_bound} derived from the parameters"
                );

                keys = keys
                    .lift_to_z128_integrated(&mut session_z64, &mut session_z128)
                    .await
                    .unwrap();
                assert_eq!(count_z64_subkeys(&keys), 0);

                let rounds_z64 = session_z64.network().get_current_round().await;
                let rounds_z128 = session_z128.network().get_current_round().await;
                assert_eq!(
                    rounds_z64, rounds_z128,
                    "the lift sessions must end at the same round"
                );
                let spent = rounds_z128 - rounds;
                rounds = rounds_z128;
                assert_eq!(spent, fault_free_rounds(liftable));
                assert!(
                    spent <= declared,
                    "the lift spent {spent} rounds but {declared} were budgeted"
                );
            }
            // The second lift had nothing to do, the third lifted at least the three
            // sub-keys every keyset has.
            assert_eq!(liftable_seen[1], 0);
            assert!(liftable_seen[2] >= 3);
        };

        let num_parties = 4;
        let threshold = 1;
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

        let mut tasks = JoinSet::new();
        for party in roles {
            let session_z64 = test_runtime_z64
                .small_session_for_party(
                    SessionId::from(1),
                    party,
                    Some(AesRng::seed_from_u64(party.one_based() as u64 + 64)),
                )
                .await;
            let session_z128 = test_runtime_z128
                .small_session_for_party(
                    SessionId::from(2),
                    party,
                    Some(AesRng::seed_from_u64(party.one_based() as u64 + 128)),
                )
                .await;
            tasks.spawn(task(session_z64, session_z128));
        }
        let results = tasks.join_all().await;
        assert_eq!(results.len(), num_parties);
    }

    mod test_definalizable {
        use super::super::{
            Definalizable, GlweSecretKeyShareEnum, LweSecretKeyShareEnum, PrivateKeySet,
        };
        use crate::tfhe_internals::{
            glwe_key::GlweSecretKeyShare,
            lwe_key::LweSecretKeyShare,
            parameters::{BC_PARAMS_NO_SNS, PARAMS_TEST_BK_SNS},
        };
        use algebra::{
            base_ring::{Z64, Z128},
            galois_rings::degree_4::ResiduePolyF4Z128,
            sharing::share::Share,
        };
        use std::num::Wrapping;
        use threshold_types::role::Role;

        #[test]
        fn test_definalizable_z128_round_trip_no_sns() {
            let keyset = PrivateKeySet::<4>::init_dummy(*BC_PARAMS_NO_SNS);
            let params = *BC_PARAMS_NO_SNS;

            let generic = Definalizable::<Z128, 4>::to_generic(&keyset, *BC_PARAMS_NO_SNS)
                .expect("to_generic should succeed for Z128 keys without SNS");

            assert!(generic.glwe_secret_key_share_sns.is_none());
            assert!(generic.glwe_secret_key_share_sns_compression.is_none());
            assert!(generic.oprf_secret_key_share.is_some());

            let refinalized = generic.finalize_keyset(params.classic_pbs());
            assert_eq!(keyset, refinalized);
        }

        #[test]
        fn test_definalizable_z128_round_trip_with_sns() {
            let mut keyset = PrivateKeySet::<4>::init_dummy(PARAMS_TEST_BK_SNS);
            keyset.glwe_secret_key_share_sns_as_lwe = Some(LweSecretKeyShare { data: vec![] });
            keyset.glwe_sns_compression_key_as_lwe = Some(LweSecretKeyShare { data: vec![] });

            let generic = Definalizable::<Z128, 4>::to_generic(&keyset, PARAMS_TEST_BK_SNS)
                .expect("to_generic should succeed for Z128 keys with SNS");

            assert!(generic.glwe_secret_key_share_sns.is_some());
            assert!(generic.glwe_secret_key_share_sns_compression.is_some());
            assert!(generic.oprf_secret_key_share.is_some());

            let params = PARAMS_TEST_BK_SNS;
            let refinalized = generic.finalize_keyset(params.classic_pbs());
            assert_eq!(keyset, refinalized);
        }

        #[test]
        fn test_definalizable_z128_rejects_z64_keys() {
            let params = *BC_PARAMS_NO_SNS;
            let keyset = PrivateKeySet::<4> {
                lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z64(LweSecretKeyShare {
                    data: vec![],
                }),
                lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z64(LweSecretKeyShare {
                    data: vec![],
                }),
                glwe_secret_key_share: GlweSecretKeyShareEnum::Z64(GlweSecretKeyShare {
                    data: vec![],
                    polynomial_size: params.polynomial_size(),
                }),
                glwe_secret_key_share_sns_as_lwe: None,
                oprf_secret_key_share: None,
                glwe_secret_key_share_compression: None,
                glwe_sns_compression_key_as_lwe: None,
                parameters: params.classic_pbs(),
            };

            match Definalizable::<Z128, 4>::to_generic(&keyset, *BC_PARAMS_NO_SNS) {
                Ok(_) => panic!("should fail for Z64 keys"),
                Err(e) => {
                    let err_msg = e.to_string();
                    assert!(
                        err_msg.contains("Expected Z128"),
                        "Expected error about Z128, got: {err_msg}"
                    );
                }
            }
        }

        #[test]
        fn test_definalizable_z128_sns_key_with_wrong_params() {
            let mut keyset = PrivateKeySet::<4>::init_dummy(*BC_PARAMS_NO_SNS);
            keyset.glwe_secret_key_share_sns_as_lwe = Some(LweSecretKeyShare { data: vec![] });

            match Definalizable::<Z128, 4>::to_generic(&keyset, *BC_PARAMS_NO_SNS) {
                Ok(_) => panic!("should fail with WithoutSnS params"),
                Err(e) => {
                    let err_msg = e.to_string();
                    assert!(
                        err_msg.contains("WithoutSnS"),
                        "Expected error about WithoutSnS, got: {err_msg}"
                    );
                }
            }
        }

        #[test]
        fn test_definalizable_z64_round_trip() {
            let keyset = PrivateKeySet::<4>::init_dummy(*BC_PARAMS_NO_SNS);

            let generic = Definalizable::<Z64, 4>::to_generic(&keyset, *BC_PARAMS_NO_SNS)
                .expect("to_generic should succeed for Z64 conversion");

            assert!(generic.glwe_secret_key_share_sns.is_none());
            assert!(generic.glwe_secret_key_share_sns_compression.is_none());
            assert!(generic.oprf_secret_key_share.is_some());

            let params = *BC_PARAMS_NO_SNS;
            let refinalized = generic.finalize_keyset(params.classic_pbs());

            // After Z64 round-trip, keys should be Z64
            assert!(matches!(
                refinalized.lwe_compute_secret_key_share,
                LweSecretKeyShareEnum::Z64(_)
            ));
            assert!(matches!(
                refinalized.lwe_encryption_secret_key_share,
                LweSecretKeyShareEnum::Z64(_)
            ));
            assert!(matches!(
                refinalized.glwe_secret_key_share,
                GlweSecretKeyShareEnum::Z64(_)
            ));
        }

        #[test]
        fn test_definalizable_z64_rejects_sns_keys() {
            let mut keyset = PrivateKeySet::<4>::init_dummy(*BC_PARAMS_NO_SNS);
            keyset.glwe_secret_key_share_sns_as_lwe = Some(LweSecretKeyShare { data: vec![] });

            match Definalizable::<Z64, 4>::to_generic(&keyset, *BC_PARAMS_NO_SNS) {
                Ok(_) => panic!("should fail with SNS keys"),
                Err(e) => {
                    let err_msg = e.to_string();
                    assert!(
                        err_msg.contains("SNS keys"),
                        "Expected error about SNS keys, got: {err_msg}"
                    );
                }
            }
        }

        #[test]
        fn test_definalizable_z128_with_non_empty_data() {
            let role = Role::indexed_from_one(1);
            let val = ResiduePolyF4Z128::from_scalar(Wrapping(42u128));
            let share = Share::new(role, val);

            let params = *BC_PARAMS_NO_SNS;
            let keyset = PrivateKeySet::<4> {
                lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                    data: vec![share],
                }),
                lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                    data: vec![share],
                }),
                glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                    data: vec![share],
                    polynomial_size: params.polynomial_size(),
                }),
                glwe_secret_key_share_sns_as_lwe: None,
                oprf_secret_key_share: Some(LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                    data: vec![share],
                })),
                glwe_secret_key_share_compression: None,
                glwe_sns_compression_key_as_lwe: None,
                parameters: params.classic_pbs(),
            };

            let generic = Definalizable::<Z128, 4>::to_generic(&keyset, *BC_PARAMS_NO_SNS)
                .expect("to_generic should succeed with non-empty data");
            let refinalized = generic.finalize_keyset(params.classic_pbs());
            assert_eq!(keyset, refinalized);
        }
    }
}
