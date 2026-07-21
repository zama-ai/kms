use crate::{
    config::BatchParams,
    online::{
        preprocessing::{BasePreprocessing, memory::InMemoryBasePreprocessing},
        reshare::{
            Expected, NotExpected, Reshare, SecureSameSetReshare, SecureTwoSetsReshareAsBothSets,
            SecureTwoSetsReshareAsSet1, SecureTwoSetsReshareAsSet2,
        },
    },
    runtime::sessions::base_session::{BaseSessionHandles, GenericBaseSessionHandles},
    tfhe_internals::{
        compression_decompression_key::CompressionPrivateKeyShares,
        glwe_key::GlweSecretKeyShare,
        lwe_key::LweSecretKeyShare,
        parameters::{DKGParams, DkgMode},
        private_keysets::{
            CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, LweSecretKeyShareEnum,
            PrivateKeySet,
        },
    },
};
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::ResiduePoly,
    structure_traits::{ErrorCorrect, Invert, Syndrome},
};
use error_utils::anyhow_error_and_log;
use threshold_types::role::TwoSetsRole;

use tfhe::shortint::parameters::CompressionParameters;
use tracing::instrument;

pub struct ResharePreprocRequired {
    pub batch_params_128: BatchParams,
    pub batch_params_64: BatchParams,
}

impl ResharePreprocRequired {
    /// Computes the number of randoms needed to reshare a private key set
    /// where `num_parties_reshare_from` is the number of parties holding the input shares
    /// (i.e. everyone in same set resharing, or the first set in two sets resharing)
    /// and `oprf_key_present` says whether the old keyset contains a dedicated OPRF key.
    ///
    /// NOTE: A [`PrivateKeySet`] is expected to be either all Z64 or all Z128 depending on the DKG parameters.
    pub fn new(
        num_parties_reshare_from: usize,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> Self {
        let mut num_randoms_128 = 0;
        let mut num_randoms_64 = 0;

        match parameters.dkg_mode() {
            DkgMode::Z64 => {
                num_randoms_64 += parameters.lwe_hat_dimension().0;
                num_randoms_64 += parameters.lwe_dimension().0;
                if oprf_key_present {
                    num_randoms_64 += parameters.lwe_dimension().0;
                }
                num_randoms_64 +=
                    parameters.glwe_sk_num_bits() + parameters.compression_sk_num_bits()
            }
            DkgMode::Z128 => {
                num_randoms_128 += parameters.lwe_hat_dimension().0;
                num_randoms_128 += parameters.lwe_dimension().0;
                if oprf_key_present {
                    num_randoms_128 += parameters.lwe_dimension().0;
                }
                num_randoms_128 +=
                    parameters.glwe_sk_num_bits() + parameters.compression_sk_num_bits();
                if let Some(p) = parameters.sns() {
                    num_randoms_128 += p.glwe_sk_num_bits_sns() + p.sns_compression_sk_num_bits();
                }
            }
        }

        num_randoms_128 *= num_parties_reshare_from;
        num_randoms_64 *= num_parties_reshare_from;

        ResharePreprocRequired {
            batch_params_128: BatchParams {
                triples: 0,
                randoms: num_randoms_128,
            },
            batch_params_64: BatchParams {
                triples: 0,
                randoms: num_randoms_64,
            },
        }
    }
}

#[async_trait::async_trait]
pub trait ReshareSecretKeys: Send + Sync + Sized {
    /// Reshare a secret key share within the same set of parties such that if a party failed during DKG,
    ///  it can catch up.
    /// - `session` is the regular session handle for the parties involved in the resharing
    /// - `input_share` is `Some` for parties holding an input share, and `None` otherwise (e.g. if DKG failed)
    /// - `preproc128` and `preproc64` are the preprocessing instances for Z128 and Z64 operations respectively. See [`ResharePreprocRequired`] to know how much preprocessing is needed.
    /// - `parameters` are the DKG parameters
    /// - `oprf_key_present` is true only when the old keyset contains a dedicated OPRF key
    ///
    /// Returns the party's new secret key share
    async fn reshare_sk_same_set<
        S: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        session: &mut S,
        preproc128: &mut P128,
        preproc64: &mut P64,
        input_share: &mut Option<PrivateKeySet<EXTENSION_DEGREE>>,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome;

    /// __THIS FUNCTION IS FOR PARTIES IN S1 ONLY__
    /// i.e. with Role [`TwoSetsRole::Set1`]
    ///
    /// Reshare a secret key share from parties in Set1 to parties in Set2
    /// - `two_sets_session` is the session handle that contains parties in both Set1 and Set2
    /// - `input_share` is the input share held by the party in Set1 that will be reshared
    /// - `parameters` are the DKG parameters
    /// - `oprf_key_present` is true only when the old keyset contains a dedicated OPRF key
    ///
    /// Returns `()` since parties in Set1 do not receive any new share
    async fn reshare_sk_two_sets_as_s1<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        const EXTENSION_DEGREE: usize,
    >(
        two_sets_session: &mut S,
        input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome;

    /// __THIS FUNCTION IS FOR PARTIES IN S2 ONLY__
    /// i.e. with Role [`TwoSetsRole::Set2`]
    ///
    /// Reshare a secret key share from parties in Set1 to parties in Set2
    /// - `sessions` is a tuple containing the session handle that contains parties in both Set1 and Set2 as well as the regular session handle for parties in Set2
    /// - `preproc128` and `preproc64` are the preprocessing instances for Z128 and Z64 operations respectively. See [`ResharePreprocRequired`] to know how much preprocessing is needed.
    /// - `parameters` are the DKG parameters
    /// - `oprf_key_present` is true only when the old keyset contains a dedicated OPRF key
    ///
    /// Returns the party's new secret key share
    async fn reshare_sk_two_sets_as_s2<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        Sess: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        sessions: &mut (S, Sess),
        preproc128: &mut P128,
        preproc64: &mut P64,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome;

    /// __THIS FUNCTION IS FOR PARTIES IN BOTH S1 AND S2__
    /// i.e. with Role [`TwoSetsRole::Both`]
    ///
    /// Reshare a secret key share from parties in Set1 to parties in Set2
    /// - `sessions` is a tuple containing the session handle that contains parties in both Set1 and Set2 as well as the regular session handle for parties in Set2
    /// - `preproc128` and `preproc64` are the preprocessing instances for Z128 and Z64 operations respectively. See [`ResharePreprocRequired`] to know how much preprocessing is needed.
    /// - `input_share` is the input share held by the party in Set1 that will be reshared
    /// - `parameters` are the DKG parameters
    /// - `oprf_key_present` is true only when the old keyset contains a dedicated OPRF key
    ///
    /// Returns the party's new secret key share
    async fn reshare_sk_two_sets_as_both_sets<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        Sess: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        sessions: &mut (S, Sess),
        preproc128: &mut P128,
        preproc64: &mut P64,
        input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome;
}

#[derive(Default)]
pub struct SecureReshareSecretKeys;

#[async_trait::async_trait]
impl ReshareSecretKeys for SecureReshareSecretKeys {
    #[instrument(
    name = "ReShare (same sets)",
    skip(preproc128, preproc64, session, input_share)
    fields(sid=?session.session_id(),my_role=?session.my_role())
    )]
    async fn reshare_sk_same_set<
        S: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        session: &mut S,
        preproc128: &mut P128,
        preproc64: &mut P64,
        input_share: &mut Option<PrivateKeySet<EXTENSION_DEGREE>>,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        reshare_sk::<SecureSameSetReshare<S>, _, _, _>(
            Expected(preproc128),
            Expected(preproc64),
            session,
            input_share.as_mut(),
            parameters,
            oprf_key_present,
        )
        .await?
        .ok_or_else(|| anyhow_error_and_log("Expected an output in same set reshare"))
    }

    #[instrument(
    name = "ReShare (as set 1)",
    skip_all,
    fields(sid=?two_sets_session.session_id(),my_role=?two_sets_session.my_role())
    )]
    async fn reshare_sk_two_sets_as_s1<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        const EXTENSION_DEGREE: usize,
    >(
        two_sets_session: &mut S,
        input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let _ = reshare_sk::<SecureTwoSetsReshareAsSet1<S>, _, _, _>(
            NotExpected::<&mut InMemoryBasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
                _marker: std::marker::PhantomData,
            },
            NotExpected::<&mut InMemoryBasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
                _marker: std::marker::PhantomData,
            },
            two_sets_session,
            Expected(input_share),
            parameters,
            oprf_key_present,
        )
        .await?;
        Ok(())
    }

    #[instrument(name = "ReShare (as set 2)", skip_all, fields(sid, my_role))]
    async fn reshare_sk_two_sets_as_s2<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        Sess: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        sessions: &mut (S, Sess),
        preproc128: &mut P128,
        preproc64: &mut P64,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let span = tracing::Span::current();
        span.record("sid", format!("{:?}", sessions.0.session_id()));
        span.record("my_role", format!("{:?}", sessions.0.my_role()));
        reshare_sk::<SecureTwoSetsReshareAsSet2<S, Sess>, _, _, _>(
            Expected(preproc128),
            Expected(preproc64),
            sessions,
            NotExpected {
                _marker: std::marker::PhantomData,
            },
            parameters,
            oprf_key_present,
        )
        .await?
        .ok_or_else(|| anyhow_error_and_log("Expected an output in two sets reshare"))
    }

    #[instrument(name = "ReShare (as both sets)", skip_all, fields(sid, my_role))]
    async fn reshare_sk_two_sets_as_both_sets<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        Sess: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        sessions: &mut (S, Sess),
        preproc128: &mut P128,
        preproc64: &mut P64,
        input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        parameters: DKGParams,
        oprf_key_present: bool,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let span = tracing::Span::current();
        span.record("sid", format!("{:?}", sessions.0.session_id()));
        span.record("my_role", format!("{:?}", sessions.0.my_role()));
        reshare_sk::<SecureTwoSetsReshareAsBothSets<S, Sess>, _, _, _>(
            Expected(preproc128),
            Expected(preproc64),
            sessions,
            Expected(input_share),
            parameters,
            oprf_key_present,
        )
        .await?
        .ok_or_else(|| anyhow_error_and_log("Expected an output in two sets reshare"))
    }
}

pub(crate) async fn reshare_sk<
    R: Reshare + Default,
    P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
    P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
    const EXTENSION_DEGREE: usize,
>(
    mut preproc128: R::MaybeExpectedPreprocessing<&mut P128>,
    mut preproc64: R::MaybeExpectedPreprocessing<&mut P64>,
    sessions: &mut R::ReshareSessions,
    input_share: R::MaybeExpectedInputShares<&mut PrivateKeySet<EXTENSION_DEGREE>>,
    parameters: DKGParams,
    oprf_key_present: bool,
) -> anyhow::Result<Option<PrivateKeySet<EXTENSION_DEGREE>>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    let reshare = R::default();
    let mut input_share = input_share.into();
    // Reshare the GLWE sns key
    let glwe_secret_key_share_sns_as_lwe = if let Some(sns_params) = parameters.sns() {
        let expected_key_size = sns_params.glwe_sk_num_bits_sns();
        let maybe_key = input_share.as_mut().and_then(|s| {
            s.glwe_secret_key_share_sns_as_lwe
                .as_mut()
                .map(|key| key.data.as_mut())
        });
        let data = reshare
            .execute(
                sessions,
                &mut preproc128,
                &mut R::MaybeExpectedInputShares::from(maybe_key),
                expected_key_size,
            )
            .await?;
        (true, data.into().map(|data| LweSecretKeyShare { data }))
    } else {
        (false, None)
    };

    // Reshare the LWE compute key
    let expected_key_size = parameters.lwe_dimension().0;
    let lwe_compute_secret_key_share = match parameters.dkg_mode() {
        DkgMode::Z64 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.lwe_compute_secret_key_share
                        .try_cast_mut_to_z64()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc64,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            data.into()
                .map(|data| LweSecretKeyShareEnum::Z64(LweSecretKeyShare { data }))
        }
        DkgMode::Z128 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.lwe_compute_secret_key_share
                        .try_cast_mut_to_z128()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc128,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            data.into()
                .map(|data| LweSecretKeyShareEnum::Z128(LweSecretKeyShare { data }))
        }
    };

    // Reshare the LWE PKe key
    let expected_key_size = parameters.lwe_hat_dimension().0;
    let polynomial_size = parameters.polynomial_size();
    let lwe_encryption_secret_key_share = match parameters.dkg_mode() {
        DkgMode::Z64 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.lwe_encryption_secret_key_share
                        .try_cast_mut_to_z64()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc64,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            data.into()
                .map(|data| LweSecretKeyShareEnum::Z64(LweSecretKeyShare { data }))
        }
        DkgMode::Z128 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.lwe_encryption_secret_key_share
                        .try_cast_mut_to_z128()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc128,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            data.into()
                .map(|data| LweSecretKeyShareEnum::Z128(LweSecretKeyShare { data }))
        }
    };

    // Reshare the dedicated OPRF LWE key only when the old keyset has one.
    let oprf_secret_key_share = if oprf_key_present {
        let expected_key_size = parameters.lwe_dimension().0;
        match parameters.dkg_mode() {
            DkgMode::Z64 => {
                let maybe_key = input_share
                    .as_mut()
                    .and_then(|s| {
                        s.oprf_secret_key_share
                            .as_mut()
                            .map(|key| key.try_cast_mut_to_z64().map(|key| key.data.as_mut()))
                    })
                    .transpose()
                    .map_err(|e| anyhow_error_and_log(e.to_string()))?;
                let data = reshare
                    .execute(
                        sessions,
                        &mut preproc64,
                        &mut R::MaybeExpectedInputShares::from(maybe_key),
                        expected_key_size,
                    )
                    .await?;
                data.into()
                    .map(|data| LweSecretKeyShareEnum::Z64(LweSecretKeyShare { data }))
            }
            DkgMode::Z128 => {
                let maybe_key = input_share
                    .as_mut()
                    .and_then(|s| {
                        s.oprf_secret_key_share
                            .as_mut()
                            .map(|key| key.try_cast_mut_to_z128().map(|key| key.data.as_mut()))
                    })
                    .transpose()
                    .map_err(|e| anyhow_error_and_log(e.to_string()))?;
                let data = reshare
                    .execute(
                        sessions,
                        &mut preproc128,
                        &mut R::MaybeExpectedInputShares::from(maybe_key),
                        expected_key_size,
                    )
                    .await?;
                data.into()
                    .map(|data| LweSecretKeyShareEnum::Z128(LweSecretKeyShare { data }))
            }
        }
    } else {
        None
    };

    // Reshare the GLWE compute key
    let expected_key_size = parameters.glwe_sk_num_bits();
    let glwe_secret_key_share = match parameters.dkg_mode() {
        DkgMode::Z64 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.glwe_secret_key_share
                        .try_cast_mut_to_z64()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc64,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            data.into().map(|data| {
                GlweSecretKeyShareEnum::Z64(GlweSecretKeyShare {
                    data,
                    polynomial_size,
                })
            })
        }
        DkgMode::Z128 => {
            let maybe_key = input_share
                .as_mut()
                .map(|s| {
                    s.glwe_secret_key_share
                        .try_cast_mut_to_z128()
                        .map(|key| key.data.as_mut())
                })
                .transpose()
                .map_err(|e| anyhow_error_and_log(e.to_string()))?;
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc128,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            data.into().map(|data| {
                GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                    data,
                    polynomial_size,
                })
            })
        }
    };

    // Reshare the GLWE compression key
    let glwe_secret_key_share_compression =
        if let Some(compression_params) = parameters.compression_decompression_params() {
            let polynomial_size = compression_params
                .raw_compression_parameters
                .packing_ks_polynomial_size;
            let expected_key_size = parameters.compression_sk_num_bits();
            (
                true,
                match parameters.dkg_mode() {
                    DkgMode::Z64 => {
                        // Extract the GLWE secret key share for the compression scheme if any
                        let maybe_key = input_share
                            .as_mut()
                            .and_then(|s| {
                                s.glwe_secret_key_share_compression.as_mut().map(
                                    |compression_sk_share| {
                                        compression_sk_share
                                            .try_cast_mut_to_z64()
                                            .map(|key| key.post_packing_ks_key.data.as_mut())
                                    },
                                )
                            })
                            .transpose()
                            .map_err(|e| anyhow_error_and_log(e.to_string()))?;
                        let data = reshare
                            .execute(
                                sessions,
                                &mut preproc64,
                                &mut R::MaybeExpectedInputShares::from(maybe_key),
                                expected_key_size,
                            )
                            .await?;
                        data.into().map(|data| {
                            CompressionPrivateKeySharesEnum::Z64(CompressionPrivateKeyShares {
                                post_packing_ks_key: GlweSecretKeyShare {
                                    data,
                                    polynomial_size,
                                },
                                params: CompressionParameters::Classic(
                                    compression_params.raw_compression_parameters,
                                ),
                            })
                        })
                    }
                    DkgMode::Z128 => {
                        // Extract the GLWE secret key share for the compression scheme if any
                        let maybe_key = input_share
                            .as_mut()
                            .and_then(|s| {
                                s.glwe_secret_key_share_compression.as_mut().map(
                                    |compression_sk_share| {
                                        compression_sk_share
                                            .try_cast_mut_to_z128()
                                            .map(|key| key.post_packing_ks_key.data.as_mut())
                                    },
                                )
                            })
                            .transpose()
                            .map_err(|e| anyhow_error_and_log(e.to_string()))?;
                        let data = reshare
                            .execute(
                                sessions,
                                &mut preproc128,
                                &mut R::MaybeExpectedInputShares::from(maybe_key),
                                expected_key_size,
                            )
                            .await?;
                        data.into().map(|data| {
                            CompressionPrivateKeySharesEnum::Z128(CompressionPrivateKeyShares {
                                post_packing_ks_key: GlweSecretKeyShare {
                                    data,
                                    polynomial_size,
                                },
                                params: CompressionParameters::Classic(
                                    compression_params.raw_compression_parameters,
                                ),
                            })
                        })
                    }
                },
            )
        } else {
            (false, None)
        };

    // Reshare the GLWE sns compression key
    let glwe_sns_compression_key_as_lwe = if let Some(params_sns) = parameters.sns() {
        if params_sns.sns_compression_params().is_some() {
            // NOTE (bugfix): this reshares the SnS *compression* key, so it must
            // be sized with the SnS compression key size. The legacy code used
            // `compression_sk_num_bits()`, which on the old `DKGParamsSnS`
            // delegated to the *regular* compression params — the wrong key size.
            // It went unnoticed because the only parameter set ever resharded in
            // tests (`PARAMS_TEST_BK_SNS`) has identical regular and SnS
            // compression dimensions (256 == 256), masking the discrepancy.
            // Fixed here to use the SnS compression key size.
            let expected_key_size = params_sns.sns_compression_sk_num_bits();
            let maybe_key = input_share.as_mut().and_then(|s| {
                s.glwe_sns_compression_key_as_lwe
                    .as_mut()
                    .map(|key| key.data.as_mut())
            });
            let data = reshare
                .execute(
                    sessions,
                    &mut preproc128,
                    &mut R::MaybeExpectedInputShares::from(maybe_key),
                    expected_key_size,
                )
                .await?;
            (true, data.into().map(|data| LweSecretKeyShare { data }))
        } else {
            (false, None)
        }
    } else {
        (false, None)
    };

    match (
        lwe_encryption_secret_key_share,
        lwe_compute_secret_key_share,
        glwe_secret_key_share,
    ) {
        (
            Some(lwe_encryption_secret_key_share),
            Some(lwe_compute_secret_key_share),
            Some(glwe_secret_key_share),
        ) => {
            let glwe_secret_key_share_sns_as_lwe = if glwe_secret_key_share_sns_as_lwe.0
                && glwe_secret_key_share_sns_as_lwe.1.is_none()
            {
                return Err(anyhow_error_and_log(
                    "Expected GLWE SNS secret key share to be present",
                ));
            } else {
                glwe_secret_key_share_sns_as_lwe.1
            };

            let glwe_secret_key_share_compression = if glwe_secret_key_share_compression.0
                && glwe_secret_key_share_compression.1.is_none()
            {
                return Err(anyhow_error_and_log(
                    "Expected GLWE compression secret key share to be present",
                ));
            } else {
                glwe_secret_key_share_compression.1
            };

            let glwe_sns_compression_key_as_lwe = if glwe_sns_compression_key_as_lwe.0
                && glwe_sns_compression_key_as_lwe.1.is_none()
            {
                return Err(anyhow_error_and_log(
                    "Expected GLWE SNS compression secret key share to be present",
                ));
            } else {
                glwe_sns_compression_key_as_lwe.1
            };
            tracing::info!("Resharing completed, output is expected.");
            Ok(Some(PrivateKeySet {
                lwe_encryption_secret_key_share,
                lwe_compute_secret_key_share,
                oprf_secret_key_share,
                glwe_secret_key_share,
                glwe_secret_key_share_sns_as_lwe,
                parameters: parameters.classic_pbs(),
                glwe_secret_key_share_compression,
                glwe_sns_compression_key_as_lwe,
            }))
        }
        (None, None, None) => {
            tracing::info!("Resharing completed, no output is expected.");
            Ok(None)
        }
        (a, b, c) => Err(anyhow_error_and_log(format!(
            "Either all output shares must be present or none: {}, {}, {}",
            a.is_some(),
            b.is_some(),
            c.is_some(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::preprocessing::RandomPreprocessing;
    use crate::online::preprocessing::memory::InMemoryBasePreprocessing;
    use crate::runtime::sessions::base_session::{BaseSession, GenericBaseSession};
    use crate::runtime::sessions::small_session::SmallSession;
    use crate::tests::helper::tests::generate_keys_deterministically;
    use crate::tests::helper::tests_and_benches::{
        execute_protocol_small, execute_protocol_two_sets,
    };
    use crate::tfhe_internals::parameters::PARAMS_TEST_RESHARE;
    use crate::tfhe_internals::test_feature::{
        ClientKeyView, KeySet, keygen_all_party_shares_from_client_key, to_hl_client_key,
    };
    use crate::{
        online::preprocessing::dummy::DummyPreprocessing,
        runtime::sessions::session_parameters::GenericParameterHandles,
    };
    use aes_prng::AesRng;
    use algebra::{
        sharing::{
            shamir::{InputOp, RevealOp, ShamirSharings},
            share::Share,
        },
        structure_traits::{BaseRing, Ring, Sample},
    };
    use itertools::Itertools;
    use rand::SeedableRng;
    use std::fmt::Display;
    use std::sync::LazyLock;
    use tfhe::core_crypto::entities::{GlweSecretKey, LweSecretKey};
    use tfhe::prelude::Tagged;
    use tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
    use threshold_types::network::NetworkMode;
    use threshold_types::role::{Role, TwoSetsRole, TwoSetsThreshold};

    /// The reshare-test keyset, generated once (deterministically) and shared by
    /// every party and every reshare test — cheap `PARAMS_TEST_RESHARE` keys mean
    /// an in-memory cache is enough (no need to persist to a file as we do for the
    /// expensive production keyset).
    static RESHARE_KEYSET: LazyLock<KeySet> = LazyLock::new(|| {
        generate_keys_deterministically(PARAMS_TEST_RESHARE, tfhe::Tag::default())
    });

    #[tokio::test(flavor = "multi_thread")]
    async fn reshare_no_error() {
        simulate_reshare_same_set::<3>(false, false)
            .await
            .expect("Reshare no error for degree 3 failed");
        simulate_reshare_same_set::<4>(false, false)
            .await
            .expect("Reshare no error for degree 4 failed");
        simulate_reshare_same_set::<5>(false, false)
            .await
            .expect("Reshare no error for degree 5 failed");
        simulate_reshare_same_set::<6>(false, false)
            .await
            .expect("Reshare no error for degree 6 failed");
        simulate_reshare_same_set::<7>(false, false)
            .await
            .expect("Reshare no error for degree 7 failed");
        simulate_reshare_same_set::<8>(false, false)
            .await
            .expect("Reshare no error for degree 8 failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reshare_with_error() {
        simulate_reshare_same_set::<3>(true, false)
            .await
            .expect("Reshare with error for degree 3 failed");
        simulate_reshare_same_set::<4>(true, false)
            .await
            .expect("Reshare with error for degree 4 failed");
        simulate_reshare_same_set::<5>(true, false)
            .await
            .expect("Reshare with error for degree 5 failed");
        simulate_reshare_same_set::<6>(true, false)
            .await
            .expect("Reshare with error for degree 6 failed");
        simulate_reshare_same_set::<7>(true, false)
            .await
            .expect("Reshare with error for degree 7 failed");
        simulate_reshare_same_set::<8>(true, false)
            .await
            .expect("Reshare with error for degree 8 failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reshare_with_missing() {
        simulate_reshare_same_set::<3>(false, true)
            .await
            .expect("Reshare with missing for degree 3 failed");
        simulate_reshare_same_set::<4>(false, true)
            .await
            .expect("Reshare with missing for degree 4 failed");
        simulate_reshare_same_set::<5>(false, true)
            .await
            .expect("Reshare with missing for degree 5 failed");
        simulate_reshare_same_set::<6>(false, true)
            .await
            .expect("Reshare with missing for degree 6 failed");
        simulate_reshare_same_set::<7>(false, true)
            .await
            .expect("Reshare with missing for degree 7 failed");
        simulate_reshare_same_set::<8>(false, true)
            .await
            .expect("Reshare with missing for degree 8 failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    async fn reshare_no_error_f4_two_sets(
        #[values(0, 2, 4)] intersection_size: usize,
    ) -> anyhow::Result<()> {
        let num_parties_s1 = 7;
        let num_parties_s2 = 4;
        let threshold = TwoSetsThreshold {
            threshold_set_1: 2,
            threshold_set_2: 1,
        };
        simulate_reshare_two_sets::<4>(
            false,
            num_parties_s1,
            num_parties_s2,
            intersection_size,
            threshold,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    async fn reshare_with_error_f4_two_sets(
        #[values(0, 2, 4)] intersection_size: usize,
    ) -> anyhow::Result<()> {
        let num_parties_s1 = 7;
        let num_parties_s2 = 4;
        let threshold = TwoSetsThreshold {
            threshold_set_1: 2,
            threshold_set_2: 1,
        };
        simulate_reshare_two_sets::<4>(
            true,
            num_parties_s1,
            num_parties_s2,
            intersection_size,
            threshold,
        )
        .await
    }

    async fn simulate_reshare_same_set<const EXTENSION_DEGREE: usize>(
        add_error: bool,
        remove_share: bool,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let num_parties = 7;
        let threshold = 2;

        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        _added_info: Option<String>| async move {
            // Small, self-consistent params with pairwise-distinct key sizes,
            // generated deterministically so every party derives the same keyset.
            let params = PARAMS_TEST_RESHARE;
            let keyset = RESHARE_KEYSET.clone();

            let key_shares = generate_key_with_error_in_s1(
                keyset,
                params,
                session.num_parties(),
                session.threshold() as usize,
                add_error,
            )
            .unwrap();
            let oprf_key_present = key_shares
                .iter()
                .any(|share| share.oprf_secret_key_share.is_some());

            let party_keyshare = session.my_role().get_from(&key_shares).unwrap().clone();
            let mut preproc = DummyPreprocessing::new(42, &session);

            //Testing ResharePreprocRequired
            let preproc_required =
                ResharePreprocRequired::new(session.num_parties(), params, oprf_key_present);

            let mut new_preproc_64 = InMemoryBasePreprocessing {
                available_triples: Vec::new(),
                available_randoms: preproc
                    .next_random_vec(preproc_required.batch_params_64.randoms)
                    .unwrap(),
            };

            let mut new_preproc_128 = InMemoryBasePreprocessing {
                available_triples: Vec::new(),
                available_randoms: preproc
                    .next_random_vec(preproc_required.batch_params_128.randoms)
                    .unwrap(),
            };

            let mut my_contribution =
                if session.my_role() == Role::indexed_from_zero(0) && remove_share {
                    // simulating that the first party lost its key share
                    None
                } else {
                    Some(party_keyshare)
                };

            let out = SecureReshareSecretKeys::reshare_sk_same_set(
                &mut session,
                &mut new_preproc_128,
                &mut new_preproc_64,
                &mut my_contribution,
                params,
                oprf_key_present,
            )
            .await
            .unwrap();

            //Making sure ResharPreprocRequired doesn't ask for too much preprocessing
            assert_eq!(new_preproc_64.available_randoms.len(), 0);
            assert_eq!(new_preproc_128.available_randoms.len(), 0);
            assert_eq!(out.oprf_secret_key_share.is_some(), oprf_key_present);
            (session.my_role(), out, my_contribution)
        };

        let mut results = execute_protocol_small::<_, _, _, EXTENSION_DEGREE>(
            num_parties,
            threshold as u8,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        )
        .await;

        // we need to sort by identities and then reconstruct
        results.sort_by_key(|a| a.0);
        let (new_shares, old_shares): (Vec<_>, Vec<_>) =
            results.into_iter().map(|(_, b, c)| (b, c)).unzip();

        // The reshared shares must reconstruct to the *full* original client key.
        let reference_client_key = RESHARE_KEYSET.client_key.clone();
        let tag = reference_client_key.tag().clone();

        let reconstructed =
            reconstruct_client_key(&new_shares, PARAMS_TEST_RESHARE, tag.clone(), threshold, 0)?;
        assert_same_client_key(&reconstructed, &reference_client_key);

        // Also reconstruct from only threshold+1 shares (index 0 is party 1, the
        // corrupt/missing one when `add_error`/`remove_share` is set — its *new*
        // share is still valid after reshare).
        let reconstructed_partial = reconstruct_client_key(
            &new_shares[0..=threshold],
            PARAMS_TEST_RESHARE,
            tag,
            threshold,
            0,
        )?;
        assert_same_client_key(&reconstructed_partial, &reference_client_key);

        // check that the old shares have been zeroized
        for osh in old_shares.into_iter().flatten() {
            osh.glwe_secret_key_share_sns_as_lwe
                .unwrap()
                .data_iter()
                .for_each(|x| assert!(x.is_zero()));
        }
        Ok(())
    }

    async fn simulate_reshare_two_sets<const EXTENSION_DEGREE: usize>(
        add_error: bool,
        num_parties_s1: usize,
        num_parties_s2: usize,
        intersection_size: usize,
        threshold: TwoSetsThreshold,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let mut task = |mut common_session: GenericBaseSession<TwoSetsRole>,
                        session_set_1: Option<BaseSession>,
                        session_set_2: Option<BaseSession>| async move {
            let new_params = PARAMS_TEST_RESHARE;
            let keyset = RESHARE_KEYSET.clone();
            let oprf_key_present = ClientKeyView::new(&keyset.client_key)
                .raw_oprf_client_key()
                .is_some();
            let mut party_keyshare = if let Some(session_set_1) = session_set_1.as_ref() {
                let key_shares = generate_key_with_error_in_s1(
                    keyset,
                    new_params,
                    session_set_1.num_parties(),
                    session_set_1.threshold() as usize,
                    add_error,
                )
                .unwrap();

                Some(
                    session_set_1
                        .my_role()
                        .get_from(&key_shares)
                        .unwrap()
                        .clone(),
                )
            } else {
                None
            };

            let (mut preproc_64, mut preproc_128) = if let Some(session_set_2) =
                session_set_2.as_ref()
            {
                let mut preproc = DummyPreprocessing::new(42, session_set_2);

                //Testing ResharePreprocRequired
                let num_parties_set_1 = common_session
                    .roles()
                    .iter()
                    .filter(|p| p.is_set1())
                    .count();
                assert_eq!(num_parties_set_1, num_parties_s1);
                let preproc_required =
                    ResharePreprocRequired::new(num_parties_set_1, new_params, oprf_key_present);

                let new_preproc_64 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: preproc
                        .next_random_vec(preproc_required.batch_params_64.randoms)
                        .unwrap(),
                };

                let new_preproc_128 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: preproc
                        .next_random_vec(preproc_required.batch_params_128.randoms)
                        .unwrap(),
                };
                (Some(new_preproc_64), Some(new_preproc_128))
            } else {
                (None, None)
            };

            let my_role = common_session.my_role();
            let out = match my_role {
                TwoSetsRole::Set1(_) => {
                    let mut party_keyshare = party_keyshare.unwrap();
                    SecureReshareSecretKeys::reshare_sk_two_sets_as_s1(
                        &mut common_session,
                        &mut party_keyshare,
                        new_params,
                        oprf_key_present,
                    )
                    .await
                    .unwrap();
                    party_keyshare
                }
                TwoSetsRole::Set2(_) => SecureReshareSecretKeys::reshare_sk_two_sets_as_s2(
                    &mut (common_session, session_set_2.unwrap()),
                    preproc_128.as_mut().unwrap(),
                    preproc_64.as_mut().unwrap(),
                    new_params,
                    oprf_key_present,
                )
                .await
                .unwrap(),
                TwoSetsRole::Both(_) => SecureReshareSecretKeys::reshare_sk_two_sets_as_both_sets(
                    &mut (common_session, session_set_2.unwrap()),
                    preproc_128.as_mut().unwrap(),
                    preproc_64.as_mut().unwrap(),
                    party_keyshare.as_mut().unwrap(),
                    new_params,
                    oprf_key_present,
                )
                .await
                .unwrap(),
            };

            //Making sure ResharPreprocRequired doesn't ask for too much preprocessing
            if let Some(p) = preproc_64 {
                assert_eq!(p.available_randoms.len(), 0)
            }
            if let Some(p) = preproc_128 {
                assert_eq!(p.available_randoms.len(), 0)
            }
            assert_eq!(out.oprf_secret_key_share.is_some(), oprf_key_present);

            (my_role, out)
        };

        let results = execute_protocol_two_sets::<
            _,
            _,
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >(
            num_parties_s1,
            num_parties_s2,
            intersection_size,
            threshold,
            None,
            NetworkMode::Sync,
            &mut task,
        )
        .await;

        let (results_set_1_only, mut results_set_2_and_both): (Vec<_>, Vec<_>) =
            results.into_iter().partition_map(|(role, out)| match role {
                TwoSetsRole::Set1(role) => itertools::Either::Left((role, out)),
                TwoSetsRole::Set2(role) => itertools::Either::Right((role, out)),
                TwoSetsRole::Both(dual_role) => {
                    itertools::Either::Right((dual_role.role_set_2, out))
                }
            });

        // we need to sort by identities and then reconstruct
        results_set_2_and_both.sort_by_key(|a| a.0);
        let new_shares: Vec<_> = results_set_2_and_both.into_iter().map(|(_, b)| b).collect();

        // The reshared shares (set 2) must reconstruct to the full original client key.
        let reference_client_key = RESHARE_KEYSET.client_key.clone();
        let reconstructed = reconstruct_client_key(
            &new_shares,
            PARAMS_TEST_RESHARE,
            reference_client_key.tag().clone(),
            threshold.threshold_set_2 as usize,
            0,
        )?;
        assert_same_client_key(&reconstructed, &reference_client_key);

        // check old shares are zero
        for (role, osh) in results_set_1_only.into_iter() {
            let all_zero = osh
                .glwe_secret_key_share_sns_as_lwe
                .as_ref()
                .unwrap()
                .data_iter()
                .all(|x| x.is_zero());
            assert!(all_zero, "Role {role:?} did not zeroize its old share");
        }
        Ok(())
    }

    /// Error-reconstructs each secret bit from its per-party [`Share`]s.
    ///
    /// `shares` is party-major (`shares[party][bit]`)
    fn reconstruct_shares_to_scalar<Z: BaseRing + Display, const EXTENSION_DEGREE: usize>(
        shares: &[&[Share<ResiduePoly<Z, EXTENSION_DEGREE>>]],
        threshold: usize,
        max_errors: usize,
    ) -> Vec<Z>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
        ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>:
            RevealOp<ResiduePoly<Z, EXTENSION_DEGREE>>,
        ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>: InputOp<ResiduePoly<Z, EXTENSION_DEGREE>>,
    {
        let num_bits = shares[0].len();
        (0..num_bits)
            .map(|j| {
                let bit_shares = shares.iter().map(|party| party[j]).collect();
                ShamirSharings::create(bit_shares)
                    .error_reconstruct(threshold, max_errors)
                    .unwrap()
                    .to_scalar()
                    .unwrap()
            })
            .collect()
    }

    /// Reconstructs a flat `u64` secret-key container from a per-party
    /// [`LweSecretKeyShareEnum`] extractor (handles both Z64 and Z128 shares;
    /// key bits are 0/1 so widening a Z128 reconstruction to `u64` is lossless).
    /// `extract` returns a *reference*, so no per-party key-share is cloned.
    fn recon_lwe_enum_u64<const EXTENSION_DEGREE: usize>(
        shares: &[PrivateKeySet<EXTENSION_DEGREE>],
        extract: impl Fn(&PrivateKeySet<EXTENSION_DEGREE>) -> &LweSecretKeyShareEnum<EXTENSION_DEGREE>,
        threshold: usize,
        max_errors: usize,
    ) -> Vec<u64>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        match extract(&shares[0]) {
            LweSecretKeyShareEnum::Z64(_) => {
                let per_party: Vec<_> = shares
                    .iter()
                    .map(|s| match extract(s) {
                        LweSecretKeyShareEnum::Z64(inner) => inner.data.as_slice(),
                        LweSecretKeyShareEnum::Z128(_) => {
                            unreachable!("inconsistent share domain across parties")
                        }
                    })
                    .collect();
                reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0)
                    .collect_vec()
            }
            LweSecretKeyShareEnum::Z128(_) => {
                let per_party: Vec<_> = shares
                    .iter()
                    .map(|s| match extract(s) {
                        LweSecretKeyShareEnum::Z128(inner) => inner.data.as_slice(),
                        LweSecretKeyShareEnum::Z64(_) => {
                            unreachable!("inconsistent share domain across parties")
                        }
                    })
                    .collect();
                reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0 as u64)
                    .collect_vec()
            }
        }
    }

    /// Same as [`recon_lwe_enum_u64`] for a [`GlweSecretKeyShareEnum`].
    fn recon_glwe_enum_u64<const EXTENSION_DEGREE: usize>(
        shares: &[PrivateKeySet<EXTENSION_DEGREE>],
        extract: impl Fn(&PrivateKeySet<EXTENSION_DEGREE>) -> &GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
        threshold: usize,
        max_errors: usize,
    ) -> Vec<u64>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        match extract(&shares[0]) {
            GlweSecretKeyShareEnum::Z64(_) => {
                let per_party: Vec<_> = shares
                    .iter()
                    .map(|s| match extract(s) {
                        GlweSecretKeyShareEnum::Z64(inner) => inner.data.as_slice(),
                        GlweSecretKeyShareEnum::Z128(_) => {
                            unreachable!("inconsistent share domain across parties")
                        }
                    })
                    .collect();
                reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0)
                    .collect_vec()
            }
            GlweSecretKeyShareEnum::Z128(_) => {
                let per_party: Vec<_> = shares
                    .iter()
                    .map(|s| match extract(s) {
                        GlweSecretKeyShareEnum::Z128(inner) => inner.data.as_slice(),
                        GlweSecretKeyShareEnum::Z64(_) => {
                            unreachable!("inconsistent share domain across parties")
                        }
                    })
                    .collect();
                reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0 as u64)
                    .collect_vec()
            }
        }
    }

    /// Reconstructs a flat `u128` container from a per-party 128-bit
    /// [`LweSecretKeyShare`] extractor (the SnS / SnS-compression keys, which
    /// are always stored as `u128`). `extract` returns a *reference*.
    fn recon_lwe_z128_u128<const EXTENSION_DEGREE: usize>(
        shares: &[PrivateKeySet<EXTENSION_DEGREE>],
        extract: impl Fn(&PrivateKeySet<EXTENSION_DEGREE>) -> &LweSecretKeyShare<Z128, EXTENSION_DEGREE>,
        threshold: usize,
        max_errors: usize,
    ) -> Vec<u128>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let per_party: Vec<_> = shares.iter().map(|s| extract(s).data.as_slice()).collect();
        reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
            .into_iter()
            .map(|x| x.0)
            .collect_vec()
    }

    /// Reconstructs the regular-compression secret key (`u64`) from a per-party
    /// [`CompressionPrivateKeySharesEnum`] extractor (returns a *reference*).
    fn recon_compression_enum_u64<const EXTENSION_DEGREE: usize>(
        shares: &[PrivateKeySet<EXTENSION_DEGREE>],
        extract: impl Fn(
            &PrivateKeySet<EXTENSION_DEGREE>,
        ) -> &CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>,
        threshold: usize,
        max_errors: usize,
    ) -> Vec<u64>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        match extract(&shares[0]) {
            CompressionPrivateKeySharesEnum::Z64(_) => {
                let per_party: Vec<_> = shares
                    .iter()
                    .map(|s| match extract(s) {
                        CompressionPrivateKeySharesEnum::Z64(inner) => {
                            inner.post_packing_ks_key.data.as_slice()
                        }
                        CompressionPrivateKeySharesEnum::Z128(_) => {
                            unreachable!("inconsistent compression share domain across parties")
                        }
                    })
                    .collect();
                reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0)
                    .collect_vec()
            }
            CompressionPrivateKeySharesEnum::Z128(_) => {
                let per_party: Vec<_> = shares
                    .iter()
                    .map(|s| match extract(s) {
                        CompressionPrivateKeySharesEnum::Z128(inner) => {
                            inner.post_packing_ks_key.data.as_slice()
                        }
                        CompressionPrivateKeySharesEnum::Z64(_) => {
                            unreachable!("inconsistent compression share domain across parties")
                        }
                    })
                    .collect();
                reconstruct_shares_to_scalar(&per_party, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0 as u64)
                    .collect_vec()
            }
        }
    }

    /// Asserts two client keys are byte-identical, component by component (a
    /// whole-key byte compare only says "different"; this names the offending
    /// field). Covers every component: compute key, dedicated CPK, compression,
    /// noise-squashing, SnS-compression, re-randomization params, OPRF, and tag.
    fn assert_same_client_key(a: &tfhe::ClientKey, b: &tfhe::ClientKey) {
        let (ai, acpk, acomp, ans, ansc, arerand, aoprf, atag) = a.clone().into_raw_parts();
        let (bi, bcpk, bcomp, bns, bnsc, brerand, boprf, btag) = b.clone().into_raw_parts();
        macro_rules! same_field {
            ($x:expr, $y:expr, $name:literal) => {
                assert_eq!(
                    bc2wrap::serialize(&$x).unwrap(),
                    bc2wrap::serialize(&$y).unwrap(),
                    concat!("client key mismatch: ", $name),
                );
            };
        }
        same_field!(ai, bi, "integer/compute client key");
        same_field!(acpk, bcpk, "dedicated compact private key");
        same_field!(acomp, bcomp, "compression private key");
        same_field!(ans, bns, "noise squashing private key");
        same_field!(ansc, bnsc, "sns compression private key");
        same_field!(arerand, brerand, "re-randomization parameters");
        same_field!(aoprf, boprf, "oprf private key");
        same_field!(atag, btag, "tag");
    }

    /// Reconstructs the **full** `tfhe::ClientKey` from the reshared
    /// `PrivateKeySet` shares, so a test can compare it against the original
    /// client key. This reconstructs *every* secret-key component — compute LWE,
    /// encryption LWE, GLWE, SnS GLWE, regular + SnS compression, and OPRF — and
    /// reassembles them via [`to_hl_client_key`], so every reshare reconstruction
    /// path is exercised.
    ///
    /// `tfhe::ClientKey` is not `PartialEq`; callers compare the result to the
    /// original with [`assert_same_client_key`].
    fn reconstruct_client_key<const EXTENSION_DEGREE: usize>(
        shares: &[PrivateKeySet<EXTENSION_DEGREE>],
        params: DKGParams,
        tag: tfhe::Tag,
        threshold: usize,
        max_errors: usize,
    ) -> anyhow::Result<tfhe::ClientKey>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let lwe_secret_key = LweSecretKey::from_container(recon_lwe_enum_u64(
            shares,
            |s| &s.lwe_compute_secret_key_share,
            threshold,
            max_errors,
        ));

        // Only pass the encryption key when there is a dedicated CPK; otherwise it
        // is the very same key as the compute LWE key and `to_hl_client_key`
        // expects `None`.
        let dedicated_compact_private_key = params.has_dedicated_compact_pk_params().then(|| {
            LweSecretKey::from_container(recon_lwe_enum_u64(
                shares,
                |s| &s.lwe_encryption_secret_key_share,
                threshold,
                max_errors,
            ))
        });

        let glwe_secret_key = GlweSecretKey::from_container(
            recon_glwe_enum_u64(shares, |s| &s.glwe_secret_key_share, threshold, max_errors),
            params.polynomial_size(),
        );

        let compression_key = params.compression().map(|comp| {
            GlweSecretKey::from_container(
                recon_compression_enum_u64(
                    shares,
                    |s| {
                        s.glwe_secret_key_share_compression
                            .as_ref()
                            .expect("compression share present when params carry compression")
                    },
                    threshold,
                    max_errors,
                ),
                comp.packing_ks_polynomial_size(),
            )
        });

        let sns_secret_key = params.sns().map(|sns| {
            GlweSecretKey::from_container(
                recon_lwe_z128_u128(
                    shares,
                    |s| {
                        s.glwe_secret_key_share_sns_as_lwe
                            .as_ref()
                            .expect("SnS share present when params carry SnS")
                    },
                    threshold,
                    max_errors,
                ),
                sns.polynomial_size_sns(),
            )
        });

        let sns_compression_secret_key =
            params
                .sns()
                .and_then(|s| s.sns_compression_params())
                .map(|sns_comp_params| {
                    let container = recon_lwe_z128_u128(
                        shares,
                        |s| {
                            s.glwe_sns_compression_key_as_lwe.as_ref().expect(
                                "SnS-compression share present when params carry SnS compression",
                            )
                        },
                        threshold,
                        max_errors,
                    );
                    NoiseSquashingCompressionPrivateKey::from_raw_parts(
                        GlweSecretKey::from_container(
                            container,
                            sns_comp_params.packing_ks_polynomial_size,
                        ),
                        sns_comp_params,
                    )
                });

        let oprf_private_lwe_sk = shares[0].oprf_secret_key_share.is_some().then(|| {
            LweSecretKey::from_container(recon_lwe_enum_u64(
                shares,
                |s| {
                    s.oprf_secret_key_share
                        .as_ref()
                        .expect("OPRF share present on all parties when present on party 0")
                },
                threshold,
                max_errors,
            ))
        });

        to_hl_client_key(
            &params,
            tag,
            lwe_secret_key,
            glwe_secret_key,
            dedicated_compact_private_key,
            compression_key,
            sns_secret_key,
            sns_compression_secret_key,
            oprf_private_lwe_sk,
        )
    }

    /// Overwrites every share value in `data` with a fresh random sample (keeping
    /// party 0's role) — turns a party's correct share into a corrupt one.
    fn corrupt_shares_in_place<Z, const EXTENSION_DEGREE: usize>(
        data: &mut [Share<ResiduePoly<Z, EXTENSION_DEGREE>>],
        rng: &mut AesRng,
    ) where
        Z: Clone,
        ResiduePoly<Z, EXTENSION_DEGREE>: Sample + Ring,
    {
        for share in data.iter_mut() {
            *share = Share::new(
                Role::indexed_from_zero(0),
                ResiduePoly::<Z, EXTENSION_DEGREE>::sample(rng),
            );
        }
    }

    fn corrupt_lwe_enum<const EXTENSION_DEGREE: usize>(
        key: &mut LweSecretKeyShareEnum<EXTENSION_DEGREE>,
        rng: &mut AesRng,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Sample + Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Sample + Ring,
    {
        match key {
            LweSecretKeyShareEnum::Z64(inner) => corrupt_shares_in_place(&mut inner.data, rng),
            LweSecretKeyShareEnum::Z128(inner) => corrupt_shares_in_place(&mut inner.data, rng),
        }
    }

    fn corrupt_glwe_enum<const EXTENSION_DEGREE: usize>(
        key: &mut GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
        rng: &mut AesRng,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Sample + Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Sample + Ring,
    {
        match key {
            GlweSecretKeyShareEnum::Z64(inner) => corrupt_shares_in_place(&mut inner.data, rng),
            GlweSecretKeyShareEnum::Z128(inner) => corrupt_shares_in_place(&mut inner.data, rng),
        }
    }

    fn corrupt_compression_enum<const EXTENSION_DEGREE: usize>(
        key: &mut CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>,
        rng: &mut AesRng,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Sample + Ring,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Sample + Ring,
    {
        match key {
            CompressionPrivateKeySharesEnum::Z64(inner) => {
                corrupt_shares_in_place(&mut inner.post_packing_ks_key.data, rng)
            }
            CompressionPrivateKeySharesEnum::Z128(inner) => {
                corrupt_shares_in_place(&mut inner.post_packing_ks_key.data, rng)
            }
        }
    }

    /// Generates the per-party `PrivateKeySet` shares of `keyset`. When
    /// `add_error` is set, *every* component of party 0's share is corrupted
    /// (still a single bad party, hence error-correctable), so reshare's handling
    /// of a corrupt contribution is exercised for all key types. Sanity-checks
    /// that the full client key still reconstructs from the (possibly errored)
    /// shares before returning them.
    fn generate_key_with_error_in_s1<const EXTENSION_DEGREE: usize>(
        keyset: KeySet,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        add_error: bool,
    ) -> anyhow::Result<Vec<PrivateKeySet<EXTENSION_DEGREE>>>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        // generate the key shares
        let mut rng = AesRng::seed_from_u64(4242);
        let mut key_shares = keygen_all_party_shares_from_client_key(
            &keyset.client_key,
            params.classic_pbs(),
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();

        if add_error {
            // Corrupt *every* component of party 0's share (still a single bad
            // party, so it stays error-correctable), so reshare's handling of a
            // corrupt contribution is exercised for all key types — not just the
            // compute LWE/GLWE and SnS-GLWE keys.
            let bad = &mut key_shares[0];
            corrupt_lwe_enum(&mut bad.lwe_compute_secret_key_share, &mut rng);
            corrupt_lwe_enum(&mut bad.lwe_encryption_secret_key_share, &mut rng);
            corrupt_glwe_enum(&mut bad.glwe_secret_key_share, &mut rng);
            if let Some(sns) = bad.glwe_secret_key_share_sns_as_lwe.as_mut() {
                corrupt_shares_in_place(&mut sns.data, &mut rng);
            }
            if let Some(comp) = bad.glwe_secret_key_share_compression.as_mut() {
                corrupt_compression_enum(comp, &mut rng);
            }
            if let Some(sns_comp) = bad.glwe_sns_compression_key_as_lwe.as_mut() {
                corrupt_shares_in_place(&mut sns_comp.data, &mut rng);
            }
            if let Some(oprf) = bad.oprf_secret_key_share.as_mut() {
                corrupt_lwe_enum(oprf, &mut rng);
            }
        }

        // Sanity check: the *full* client key must still reconstruct from these
        // shares (error correction tolerates the single corrupt party).
        let reconstructed = reconstruct_client_key(
            &key_shares,
            params,
            keyset.client_key.tag().clone(),
            threshold,
            usize::from(add_error),
        )?;
        assert_same_client_key(&reconstructed, &keyset.client_key);

        Ok(key_shares)
    }
}
