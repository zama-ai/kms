use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Syndrome},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        online::{
            preprocessing::{memory::InMemoryBasePreprocessing, BasePreprocessing},
            reshare::{
                Expected, NotExpected, Reshare, SecureSameSetReshare,
                SecureTwoSetsReshareAsBothSets, SecureTwoSetsReshareAsSet1,
                SecureTwoSetsReshareAsSet2,
            },
        },
        runtime::{
            party::TwoSetsRole,
            sessions::base_session::{BaseSessionHandles, GenericBaseSessionHandles},
        },
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares,
            glwe_key::GlweSecretKeyShare,
            lwe_key::LweSecretKeyShare,
            parameters::{DKGParams, DKGParamsBasics, DkgMode},
            private_keysets::{
                CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, LweSecretKeyShareEnum,
                PrivateKeySet,
            },
        },
    },
};

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
    ///
    /// NOTE: A [`PrivateKeySet`] is exepected to be either all Z64 or all Z128 depending on the DKG parameters.
    pub fn new(num_parties_reshare_from: usize, parameters: DKGParams) -> Self {
        let params = parameters.get_params_basics_handle();
        let mut num_randoms_128 = 0;
        let mut num_randoms_64 = 0;

        match parameters.get_params_basics_handle().get_dkg_mode() {
            DkgMode::Z64 => {
                num_randoms_64 += params.lwe_hat_dimension().0;
                num_randoms_64 += params.lwe_dimension().0;
                num_randoms_64 += params.glwe_sk_num_bits() + params.compression_sk_num_bits()
            }
            DkgMode::Z128 => {
                num_randoms_128 += params.lwe_hat_dimension().0;
                num_randoms_128 += params.lwe_dimension().0;
                num_randoms_128 += params.glwe_sk_num_bits() + params.compression_sk_num_bits();
                if let DKGParams::WithSnS(p) = parameters {
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
    ///
    /// Returns `()` since parties in Set1 do not receive any new share
    async fn reshare_sk_two_sets_as_s1<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        const EXTENSION_DEGREE: usize,
    >(
        two_sets_session: &mut S,
        input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        parameters: DKGParams,
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
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let span = tracing::Span::current();
        span.record("sid", format!("{:?}", &sessions.0.session_id()));
        span.record("my_role", format!("{:?}", &sessions.0.my_role()));
        reshare_sk::<SecureTwoSetsReshareAsSet2<S, Sess>, _, _, _>(
            Expected(preproc128),
            Expected(preproc64),
            sessions,
            NotExpected {
                _marker: std::marker::PhantomData,
            },
            parameters,
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
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let span = tracing::Span::current();
        span.record("sid", format!("{:?}", &sessions.0.session_id()));
        span.record("my_role", format!("{:?}", &sessions.0.my_role()));
        reshare_sk::<SecureTwoSetsReshareAsBothSets<S, Sess>, _, _, _>(
            Expected(preproc128),
            Expected(preproc64),
            sessions,
            Expected(input_share),
            parameters,
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
) -> anyhow::Result<Option<PrivateKeySet<EXTENSION_DEGREE>>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    let reshare = R::default();
    let mut input_share = input_share.into();
    // Reshare the GLWE sns key
    let glwe_secret_key_share_sns_as_lwe = if let DKGParams::WithSnS(sns_params) = parameters {
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

    let basic_params_handle = parameters.get_params_basics_handle();

    // Reshare the LWE compute key
    let expected_key_size = basic_params_handle.lwe_dimension().0;
    let lwe_compute_secret_key_share = match parameters.get_params_basics_handle().get_dkg_mode() {
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
    let expected_key_size = basic_params_handle.lwe_hat_dimension().0;
    let polynomial_size = basic_params_handle.polynomial_size();
    let lwe_encryption_secret_key_share = match parameters.get_params_basics_handle().get_dkg_mode()
    {
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

    // Reshare the GLWE compute key
    let expected_key_size = basic_params_handle.glwe_sk_num_bits();
    let glwe_secret_key_share = match parameters.get_params_basics_handle().get_dkg_mode() {
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
    let glwe_secret_key_share_compression = if let Some(compression_params) =
        basic_params_handle.get_compression_decompression_params()
    {
        let polynomial_size = compression_params
            .raw_compression_parameters
            .packing_ks_polynomial_size;
        let expected_key_size = basic_params_handle.compression_sk_num_bits();
        (
            true,
            match parameters.get_params_basics_handle().get_dkg_mode() {
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
    let glwe_sns_compression_key_as_lwe = match parameters {
        DKGParams::WithoutSnS(_) => (false, None),
        DKGParams::WithSnS(params_sns) => {
            if params_sns.sns_compression_params.is_some() {
                let expected_key_size = params_sns.compression_sk_num_bits();
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
        }
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
                glwe_secret_key_share,
                glwe_secret_key_share_sns_as_lwe,
                parameters: basic_params_handle.to_classic_pbs_parameters(),
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
    use crate::algebra::structure_traits::{BaseRing, Ring};
    use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
    use crate::execution::online::preprocessing::RandomPreprocessing;
    use crate::execution::runtime::party::{Role, TwoSetsThreshold};
    use crate::execution::runtime::sessions::base_session::{BaseSession, GenericBaseSession};
    use crate::execution::runtime::sessions::small_session::SmallSession;
    use crate::execution::sharing::shamir::{RevealOp, ShamirSharings};
    use crate::execution::sharing::share::Share;
    use crate::execution::tfhe_internals::parameters::{DKGParamsRegular, DKGParamsSnS};
    use crate::execution::tfhe_internals::test_feature::{
        keygen_all_party_shares_from_keyset, KeySet,
    };
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests_and_benches::{
        execute_protocol_small, execute_protocol_two_sets,
    };
    use crate::tests::test_data_setup::tests::TEST_PARAMETERS;
    use crate::{
        algebra::structure_traits::Sample,
        execution::{
            constants::SMALL_TEST_KEY_PATH, online::preprocessing::dummy::DummyPreprocessing,
            runtime::sessions::session_parameters::GenericParameterHandles,
            sharing::shamir::InputOp,
        },
        file_handling::tests::read_element,
    };
    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;
    use std::fmt::Display;
    use tfhe::boolean::prelude::GlweDimension;
    use tfhe::core_crypto::entities::GlweSecretKey;
    use tfhe::shortint::client_key::atomic_pattern::{
        AtomicPatternClientKey, StandardAtomicPatternClientKey,
    };
    use tfhe::shortint::noise_squashing::NoiseSquashingPrivateKey;
    use tfhe::shortint::prelude::ModulusSwitchType;
    use tfhe::shortint::PBSParameters;
    use tfhe::{core_crypto::entities::LweSecretKey, shortint::ClassicPBSParameters};

    #[tokio::test]
    async fn reshare_no_error_f4() -> anyhow::Result<()> {
        simulate_reshare_same_set::<4>(false, false).await
    }

    #[tokio::test]
    async fn reshare_with_error_f4() -> anyhow::Result<()> {
        simulate_reshare_same_set::<4>(true, false).await
    }

    #[tokio::test]
    async fn reshare_with_missing_f4() -> anyhow::Result<()> {
        simulate_reshare_same_set::<4>(false, true).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    async fn reshare_no_error_f3() -> anyhow::Result<()> {
        simulate_reshare_same_set::<3>(false, false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    async fn reshare_with_error_f3() -> anyhow::Result<()> {
        simulate_reshare_same_set::<3>(true, false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    async fn reshare_with_missing_f3() -> anyhow::Result<()> {
        simulate_reshare_same_set::<3>(false, true).await
    }

    #[cfg(feature = "extension_degree_5")]
    #[tokio::test]
    async fn reshare_no_error_f5() -> anyhow::Result<()> {
        simulate_reshare_same_set::<5>(false, false).await
    }

    #[cfg(feature = "extension_degree_5")]
    #[tokio::test]
    async fn reshare_with_error_f5() -> anyhow::Result<()> {
        simulate_reshare_same_set::<5>(true, false).await
    }

    #[cfg(feature = "extension_degree_5")]
    #[tokio::test]
    async fn reshare_with_missing_f5() -> anyhow::Result<()> {
        simulate_reshare_same_set::<5>(false, true).await
    }

    #[cfg(feature = "extension_degree_6")]
    #[tokio::test]
    async fn reshare_no_error_f6() -> anyhow::Result<()> {
        simulate_reshare_same_set::<6>(false, false).await
    }

    #[cfg(feature = "extension_degree_6")]
    #[tokio::test]
    async fn reshare_with_error_f6() -> anyhow::Result<()> {
        simulate_reshare_same_set::<6>(true, false).await
    }

    #[cfg(feature = "extension_degree_6")]
    #[tokio::test]
    async fn reshare_with_missing_f6() -> anyhow::Result<()> {
        simulate_reshare_same_set::<6>(false, true).await
    }

    #[cfg(feature = "extension_degree_7")]
    #[tokio::test]
    async fn reshare_no_error_f7() -> anyhow::Result<()> {
        simulate_reshare_same_set::<7>(false, false).await
    }

    #[cfg(feature = "extension_degree_7")]
    #[tokio::test]
    async fn reshare_with_error_f7() -> anyhow::Result<()> {
        simulate_reshare_same_set::<7>(true, false).await
    }

    #[cfg(feature = "extension_degree_7")]
    #[tokio::test]
    async fn reshare_with_missing_f7() -> anyhow::Result<()> {
        simulate_reshare_same_set::<7>(false, true).await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    async fn reshare_no_error_f8() -> anyhow::Result<()> {
        simulate_reshare_same_set::<8>(false, false).await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    async fn reshare_with_error_f8() -> anyhow::Result<()> {
        simulate_reshare_same_set::<8>(true, false).await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    async fn reshare_with_missing_f8() -> anyhow::Result<()> {
        simulate_reshare_same_set::<8>(false, true).await
    }

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
            let mut keyset: KeySet =
                read_element(std::path::Path::new(SMALL_TEST_KEY_PATH)).unwrap();

            // we make the shares shorter to make sure the test doesn't take too long
            // NOTE that TEST_PARAMETERS must be the parameters of SMALL_TEST_KEY_PATH
            let new_params = get_truncated_client_keys_params(TEST_PARAMETERS);
            truncate_client_keys(&mut keyset, new_params);

            let (key_shares, expected_sk) = generate_key_with_error_in_s1(
                keyset,
                new_params,
                session.num_parties(),
                session.threshold() as usize,
                add_error,
            )
            .unwrap();

            let party_keyshare = session.my_role().get_from(&key_shares).unwrap().clone();
            let mut preproc = DummyPreprocessing::new(42, &session);

            //Testing ResharePreprocRequired
            let preproc_required = ResharePreprocRequired::new(session.num_parties(), new_params);

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
                new_params,
            )
            .await
            .unwrap();

            //Making sure ResharPreprocRequired doesn't ask for too much preprocessing
            assert_eq!(new_preproc_64.available_randoms.len(), 0);
            assert_eq!(new_preproc_128.available_randoms.len(), 0);
            (session.my_role(), out, my_contribution, expected_sk)
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
        results.sort_by(|a, b| a.0.cmp(&(b.0)));
        let (new_shares, (old_shares, expected_sks)): (Vec<_>, (Vec<_>, Vec<_>)) =
            results.into_iter().map(|(_, b, c, d)| (b, (c, d))).unzip();
        let actual_sk = reconstruct_sk(new_shares.clone(), threshold, 0);

        let mut expected_sks_iter = expected_sks.into_iter();
        let expected_sk = expected_sks_iter.next().unwrap();
        expected_sks_iter.for_each(|v| assert_eq!(v, expected_sk));
        // check results
        assert_eq!(actual_sk, expected_sk);

        // Also try to reconstruct with only some shares (including 0 (i.e. Party 1) as it's always the corrupt/missing one when add_error is true)
        let partial_shares = new_shares[0..=threshold].to_vec();
        let actual_sk = reconstruct_sk(partial_shares, threshold, 0);
        assert_eq!(actual_sk, expected_sk);

        // check that the old shares have been zeroized
        for osh in old_shares.into_iter().flatten() {
            osh.glwe_secret_key_share_sns_as_lwe
                .unwrap()
                .data_as_raw_vec()
                .iter()
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
            let new_params = get_truncated_client_keys_params(TEST_PARAMETERS);
            let (mut party_keyshare, expected_sk, _key_shares) = if let Some(session_set_1) =
                session_set_1.as_ref()
            {
                let mut keyset = read_element(std::path::Path::new(SMALL_TEST_KEY_PATH)).unwrap();
                // we make the shares shorter to make sure the test doesn't take too long

                truncate_client_keys(&mut keyset, new_params);

                let (key_shares, expected_sk) = generate_key_with_error_in_s1(
                    keyset,
                    new_params,
                    session_set_1.num_parties(),
                    session_set_1.threshold() as usize,
                    add_error,
                )
                .unwrap();

                let party_keyshare = session_set_1
                    .my_role()
                    .get_from(&key_shares)
                    .unwrap()
                    .clone();
                (Some(party_keyshare), Some(expected_sk), Some(key_shares))
            } else {
                (None, None, None)
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
                let preproc_required = ResharePreprocRequired::new(num_parties_set_1, new_params);

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
                )
                .await
                .unwrap(),
                TwoSetsRole::Both(_) => SecureReshareSecretKeys::reshare_sk_two_sets_as_both_sets(
                    &mut (common_session, session_set_2.unwrap()),
                    preproc_128.as_mut().unwrap(),
                    preproc_64.as_mut().unwrap(),
                    party_keyshare.as_mut().unwrap(),
                    new_params,
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

            (my_role, out, expected_sk)
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

        let (results_set_1_only, mut results_set_2_and_both): (Vec<_>, Vec<_>) = results
            .into_iter()
            .partition_map(|(role, out, expected_sk)| match role {
                TwoSetsRole::Set1(role) => itertools::Either::Left((role, out, expected_sk)),
                TwoSetsRole::Set2(role) => itertools::Either::Right((role, out, expected_sk)),
                TwoSetsRole::Both(dual_role) => {
                    itertools::Either::Right((dual_role.role_set_2, out, expected_sk))
                }
            });

        // we need to sort by identities and then reconstruct
        results_set_2_and_both.sort_by(|a, b| a.0.cmp(&(b.0)));
        let new_shares: Vec<_> = results_set_2_and_both
            .into_iter()
            .map(|(_, b, _)| b)
            .collect();
        let actual_sk = reconstruct_sk(new_shares.clone(), threshold.threshold_set_2 as usize, 0);

        let (should_be_zeroized_shares, expected_sks): (Vec<_>, Vec<_>) = results_set_1_only
            .into_iter()
            .map(|(role, out, expected_sk)| ((role, out), expected_sk.unwrap()))
            .unzip();

        let mut expected_sks_iter = expected_sks.into_iter();
        let expected_sk = expected_sks_iter.next().unwrap();
        expected_sks_iter.for_each(|v| assert_eq!(v, expected_sk));
        // check results
        assert_eq!(actual_sk, expected_sk);

        // check old shares are zero
        for (role, osh) in should_be_zeroized_shares.into_iter() {
            if !osh
                .glwe_secret_key_share_sns_as_lwe
                .clone()
                .unwrap()
                .data_as_raw_vec()
                .iter()
                .all(|x| x.is_zero())
            {
                println!("Role {:?} did not zeroize its old share! : {:?}", role, osh);
            }
            osh.glwe_secret_key_share_sns_as_lwe
                .unwrap()
                .data_as_raw_vec()
                .iter()
                .for_each(|x| assert!(x.is_zero()));
        }
        Ok(())
    }

    // We return test params to use to truncate the keys
    fn get_truncated_client_keys_params(params: DKGParams) -> DKGParams {
        let new_sns_params = if let DKGParams::WithSnS(sns_params) = params {
            let mut new_sns_params = sns_params.sns_params;

            let sns_private_key_len = 8;
            let sns_poly_size = tfhe::shortint::prelude::PolynomialSize(1);
            match &mut new_sns_params {
                tfhe::shortint::parameters::NoiseSquashingParameters::Classic(
                    noise_squashing_classic_parameters,
                ) => {
                    noise_squashing_classic_parameters.polynomial_size = sns_poly_size;
                    noise_squashing_classic_parameters.glwe_dimension =
                        GlweDimension(sns_private_key_len);
                }
                tfhe::shortint::parameters::NoiseSquashingParameters::MultiBit(
                    noise_squashing_multi_bit_parameters,
                ) => {
                    noise_squashing_multi_bit_parameters.polynomial_size = sns_poly_size;
                    noise_squashing_multi_bit_parameters.glwe_dimension =
                        GlweDimension(sns_private_key_len);
                }
            }
            Some(new_sns_params)
        } else {
            None
        };
        let params = PBSParameters::PBS(
            params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
        );
        let test_lwe_dim = params.lwe_dimension().0.min(8);
        let test_glwe_dim = params.glwe_dimension().0.min(1);
        let test_poly_size = params.polynomial_size().0.min(10);
        let new_pbs_params = ClassicPBSParameters {
            lwe_dimension: tfhe::integer::parameters::LweDimension(test_lwe_dim),
            glwe_dimension: tfhe::integer::parameters::GlweDimension(test_glwe_dim),
            polynomial_size: tfhe::integer::parameters::PolynomialSize(test_poly_size),
            lwe_noise_distribution: params.lwe_noise_distribution(),
            glwe_noise_distribution: params.glwe_noise_distribution(),
            pbs_base_log: params.pbs_base_log(),
            pbs_level: params.pbs_level(),
            ks_base_log: params.ks_base_log(),
            ks_level: params.ks_level(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            max_noise_level: params.max_noise_level(),
            // currently there's no getter for log2_p_fail, so we set it manually
            // doesn't matter what it is
            log2_p_fail: -80.,
            ciphertext_modulus: params.ciphertext_modulus(),
            encryption_key_choice: params.encryption_key_choice(),
            modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
        };

        let regular_params = DKGParamsRegular {
            dkg_mode: DkgMode::Z128,
            sec: 128,
            ciphertext_parameters: new_pbs_params,
            dedicated_compact_public_key_parameters: None,
            compression_decompression_parameters: None,
            cpk_re_randomization_ksk_params: None,
            secret_key_deviations: None,
        };

        if let Some(new_sns_params) = new_sns_params {
            DKGParams::WithSnS(DKGParamsSnS {
                regular_params,
                sns_params: new_sns_params,
                sns_compression_params: None,
            })
        } else {
            DKGParams::WithoutSnS(regular_params)
        }
    }

    // We truncate the keys in the keyset to make the test faster
    // to match the sizes in the target parameters
    fn truncate_client_keys(keyset: &mut KeySet, target_params: DKGParams) {
        let new_sns_private_key = if let DKGParams::WithSnS(sns_params) = target_params {
            let (raw_sns_private_key, _) = keyset
                .client_key
                .clone()
                .into_raw_parts()
                .3
                .unwrap()
                .into_raw_parts()
                .into_raw_parts();

            let sns_private_key_len = sns_params.glwe_dimension_sns().0;
            let sns_poly_size = sns_params.polynomial_size_sns();
            let new_raw_sns_private_key = GlweSecretKey::from_container(
                raw_sns_private_key.into_container()[..sns_private_key_len * sns_poly_size.0]
                    .to_vec(),
                sns_poly_size,
            );

            Some(
                tfhe::integer::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                    NoiseSquashingPrivateKey::from_raw_parts(
                        new_raw_sns_private_key,
                        sns_params.sns_params,
                    ),
                ),
            )
        } else {
            None
        };

        let (glwe_raw, lwe_raw, _, _) = match keyset
            .client_key
            .to_owned()
            .into_raw_parts()
            .0
            .into_raw_parts()
            .atomic_pattern
        {
            tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey::Standard(
                standard_atomic_pattern_client_key,
            ) => standard_atomic_pattern_client_key.into_raw_parts(),
            tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey::KeySwitch32(_) => {
                panic!("KeySwitch32 is not supported in this test")
            }
        };

        let target_params = target_params.get_params_basics_handle();

        let test_lwe_dim = target_params.lwe_dimension().0;
        let test_glwe_dim = target_params.glwe_dimension().0;
        let test_poly_size = target_params.polynomial_size().0;
        let lwe_cont: Vec<u64> = lwe_raw.into_container();
        let con = lwe_cont[..test_lwe_dim].to_vec();
        let new_lwe_raw = LweSecretKey::from_container(con);
        let glwe_cont = glwe_raw.into_container();
        let con = glwe_cont[..test_poly_size * test_glwe_dim].to_vec();
        let new_glwe_raw = GlweSecretKey::from_container(
            con,
            tfhe::integer::parameters::PolynomialSize(test_poly_size),
        );

        let sck = StandardAtomicPatternClientKey::from_raw_parts(
            new_glwe_raw,
            new_lwe_raw,
            PBSParameters::PBS(target_params.to_classic_pbs_parameters()),
            None,
        );
        let sck = tfhe::shortint::ClientKey {
            atomic_pattern: AtomicPatternClientKey::Standard(sck),
        };
        let sck = tfhe::integer::ClientKey::from_raw_parts(sck);

        let ck = tfhe::ClientKey::from_raw_parts(
            sck,
            None,
            None,
            new_sns_private_key,
            None,
            None,
            tfhe::Tag::default(),
        );
        keyset.client_key = ck;
    }

    fn reconstruct_shares_to_scalar<Z: BaseRing + Display, const EXTENSION_DEGREE: usize>(
        shares: Vec<Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>,
        threshold: usize,
        max_errors: usize,
    ) -> Vec<Z>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
        ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>:
            RevealOp<ResiduePoly<Z, EXTENSION_DEGREE>>,
        ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>: InputOp<ResiduePoly<Z, EXTENSION_DEGREE>>,
    {
        let parties = shares.len();
        let mut out = Vec::with_capacity(shares[0].len());
        for j in 0..shares[0].len() {
            let mut bit_shares = Vec::with_capacity(parties);
            (0..parties).for_each(|i| {
                bit_shares.push(Share::new(
                    Role::indexed_from_zero(i),
                    *shares[i].get(j).unwrap(),
                ));
            });
            let first_bit_sharing = ShamirSharings::create(bit_shares);
            let rec = first_bit_sharing
                .err_reconstruct(threshold, max_errors)
                .unwrap();
            let inner_rec = rec.to_scalar().unwrap();
            out.push(inner_rec)
        }
        out
    }

    fn reconstruct_sk<const EXTENSION_DEGREE: usize>(
        shares: Vec<PrivateKeySet<EXTENSION_DEGREE>>,
        threshold: usize,
        max_errors: usize,
    ) -> (Vec<u128>, Vec<u64>, Vec<u64>)
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        // reconstruct the 128-bit glwe_sns key
        let shares128 = shares
            .iter()
            .map(|x| {
                x.glwe_secret_key_share_sns_as_lwe
                    .clone()
                    .unwrap()
                    .data_as_raw_vec()
            })
            .collect_vec();
        let glwe_sns_sk128 = reconstruct_shares_to_scalar(shares128, threshold, max_errors)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

        // reconstruct the lwe key which may have 64-bit or 128-bit shares
        // so we need to this workaround to handle both cases
        let lwe_sk64 = match shares[0].lwe_compute_secret_key_share {
            LweSecretKeyShareEnum::Z64(_) => {
                let shares64 = shares
                    .iter()
                    .map(|x| {
                        x.lwe_compute_secret_key_share
                            .clone()
                            .unsafe_cast_to_z64()
                            .data_as_raw_vec()
                    })
                    .collect_vec();
                reconstruct_shares_to_scalar(shares64, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0)
                    .collect_vec()
            }
            LweSecretKeyShareEnum::Z128(_) => {
                let shares128 = shares
                    .iter()
                    .map(|x| {
                        x.lwe_compute_secret_key_share
                            .clone()
                            .unsafe_cast_to_z128()
                            .data_as_raw_vec()
                    })
                    .collect_vec();
                reconstruct_shares_to_scalar(shares128, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0 as u64)
                    .collect_vec()
            }
        };

        // reconstruct the glwe key, which may have 64-bit or 128-bit shares
        // so we need to this workaround to handle both cases
        let glwe_sk64 = match shares[0].glwe_secret_key_share {
            GlweSecretKeyShareEnum::Z64(_) => {
                let shares64 = shares
                    .iter()
                    .map(|x| {
                        x.glwe_secret_key_share
                            .clone()
                            .unsafe_cast_to_z64()
                            .data_as_raw_vec()
                    })
                    .collect_vec();
                reconstruct_shares_to_scalar(shares64, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0)
                    .collect_vec()
            }
            GlweSecretKeyShareEnum::Z128(_) => {
                let shares128 = shares
                    .iter()
                    .map(|x| {
                        x.glwe_secret_key_share
                            .clone()
                            .unsafe_cast_to_z128()
                            .data_as_raw_vec()
                    })
                    .collect_vec();
                reconstruct_shares_to_scalar(shares128, threshold, max_errors)
                    .into_iter()
                    .map(|x| x.0 as u64)
                    .collect_vec()
            }
        };

        (glwe_sns_sk128, lwe_sk64, glwe_sk64)
    }

    #[allow(clippy::type_complexity)]
    fn generate_key_with_error_in_s1<const EXTENSION_DEGREE: usize>(
        keyset: KeySet,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        add_error: bool,
    ) -> anyhow::Result<(
        Vec<PrivateKeySet<EXTENSION_DEGREE>>,
        (Vec<u128>, Vec<u64>, Vec<u64>),
    )>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        // generate the key shares
        let mut rng = AesRng::seed_from_u64(4242);
        let mut key_shares = keygen_all_party_shares_from_keyset(
            &keyset,
            params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();

        if add_error {
            key_shares[0] = PrivateKeySet {
                lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1].lwe_compute_secret_key_share.len()
                    ],
                }),
                lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1].lwe_encryption_secret_key_share.len()
                    ],
                }),
                glwe_secret_key_share: match key_shares[0].glwe_secret_key_share {
                    GlweSecretKeyShareEnum::Z64(_) => {
                        GlweSecretKeyShareEnum::Z64(GlweSecretKeyShare {
                            data: vec![
                                Share::new(
                                    Role::indexed_from_zero(0),
                                    ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(&mut rng)
                                );
                                key_shares[1].glwe_secret_key_share.len()
                            ],
                            polynomial_size: key_shares[1].glwe_secret_key_share.polynomial_size(),
                        })
                    }
                    GlweSecretKeyShareEnum::Z128(_) => {
                        GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                            data: vec![
                                Share::new(
                                    Role::indexed_from_zero(0),
                                    ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng)
                                );
                                key_shares[1].glwe_secret_key_share.len()
                            ],
                            polynomial_size: key_shares[1].glwe_secret_key_share.polynomial_size(),
                        })
                    }
                },
                glwe_secret_key_share_sns_as_lwe: Some(LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1]
                            .glwe_secret_key_share_sns_as_lwe
                            .clone()
                            .unwrap()
                            .data
                            .len()
                    ],
                }),
                parameters: key_shares[1].parameters,
                glwe_secret_key_share_compression: key_shares[0]
                    .glwe_secret_key_share_compression
                    .clone(),
                glwe_sns_compression_key_as_lwe: key_shares[0]
                    .glwe_sns_compression_key_as_lwe
                    .clone()
                    .map(|mut inner| {
                        inner.data[0] = Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z128, EXTENSION_DEGREE>::sample(&mut rng),
                        );
                        inner
                    }),
            }
        }
        // sanity check that we can still reconstruct
        let expected_sk = (
            keyset
                .get_raw_glwe_client_sns_key_as_lwe()
                .unwrap()
                .into_container(),
            keyset.get_raw_lwe_client_key().to_owned().into_container(),
            keyset.get_raw_glwe_client_key().to_owned().into_container(),
        );
        // We have at most 1 error, the one we just added
        let rec_sk = reconstruct_sk(key_shares.clone(), threshold, 1);
        assert_eq!(rec_sk, expected_sk);

        Ok((key_shares, expected_sk))
    }
}
