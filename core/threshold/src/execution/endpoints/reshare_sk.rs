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
                Expected, NotExpected, Optional, Reshare, SecureSameSetReshare,
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
                CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, PrivateKeySet,
            },
        },
    },
};

use tracing::instrument;

pub struct ResharePreprocRequired {
    pub batch_params_128: BatchParams,
    pub batch_params_64: BatchParams,
}

impl ResharePreprocRequired {
    /// Computes the number of randoms needed to reshare a private key set
    /// where `num_parties_reshare_from` is the number of parties holding the input shares
    /// (i.e. everyone in same set resharing, or the first set in two sets resharing)
    pub fn new(num_parties_reshare_from: usize, parameters: DKGParams) -> Self {
        let params = parameters.get_params_basics_handle();
        let mut num_randoms_128 = 0;
        let mut num_randoms_64 = 0;

        num_randoms_64 += params.lwe_hat_dimension().0;

        num_randoms_64 += params.lwe_dimension().0;

        match parameters.get_params_basics_handle().get_dkg_mode() {
            DkgMode::Z64 => {
                num_randoms_64 += params.glwe_sk_num_bits() + params.compression_sk_num_bits()
            }
            DkgMode::Z128 => {
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
pub trait ReshareSecretKeys {
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
            Optional(input_share.as_mut()),
            parameters,
        )
        .await?
        .ok_or_else(|| anyhow_error_and_log("Expected an output in same set reshare"))
    }

    #[instrument(
    name = "ReShare (as set 1)",
    skip(two_sets_session, input_share)
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

    #[instrument(
    name = "ReShare (as set 2)",
    skip(sessions, preproc128, preproc64)
    fields(sid,my_role)
    )]
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

    #[instrument(
    name = "ReShare (as both sets)",
    skip(sessions, preproc128, preproc64)
    fields(sid,my_role)
    )]
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
        (true, data.map(|data| LweSecretKeyShare { data }))
    } else {
        (false, None)
    };

    let basic_params_handle = parameters.get_params_basics_handle();

    // Reshare the LWE compute key
    let expected_key_size = basic_params_handle.lwe_dimension().0;
    let maybe_key = input_share
        .as_mut()
        .map(|s| s.lwe_compute_secret_key_share.data.as_mut());
    let data = reshare
        .execute(
            sessions,
            &mut preproc64,
            &mut R::MaybeExpectedInputShares::from(maybe_key),
            expected_key_size,
        )
        .await?;
    let lwe_compute_secret_key_share = data.map(|data| LweSecretKeyShare { data });

    // Reshare the LWE PKe key
    let expected_key_size = basic_params_handle.lwe_hat_dimension().0;
    let polynomial_size = basic_params_handle.polynomial_size();
    let maybe_key = input_share
        .as_mut()
        .map(|s| s.lwe_encryption_secret_key_share.data.as_mut());
    let data = reshare
        .execute(
            sessions,
            &mut preproc64,
            &mut R::MaybeExpectedInputShares::from(maybe_key),
            expected_key_size,
        )
        .await?;

    let lwe_encryption_secret_key_share = data.map(|data| LweSecretKeyShare { data });

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
            data.map(|data| {
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
            data.map(|data| {
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
                    data.map(|data| {
                        CompressionPrivateKeySharesEnum::Z64(CompressionPrivateKeyShares {
                            post_packing_ks_key: GlweSecretKeyShare {
                                data,
                                polynomial_size,
                            },
                            params: compression_params.raw_compression_parameters,
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
                    data.map(|data| {
                        CompressionPrivateKeySharesEnum::Z128(CompressionPrivateKeyShares {
                            post_packing_ks_key: GlweSecretKeyShare {
                                data,
                                polynomial_size,
                            },
                            params: compression_params.raw_compression_parameters,
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
                (true, data.map(|data| LweSecretKeyShare { data }))
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
    use crate::execution::runtime::party::Role;
    use crate::execution::sharing::shamir::{RevealOp, ShamirSharings};
    use crate::execution::sharing::share::Share;
    use crate::execution::tfhe_internals::parameters::{DKGParamsRegular, DKGParamsSnS};
    use crate::execution::tfhe_internals::test_feature::{
        keygen_all_party_shares_from_keyset, KeySet,
    };
    use crate::networking::NetworkMode;
    use crate::{
        algebra::structure_traits::Sample,
        error::error_handler::anyhow_error_and_log,
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::{
                sessions::session_parameters::GenericParameterHandles,
                test_runtime::{generate_fixed_roles, DistributedTestRuntime},
            },
            sharing::shamir::InputOp,
        },
        file_handling::tests::read_element,
        session_id::SessionId,
    };
    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;
    use std::{collections::HashMap, fmt::Display};
    use tfhe::boolean::prelude::GlweDimension;
    use tfhe::core_crypto::entities::GlweSecretKey;
    use tfhe::shortint::client_key::atomic_pattern::{
        AtomicPatternClientKey, StandardAtomicPatternClientKey,
    };
    use tfhe::shortint::noise_squashing::NoiseSquashingPrivateKey;
    use tfhe::shortint::prelude::ModulusSwitchType;
    use tfhe::shortint::PBSParameters;
    use tfhe::{core_crypto::entities::LweSecretKey, shortint::ClassicPBSParameters};
    use tokio::task::JoinSet;

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

        // reconstruct the 64-bit lwe key
        let shares64 = shares
            .iter()
            .map(|x| x.lwe_compute_secret_key_share.clone().data_as_raw_vec())
            .collect_vec();
        let lwe_sk64 = reconstruct_shares_to_scalar(shares64, threshold, max_errors)
            .into_iter()
            .map(|x| x.0)
            .collect_vec();

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

    #[test]
    fn reshare_no_error_f4() -> anyhow::Result<()> {
        simulate_reshare::<4>(false, false)
    }

    #[test]
    fn reshare_with_error_f4() -> anyhow::Result<()> {
        simulate_reshare::<4>(true, false)
    }

    #[test]
    fn reshare_with_missing_f4() -> anyhow::Result<()> {
        simulate_reshare::<4>(false, true)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn reshare_no_error_f3() -> anyhow::Result<()> {
        simulate_reshare::<3>(false, false)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn reshare_with_error_f3() -> anyhow::Result<()> {
        simulate_reshare::<3>(true, false)
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn reshare_with_missing_f3() -> anyhow::Result<()> {
        simulate_reshare::<3>(false, true)
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn reshare_no_error_f5() -> anyhow::Result<()> {
        simulate_reshare::<5>(false, false)
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn reshare_with_error_f5() -> anyhow::Result<()> {
        simulate_reshare::<5>(true, false)
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn reshare_with_missing_f5() -> anyhow::Result<()> {
        simulate_reshare::<5>(false, true)
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn reshare_no_error_f6() -> anyhow::Result<()> {
        simulate_reshare::<6>(false, false)
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn reshare_with_error_f6() -> anyhow::Result<()> {
        simulate_reshare::<6>(true, false)
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn reshare_with_missing_f6() -> anyhow::Result<()> {
        simulate_reshare::<6>(false, true)
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn reshare_no_error_f7() -> anyhow::Result<()> {
        simulate_reshare::<7>(false, false)
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn reshare_with_error_f7() -> anyhow::Result<()> {
        simulate_reshare::<7>(true, false)
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn reshare_with_missing_f7() -> anyhow::Result<()> {
        simulate_reshare::<7>(false, true)
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn reshare_no_error_f8() -> anyhow::Result<()> {
        simulate_reshare::<8>(false, false)
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn reshare_with_error_f8() -> anyhow::Result<()> {
        simulate_reshare::<8>(true, false)
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn reshare_with_missing_f8() -> anyhow::Result<()> {
        simulate_reshare::<8>(false, true)
    }

    fn simulate_reshare<const EXTENSION_DEGREE: usize>(
        add_error: bool,
        remove_share: bool,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let num_parties = 7;
        let threshold = 2;

        let mut keyset: KeySet = read_element(std::path::Path::new(SMALL_TEST_KEY_PATH)).unwrap();

        // we make the shares shorter to make sure the test doesn't take too long
        let new_params = truncate_client_keys(&mut keyset);

        // generate the key shares
        let mut rng = AesRng::from_entropy();
        let mut key_shares = keygen_all_party_shares_from_keyset(
            &keyset,
            new_params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();

        let roles = generate_fixed_roles(num_parties);
        //Reshare assumes Sync network
        let mut runtime: DistributedTestRuntime<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            Role,
            EXTENSION_DEGREE,
        > = DistributedTestRuntime::new(roles, threshold as u8, NetworkMode::Sync, None);
        if add_error {
            key_shares[0] = PrivateKeySet {
                lwe_compute_secret_key_share: LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1].lwe_compute_secret_key_share.data.len()
                    ],
                },
                lwe_encryption_secret_key_share: LweSecretKeyShare {
                    data: vec![
                        Share::new(
                            Role::indexed_from_zero(0),
                            ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(&mut rng)
                        );
                        key_shares[1].lwe_encryption_secret_key_share.data.len()
                    ],
                },
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

        runtime.setup_sks(key_shares);

        let session_id = SessionId::from(2);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for role in &runtime.roles {
            let party_keyshare = runtime
                .keyshares
                .clone()
                .map(|ks| ks[role.one_based() - 1].clone())
                .ok_or_else(|| {
                    anyhow_error_and_log("key share not set during decryption".to_string())
                })?;
            let mut session = runtime.large_session_for_party(session_id, *role);

            set.spawn(async move {
                let mut preproc128 =
                    DummyPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(42, &session);
                let mut preproc64 =
                    DummyPreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new(42, &session);

                //Testing ResharePreprocRequired
                let preproc_required =
                    ResharePreprocRequired::new(session.num_parties(), new_params);

                let mut new_preproc_64 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: preproc64
                        .next_random_vec(preproc_required.batch_params_64.randoms)
                        .unwrap(),
                };

                let mut new_preproc_128 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: preproc128
                        .next_random_vec(preproc_required.batch_params_128.randoms)
                        .unwrap(),
                };

                let mut my_contribution =
                    if session.my_role() == Role::indexed_from_zero(0) && remove_share {
                        // simulating a party that lost its key share
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
                (session.my_role(), out, my_contribution)
            });
        }

        let mut results = rt
            .block_on(async {
                let mut results = HashMap::new();
                while let Some(v) = set.join_next().await {
                    let (role, new_share, old_share) = v.unwrap();
                    results.insert(
                        role,
                        (
                            new_share,
                            old_share.map(|osh| osh.glwe_secret_key_share_sns_as_lwe.unwrap()),
                        ),
                    );
                }
                results
            })
            .into_iter()
            .collect_vec();

        // we need to sort by identities and then reconstruct
        results.sort_by(|a, b| a.0.cmp(&(b.0)));
        let (new_shares, old_shares): (Vec<_>, Vec<_>) =
            results.into_iter().map(|(_, b)| b).unzip();
        let actual_sk = reconstruct_sk(new_shares.clone(), threshold, 0);

        // check results
        assert_eq!(actual_sk, expected_sk);

        // Also try to reconstruct with only some shares (including 0 as it's always the corrupt/missing one)
        let partial_shares = new_shares[0..=threshold].to_vec();
        let actual_sk = reconstruct_sk(partial_shares, threshold, 0);
        assert_eq!(actual_sk, expected_sk);

        // check old shares are zero
        for osh in old_shares.into_iter().flatten() {
            osh.data_as_raw_vec()
                .iter()
                .for_each(|x| assert!(x.is_zero()));
        }
        Ok(())
    }

    // We truncate the keys in the keyset to make the test faster
    // We return the params that correspond to the truncated keys
    fn truncate_client_keys(keyset: &mut KeySet) -> DKGParams {
        let (raw_sns_private_key, sns_params) = keyset
            .client_key
            .clone()
            .into_raw_parts()
            .3
            .unwrap()
            .into_raw_parts()
            .into_raw_parts();
        let sns_private_key_len = 8;
        let sns_poly_size = tfhe::shortint::prelude::PolynomialSize(1);
        let new_raw_sns_private_key = GlweSecretKey::from_container(
            raw_sns_private_key.into_container()[..sns_private_key_len].to_vec(),
            sns_poly_size,
        );
        let mut new_sns_params = sns_params;

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
        let new_sns_private_key =
            tfhe::integer::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                NoiseSquashingPrivateKey::from_raw_parts(new_raw_sns_private_key, new_sns_params),
            );

        let (glwe_raw, lwe_raw, params, _) = match keyset
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

        //We update the parameters to match with our truncated keys.
        //In particular we truncate the lwe_key by picking a new lwe_dimension
        //and the glwe_key by picking a new GlweDimension and PolynomialSize
        // and set modulus switch noise reduction to standard
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
            PBSParameters::PBS(new_pbs_params),
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
            Some(new_sns_private_key),
            None,
            None,
            tfhe::Tag::default(),
        );
        keyset.client_key = ck;
        DKGParams::WithSnS(DKGParamsSnS {
            regular_params: DKGParamsRegular {
                dkg_mode: DkgMode::Z128,
                sec: 128,
                ciphertext_parameters: new_pbs_params,
                dedicated_compact_public_key_parameters: None,
                compression_decompression_parameters: None,
                cpk_re_randomization_ksk_params: None,
                secret_key_deviations: None,
            },
            sns_params: new_sns_params,
            sns_compression_params: None,
        })
    }
}
