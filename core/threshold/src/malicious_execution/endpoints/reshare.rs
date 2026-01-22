use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Syndrome},
    },
    execution::{
        endpoints::reshare_sk::ReshareSecretKeys,
        online::preprocessing::BasePreprocessing,
        runtime::{
            party::TwoSetsRole,
            sessions::base_session::{BaseSessionHandles, GenericBaseSessionHandles},
        },
        tfhe_internals::{parameters::DKGParams, private_keysets::PrivateKeySet},
    },
};

pub struct MaliciousReshareWaitAndDoNothing {}

#[tonic::async_trait]
impl ReshareSecretKeys for MaliciousReshareWaitAndDoNothing {
    async fn reshare_sk_same_set<
        S: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        _session: &mut S,
        _preproc128: &mut P128,
        _preproc64: &mut P64,
        _input_share: &mut Option<PrivateKeySet<EXTENSION_DEGREE>>,
        parameters: DKGParams,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let private_key_set = PrivateKeySet::<EXTENSION_DEGREE>::init_dummy(parameters);

        Ok(private_key_set)
    }

    async fn reshare_sk_two_sets_as_s1<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        const EXTENSION_DEGREE: usize,
    >(
        _two_sets_session: &mut S,
        _input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        _parameters: DKGParams,
    ) -> anyhow::Result<()>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        Ok(())
    }

    async fn reshare_sk_two_sets_as_s2<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        Sess: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        _sessions: &mut (S, Sess),
        _preproc128: &mut P128,
        _preproc64: &mut P64,
        parameters: DKGParams,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let private_key_set = PrivateKeySet::<EXTENSION_DEGREE>::init_dummy(parameters);

        Ok(private_key_set)
    }

    async fn reshare_sk_two_sets_as_both_sets<
        S: GenericBaseSessionHandles<TwoSetsRole>,
        Sess: BaseSessionHandles,
        P128: BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send,
        P64: BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send,
        const EXTENSION_DEGREE: usize,
    >(
        _sessions: &mut (S, Sess),
        _preproc128: &mut P128,
        _preproc64: &mut P64,
        _input_share: &mut PrivateKeySet<EXTENSION_DEGREE>,
        parameters: DKGParams,
    ) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let private_key_set = PrivateKeySet::<EXTENSION_DEGREE>::init_dummy(parameters);

        Ok(private_key_set)
    }
}
