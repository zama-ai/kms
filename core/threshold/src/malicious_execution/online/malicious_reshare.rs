use tonic::async_trait;
use zeroize::Zeroize;

use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect, Invert, Syndrome},
    },
    execution::{
        online::{
            preprocessing::BasePreprocessing,
            reshare::{Expected, NotExpected, Reshare},
        },
        runtime::{
            party::TwoSetsRole,
            sessions::base_session::{BaseSession, GenericBaseSession},
        },
        sharing::share::Share,
    },
    ProtocolDescription,
};

#[derive(Default, Clone)]
pub struct DropReshareAsSet1;

impl ProtocolDescription for DropReshareAsSet1 {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{}-DropReshareAsSet1", indent)
    }
}

#[async_trait]
impl Reshare for DropReshareAsSet1 {
    type ReshareSessions = GenericBaseSession<TwoSetsRole>;
    // As set 1 preprocessing is not needed
    type MaybeExpectedPreprocessing<T> = NotExpected<T>;
    // As set 1 I have an input to reshare
    type MaybeExpectedInputShares<T> = Expected<T>;

    type MaybeExpectedOutput<T> = Option<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        _sessions: &mut Self::ReshareSessions,
        _preproc: &mut NotExpected<&mut Prep>,
        _input_shares: &mut Expected<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        _expected_input_len: usize,
    ) -> anyhow::Result<Option<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        Ok(None)
    }
}

#[derive(Default, Clone)]
pub struct DropReshareAsSet2;

impl ProtocolDescription for DropReshareAsSet2 {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{}-DropReshareAsSet2", indent)
    }
}

#[async_trait]
impl Reshare for DropReshareAsSet2 {
    type ReshareSessions = (GenericBaseSession<TwoSetsRole>, BaseSession);
    // As set 2 preprocessing is required
    type MaybeExpectedPreprocessing<T> = Expected<T>;
    // As set 2 I don't have an input to reshare
    type MaybeExpectedInputShares<T> = NotExpected<T>;
    type MaybeExpectedOutput<T> = Option<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        _sessions: &mut Self::ReshareSessions,
        _preproc: &mut Expected<&mut Prep>,
        _input_shares: &mut NotExpected<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        _expected_input_len: usize,
    ) -> anyhow::Result<Option<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        Ok(None)
    }
}

#[derive(Default, Clone)]
pub struct DropReshareAsBothSets;

impl ProtocolDescription for DropReshareAsBothSets {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{}-DropReshareAsBothSets", indent)
    }
}

#[async_trait]
impl Reshare for DropReshareAsBothSets {
    type ReshareSessions = (GenericBaseSession<TwoSetsRole>, BaseSession);
    // As both sets preprocessing is always required
    type MaybeExpectedPreprocessing<T> = Expected<T>;
    // As both sets I have an input to reshare
    type MaybeExpectedInputShares<T> = Expected<T>;
    type MaybeExpectedOutput<T> = Option<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        _sessions: &mut Self::ReshareSessions,
        _preproc: &mut Expected<&mut Prep>,
        _input_shares: &mut Expected<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        _expected_input_len: usize,
    ) -> anyhow::Result<Option<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        Ok(None)
    }
}
