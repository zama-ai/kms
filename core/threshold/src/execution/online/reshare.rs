use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        poly::Poly,
        structure_traits::{
            BaseRing, ErrorCorrect, Invert, Ring, RingWithExceptionalSequence, Syndrome, Zero,
        },
        syndrome::lagrange_numerators,
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::{
            broadcast::{Broadcast, SyncReliableBroadcast},
            p2p::generic_receive_from_all_senders_with_role_transform,
        },
        online::preprocessing::BasePreprocessing,
        runtime::{
            party::{Role, TwoSetsRole},
            sessions::base_session::{BaseSession, BaseSessionHandles, GenericBaseSessionHandles},
        },
        sharing::{
            open::{ExternalOpeningInfo, RobustOpen, SecureRobustOpen},
            shamir::ShamirSharings,
            share::Share,
        },
    },
    networking::value::{BroadcastValue, NetworkValue},
    ProtocolDescription,
};
use itertools::{izip, Itertools};
use std::{
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet},
    sync::Arc,
};
use tokio::task::JoinSet;
use tonic::async_trait;
use zeroize::Zeroize;

pub struct NotExpected<T> {
    pub _marker: std::marker::PhantomData<T>,
}

impl<T> Default for NotExpected<T> {
    fn default() -> Self {
        NotExpected {
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct Expected<T>(pub T);

pub trait MaybeExpected<T>: From<Option<T>> + Into<Option<T>> {}

impl<T> From<Option<T>> for NotExpected<T> {
    fn from(value: Option<T>) -> Self {
        assert!(value.is_none(), "Expected no value, but got Some");
        NotExpected {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> From<NotExpected<T>> for Option<T> {
    fn from(_: NotExpected<T>) -> Self {
        None
    }
}

impl<T> From<Option<T>> for Expected<T> {
    fn from(value: Option<T>) -> Self {
        assert!(value.is_some(), "Expected Some value, but got None");
        Expected(value.unwrap())
    }
}

impl<T> From<Expected<T>> for Option<T> {
    fn from(value: Expected<T>) -> Self {
        Some(value.0)
    }
}

impl<T> MaybeExpected<T> for NotExpected<T> {}
impl<T> MaybeExpected<T> for Expected<T> {}
impl<T> MaybeExpected<T> for Option<T> {}

#[async_trait]
pub trait Reshare: ProtocolDescription + Send + Sync + Clone {
    type ReshareSessions;
    // This associated type allows us to have optional preprocessing
    // that is compiler enforced.
    type MaybeExpectedPreprocessing<Z>: MaybeExpected<Z>;
    // This associated type allows us to have optional input shares
    // that is compiler enforced
    type MaybeExpectedInputShares<Z>: MaybeExpected<Z>;
    // This associated type allows us to have optional output shares
    // that is compiler enforced
    type MaybeExpectedOutput<Z>: MaybeExpected<Z>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        sessions: &mut Self::ReshareSessions,
        preproc: &mut Self::MaybeExpectedPreprocessing<&mut Prep>,
        input_shares: &mut Self::MaybeExpectedInputShares<
            &mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>,
        >,
        expected_input_len: usize,
    ) -> anyhow::Result<Self::MaybeExpectedOutput<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome;
}

pub type SecureSameSetReshare<Ses> =
    RealSameSetsReshare<Ses, SecureRobustOpen, SyncReliableBroadcast>;

pub struct RealSameSetsReshare<
    Ses: BaseSessionHandles,
    OpenProtocol: RobustOpen,
    BroadcastProtocol: Broadcast,
> {
    session_marker: std::marker::PhantomData<Ses>,
    open_protocol: OpenProtocol,
    broadcast_protocol: BroadcastProtocol,
}

impl<Ses: BaseSessionHandles, OpenProtocol: RobustOpen, BroadcastProtocol: Broadcast> Clone
    for RealSameSetsReshare<Ses, OpenProtocol, BroadcastProtocol>
{
    fn clone(&self) -> Self {
        RealSameSetsReshare {
            session_marker: std::marker::PhantomData::<Ses>,
            open_protocol: self.open_protocol.clone(),
            broadcast_protocol: self.broadcast_protocol.clone(),
        }
    }
}

impl<
        Ses: BaseSessionHandles,
        OpenProtocol: RobustOpen + Default,
        BroadcastProtocol: Broadcast + Default,
    > Default for RealSameSetsReshare<Ses, OpenProtocol, BroadcastProtocol>
{
    fn default() -> Self {
        RealSameSetsReshare {
            session_marker: std::marker::PhantomData::<Ses>,
            open_protocol: OpenProtocol::default(),
            broadcast_protocol: BroadcastProtocol::default(),
        }
    }
}

impl<Ses: BaseSessionHandles, OpenProtocol: RobustOpen, BroadcastProtocol: Broadcast>
    ProtocolDescription for RealSameSetsReshare<Ses, OpenProtocol, BroadcastProtocol>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{indent}-SameSetsReshare:\n{}\n{}",
            OpenProtocol::protocol_desc(depth + 1),
            BroadcastProtocol::protocol_desc(depth + 1),
        )
    }
}

#[async_trait]
impl<Ses: BaseSessionHandles, OpenProtocol: RobustOpen, BroadcastProtocol: Broadcast> Reshare
    for RealSameSetsReshare<Ses, OpenProtocol, BroadcastProtocol>
{
    type ReshareSessions = Ses;
    // For same set resharing, preprocessing is always required
    type MaybeExpectedPreprocessing<T> = Expected<T>;
    // This is optional as a legacy use of this protocol
    // was to reshare after a failed DKG where all parties
    // might not have input to share.
    type MaybeExpectedInputShares<T> = Option<T>;
    // In same set resharing we always have output shares
    type MaybeExpectedOutput<T> = Expected<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        sessions: &mut Self::ReshareSessions,
        preproc: &mut Expected<&mut Prep>,
        input_shares: &mut Option<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        expected_input_len: usize,
    ) -> anyhow::Result<Expected<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        Ok(Expected(
            reshare_same_sets(
                preproc.0,
                sessions,
                input_shares,
                expected_input_len,
                &self.open_protocol,
                &self.broadcast_protocol,
            )
            .await?,
        ))
    }
}

pub type SecureTwoSetsReshareAsSet1<TwoSetsSes> =
    RealTwoSetsReshareAsSet1<TwoSetsSes, SecureRobustOpen, SyncReliableBroadcast>;

pub struct RealTwoSetsReshareAsSet1<
    TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
    OpenProtocol: RobustOpen,
    BroadcastProtocol: Broadcast,
> {
    two_sets_session_marker: std::marker::PhantomData<TwoSetsSes>,
    open_protocol: OpenProtocol,
    broadcast_protocol: BroadcastProtocol,
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > Clone for RealTwoSetsReshareAsSet1<TwoSetsSes, OpenProtocol, BroadcastProtocol>
{
    fn clone(&self) -> Self {
        RealTwoSetsReshareAsSet1 {
            two_sets_session_marker: std::marker::PhantomData::<TwoSetsSes>,
            open_protocol: self.open_protocol.clone(),
            broadcast_protocol: self.broadcast_protocol.clone(),
        }
    }
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OpenProtocol: RobustOpen + Default,
        BroadcastProtocol: Broadcast + Default,
    > Default for RealTwoSetsReshareAsSet1<TwoSetsSes, OpenProtocol, BroadcastProtocol>
{
    fn default() -> Self {
        RealTwoSetsReshareAsSet1 {
            two_sets_session_marker: std::marker::PhantomData::<TwoSetsSes>,
            open_protocol: OpenProtocol::default(),
            broadcast_protocol: BroadcastProtocol::default(),
        }
    }
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > ProtocolDescription
    for RealTwoSetsReshareAsSet1<TwoSetsSes, OpenProtocol, BroadcastProtocol>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{indent}-SameSetsReshareAsSet1:\n{}\n{}",
            OpenProtocol::protocol_desc(depth + 1),
            BroadcastProtocol::protocol_desc(depth + 1),
        )
    }
}

#[async_trait]
impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > Reshare for RealTwoSetsReshareAsSet1<TwoSetsSes, OpenProtocol, BroadcastProtocol>
{
    type ReshareSessions = TwoSetsSes;
    // As set 1 preprocessing is not needed
    type MaybeExpectedPreprocessing<T> = NotExpected<T>;
    // As set 1 I have an input to reshare
    type MaybeExpectedInputShares<T> = Expected<T>;
    // As set 1 I never have an output
    type MaybeExpectedOutput<T> = NotExpected<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        sessions: &mut Self::ReshareSessions,
        _preproc: &mut NotExpected<&mut Prep>,
        input_shares: &mut Expected<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        expected_input_len: usize,
    ) -> anyhow::Result<NotExpected<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        assert!(sessions.my_role().is_set1() && !sessions.my_role().is_set2());
        if reshare_two_sets::<_, BaseSession, _, _, Prep, _, _>(
            sessions,
            None,
            None,
            Some(input_shares.0),
            expected_input_len,
            &self.open_protocol,
            &self.broadcast_protocol,
        )
        .await?
        .is_some()
        {
            return Err(anyhow_error_and_log(
                "Parties in set 1 should not receive output shares during resharing.",
            ));
        } else {
            Ok(NotExpected {
                _marker: std::marker::PhantomData,
            })
        }
    }
}

pub type SecureTwoSetsReshareAsSet2<TwoSetsSes, OneSetSes> =
    RealTwoSetsReshareAsSet2<TwoSetsSes, OneSetSes, SecureRobustOpen, SyncReliableBroadcast>;

pub struct RealTwoSetsReshareAsSet2<
    TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
    OneSetSes: BaseSessionHandles,
    RobustOpenProtocol: RobustOpen,
    BroadcastProtocol: Broadcast,
> {
    two_sets_session_marker: std::marker::PhantomData<TwoSetsSes>,
    one_set_session_marker: std::marker::PhantomData<OneSetSes>,
    open_protocol: RobustOpenProtocol,
    broadcast_protocol: BroadcastProtocol,
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > Clone
    for RealTwoSetsReshareAsSet2<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    fn clone(&self) -> Self {
        RealTwoSetsReshareAsSet2 {
            two_sets_session_marker: std::marker::PhantomData::<TwoSetsSes>,
            one_set_session_marker: std::marker::PhantomData::<OneSetSes>,
            open_protocol: self.open_protocol.clone(),
            broadcast_protocol: self.broadcast_protocol.clone(),
        }
    }
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen + Default,
        BroadcastProtocol: Broadcast + Default,
    > Default
    for RealTwoSetsReshareAsSet2<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    fn default() -> Self {
        RealTwoSetsReshareAsSet2 {
            two_sets_session_marker: std::marker::PhantomData::<TwoSetsSes>,
            one_set_session_marker: std::marker::PhantomData::<OneSetSes>,
            open_protocol: RobustOpenProtocol::default(),
            broadcast_protocol: BroadcastProtocol::default(),
        }
    }
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > ProtocolDescription
    for RealTwoSetsReshareAsSet2<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{indent}-SameSetsReshareAsSet2:\n{}\n{}",
            RobustOpenProtocol::protocol_desc(depth + 1),
            BroadcastProtocol::protocol_desc(depth + 1),
        )
    }
}

#[async_trait]
impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > Reshare
    for RealTwoSetsReshareAsSet2<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    type ReshareSessions = (TwoSetsSes, OneSetSes);
    // As set 2 preprocessing is required
    type MaybeExpectedPreprocessing<T> = Expected<T>;
    // As set 2 I don't have an input to reshare
    type MaybeExpectedInputShares<T> = NotExpected<T>;
    // As set 2 I alway have an output
    type MaybeExpectedOutput<T> = Expected<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        sessions: &mut Self::ReshareSessions,
        preproc: &mut Expected<&mut Prep>,
        _input_shares: &mut NotExpected<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        expected_input_len: usize,
    ) -> anyhow::Result<Expected<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let (two_set_session, my_set_session) = sessions;
        assert!(two_set_session.my_role().is_set2() && !two_set_session.my_role().is_set1());
        if let Some(res) = reshare_two_sets(
            two_set_session,
            Some(my_set_session),
            Some(preproc.0),
            None,
            expected_input_len,
            &self.open_protocol,
            &self.broadcast_protocol,
        )
        .await?
        {
            Ok(Expected(res))
        } else {
            return Err(anyhow_error_and_log(
                "Parties in set 2 should receive output shares during resharing.",
            ));
        }
    }
}

pub type SecureTwoSetsReshareAsBothSets<TwoSetsSes, OneSetSes> =
    RealTwoSetsReshareAsBothSets<TwoSetsSes, OneSetSes, SecureRobustOpen, SyncReliableBroadcast>;

pub struct RealTwoSetsReshareAsBothSets<
    TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
    OneSetSes: BaseSessionHandles,
    RobustOpenProtocol: RobustOpen,
    BroadcastProtocol: Broadcast,
> {
    two_sets_session_marker: std::marker::PhantomData<TwoSetsSes>,
    one_set_session_marker: std::marker::PhantomData<OneSetSes>,
    open_protocol: RobustOpenProtocol,
    broadcast_protocol: BroadcastProtocol,
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > Clone
    for RealTwoSetsReshareAsBothSets<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    fn clone(&self) -> Self {
        RealTwoSetsReshareAsBothSets {
            two_sets_session_marker: std::marker::PhantomData::<TwoSetsSes>,
            one_set_session_marker: std::marker::PhantomData::<OneSetSes>,
            open_protocol: self.open_protocol.clone(),
            broadcast_protocol: self.broadcast_protocol.clone(),
        }
    }
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen + Default,
        BroadcastProtocol: Broadcast + Default,
    > Default
    for RealTwoSetsReshareAsBothSets<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    fn default() -> Self {
        RealTwoSetsReshareAsBothSets {
            two_sets_session_marker: std::marker::PhantomData::<TwoSetsSes>,
            one_set_session_marker: std::marker::PhantomData::<OneSetSes>,
            open_protocol: RobustOpenProtocol::default(),
            broadcast_protocol: BroadcastProtocol::default(),
        }
    }
}

impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > ProtocolDescription
    for RealTwoSetsReshareAsBothSets<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{indent}-SameSetsReshareAsBothSets:\n{}\n{}",
            RobustOpenProtocol::protocol_desc(depth + 1),
            BroadcastProtocol::protocol_desc(depth + 1),
        )
    }
}

#[async_trait]
impl<
        TwoSetsSes: GenericBaseSessionHandles<TwoSetsRole>,
        OneSetSes: BaseSessionHandles,
        RobustOpenProtocol: RobustOpen,
        BroadcastProtocol: Broadcast,
    > Reshare
    for RealTwoSetsReshareAsBothSets<TwoSetsSes, OneSetSes, RobustOpenProtocol, BroadcastProtocol>
{
    type ReshareSessions = (TwoSetsSes, OneSetSes);
    // As both sets preprocessing is always required
    type MaybeExpectedPreprocessing<T> = Expected<T>;
    // As both sets I have an input to reshare
    type MaybeExpectedInputShares<T> = Expected<T>;
    // As both sets I always have an output
    type MaybeExpectedOutput<T> = Expected<T>;

    async fn execute<
        Prep: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
        Z: BaseRing + Zeroize,
        const EXTENSION_DEGREE: usize,
    >(
        &self,
        sessions: &mut Self::ReshareSessions,
        preproc: &mut Expected<&mut Prep>,
        input_shares: &mut Expected<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
        expected_input_len: usize,
    ) -> anyhow::Result<Expected<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
    {
        let (two_set_session, my_set_session) = sessions;
        assert!(two_set_session.my_role().is_set1() && two_set_session.my_role().is_set2());
        if let Some(res) = reshare_two_sets(
            two_set_session,
            Some(my_set_session),
            Some(preproc.0),
            Some(input_shares.0),
            expected_input_len,
            &self.open_protocol,
            &self.broadcast_protocol,
        )
        .await?
        {
            Ok(Expected(res))
        } else {
            return Err(anyhow_error_and_log(
                "Parties in both sets should receive output shares during resharing.",
            ));
        }
    }
}

// Note: Can't really split into 2 functions one for sender one for receiver
// because we have parties in both sets.
// We __ALWAYS__ reshare from set1 to set2
pub async fn reshare_two_sets<
    TwoSetsSession: GenericBaseSessionHandles<TwoSetsRole>,
    OneSetSession: BaseSessionHandles,
    OpenProtocol: RobustOpen,
    BroadcastProtocol: Broadcast,
    P: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
    Z: BaseRing + Zeroize,
    const EXTENSION_DEGREE: usize,
>(
    two_sets_session: &mut TwoSetsSession,
    set_2_session: Option<&mut OneSetSession>,
    preproc: Option<&mut P>,
    input_shares: Option<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    expected_input_len: usize,
    open_protocol: &OpenProtocol,
    broadcast_protocol: &BroadcastProtocol,
) -> anyhow::Result<Option<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    // If I belong to set 2, fetch the masks to send to set 1
    let masks_to_resharers = if two_sets_session.my_role().is_set2() {
        if let Some(preproc) = preproc {
            // setup r_{i,j} shares
            let mut inner_masks_to_resharers = HashMap::new();
            for role in two_sets_session.get_all_sorted_roles() {
                if role.is_set1() {
                    let v = preproc
                        .next_random_vec(expected_input_len)?
                        .into_iter()
                        .map(|v| v.value())
                        .collect_vec();
                    inner_masks_to_resharers.insert(*role, v);
                }
            }
            Some(inner_masks_to_resharers)
        } else {
            return Err(anyhow_error_and_log(
                "Preprocessing is required for parties in set 2 during resharing",
            ));
        }
    } else {
        None
    };

    let external_opening_information = if two_sets_session.my_role().is_set1() {
        // If I belong to set 1, prepare to receive the masks from set 2
        Some(ExternalOpeningInfo::FromSet2(expected_input_len))
    } else {
        None
    };

    // Parties from set_2 open masks to parties in set_1
    let masks_opened = open_protocol
        .robust_open_list_to_set::<ResiduePoly<Z, EXTENSION_DEGREE>, _>(
            two_sets_session,
            masks_to_resharers.clone(),
            two_sets_session.threshold().threshold_set_2 as usize,
            external_opening_information,
        )
        .await?;

    // Increase round counter on the shared session
    two_sets_session.network().increase_round_counter().await;

    // Parties in set 1 mask their share of the key and send to parties in set 2
    // if ever I am in both sets I remember my own masked share
    let my_masked_shares = if two_sets_session.my_role().is_set1() {
        if let (Some(input_shares), Some(mut rs_opened)) = (input_shares, masks_opened) {
            if input_shares.len() != expected_input_len || rs_opened.len() != expected_input_len {
                return Err(anyhow_error_and_log(format!(
                    "Expected the amount of input shares ({}), the amount of masks ({}) and expected_input_len ({}), to be equal.",
                    input_shares.len(),
                    rs_opened.len(),
                    expected_input_len,
                )));
            }
            let mut vj = Vec::with_capacity(expected_input_len);
            for (r, s) in rs_opened.iter().zip_eq(input_shares.iter()) {
                vj.push(*r + s.value());
            }

            // erase the memory of sk_share and rj
            for share in input_shares.iter_mut() {
                share.zeroize();
            }
            for r in rs_opened.iter_mut() {
                r.zeroize();
            }

            // Send the masked shares to parties in set 2
            // except myself if I am in both sets
            let values_to_send = Arc::new(NetworkValue::VecRingValue(vj.clone()).to_network());
            for party in two_sets_session.get_all_sorted_roles() {
                if party.is_set2() && party != &two_sets_session.my_role() {
                    two_sets_session
                        .network()
                        .send(Arc::clone(&values_to_send), party)
                        .await?;
                }
            }
            Some(vj)
        } else {
            return Err(anyhow_error_and_log(
                "Input shares and masks are required for parties in set 1 during resharing.",
            ));
        }
    } else {
        None
    };

    // Parties in set 2 receive the masked shares from parties in set 1
    // and finish the resharing
    if two_sets_session.my_role().is_set2() {
        let my_set_session = if let Some(s) = set_2_session {
            s
        } else {
            return Err(anyhow_error_and_log(
                "One-set session is required for parties in set 2 during resharing.",
            ));
        };

        let mut multicast_results = if let Some(my_masked_share) = my_masked_shares {
            let my_role_set_1 = match two_sets_session.my_role() {
                TwoSetsRole::Both(dual_role) => dual_role.role_set_1,
                // We panic here as this must be a bug if we are not in both sets
                _ => panic!("Expected to be in both sets"),
            };
            BTreeMap::from([(my_role_set_1, my_masked_share)])
        } else {
            BTreeMap::new()
        };
        // Receive the masked shares from parties in set 1
        let parties_in_s1 = two_sets_session
            .get_all_sorted_roles()
            .clone()
            .into_iter()
            .filter(|r| r.is_set1())
            .collect();

        let mut jobs = JoinSet::new();
        let transform_s1_to_role = |sender: &TwoSetsRole, _external_opening_info: ()| match sender {
            TwoSetsRole::Set1(role) => *role,
            TwoSetsRole::Both(dual_role) => dual_role.role_set_1,
            // Here it is OK to panic because this function is only called for parties in set 1
            TwoSetsRole::Set2(role) => {
                panic!("Expected to receive from set 1 parties, got {:?}", role)
            }
        };

        generic_receive_from_all_senders_with_role_transform(
            &mut jobs,
            two_sets_session,
            &two_sets_session.my_role(),
            &parties_in_s1,
            Some(two_sets_session.corrupt_roles()),
            |msg, _id| match msg {
                NetworkValue::VecRingValue(v) => Ok(v),
                _ => Err(anyhow_error_and_log(format!(
                    "Received {}, expected a Ring value in robust open to all",
                    msg.network_type_name()
                ))),
            },
            transform_s1_to_role,
            (),
        )
        .await;

        while let Some(res) = jobs.join_next().await {
            let joined_result = if let Ok(v) = res {
                v
            } else {
                tracing::warn!(
                    "During resharing, failed to receive masked share from party in set 1"
                );
                continue;
            };

            match joined_result {
                Ok((role, result)) => {
                    if let Ok(values) = result {
                        multicast_results.insert(role, values);
                    } else {
                        tracing::warn!(
                            "During resharing, failed to receive masked share from party {} in set 1: {}",
                            role,
                            result.err().unwrap()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("During resharing, Some party has timed out: {}", e);
                }
            }
        }

        let parties_in_s1 = parties_in_s1
            .iter()
            .map(|role| transform_s1_to_role(role, ()))
            .collect::<HashSet<_>>();
        // Make sure I have something to say for all roles in s1, even if it's an empty vec
        for role_in_s1 in parties_in_s1.iter() {
            multicast_results
                .entry(*role_in_s1)
                .or_insert_with(Vec::new);
        }

        // Broadcast those received values within set 2
        let broadcast_results = broadcast_protocol
            .broadcast_from_all(
                my_set_session,
                BroadcastValue::MapRingVector(multicast_results),
            )
            .await?;

        // For each of the received values, take the majority vote
        let agreed_contributions_from_s1 = take_majority_vote_on_broadcasts(
            my_set_session,
            broadcast_results,
            &parties_in_s1,
            expected_input_len,
        )?;

        // Compute my share of the unmasked secret
        if let Some(rs_shares) = masks_to_resharers {
            let rs_shares = rs_shares
                .into_iter()
                .map(|(role, value)| (transform_s1_to_role(&role, ()), value))
                .collect::<HashMap<_, _>>();

            let unmasked_reshared_shares = unmask_reshared_shares(
                agreed_contributions_from_s1,
                rs_shares,
                expected_input_len,
            )?;

            // Everything below this should be similar as if we were resharing to same set
            return Ok(Some(
                open_syndromes_and_correct_errors(
                    my_set_session,
                    unmasked_reshared_shares,
                    parties_in_s1.into_iter().collect_vec(),
                    two_sets_session.threshold().threshold_set_1 as usize,
                    expected_input_len,
                    open_protocol,
                )
                .await?,
            ));
        } else {
            return Err(anyhow_error_and_log(
                "Masks from set 2 are required for parties in set 2 during resharing.",
            ));
        };
    }

    Ok(None)
}

pub async fn reshare_same_sets<
    Ses: BaseSessionHandles,
    OpenProtocol: RobustOpen,
    BroadcastProtocol: Broadcast,
    P: BasePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send,
    Z: BaseRing + Zeroize,
    const EXTENSION_DEGREE: usize,
>(
    preproc: &mut P,
    session: &mut Ses,
    input_shares: &mut Option<&mut Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    expected_input_len: usize,
    open_protocol: &OpenProtocol,
    broadcast_protocol: &BroadcastProtocol,
) -> anyhow::Result<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    // we need share_count shares for every party in the initial set of size n1
    let n1 = session.num_parties();
    let mut all_roles_sorted = session.roles().iter().cloned().collect_vec();
    all_roles_sorted.sort();

    // setup r_{i,j} shares
    let mut masks_to_resharers = HashMap::with_capacity(n1);
    for role in &all_roles_sorted {
        let v = preproc
            .next_random_vec(expected_input_len)?
            .into_iter()
            .map(|v| v.value())
            .collect_vec();
        masks_to_resharers.insert(*role, v);
    }

    // open r_{i,j} to party j
    let mut masks_opened = if let Some(result) = open_protocol
        .multi_robust_open_list_to(
            session,
            masks_to_resharers.clone(),
            session.threshold() as usize,
        )
        .await?
    {
        result
    } else {
        return Err(anyhow_error_and_log("Failed to robust open r_{i,j}"));
    };

    // opened[0] is r_j
    if masks_opened.len() != expected_input_len {
        return Err(anyhow_error_and_log(format!(
            "Expected the amount of input shares; {}, and openings; {}, to be equal",
            expected_input_len,
            masks_opened.len()
        )));
    }

    // Broadcast our part of the resharing if we have keys to reshare,
    // If we have nothing to reshare, we just broadcast Bot
    let my_broadcast_masked_shares = if let Some(input_shares) = input_shares {
        if input_shares.len() != expected_input_len {
            return Err(anyhow_error_and_log(format!(
                "Expected the amount of input shares ({}), and expected_input_len ({}), to be equal.",
                input_shares.len(),
                expected_input_len,
            )));
        }
        let vj = masks_opened
            .iter()
            .zip_eq(input_shares.clone())
            .map(|(r, s)| *r + s.value())
            .collect_vec();

        // erase the memory of sk_share and rj
        for share in &mut **input_shares {
            share.zeroize();
        }
        for r in &mut masks_opened {
            r.zeroize();
        }

        // We are resharing to the same set,
        // so we go straight to the sync-broadcast
        BroadcastValue::RingVector(vj)
    } else {
        BroadcastValue::Bot
    };

    let all_broadcast_masked_shares = broadcast_protocol
        .broadcast_from_all(session, my_broadcast_masked_shares)
        .await?;

    // Process the received broadcasts
    let all_broadcast_masked_shares = all_broadcast_masked_shares
        .into_iter()
        .map(|(role, msg)| {
            if let BroadcastValue::RingVector(v) = msg {
                (role, v)
            } else if let BroadcastValue::Bot = msg {
                tracing::warn!("During resharing, received Bot from {}", role);
                (role, Vec::new())
            } else {
                // Any other variant is malicious behavior
                // since it's broadcast we can add it to malicious parties
                session.add_corrupt(role);
                tracing::error!(
                    "During resharing, unexpected broadcast. Adding {} to corrupt parties",
                    role
                );
                (role, Vec::new())
            }
        })
        .collect::<HashMap<_, _>>();

    let unmasked_reshared_shares = unmask_reshared_shares(
        all_broadcast_masked_shares,
        masks_to_resharers,
        expected_input_len,
    )?;

    open_syndromes_and_correct_errors(
        session,
        unmasked_reshared_shares,
        all_roles_sorted.clone(),
        session.threshold() as usize,
        expected_input_len,
        open_protocol,
    )
    .await
}

fn unmask_reshared_shares<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    agreed_contributions_from_resharers: HashMap<Role, Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>,
    mut masks_to_resharers: HashMap<Role, Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>,
    expected_input_len: usize,
) -> anyhow::Result<Vec<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    let mut s_share_vec = vec![vec![]; expected_input_len];
    for (resharer_role, vs) in agreed_contributions_from_resharers.into_iter() {
        let rs_share_iter = masks_to_resharers
            .remove(&resharer_role)
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                    "Missing mask share from party {:?} in set 2 during resharing",
                    resharer_role
                ))
            })?
            .clone();
        // rs_share_iter length can be trusted as we generated it ourselves
        // Note: should be equal to expected_input_len
        if vs.len() != rs_share_iter.len() {
            tracing::warn!(
                    "Mistmatch in lengths during resharing: vs.len() = {}, rs_share_iter.len() = {}. Will pad with zeros.",
                    vs.len(),
                    rs_share_iter.len()
                );
        }

        let mut s_share = Vec::with_capacity(expected_input_len);

        for (index, r) in rs_share_iter.into_iter().enumerate() {
            if let Some(v) = vs.get(index) {
                s_share.push(*v - r);
            } else {
                // pad with zero if we don't have enough values
                s_share.push(ResiduePoly::<Z, EXTENSION_DEGREE>::ZERO - r);
            }
        }

        // usually we'd do `s_vec.push((sender, s_share))`
        // but we want to transpose the result so we insert s_share
        // in a "tranposed way"
        // Note that `zip_eq` may panic, but it would imply a bug in this method
        for (v, s) in s_share_vec.iter_mut().zip_eq(s_share) {
            v.push(Share::new(resharer_role, s));
        }
    }

    Ok(s_share_vec)
}

fn take_majority_vote_on_broadcasts<
    Z: BaseRing,
    const EXTENSION_DEGREE: usize,
    Ses: BaseSessionHandles,
>(
    my_set_session: &mut Ses,
    broadcast_results: HashMap<Role, BroadcastValue<ResiduePoly<Z, EXTENSION_DEGREE>>>,
    parties_in_s1: &HashSet<Role>,
    expected_input_len: usize,
) -> anyhow::Result<HashMap<Role, Vec<ResiduePoly<Z, EXTENSION_DEGREE>>>> {
    let mut votes = HashMap::with_capacity(parties_in_s1.len());
    for (sender_in_s2, broadcast_result) in broadcast_results.into_iter() {
        if let BroadcastValue::MapRingVector(mut map_ring_vector) = broadcast_result {
            // We are exploring the purported `multicast_results` receive from `sender_in_s2`
            // and we register its votes
            for role_in_s1 in parties_in_s1.iter() {
                if let Some(values) = map_ring_vector.remove(role_in_s1) {
                    let candidates_for_role_in_s1 = votes.entry(*role_in_s1).or_insert_with(|| {
                        vec![
                            HashMap::<_, usize>::with_capacity(my_set_session.num_parties());
                            expected_input_len
                        ]
                    });
                    let mut values_iter = values.into_iter();
                    for candidate_for_role_in_s1 in candidates_for_role_in_s1.iter_mut() {
                        if let Some(value) = values_iter.next() {
                            // Using the raw coefs here to be able to use a BinaryHeap later on
                            // so we have a deterministic ordering even if we have equal number of votes
                            *candidate_for_role_in_s1.entry(value.coefs).or_default() += 1_usize;
                        }
                    }
                } else {
                    // Note that this may be because the sender sent an empty vec (or nothing)
                    tracing::warn!(
                        "During resharing, party {:?} did not provide values for party {:?}",
                        sender_in_s2,
                        role_in_s1
                    );
                }
            }
        } else {
            tracing::warn!(
                    "During resharing, unexpected broadcast. Adding party {sender_in_s2:?} to corrupt parties"
                );
            my_set_session.add_corrupt(sender_in_s2);
        }
    }

    // Now we take the majority vote for each party in set 1
    let mut agreed_contributions_from_s1 = HashMap::with_capacity(parties_in_s1.len());
    for (role_in_s1, candidates_for_role_in_s1) in votes.into_iter() {
        let mut agreed_values = Vec::with_capacity(expected_input_len);
        for (idx, candidate_for_role_in_s1) in candidates_for_role_in_s1.into_iter().enumerate() {
            // Take the max with a deterministic ordering even if there's a tie in votes
            // because it's then ordered on the raw coefficients
            // Note: Heap might be overkill since we only need to track the max...
            let mut heap = BinaryHeap::new();
            for (value, count) in candidate_for_role_in_s1.into_iter() {
                heap.push((count, value));
            }
            if let Some((count, value)) = heap.pop() {
                tracing::debug!(
                    "During resharing, party {:?} got {} votes for its {idx}th value ",
                    role_in_s1,
                    count,
                );
                agreed_values.push(ResiduePoly::from_array(value));
            } else {
                tracing::warn!(
                    "During resharing, no majority vote could be found for party {:?}",
                    role_in_s1
                );
            }
        }
        agreed_contributions_from_s1.insert(role_in_s1, agreed_values);
    }
    Ok(agreed_contributions_from_s1)
}

async fn open_syndromes_and_correct_errors<
    Z: BaseRing,
    OpenProtocol: RobustOpen,
    Ses: BaseSessionHandles,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut Ses,
    unmasked_reshared_shares: Vec<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    resharing_set: Vec<Role>,
    threshold_resharers: usize,
    expected_input_len: usize,
    open_protocol: &OpenProtocol,
) -> anyhow::Result<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome,
{
    let resharing_set_sorted = resharing_set.iter().cloned().sorted().collect_vec();
    let num_parties_resharing_set = resharing_set_sorted.len();
    // To avoid calling robust open many times sequentially,
    // we first compute the syndrome shares and then put
    // all the syndrome shares into a n1*share_count vector and call robust open once
    // upon receiving the result we unpack the long vector into a 2D vector
    let mut all_shamir_shares = Vec::with_capacity(expected_input_len);
    let mut all_syndrome_poly_shares =
        Vec::with_capacity(expected_input_len * num_parties_resharing_set);
    for shares in unmasked_reshared_shares {
        let shamir_sharing = ShamirSharings::create(shares);
        let syndrome_share = ResiduePoly::<Z, EXTENSION_DEGREE>::syndrome_compute(
            &shamir_sharing,
            threshold_resharers,
        )?;
        all_shamir_shares.push(shamir_sharing);
        all_syndrome_poly_shares.append(&mut syndrome_share.into_container());
    }

    let all_syndrome_polys = match open_protocol
        .robust_open_list_to_all(
            session,
            all_syndrome_poly_shares,
            session.threshold() as usize,
        )
        .await?
    {
        Some(xs) => xs,
        None => {
            return Err(anyhow_error_and_log("missing opening".to_string()));
        }
    };

    // now we create chunks from the received syndrome polynomials
    // and create the secret key share
    let mut new_sk_share = Vec::with_capacity(expected_input_len);
    let syndrome_length = num_parties_resharing_set - (threshold_resharers + 1);
    let chunks = all_syndrome_polys.chunks_exact(syndrome_length);
    if chunks.len() != all_shamir_shares.len() {
        return Err(anyhow_error_and_log(format!(
            "Expected the amount of syndrome chunks; {}, and shamir shares; {}, to be equal",
            chunks.len(),
            all_shamir_shares.len()
        )));
    }

    let lagrange_numerators = make_lagrange_numerators(&resharing_set_sorted)?;
    let deltas = resharing_set_sorted
        .iter()
        .map(|role| delta0i(&lagrange_numerators, role))
        .collect::<Result<Vec<_>, _>>()?;

    for (s, shamir_sharing) in chunks.zip_eq(all_shamir_shares) {
        let syndrome_poly = Poly::from_coefs(s.iter().copied().collect_vec());
        let opened_syndrome = ResiduePoly::<Z, EXTENSION_DEGREE>::syndrome_decode(
            syndrome_poly,
            &resharing_set_sorted,
            threshold_resharers,
        )?;

        let res: ResiduePoly<Z, EXTENSION_DEGREE> =
            izip!(shamir_sharing.shares, &deltas, opened_syndrome)
                .map(|(s, d, e)| *d * (s.value() - e))
                .sum();
        new_sk_share.push(Share::new(session.my_role(), res));
    }

    Ok(new_sk_share)
}

// this is the L_i in the spec
fn make_lagrange_numerators<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    sorted_roles: &[Role],
) -> anyhow::Result<Vec<Poly<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    // embed party IDs into the ring
    let parties: Vec<_> = sorted_roles
        .iter()
        .map(ResiduePoly::<Z, EXTENSION_DEGREE>::embed_role_to_exceptional_sequence)
        .collect::<Result<Vec<_>, _>>()?;

    // lagrange numerators from Eq.15
    let out = lagrange_numerators(&parties);
    Ok(out)
}

// Define delta_i(Z) = L_i(Z) / L_i(\alpha_i)
// where L_i(Z) = \Pi_{i \ne j} (Z - \alpha_i)
// This function evaluates delta_i(0)
fn delta0i<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    lagrange_numerators: &[Poly<ResiduePoly<Z, EXTENSION_DEGREE>>],
    party_role: &Role,
) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring + Invert,
{
    let zero = ResiduePoly::<Z, EXTENSION_DEGREE>::get_from_exceptional_sequence(0)?;
    let alphai =
        ResiduePoly::<Z, EXTENSION_DEGREE>::embed_role_to_exceptional_sequence(party_role)?;
    let denom = lagrange_numerators[party_role].eval(&alphai);
    let inv_denom = denom.invert()?;
    Ok(inv_denom * lagrange_numerators[party_role].eval(&zero))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::base_ring::Z128;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z128;
    use crate::algebra::structure_traits::FromU128;
    use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
    use crate::execution::online::triple::open_list;
    use crate::execution::runtime::party::{DualRole, TwoSetsThreshold};
    use crate::execution::runtime::sessions::base_session::{
        BaseSession, GenericBaseSession, TwoSetsBaseSession,
    };
    use crate::execution::sharing::open::test::deterministically_compute_my_shares;
    use crate::execution::{
        online::preprocessing::dummy::DummyPreprocessing,
        runtime::sessions::session_parameters::GenericParameterHandles,
    };
    use crate::malicious_execution::communication::malicious_broadcast::{
        MaliciousBroadcastDrop, MaliciousBroadcastRandomizer, MaliciousBroadcastSender,
        MaliciousBroadcastSenderEcho,
    };
    use crate::malicious_execution::online::malicious_reshare::{
        DropReshareAsBothSets, DropReshareAsSet1, DropReshareAsSet2,
    };
    use crate::malicious_execution::open::malicious_open::{
        MaliciousRobustOpenDrop, MaliciousRobustOpenLie,
    };
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests::execute_protocol_two_sets_w_malicious;

    use std::collections::HashMap;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_reshare_two_sets_honest() {
        test_reshare_two_sets::<Z128, _, _, _, 4>(
            7,
            4,
            3,
            TwoSetsThreshold {
                threshold_set_1: 2,
                threshold_set_2: 1,
            },
            HashSet::new(),
            SecureTwoSetsReshareAsSet1::default(),
            SecureTwoSetsReshareAsSet2::default(),
            SecureTwoSetsReshareAsBothSets::default(),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_reshare_two_sets_drop() {
        test_reshare_two_sets::<Z128, _, _, _, 4>(
            7,
            4,
            2,
            TwoSetsThreshold {
                threshold_set_1: 2,
                threshold_set_2: 1,
            },
            HashSet::from([
                TwoSetsRole::Set1(Role::indexed_from_one(4)),
                TwoSetsRole::Both(DualRole {
                    role_set_1: Role::indexed_from_one(2),
                    role_set_2: Role::indexed_from_one(3),
                }),
            ]),
            DropReshareAsSet1,
            DropReshareAsSet2,
            DropReshareAsBothSets,
        )
        .await;
    }

    #[rstest::rstest]
    async fn test_reshare_malicious_subprotocols<
        RO: RobustOpen + 'static,
        BC: Broadcast + 'static,
    >(
        #[values((
            7,
            4,
            2,
            TwoSetsThreshold {
                threshold_set_1: 2,
                threshold_set_2: 1,
            },
            HashSet::from([
                TwoSetsRole::Set1(Role::indexed_from_one(4)),
                TwoSetsRole::Both(DualRole {
                    role_set_1: Role::indexed_from_one(2),
                    role_set_2: Role::indexed_from_one(3),
                }),
            ])),
            (
            4,
            7,
            4,
            TwoSetsThreshold {
                threshold_set_1: 1,
                threshold_set_2: 2,
            },
            HashSet::from([
                TwoSetsRole::Set2(Role::indexed_from_one(6)),
                TwoSetsRole::Both(DualRole {
                    role_set_1: Role::indexed_from_one(3),
                    role_set_2: Role::indexed_from_one(4),
                }),
            ])

        ))]
        (num_parties_s1, num_parties_s2, intersection_size, threshold, malicious_roles): (
            usize,
            usize,
            usize,
            TwoSetsThreshold,
            HashSet<TwoSetsRole>,
        ),
        #[values(MaliciousRobustOpenDrop::default(), MaliciousRobustOpenLie::default())]
        open_protocol: RO,
        #[values(
            MaliciousBroadcastDrop::default(),
            MaliciousBroadcastSender::default(),
            MaliciousBroadcastSenderEcho::default(),
            MaliciousBroadcastRandomizer::default()
        )]
        broadcast_protocol: BC,
    ) {
        let reshare_s1 = RealTwoSetsReshareAsSet1 {
            open_protocol: open_protocol.clone(),
            broadcast_protocol: broadcast_protocol.clone(),
            two_sets_session_marker: std::marker::PhantomData::<GenericBaseSession<TwoSetsRole>>,
        };

        let reshare_s2 = RealTwoSetsReshareAsSet2 {
            open_protocol: open_protocol.clone(),
            broadcast_protocol: broadcast_protocol.clone(),
            two_sets_session_marker: std::marker::PhantomData::<GenericBaseSession<TwoSetsRole>>,
            one_set_session_marker: std::marker::PhantomData::<BaseSession>,
        };

        let reshare_both = RealTwoSetsReshareAsBothSets {
            open_protocol,
            broadcast_protocol,
            two_sets_session_marker: std::marker::PhantomData::<GenericBaseSession<TwoSetsRole>>,
            one_set_session_marker: std::marker::PhantomData::<BaseSession>,
        };

        test_reshare_two_sets::<Z128, _, _, _, 4>(
            num_parties_s1,
            num_parties_s2,
            intersection_size,
            threshold,
            malicious_roles,
            reshare_s1,
            reshare_s2,
            reshare_both,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn test_reshare_two_sets<
        Z: BaseRing + Zeroize,
    // Restrict the strateies to meaningful inputs
        R1: for<'a> Reshare<
            ReshareSessions = GenericBaseSession<TwoSetsRole>,
            MaybeExpectedInputShares<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>> = Expected<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>>,
            MaybeExpectedPreprocessing<&'a mut InMemoryBasePreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>> = NotExpected<
                &'a mut InMemoryBasePreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>,
            >,
        > + 'static,
        R2: for<'a> Reshare<
            ReshareSessions = (GenericBaseSession<TwoSetsRole>,BaseSession),
            MaybeExpectedInputShares<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>> = NotExpected<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>>,
            MaybeExpectedPreprocessing<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>> = Expected<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>>,
        > + 'static,
        R3: for<'a> Reshare<
            ReshareSessions = (GenericBaseSession<TwoSetsRole>,BaseSession),
            MaybeExpectedInputShares<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>> = Expected<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>>,
            MaybeExpectedPreprocessing<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>> = Expected<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>>,
        > + 'static,
        const EXTENSION_DEGREE: usize,
    >(
        num_parties_s1: usize,
        num_parties_s2: usize,
        intersection_size: usize,
        threshold: TwoSetsThreshold,
        malicious_parties: HashSet<TwoSetsRole>,
        malicious_reshare_set_1: R1,
        malicious_reshare_set_2: R2,
        malicious_reshare_both_sets: R3,
    ) where ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome{
        let num_secrets = 10;

        let mut task_honest = |two_sets_session: TwoSetsBaseSession,
                               set_1_session: Option<BaseSession>,
                               set_2_session: Option<BaseSession>| async move {
            generic_task(
                two_sets_session,
                set_1_session,
                set_2_session,
                SecureTwoSetsReshareAsSet1::default(),
                SecureTwoSetsReshareAsSet2::default(),
                SecureTwoSetsReshareAsBothSets::default(),
                num_secrets,
            )
            .await
        };

        let mut task_malicious = |two_sets_session: TwoSetsBaseSession,
                                  set_1_session: Option<BaseSession>,
                                  set_2_session: Option<BaseSession>,
                                  (
            malicious_reshare_set_1,
            malicious_reshare_set_2,
            malicious_reshare_both_sets,
        ): (R1, R2, R3)| async move {
            generic_task(
                two_sets_session,
                set_1_session,
                set_2_session,
                malicious_reshare_set_1,
                malicious_reshare_set_2,
                malicious_reshare_both_sets,
                num_secrets,
            )
            .await
        };
        let (result_honests, _result_malicious) = execute_protocol_two_sets_w_malicious::<
            _,
            _,
            _,
            _,
            _,
            ResiduePoly<Z, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >(
            num_parties_s1,
            num_parties_s2,
            intersection_size,
            threshold,
            malicious_parties.clone(),
            (
                malicious_reshare_set_1,
                malicious_reshare_set_2,
                malicious_reshare_both_sets,
            ),
            NetworkMode::Sync,
            &mut task_honest,
            &mut task_malicious,
        )
        .await;

        assert_eq!(
            result_honests.len(),
            num_parties_s2 + num_parties_s1 - intersection_size - malicious_parties.len()
        );
        let mut honest_iter = result_honests.into_iter();
        let pivot = honest_iter.next().unwrap();
        for (role, inner_secrets) in honest_iter {
            assert_eq!(
                inner_secrets, pivot.1,
                "mismatch between pivot role {} and role {}",
                pivot.0, role
            );
        }
    }

    async fn generic_task<
        Z: BaseRing + Zeroize,
    // Restrict the strateies to meaningful inputs
        R1: for<'a> Reshare<
            ReshareSessions = GenericBaseSession<TwoSetsRole>,
            MaybeExpectedInputShares<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>> = Expected<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>>,
            MaybeExpectedPreprocessing<&'a mut InMemoryBasePreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>> = NotExpected<
                &'a mut InMemoryBasePreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>,
            >,
        > + 'static,
        R2: for<'a> Reshare<
            ReshareSessions = (GenericBaseSession<TwoSetsRole>,BaseSession),
            MaybeExpectedInputShares<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>> = NotExpected<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>>,
            MaybeExpectedPreprocessing<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>> = Expected<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>>,
        > + 'static,
        R3: for<'a> Reshare<
            ReshareSessions = (GenericBaseSession<TwoSetsRole>,BaseSession),
            MaybeExpectedInputShares<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>> = Expected<&'a mut Vec<Share<ResiduePoly<Z,EXTENSION_DEGREE>>>>,
            MaybeExpectedPreprocessing<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>> = Expected<&'a mut DummyPreprocessing<ResiduePoly<Z,EXTENSION_DEGREE>>>,
        > + 'static,
        const EXTENSION_DEGREE: usize,
    >(
        mut two_sets_session: TwoSetsBaseSession,
        set_1_session: Option<BaseSession>,
        set_2_session: Option<BaseSession>,
        malicious_reshare_set_1: R1,
        malicious_reshare_set_2: R2,
        malicious_resahre_both_sets: R3,
        num_secrets: usize,
    ) -> Vec<ResiduePoly<Z, EXTENSION_DEGREE>>
    where ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect + Invert + Syndrome
    {
        let (my_shares, inner_secrets) = if let Some(set_1_session) = set_1_session {
            let (inner_secrets, shares) =
                deterministically_compute_my_shares::<ResiduePoly<Z, EXTENSION_DEGREE>>(
                    num_secrets,
                    set_1_session.my_role(),
                    set_1_session.num_parties(),
                    set_1_session.threshold() as usize,
                    42,
                );
            let my_shares = shares
                .into_iter()
                .map(|v| Share::new(set_1_session.my_role(), v))
                .collect_vec();
            (Some(my_shares), Some(inner_secrets))
        } else {
            (None, None)
        };

        let mut preproc = if let Some(set_2_session) = set_2_session.as_ref() {
            let preproc =
                DummyPreprocessing::<ResiduePoly<Z, EXTENSION_DEGREE>>::new(42, set_2_session);
            Some(preproc)
        } else {
            None
        };

        let (reshare_result, set_2_session) = match two_sets_session.my_role() {
            TwoSetsRole::Set1(_) => (
                malicious_reshare_set_1
                    .execute(
                        &mut two_sets_session,
                        &mut NotExpected::<&mut InMemoryBasePreprocessing<_>>::default(),
                        &mut Expected(&mut my_shares.unwrap()),
                        num_secrets,
                    )
                    .await
                    .map(|res| res.into()),
                None,
            ),
            TwoSetsRole::Set2(_) => {
                let mut sessions = (two_sets_session, set_2_session.unwrap());
                (
                    malicious_reshare_set_2
                        .execute(
                            &mut sessions,
                            &mut Expected(preproc.as_mut().unwrap()),
                            &mut NotExpected::default(),
                            num_secrets,
                        )
                        .await
                        .map(|res| res.into()),
                    Some(sessions.1),
                )
            }
            TwoSetsRole::Both(_) => {
                let mut sessions = (two_sets_session, set_2_session.unwrap());
                (
                    malicious_resahre_both_sets
                        .execute(
                            &mut sessions,
                            &mut Expected(preproc.as_mut().unwrap()),
                            &mut Expected(&mut my_shares.unwrap()),
                            num_secrets,
                        )
                        .await
                        .map(|res| res.into()),
                    Some(sessions.1),
                )
            }
        };

        if let Some(set_2_session) = set_2_session {
            let reshare_result = reshare_result.unwrap().unwrap();
            let opened_reshared = open_list(&reshare_result, &set_2_session).await.unwrap();
            opened_reshared
        } else {
            assert!(reshare_result.unwrap().is_none());
            inner_secrets.unwrap()
        }
    }

    #[test]
    fn test_majority_vote_reshare() {
        // Generate inputs to test take_majority_vote_on_broadcast
        let expected_input_len = 2;

        // P1 in S2 has received [1,2],[3,4] from parties 1,2 in S1
        let broadcast_from_p1 = BTreeMap::from([
            (
                Role::indexed_from_one(1),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(1)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(2)),
                ],
            ),
            (
                Role::indexed_from_one(2),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(3)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(4)),
                ],
            ),
        ]);
        // P2 in S2 has received [2,3],[4,5] from parties 1,2,3,4 in S1
        let broadcast_from_p2 = BTreeMap::from([
            (
                Role::indexed_from_one(1),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(2)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(3)),
                ],
            ),
            (
                Role::indexed_from_one(2),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(4)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(5)),
                ],
            ),
        ]);

        // P3 in S2 has received [1,3],[3,5] from parties 1,2,3,4 in S1
        let broadcast_from_p3 = BTreeMap::from([
            (
                Role::indexed_from_one(1),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(1)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(3)),
                ],
            ),
            (
                Role::indexed_from_one(2),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(3)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(6)),
                ],
            ),
        ]);

        // P4 in S2 has received [1,2], [_] from parties 1,2,3,4 in S1
        let broadcast_from_p4 = BTreeMap::from([
            (
                Role::indexed_from_one(1),
                vec![
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(1)),
                    ResiduePolyF4Z128::from_scalar(Z128::from_u128(2)),
                ],
            ),
            (Role::indexed_from_one(2), vec![]),
        ]);

        // Winners are :
        // - [1,3] for P1, 1 with 3 votes and 3 with tie of 2 votes but 3>2
        // - [3,6] for P2 with 2 votes but tie break because 6 is bigger
        let broadcast_results = HashMap::from([
            (
                Role::indexed_from_one(1),
                BroadcastValue::MapRingVector(broadcast_from_p1),
            ),
            (
                Role::indexed_from_one(2),
                BroadcastValue::MapRingVector(broadcast_from_p2),
            ),
            (
                Role::indexed_from_one(3),
                BroadcastValue::MapRingVector(broadcast_from_p3),
            ),
            (
                Role::indexed_from_one(4),
                BroadcastValue::MapRingVector(broadcast_from_p4),
            ),
        ]);

        let mut session = crate::tests::helper::testing::get_networkless_base_session_for_parties(
            4,
            1,
            Role::indexed_from_one(1),
        );

        let parties_in_s1 = HashSet::from([Role::indexed_from_one(1), Role::indexed_from_one(2)]);

        let majority_results = take_majority_vote_on_broadcasts(
            &mut session,
            broadcast_results,
            &parties_in_s1,
            expected_input_len,
        )
        .unwrap();

        assert_eq!(
            majority_results[&Role::indexed_from_one(1)],
            vec![
                ResiduePolyF4Z128::from_scalar(Z128::from_u128(1)),
                ResiduePolyF4Z128::from_scalar(Z128::from_u128(3))
            ]
        );
        assert_eq!(
            majority_results[&Role::indexed_from_one(2)],
            vec![
                ResiduePolyF4Z128::from_scalar(Z128::from_u128(3)),
                ResiduePolyF4Z128::from_scalar(Z128::from_u128(6))
            ]
        );
    }
}
