use aes_prng::AesRng;
use rand::SeedableRng;
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, RingWithExceptionalSequence, Zero},
    execution::{
        communication::broadcast::Broadcast,
        large_execution::vss::Vss,
        runtime::{party::Role, sessions::base_session::BaseSessionHandles},
        small_execution::{
            agree_random::AgreeRandomFromShare,
            prf::PRSSConversions,
            prss::{
                DerivePRSSState, PRSSCounters, PRSSInit, PRSSPrimitives, PRSSSetup, PRSSState,
                RobustRealPrssInit,
            },
        },
    },
    session_id::SessionId,
    ProtocolDescription,
};

/// Malicious implementation of [`PrssInit`], [`DerivePRSSState`] and [`PRSSPrimitives`]
/// (i.e. the whole PRSS suite of traits)
/// that does not participate in any comunication and returns the default output
#[derive(Clone, Default)]
pub struct MaliciousPrssDrop {}

impl ProtocolDescription for MaliciousPrssDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousPrssDrop")
    }
}

#[async_trait]
impl<Z: Zero + Clone> PRSSInit<Z> for MaliciousPrssDrop {
    type OutputType = MaliciousPrssDrop;
    async fn init<S: BaseSessionHandles>(
        &self,
        _session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
        Ok(MaliciousPrssDrop {})
    }
}

impl<Z: Zero + Clone> DerivePRSSState<Z> for MaliciousPrssDrop {
    type OutputType = MaliciousPrssDrop;
    fn new_prss_session_state(&self, _sid: SessionId) -> Self::OutputType {
        MaliciousPrssDrop {}
    }
}

#[async_trait]
impl<Z: Zero + Clone> PRSSPrimitives<Z> for MaliciousPrssDrop {
    /// Always return [`Z::ZERO`]
    async fn prss_next_vec(&mut self, _party_id: Role, amount: usize) -> anyhow::Result<Vec<Z>> {
        Ok(vec![Z::ZERO; amount])
    }

    /// Always return [`Z::ZERO`]
    async fn przs_next_vec(
        &mut self,
        _party_id: Role,
        _threshold: u8,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        Ok(vec![Z::ZERO; amount])
    }

    /// Always return [`Z::ZERO`]
    async fn mask_next_vec(
        &mut self,
        _party_id: Role,
        _bd: u128,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        Ok(vec![Z::ZERO; amount])
    }

    /// Does nothing and returns an empty map
    async fn prss_check<S: BaseSessionHandles>(
        &self,
        _session: &mut S,
        _ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        Ok(HashMap::new())
    }
    /// Does nothing and returns an empty map
    async fn przs_check<S: BaseSessionHandles>(
        &self,
        _session: &mut S,
        _ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        Ok(HashMap::new())
    }

    /// Returns all counters set to 0
    fn get_counters(&self) -> PRSSCounters {
        PRSSCounters::default()
    }
}

//TODO: Need to refactor a bit those strategies to avoid having the struct
//that implements the init be dep. on the underlying ring because moby
//takes in only a single PRSSInit strategy and not one per ring.

/// Malicious implementation of [`PrssInit`], [`DerivePRSSState`] and [`PRSSPrimitives`]
/// such that it does the [`PrssInit`] robust version and check honestly BUT lies in all the Next()
/// The output of the Next functions is derived from the internal rng of this struct.
#[derive(Clone)]
pub struct MaliciousPrssHonestInitRobustThenRandom<
    A,
    V,
    Bcast: Broadcast,
    Z: Default + Clone + Serialize,
> {
    rng: AesRng,
    agree_random: A,
    vss: V,
    broadcast: Bcast,
    prss_setup: Option<PRSSSetup<Z>>,
    prss_state: Option<PRSSState<Z, Bcast>>,
}

impl<
        A: ProtocolDescription,
        V: ProtocolDescription,
        Bcast: Broadcast,
        Z: Default + Clone + Serialize,
    > ProtocolDescription for MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{}-MaliciousPrssHonestInitRobustThenRandom:\n{}\n{}\n{}",
            indent,
            A::protocol_desc(depth + 1),
            V::protocol_desc(depth + 1),
            Bcast::protocol_desc(depth + 1)
        )
    }
}

impl<A: Default, V: Default, Bcast: Broadcast + Default, Z: Default + Clone + Serialize> Default
    for MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>
{
    fn default() -> Self {
        Self {
            // Fixed seed to make all tests deterministic
            rng: AesRng::seed_from_u64(42),
            agree_random: A::default(),
            vss: V::default(),
            broadcast: Bcast::default(),
            prss_setup: None,
            prss_state: None,
        }
    }
}

#[async_trait]
impl<
        A: AgreeRandomFromShare + 'static,
        V: Vss + 'static,
        Bcast: Broadcast + 'static,
        Z: ErrorCorrect + Invert + PRSSConversions,
    > PRSSInit<Z> for MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>
{
    type OutputType = MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>;

    async fn init<S: BaseSessionHandles>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
        // Does the init honestly
        let setup = RobustRealPrssInit::new(self.agree_random.clone(), self.vss.clone())
            .init(session)
            .await?;

        // Just clone the strategies, and add the new state
        Ok(Self {
            rng: self.rng.clone(),
            agree_random: self.agree_random.clone(),
            vss: self.vss.clone(),
            broadcast: self.broadcast.clone(),
            prss_setup: Some(setup),
            prss_state: None,
        })
    }
}

impl<
        A: AgreeRandomFromShare + 'static,
        V: Vss + 'static,
        Bcast: Broadcast + 'static,
        Z: RingWithExceptionalSequence + Invert + PRSSConversions,
    > DerivePRSSState<Z> for MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>
{
    type OutputType = MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>;
    fn new_prss_session_state(&self, sid: SessionId) -> Self::OutputType {
        // Clone the strategies and state
        // and honestly derive the state
        let honest_state = self
            .prss_setup
            .as_ref()
            .unwrap()
            .new_prss_session_state(sid);
        let honest_state_custom_bcast = PRSSState {
            counters: honest_state.counters,
            prss_setup: honest_state.prss_setup,
            prfs: honest_state.prfs,
            broadcast: self.broadcast.clone(),
        };

        Self {
            rng: self.rng.clone(),
            agree_random: self.agree_random.clone(),
            vss: self.vss.clone(),
            broadcast: self.broadcast.clone(),
            prss_setup: self.prss_setup.clone(),
            prss_state: Some(honest_state_custom_bcast),
        }
    }
}

#[async_trait]
impl<
        A: AgreeRandomFromShare,
        V: Vss,
        Bcast: Broadcast,
        Z: RingWithExceptionalSequence + Invert + PRSSConversions,
    > PRSSPrimitives<Z> for MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>
{
    /// Always return some random value
    async fn prss_next_vec(&mut self, _party_id: Role, amount: usize) -> anyhow::Result<Vec<Z>> {
        Ok((0..amount).map(|_| Z::sample(&mut self.rng)).collect())
    }

    /// Always return some random value
    async fn przs_next_vec(
        &mut self,
        _party_id: Role,
        _threshold: u8,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        Ok((0..amount).map(|_| Z::sample(&mut self.rng)).collect())
    }

    /// Always return some random value
    async fn mask_next_vec(
        &mut self,
        _party_id: Role,
        _bd: u128,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        Ok((0..amount).map(|_| Z::sample(&mut self.rng)).collect())
    }

    /// Performs prss check honestly from the correctly derived prss state
    async fn prss_check<S: BaseSessionHandles>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        self.prss_state
            .as_ref()
            .unwrap()
            .prss_check(session, ctr)
            .await
    }
    /// Performs przs check honestly from the correctly derived prss state
    async fn przs_check<S: BaseSessionHandles>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        self.prss_state
            .as_ref()
            .unwrap()
            .przs_check(session, ctr)
            .await
    }

    /// Returns all counters from the honest prss_state
    fn get_counters(&self) -> PRSSCounters {
        self.prss_state.as_ref().unwrap().get_counters()
    }
}

/// Malicious implementation of [`PrssInit`], [`DerivePRSSState`] and [`PRSSPrimitives`]
/// such that it inits honestly then answers the expected types but lies about everything (including the checks).
/// Done by using [`MaliciousPrssHonestInitRobustThenRandom`] except the states
/// are always derived from a random sid and not the expected one
#[derive(Clone, Default)]
pub struct MaliciousPrssHonestInitLieAll<A, V, Bcast: Broadcast, Z: Default + Clone + Serialize> {
    agree_random: A,
    vss: V,
    broadcast: Bcast,
    prss_setup: Option<PRSSSetup<Z>>,
}

impl<
        A: ProtocolDescription,
        V: ProtocolDescription,
        Bcast: Broadcast,
        Z: Default + Clone + Serialize,
    > ProtocolDescription for MaliciousPrssHonestInitLieAll<A, V, Bcast, Z>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{}-MaliciousPrssHonestInitLieAll:\n{}\n{}\n{}",
            indent,
            A::protocol_desc(depth + 1),
            V::protocol_desc(depth + 1),
            Bcast::protocol_desc(depth + 1)
        )
    }
}

#[async_trait]
impl<
        A: AgreeRandomFromShare + 'static,
        V: Vss + 'static,
        Bcast: Broadcast + 'static,
        Z: ErrorCorrect + Invert + PRSSConversions,
    > PRSSInit<Z> for MaliciousPrssHonestInitLieAll<A, V, Bcast, Z>
{
    type OutputType = MaliciousPrssHonestInitLieAll<A, V, Bcast, Z>;

    async fn init<S: BaseSessionHandles>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
        // Does the init honestly
        let setup = RobustRealPrssInit::new(self.agree_random.clone(), self.vss.clone())
            .init(session)
            .await
            .unwrap();

        // Just clone the strategies, and add the new state
        Ok(Self {
            agree_random: self.agree_random.clone(),
            vss: self.vss.clone(),
            broadcast: self.broadcast.clone(),
            prss_setup: Some(setup),
        })
    }
}

impl<
        A: AgreeRandomFromShare + 'static,
        V: Vss + 'static,
        Bcast: Broadcast + 'static,
        Z: RingWithExceptionalSequence + Invert + PRSSConversions,
    > DerivePRSSState<Z> for MaliciousPrssHonestInitLieAll<A, V, Bcast, Z>
{
    type OutputType = MaliciousPrssHonestInitRobustThenRandom<A, V, Bcast, Z>;
    fn new_prss_session_state(&self, sid: SessionId) -> Self::OutputType {
        // Clone the strategies and state
        // but derive the state from a wrong sid
        // so none of the PRSSPrimitives will be correct
        // (including the checks)
        let sid_u128: u128 = sid.into();
        let wrong_sid = SessionId::from(sid_u128 + 42);
        let honest_state = self
            .prss_setup
            .as_ref()
            .unwrap()
            .new_prss_session_state(wrong_sid);
        let honest_state_custom_bcast = PRSSState {
            counters: honest_state.counters,
            prss_setup: honest_state.prss_setup,
            prfs: honest_state.prfs,
            broadcast: self.broadcast.clone(),
        };

        // Deterministically derive seed from sid by xoring the MSB to the LSB
        // of the session id
        let seed = ((sid_u128 >> 64) as u64) ^ (sid_u128 as u64);
        let rng = AesRng::seed_from_u64(seed);
        MaliciousPrssHonestInitRobustThenRandom {
            rng,
            agree_random: self.agree_random.clone(),
            vss: self.vss.clone(),
            broadcast: self.broadcast.clone(),
            prss_setup: self.prss_setup.clone(),
            prss_state: Some(honest_state_custom_bcast),
        }
    }
}

/// Malicious implementation of [`PrssInit`] that does not do anything
/// and returns an empty [`PRSSSetup`]
#[derive(Clone, Default)]
pub struct EmptyPrss {}

impl ProtocolDescription for EmptyPrss {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-EmptyPrss")
    }
}

#[async_trait]
impl<Z: Zero + RingWithExceptionalSequence + Invert + PRSSConversions> PRSSInit<Z> for EmptyPrss {
    type OutputType = PRSSSetup<Z>;
    async fn init<S: BaseSessionHandles>(
        &self,
        _session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
        Ok(PRSSSetup {
            sets: Arc::new(vec![]),
            alpha_powers: Arc::new(vec![]),
        })
    }
}

// PRSS that always fails on init
#[derive(Clone, Default)]
pub struct FailingPrss {}

impl ProtocolDescription for FailingPrss {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-FailingPrss")
    }
}

#[async_trait]
impl<Z: Zero + RingWithExceptionalSequence + Invert + PRSSConversions> PRSSInit<Z> for FailingPrss {
    type OutputType = PRSSSetup<Z>;
    async fn init<S: BaseSessionHandles>(
        &self,
        _session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
        Err(anyhow::anyhow!("This PRSS always fails"))
    }
}
