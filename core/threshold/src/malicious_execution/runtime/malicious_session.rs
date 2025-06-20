use std::collections::HashSet;

use crate::{
    algebra::structure_traits::{Invert, Ring, RingWithExceptionalSequence},
    execution::{
        runtime::{
            party::Role,
            session::{
                BaseSession, BaseSessionHandles, NetworkingImpl, ParameterHandles,
                SessionParameters, SmallSession, SmallSessionHandles, ToBaseSession,
            },
        },
        small_execution::{
            prf::PRSSConversions,
            prss::{DerivePRSSState, PRSSInit, PRSSPrimitives, SecurePRSSState},
        },
    },
    session_id::SessionId,
};

/// Defines a generic small session
/// that accepts any arbitrary PRSS strategy
/// (whereas the regular small session only executes the secure PRSS)
/// This is useful for testing purposes
/// where we want to use a different PRSS strategy
pub struct GenericSmallSessionStruct<Z: Ring, Prss: PRSSPrimitives<Z>> {
    pub base_session: BaseSession,
    pub prss_state: Prss,
    ring_marker: std::marker::PhantomData<Z>,
}

impl<Z: Ring, Prss: PRSSPrimitives<Z>> GenericSmallSessionStruct<Z, Prss> {
    pub async fn new_and_init_prss_state<PrssInit: PRSSInit<Z>>(
        mut base_session: BaseSession,
        prss_init: PrssInit,
    ) -> anyhow::Result<Self>
    where
        <PrssInit::OutputType as DerivePRSSState<Z>>::OutputType: Into<Prss>,
    {
        let prss_setup = prss_init.init(&mut base_session).await?;
        let session_id = base_session.session_id();
        let prss_state: Prss = prss_setup.new_prss_session_state(session_id).into();
        Self::new_from_prss_state(base_session, prss_state)
    }

    pub fn new_from_prss_state(
        base_session: BaseSession,
        prss_state: Prss,
    ) -> anyhow::Result<Self> {
        Ok(GenericSmallSessionStruct {
            base_session,
            prss_state,
            ring_marker: std::marker::PhantomData,
        })
    }
}

impl<Z: Ring, Prss: PRSSPrimitives<Z> + Clone> ParameterHandles
    for GenericSmallSessionStruct<Z, Prss>
{
    fn my_role(&self) -> Role {
        self.base_session.my_role()
    }

    fn num_parties(&self) -> usize {
        self.base_session.num_parties()
    }

    fn threshold(&self) -> u8 {
        self.base_session.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.base_session.session_id()
    }

    fn roles(&self) -> &HashSet<Role> {
        self.base_session.roles()
    }

    fn roles_mut(&mut self) -> &mut HashSet<Role> {
        self.base_session.roles_mut()
    }

    fn to_parameters(&self) -> SessionParameters {
        self.base_session.to_parameters()
    }

    fn get_all_sorted_roles(&self) -> &Vec<Role> {
        self.base_session.get_all_sorted_roles()
    }
}

impl<Z: Ring, Prss: PRSSPrimitives<Z> + Clone> BaseSessionHandles
    for GenericSmallSessionStruct<Z, Prss>
{
    type RngType = aes_prng::AesRng;
    fn rng(&mut self) -> &mut Self::RngType {
        self.base_session.rng()
    }

    fn network(&self) -> &NetworkingImpl {
        self.base_session.network()
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        self.base_session.corrupt_roles()
    }

    fn add_corrupt(&mut self, role: Role) -> bool {
        self.base_session.add_corrupt(role)
    }
}

impl<Z: Ring, Prss: PRSSPrimitives<Z> + Clone> SmallSessionHandles<Z>
    for GenericSmallSessionStruct<Z, Prss>
{
    type PRSSPrimitivesType = Prss;
    fn prss_as_mut(&mut self) -> &mut Prss {
        &mut self.prss_state
    }

    fn prss(&self) -> Prss {
        self.prss_state.to_owned()
    }
}

impl<Z: Ring, Prss: PRSSPrimitives<Z> + Clone> ToBaseSession
    for GenericSmallSessionStruct<Z, Prss>
{
    fn to_base_session(self) -> BaseSession {
        self.base_session
    }

    fn get_mut_base_session(&mut self) -> &mut BaseSession {
        &mut self.base_session
    }
}

// If the generic session uses a secure PRSS state, allow convrersion to a SmallSession
impl<Z: RingWithExceptionalSequence + Invert + PRSSConversions>
    GenericSmallSessionStruct<Z, SecurePRSSState<Z>>
{
    pub fn to_secure_small_session(self) -> SmallSession<Z> {
        SmallSession {
            base_session: self.base_session,
            prss_state: self.prss_state,
        }
    }
}
