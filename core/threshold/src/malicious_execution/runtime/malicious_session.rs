use std::collections::{HashMap, HashSet};

use rand::{CryptoRng, Rng, SeedableRng};

use crate::{
    algebra::structure_traits::Ring,
    execution::{
        runtime::{
            party::{Identity, Role},
            session::{
                BaseSessionHandles, BaseSessionStruct, NetworkingImpl, ParameterHandles,
                SmallSessionHandles,
            },
        },
        small_execution::prss::{DerivePRSSState, PRSSInit, PRSSPrimitives},
    },
    session_id::SessionId,
};

/// Defines a malicious small session
/// that accepts any arbitrary PRSS strategy
/// (whereas the regular small session only executes the secure PRSS)
#[derive(Clone)]
pub struct MaliciousSmallSessionStruct<
    Z: Ring,
    R: Rng + CryptoRng + SeedableRng,
    Prss: PRSSPrimitives<Z>,
    P: ParameterHandles,
> {
    pub base_session: BaseSessionStruct<R, P>,
    pub prss_state: Prss,
    ring_marker: std::marker::PhantomData<Z>,
}

impl<
        Z: Ring,
        R: Rng + CryptoRng + SeedableRng + Clone + Send + Sync,
        Prss: PRSSPrimitives<Z>,
        P: ParameterHandles,
    > MaliciousSmallSessionStruct<Z, R, Prss, P>
{
    pub async fn new_and_init_prss_state<PrssInit: PRSSInit<Z>>(
        mut base_session: BaseSessionStruct<R, P>,
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
        base_session: BaseSessionStruct<R, P>,
        prss_state: Prss,
    ) -> anyhow::Result<Self> {
        Ok(MaliciousSmallSessionStruct {
            base_session,
            prss_state,
            ring_marker: std::marker::PhantomData,
        })
    }
}

impl<
        Z: Ring,
        R: Rng + CryptoRng + SeedableRng + Send + Sync + Clone,
        Prss: PRSSPrimitives<Z> + Clone,
        P: ParameterHandles,
    > ParameterHandles for MaliciousSmallSessionStruct<Z, R, Prss, P>
{
    fn my_role(&self) -> anyhow::Result<Role> {
        self.base_session.my_role()
    }

    fn identity_from(&self, role: &Role) -> anyhow::Result<Identity> {
        self.base_session.identity_from(role)
    }

    fn num_parties(&self) -> usize {
        self.base_session.num_parties()
    }

    fn role_from(&self, identity: &Identity) -> anyhow::Result<Role> {
        self.base_session.role_from(identity)
    }

    fn threshold(&self) -> u8 {
        self.base_session.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.base_session.session_id()
    }

    fn own_identity(&self) -> Identity {
        self.base_session.own_identity()
    }

    fn role_assignments(&self) -> &HashMap<Role, Identity> {
        self.base_session.role_assignments()
    }
    fn set_role_assignments(&mut self, role_assignments: HashMap<Role, Identity>) {
        self.base_session.set_role_assignments(role_assignments);
    }
}

impl<
        Z: Ring,
        R: Rng + CryptoRng + SeedableRng + Send + Sync + Clone,
        Prss: PRSSPrimitives<Z> + Clone,
        P: ParameterHandles,
    > BaseSessionHandles<R> for MaliciousSmallSessionStruct<Z, R, Prss, P>
{
    fn rng(&mut self) -> &mut R {
        self.base_session.rng()
    }

    fn network(&self) -> &NetworkingImpl {
        self.base_session.network()
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        self.base_session.corrupt_roles()
    }

    fn add_corrupt(&mut self, role: Role) -> anyhow::Result<bool> {
        self.base_session.add_corrupt(role)
    }
}

impl<
        Z: Ring,
        R: Rng + CryptoRng + SeedableRng + Send + Sync + Clone,
        Prss: PRSSPrimitives<Z> + Clone,
        P: ParameterHandles,
    > SmallSessionHandles<Z, R, Prss> for MaliciousSmallSessionStruct<Z, R, Prss, P>
{
    fn prss_as_mut(&mut self) -> &mut Prss {
        &mut self.prss_state
    }

    fn prss(&self) -> Prss {
        self.prss_state.to_owned()
    }
}
