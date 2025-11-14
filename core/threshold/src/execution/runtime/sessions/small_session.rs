use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        structure_traits::{ErrorCorrect, Invert, Ring, RingWithExceptionalSequence},
    },
    execution::{
        runtime::{
            party::Role,
            sessions::{
                base_session::{
                    BaseSession, BaseSessionHandles, GenericBaseSessionHandles,
                    SingleSetNetworkingImpl, ToBaseSession,
                },
                session_parameters::{
                    DeSerializationRunTime, GenericParameterHandles, ParameterHandles,
                    SessionParameters,
                },
            },
        },
        small_execution::{
            prf::PRSSConversions,
            prss::{
                DerivePRSSState, PRSSInit, PRSSPrimitives, RobustSecurePrssInit, SecurePRSSState,
            },
        },
    },
    session_id::SessionId,
};
use aes_prng::AesRng;
use std::collections::HashSet;

pub type SmallSession64<const EXTENSION_DEGREE: usize> =
    SmallSession<crate::algebra::galois_rings::common::ResiduePoly<Z64, EXTENSION_DEGREE>>;
pub type SmallSession128<const EXTENSION_DEGREE: usize> =
    SmallSession<crate::algebra::galois_rings::common::ResiduePoly<Z128, EXTENSION_DEGREE>>;

pub trait SmallSessionHandles<Z: Ring>: BaseSessionHandles {
    type PRSSPrimitivesType: PRSSPrimitives<Z>;
    fn prss_as_mut(&mut self) -> &mut Self::PRSSPrimitivesType;
    /// Returns the non-mutable prss state if it exists or return an error
    fn prss(&self) -> Self::PRSSPrimitivesType;
}

pub struct SmallSession<Z: Ring> {
    pub base_session: BaseSession,
    pub prss_state: SecurePRSSState<Z>,
}

impl<Z> SmallSession<Z>
where
    Z: ErrorCorrect + Invert + PRSSConversions,
{
    pub async fn new_and_init_prss_state(mut base_session: BaseSession) -> anyhow::Result<Self>
    where
        Z: ErrorCorrect + Invert,
    {
        let prss_setup = RobustSecurePrssInit::default()
            .init(&mut base_session)
            .await?;
        let session_id = base_session.session_id();
        Self::new_from_prss_state(base_session, prss_setup.new_prss_session_state(session_id))
    }

    pub fn new_from_prss_state(
        base_session: BaseSession,
        prss_state: SecurePRSSState<Z>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base_session,
            prss_state,
        })
    }
}

impl<Z: Ring> GenericParameterHandles<Role> for SmallSession<Z> {
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

    fn get_deserialization_runtime(&self) -> DeSerializationRunTime {
        self.base_session.get_deserialization_runtime()
    }

    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime) {
        self.base_session
            .set_deserialization_runtime(serialization_runtime);
    }
}

impl<Z: Ring> ParameterHandles for SmallSession<Z> {}

impl<Z: Ring> GenericBaseSessionHandles<Role> for SmallSession<Z> {
    type RngType = AesRng;

    fn rng(&mut self) -> &mut Self::RngType {
        self.base_session.rng()
    }

    fn network(&self) -> &SingleSetNetworkingImpl {
        self.base_session.network()
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        self.base_session.corrupt_roles()
    }

    fn add_corrupt(&mut self, role: Role) -> bool {
        self.base_session.add_corrupt(role)
    }
}

impl<Z: Ring> BaseSessionHandles for SmallSession<Z> {}

impl<Z: RingWithExceptionalSequence + Invert + PRSSConversions> SmallSessionHandles<Z>
    for SmallSession<Z>
{
    type PRSSPrimitivesType = SecurePRSSState<Z>;

    fn prss_as_mut(&mut self) -> &mut SecurePRSSState<Z> {
        &mut self.prss_state
    }

    fn prss(&self) -> SecurePRSSState<Z> {
        self.prss_state.to_owned()
    }
}

impl<Z: Ring> ToBaseSession for SmallSession<Z> {
    fn to_base_session(self) -> BaseSession {
        self.base_session
    }
    fn get_mut_base_session(&mut self) -> &mut BaseSession {
        &mut self.base_session
    }
}
