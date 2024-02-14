use aes_prng::AesRng;
use async_trait::async_trait;
use derive_more::Display;
use rand::SeedableRng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use crate::{
    algebra::structure_traits::Ring,
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        sharing::shamir::ShamirRing,
        small_execution::prss::{PRSSSetup, PRSSState},
    },
    networking::Networking,
};

use super::party::{Identity, Role};

pub type NetworkingImpl = Arc<dyn Networking + Send + Sync>;

#[derive(Clone, Serialize, Deserialize, Display)]
pub enum DecryptionMode {
    PRSSDecrypt,
    LargeDecrypt,
    BitDecSmallDecrypt,
    BitDecLargeDecrypt,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum SetupMode {
    AllProtos,
    NoPrss,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionParameters {
    pub threshold: u8,
    pub session_id: SessionId,
    pub own_identity: Identity,
    pub role_assignments: HashMap<Role, Identity>,
}

pub trait ParameterHandles: Sync + Send + Clone {
    fn threshold(&self) -> u8;
    fn session_id(&self) -> SessionId;
    fn own_identity(&self) -> Identity;
    fn my_role(&self) -> anyhow::Result<Role>;
    fn identity_from(&self, role: &Role) -> anyhow::Result<Identity>;
    fn amount_of_parties(&self) -> usize;
    fn role_from(&self, identity: &Identity) -> anyhow::Result<Role>;
    fn role_assignments(&self) -> &HashMap<Role, Identity>;
    fn set_role_assignments(&mut self, role_assignments: HashMap<Role, Identity>);
}

impl SessionParameters {
    pub fn new(
        threshold: u8,
        session_id: SessionId,
        own_identity: Identity,
        role_assignments: HashMap<Role, Identity>,
    ) -> anyhow::Result<Self> {
        if role_assignments.len() <= threshold as usize {
            return Err(anyhow_error_and_log(format!(
                "Threshold {threshold} cannot be less than the amount of parties, {:?}",
                role_assignments.len()
            )));
        }
        let res = Self {
            threshold,
            session_id,
            own_identity: own_identity.clone(),
            role_assignments,
        };
        if res.role_from(&own_identity).is_err() {
            return Err(anyhow_error_and_log(
                "Your own role is not contained in the role_assignments".to_string(),
            ));
        }
        Ok(res)
    }
}

impl ParameterHandles for SessionParameters {
    fn my_role(&self) -> anyhow::Result<Role> {
        // Note that if `new` has been used and data has not been modified this should never result in an error
        Self::role_from(self, &self.own_identity)
    }

    fn identity_from(&self, role: &Role) -> anyhow::Result<Identity> {
        match self.role_assignments.get(role) {
            Some(identity) => Ok(identity.clone()),
            None => Err(anyhow_error_and_log(format!(
                "Role {} does not exist",
                role.one_based()
            ))),
        }
    }

    fn amount_of_parties(&self) -> usize {
        self.role_assignments.len()
    }

    /// Return Role for given Identity in this session
    fn role_from(&self, identity: &Identity) -> anyhow::Result<Role> {
        let role: Vec<&Role> = self
            .role_assignments
            .iter()
            .filter_map(|(role, cur_identity)| {
                if cur_identity == identity {
                    Some(role)
                } else {
                    None
                }
            })
            .collect();

        let role = {
            match role.len() {
                1 => Ok(role[0]),
                _ => Err(anyhow_error_and_log(format!(
                    "Unknown or ambiguous role for identity {:?}, retrieved {:?}",
                    identity, self.role_assignments
                ))),
            }?
        };

        Ok(*role)
    }

    fn threshold(&self) -> u8 {
        self.threshold
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    fn own_identity(&self) -> Identity {
        self.own_identity.clone()
    }

    fn role_assignments(&self) -> &HashMap<Role, Identity> {
        &self.role_assignments
    }

    fn set_role_assignments(&mut self, role_assignments: HashMap<Role, Identity>) {
        self.role_assignments = role_assignments;
    }
}

pub type BaseSession = BaseSessionStruct<AesRng, SessionParameters>;

#[derive(Clone)]
pub struct BaseSessionStruct<R: CryptoRngCore + Send + Sync, P: ParameterHandles> {
    pub parameters: P,
    pub networking: NetworkingImpl,
    pub rng: R,
    pub corrupt_roles: HashSet<Role>,
}
pub trait BaseSessionHandles<R: CryptoRngCore>: ParameterHandles {
    fn corrupt_roles(&self) -> &HashSet<Role>;
    fn add_corrupt(&mut self, role: Role) -> anyhow::Result<bool>;
    fn rng(&mut self) -> &mut R;
    fn network(&self) -> &NetworkingImpl;
}

impl BaseSession {
    pub fn new(
        parameters: SessionParameters,
        network: NetworkingImpl,
        rng: AesRng,
    ) -> anyhow::Result<Self> {
        Ok(BaseSessionStruct {
            parameters,
            networking: network,
            rng,
            corrupt_roles: HashSet::new(),
        })
    }
}

impl<R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> ParameterHandles
    for BaseSessionStruct<R, P>
{
    fn my_role(&self) -> anyhow::Result<Role> {
        self.parameters.my_role()
    }

    fn identity_from(&self, role: &Role) -> anyhow::Result<Identity> {
        self.parameters.identity_from(role)
    }

    fn amount_of_parties(&self) -> usize {
        self.parameters.amount_of_parties()
    }

    fn role_from(&self, identity: &Identity) -> anyhow::Result<Role> {
        self.parameters.role_from(identity)
    }

    fn threshold(&self) -> u8 {
        self.parameters.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.parameters.session_id()
    }

    fn own_identity(&self) -> Identity {
        self.parameters.own_identity()
    }

    fn role_assignments(&self) -> &HashMap<Role, Identity> {
        self.parameters.role_assignments()
    }

    fn set_role_assignments(&mut self, role_assignments: HashMap<Role, Identity>) {
        self.parameters.set_role_assignments(role_assignments);
    }
}

impl<R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> BaseSessionHandles<R>
    for BaseSessionStruct<R, P>
{
    fn rng(&mut self) -> &mut R {
        &mut self.rng
    }

    fn network(&self) -> &NetworkingImpl {
        &self.networking
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        &self.corrupt_roles
    }

    fn add_corrupt(&mut self, role: Role) -> anyhow::Result<bool> {
        Ok(self.corrupt_roles.insert(role))
    }
}

pub trait ToBaseSession<R: CryptoRngCore + Send + Sync, B: BaseSessionHandles<R>> {
    fn to_base_session(&self) -> B;
}

pub type SmallSession<Z> = SmallSessionStruct<Z, AesRng, SessionParameters>;
pub type SmallSession64 = SmallSession<crate::algebra::residue_poly::ResiduePoly64>;
pub type SmallSession128 = SmallSession<crate::algebra::residue_poly::ResiduePoly128>;

pub trait SmallSessionHandles<Z: Ring, R: CryptoRngCore>: BaseSessionHandles<R> {
    /// Return the mutable prss state as an [Option]
    fn prss_as_mut(&mut self) -> anyhow::Result<&mut PRSSState<Z>>;
    /// Returns the non-mutable prss state if it exists or return an error
    fn prss(&self) -> anyhow::Result<PRSSState<Z>>;
    /// Set the prss state
    fn set_prss(&mut self, state: Option<PRSSState<Z>>);
}

#[derive(Clone)]
pub struct SmallSessionStruct<Z: Ring, R: CryptoRngCore + Send + Sync, P: ParameterHandles> {
    pub parameters: P,
    pub network: NetworkingImpl,
    pub rng: R,
    pub corrupt_roles: HashSet<Role>,
    pub prss_state: Option<PRSSState<Z>>,
}
impl<Z: ShamirRing> SmallSession<Z> {
    pub fn new(
        session_id: SessionId,
        role_assignments: HashMap<Role, Identity>,
        network: NetworkingImpl,
        threshold: u8,
        prss_setup: Option<PRSSSetup<Z>>, // TODO this will be shared a lot so maybe it should just be a box?
        own_identity: Identity,
        rng: Option<AesRng>,
    ) -> anyhow::Result<Self> {
        Ok(SmallSessionStruct {
            parameters: SessionParameters::new(
                threshold,
                session_id,
                own_identity,
                role_assignments,
            )?,
            rng: rng.unwrap_or_else(AesRng::from_entropy),
            network,
            corrupt_roles: HashSet::new(),
            prss_state: prss_setup.map(|x| x.new_prss_session_state(session_id)),
        })
    }
}

impl<Z: Ring, R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> ParameterHandles
    for SmallSessionStruct<Z, R, P>
{
    fn my_role(&self) -> anyhow::Result<Role> {
        self.parameters.my_role()
    }

    fn identity_from(&self, role: &Role) -> anyhow::Result<Identity> {
        self.parameters.identity_from(role)
    }

    fn amount_of_parties(&self) -> usize {
        self.parameters.amount_of_parties()
    }

    fn role_from(&self, identity: &Identity) -> anyhow::Result<Role> {
        self.parameters.role_from(identity)
    }

    fn threshold(&self) -> u8 {
        self.parameters.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.parameters.session_id()
    }

    fn own_identity(&self) -> Identity {
        self.parameters.own_identity()
    }

    fn role_assignments(&self) -> &HashMap<Role, Identity> {
        self.parameters.role_assignments()
    }
    fn set_role_assignments(&mut self, role_assignments: HashMap<Role, Identity>) {
        self.parameters.set_role_assignments(role_assignments);
    }
}

impl<Z: Ring, R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> BaseSessionHandles<R>
    for SmallSessionStruct<Z, R, P>
{
    fn rng(&mut self) -> &mut R {
        &mut self.rng
    }

    fn network(&self) -> &NetworkingImpl {
        &self.network
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        &self.corrupt_roles
    }

    fn add_corrupt(&mut self, role: Role) -> anyhow::Result<bool> {
        // Observe we never add ourself to the list of corrupt parties to keep the execution going
        // This is logically the attack model we expect and hence make testing malicious behaviour easier
        if role != self.my_role()? {
            Ok(self.corrupt_roles.insert(role))
        } else {
            Ok(false)
        }
    }
}

impl<Z: Ring, R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> SmallSessionHandles<Z, R>
    for SmallSessionStruct<Z, R, P>
{
    fn prss_as_mut(&mut self) -> anyhow::Result<&mut PRSSState<Z>> {
        match self.prss_state {
            Some(ref mut state) => Ok(state),
            None => Err(anyhow_error_and_log("No PRSS state exist".to_string())),
        }
    }

    fn prss(&self) -> anyhow::Result<PRSSState<Z>> {
        let state = match &self.prss_state {
            Some(state) => state,
            None => {
                return Err(anyhow_error_and_log("No PRSS state exist".to_string()));
            }
        };
        Ok(state.to_owned())
    }

    fn set_prss(&mut self, state: Option<PRSSState<Z>>) {
        self.prss_state = state;
    }
}

impl<Z: Ring, R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles>
    ToBaseSession<R, BaseSessionStruct<R, P>> for SmallSessionStruct<Z, R, P>
{
    fn to_base_session(&self) -> BaseSessionStruct<R, P> {
        BaseSessionStruct {
            parameters: self.parameters.clone(),
            networking: self.network.clone(),
            rng: self.rng.clone(),
            corrupt_roles: self.corrupt_roles.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Debug)]
pub enum DisputeMsg {
    OK,
    CORRUPTION,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Debug)]
pub struct DisputePayload {
    msg: DisputeMsg,
    disputes: Vec<Role>,
}
pub type LargeSession = LargeSessionStruct<AesRng, SessionParameters>;

#[async_trait]
pub trait LargeSessionHandles<R: CryptoRngCore>: BaseSessionHandles<R> {
    fn disputed_roles(&self) -> &DisputeSet;
    fn my_disputes(&self) -> anyhow::Result<&BTreeSet<Role>>;
    fn add_dispute(&mut self, party_a: &Role, party_b: &Role) -> anyhow::Result<()>;
    //NOTE: REMOVED EVERYTHING WHICH HAS TO DO WITH add_dispute_and_bcast AS IT IS NOT USED ANYWHERE
    //async fn add_dispute_and_bcast(&mut self, disputed_parties: &[Role]) -> anyhow::Result<()>;
}
#[derive(Clone)]
pub struct LargeSessionStruct<R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> {
    pub parameters: P,
    pub network: NetworkingImpl,
    pub rng: R,
    pub corrupt_roles: HashSet<Role>,
    pub disputed_roles: DisputeSet,
}
impl LargeSession {
    /// Make a new [LargeSession] without any corruptions or disputes
    pub fn new(parameters: SessionParameters, network: NetworkingImpl) -> anyhow::Result<Self> {
        let parties = parameters.amount_of_parties();
        Ok(LargeSession {
            parameters,
            network,
            rng: AesRng::from_entropy(),
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(parties),
        })
    }
}
impl<R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> ParameterHandles
    for LargeSessionStruct<R, P>
{
    fn my_role(&self) -> anyhow::Result<Role> {
        self.parameters.my_role()
    }

    fn identity_from(&self, role: &Role) -> anyhow::Result<Identity> {
        self.parameters.identity_from(role)
    }

    fn amount_of_parties(&self) -> usize {
        self.parameters.amount_of_parties()
    }

    /// Return Role for given Identity in this session
    fn role_from(&self, identity: &Identity) -> anyhow::Result<Role> {
        self.parameters.role_from(identity)
    }

    fn threshold(&self) -> u8 {
        self.parameters.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.parameters.session_id()
    }

    fn own_identity(&self) -> Identity {
        self.parameters.own_identity()
    }

    fn role_assignments(&self) -> &HashMap<Role, Identity> {
        self.parameters.role_assignments()
    }
    fn set_role_assignments(&mut self, role_assignments: HashMap<Role, Identity>) {
        self.parameters.set_role_assignments(role_assignments);
    }
}
impl<R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles> BaseSessionHandles<R>
    for LargeSessionStruct<R, P>
{
    fn rng(&mut self) -> &mut R {
        &mut self.rng
    }

    fn network(&self) -> &NetworkingImpl {
        &self.network
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        &self.corrupt_roles
    }

    fn add_corrupt(&mut self, role: Role) -> anyhow::Result<bool> {
        let res = self.corrupt_roles.insert(role);
        //Make sure we now have this role in dispute with everyone
        for role_b in self.parameters.role_assignments().keys() {
            self.disputed_roles.add(&role, role_b)?;
        }
        Ok(res)
    }
}

impl<R: CryptoRngCore + Sync + Send + Clone, P: ParameterHandles>
    ToBaseSession<R, BaseSessionStruct<R, P>> for LargeSessionStruct<R, P>
{
    fn to_base_session(&self) -> BaseSessionStruct<R, P> {
        BaseSessionStruct {
            parameters: self.parameters.clone(),
            networking: self.network.clone(),
            rng: self.rng.clone(),
            corrupt_roles: self.corrupt_roles.clone(),
        }
    }
}

#[async_trait]
impl<R: CryptoRngCore + Send + Sync + Clone, P: ParameterHandles + Clone + Send + Sync>
    LargeSessionHandles<R> for LargeSessionStruct<R, P>
{
    fn disputed_roles(&self) -> &DisputeSet {
        &self.disputed_roles
    }

    fn my_disputes(&self) -> anyhow::Result<&BTreeSet<Role>> {
        self.disputed_roles.get(&self.my_role()?)
    }

    fn add_dispute(&mut self, party_a: &Role, party_b: &Role) -> anyhow::Result<()> {
        self.disputed_roles.add(party_a, party_b)?;

        //Now check whether too many dispute w/ either
        //which result in adding that party to corrupt
        self.sync_dispute_corrupt(party_a)?;
        self.sync_dispute_corrupt(party_b)?;
        Ok(())
    }
}

impl<R: CryptoRngCore + Send + Sync + Clone, P: ParameterHandles + Clone + Send + Sync>
    LargeSessionStruct<R, P>
{
    pub fn sync_dispute_corrupt(&mut self, role: &Role) -> anyhow::Result<()> {
        if self.disputed_roles.get(role)?.len() > self.threshold() as usize {
            tracing::warn!(
                "Party {role} is in conflict with too many parties, adding it to the corrupt set"
            );
            self.add_corrupt(*role)?;
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DisputeSet {
    disputed_roles: Vec<BTreeSet<Role>>,
}

impl DisputeSet {
    pub fn new(amount: usize) -> Self {
        let mut disputed_roles = Vec::with_capacity(amount);
        // Insert roles
        for _i in 1..=amount as u64 {
            disputed_roles.push(BTreeSet::new());
        }
        DisputeSet { disputed_roles }
    }

    pub fn add(&mut self, role_a: &Role, role_b: &Role) -> anyhow::Result<()> {
        // We don't allow disputes with oneself
        if role_a == role_b {
            return Ok(());
        }
        // Insert the first pair of disputes
        let disputed_roles = &mut self.disputed_roles;
        let a_disputes = disputed_roles
            .get_mut(role_a.zero_based())
            .ok_or_else(|| anyhow_error_and_log("Role does not exist".to_string()))?;
        let _ = a_disputes.insert(*role_b);
        // Insert the second pair of disputes
        let b_disputes: &mut BTreeSet<Role> = disputed_roles
            .get_mut(role_b.zero_based())
            .ok_or_else(|| anyhow_error_and_log("Role does not exist".to_string()))?;
        let _ = b_disputes.insert(*role_a);
        Ok(())
    }

    pub fn get(&self, role: &Role) -> anyhow::Result<&BTreeSet<Role>> {
        if let Some(cur) = self.disputed_roles.get(role.zero_based()) {
            Ok(cur)
        } else {
            Err(anyhow_error_and_log("Role does not exist".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionParameters;
    use crate::algebra::residue_poly::ResiduePoly128;
    use crate::execution::runtime::party::Role;
    use crate::{
        execution::runtime::session::BaseSessionHandles, tests::helper::tests::get_small_session,
    };
    use crate::{
        execution::runtime::session::ParameterHandles,
        tests::helper::tests::get_dummy_parameters_for_parties,
    };

    #[test]
    fn too_large_threshold() {
        let parties = 3;
        let params =
            get_dummy_parameters_for_parties(parties, parties as u8, Role::indexed_by_one(1));
        // Same amount of parties and threshold, which is not allowed
        assert!(SessionParameters::new(
            params.threshold(),
            params.session_id(),
            params.own_identity(),
            params.role_assignments().clone(),
        )
        .is_err());
    }

    #[test]
    fn missing_self_identity() {
        let parties = 3;
        let mut params = get_dummy_parameters_for_parties(parties, 1, Role::indexed_by_one(1));
        // remove my role
        params.role_assignments.remove(&Role::indexed_by_one(1));
        assert!(SessionParameters::new(
            params.threshold(),
            params.session_id(),
            params.own_identity(),
            params.role_assignments().clone(),
        )
        .is_err());
    }

    #[test]
    fn wont_add_self_to_corrupt() {
        let mut session = get_small_session::<ResiduePoly128>();
        // Check that I cannot add myself to the corruption set directly
        assert!(!session.add_corrupt(session.my_role().unwrap()).unwrap());
        assert_eq!(0, session.corrupt_roles().len());
    }
}
