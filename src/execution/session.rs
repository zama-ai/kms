use async_trait::async_trait;
use derive_more::Display;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use crate::{
    computation::SessionId, error::error_handler::anyhow_error_and_log, networking::Networking,
    value::BroadcastValue,
};

use super::{
    broadcast::broadcast_with_corruption,
    party::{Identity, Role},
    small_execution::prss::{PRSSSetup, PRSSState},
};

pub type NetworkingImpl = Arc<dyn Networking + Send + Sync>;

#[derive(Clone, Serialize, Deserialize, Display)]
pub enum DecryptionMode {
    PRSSDecrypt,
    Proto2Decrypt,
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
                role.0
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
                    "Unknown or ambiguous role for identity {:?}",
                    identity
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

pub type BaseSession = BaseSessionStruct<ChaCha20Rng, SessionParameters>;

#[derive(Clone)]
pub struct BaseSessionStruct<R: RngCore + Send + Sync, P: ParameterHandles> {
    pub parameters: P,
    pub networking: NetworkingImpl,
    pub rng: R,
    pub corrupt_roles: HashSet<Role>,
}
pub trait BaseSessionHandles<R: RngCore>: ParameterHandles {
    fn corrupt_roles(&self) -> &HashSet<Role>;
    fn add_corrupt(&mut self, role: Role) -> anyhow::Result<bool>;
    fn rng(&mut self) -> &mut R;
    fn network(&self) -> &NetworkingImpl;
}

impl BaseSession {
    pub fn new(
        parameters: SessionParameters,
        network: NetworkingImpl,
        rng: ChaCha20Rng,
    ) -> anyhow::Result<Self> {
        Ok(BaseSessionStruct {
            parameters,
            networking: network,
            rng,
            corrupt_roles: HashSet::new(),
        })
    }
}

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> ParameterHandles
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

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> BaseSessionHandles<R>
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

pub trait ToBaseSession<R: RngCore + Send + Sync, B: BaseSessionHandles<R>> {
    fn to_base_session(&self) -> B;
}

pub type SmallSession = SmallSessionStruct<ChaCha20Rng, SessionParameters>;
pub trait SmallSessionHandles<R: RngCore>: BaseSessionHandles<R> {
    fn prss(&mut self) -> &mut Option<PRSSState>;
}

#[derive(Clone)]
pub struct SmallSessionStruct<R: RngCore + Send + Sync, P: ParameterHandles> {
    pub parameters: P,
    pub network: NetworkingImpl,
    pub rng: R,
    pub corrupt_roles: HashSet<Role>,
    pub prss_state: Option<PRSSState>,
}
impl SmallSession {
    pub fn new(
        session_id: SessionId,
        role_assignments: HashMap<Role, Identity>,
        network: NetworkingImpl,
        threshold: u8,
        prss_setup: Option<PRSSSetup>,
        own_identity: Identity,
        rng: Option<ChaCha20Rng>,
    ) -> anyhow::Result<Self> {
        Ok(SmallSessionStruct {
            parameters: SessionParameters::new(
                threshold,
                session_id,
                own_identity,
                role_assignments,
            )?,
            rng: rng.unwrap_or_else(ChaCha20Rng::from_entropy),
            network,
            corrupt_roles: HashSet::new(),
            prss_state: prss_setup.map(|x| x.new_prss_session_state(session_id)),
        })
    }
}

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> ParameterHandles
    for SmallSessionStruct<R, P>
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

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> BaseSessionHandles<R>
    for SmallSessionStruct<R, P>
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
        Ok(self.corrupt_roles.insert(role))
    }
}

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> SmallSessionHandles<R>
    for SmallSessionStruct<R, P>
{
    fn prss(&mut self) -> &mut Option<PRSSState> {
        &mut self.prss_state
    }
}

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles>
    ToBaseSession<R, BaseSessionStruct<R, P>> for SmallSessionStruct<R, P>
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
pub type LargeSession = LargeSessionStruct<ChaCha20Rng, SessionParameters>;

#[async_trait]
pub trait LargeSessionHandles<R: RngCore>: BaseSessionHandles<R> {
    fn disputed_roles(&self) -> &DisputeSet;
    fn my_disputes(&self) -> anyhow::Result<&BTreeSet<Role>>;
    fn add_dispute(&mut self, party_a: &Role, party_b: &Role) -> anyhow::Result<()>;
    async fn add_dispute_and_bcast(&mut self, disputed_parties: &[Role]) -> anyhow::Result<()>;
}
#[derive(Clone)]
pub struct LargeSessionStruct<R: RngCore + Sync + Send + Clone, P: ParameterHandles> {
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
            rng: ChaCha20Rng::from_entropy(),
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(parties),
        })
    }
}
impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> ParameterHandles
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
impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles> BaseSessionHandles<R>
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

impl<R: RngCore + Sync + Send + Clone, P: ParameterHandles>
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
impl<R: RngCore + Send + Sync + Clone, P: ParameterHandles + Clone + Send + Sync>
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

    //Is this actually used ? Cant see where in the nist paper
    ///Add a list of dispute parties and broadcast it
    async fn add_dispute_and_bcast(&mut self, disputed_parties: &[Role]) -> anyhow::Result<()> {
        if self.corrupt_roles.contains(&self.my_role()?) {
            return Ok(());
        }
        let mut payload = DisputePayload {
            msg: DisputeMsg::OK,
            disputes: vec![],
        };
        if !disputed_parties.is_empty() {
            payload = DisputePayload {
                msg: DisputeMsg::CORRUPTION,
                disputes: disputed_parties.to_vec(),
            };
            for cur_role in disputed_parties {
                self.disputed_roles.add(&self.my_role()?, cur_role)?;
            }
        }
        let bcast_data: HashMap<Role, BroadcastValue> =
            broadcast_with_corruption(self, BroadcastValue::AddDispute(payload)).await?;
        for (cur_role, cur_payload) in bcast_data.into_iter() {
            if cur_role != self.my_role()? && !self.corrupt_roles().contains(&cur_role) {
                let payload = match cur_payload {
                    BroadcastValue::AddDispute(payload) => payload,
                    _ => {
                        return Err(anyhow_error_and_log(
                            "Unexpected data received from broadcast".to_string(),
                        ))
                    }
                };
                if payload.msg != DisputeMsg::OK {
                    for dispute_role in payload.disputes {
                        self.disputed_roles.add(&cur_role, &dispute_role)?;
                        // Check whether each party in the dispute set has more than [threshold] disputes and if so add them to the corrupt set
                        self.sync_dispute_corrupt(&dispute_role)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl<R: RngCore + Send + Sync + Clone, P: ParameterHandles + Clone + Send + Sync>
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
            .get_mut((role_a.0 - 1) as usize)
            .ok_or_else(|| anyhow_error_and_log("Role does not exist".to_string()))?;
        let _ = a_disputes.insert(*role_b);
        // Insert the second pair of disputes
        let b_disputes: &mut BTreeSet<Role> = disputed_roles
            .get_mut((role_b.0 - 1) as usize)
            .ok_or_else(|| anyhow_error_and_log("Role does not exist".to_string()))?;
        let _ = b_disputes.insert(*role_a);
        Ok(())
    }

    pub fn get(&self, role: &Role) -> anyhow::Result<&BTreeSet<Role>> {
        if let Some(cur) = self.disputed_roles.get((role.0 - 1) as usize) {
            Ok(cur)
        } else {
            Err(anyhow_error_and_log("Role does not exist".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionParameters;
    use crate::{execution::party::Role, tests::helper::tests::execute_protocol};
    use crate::{
        execution::session::{
            DisputeSet, LargeSession, LargeSessionHandles, LargeSessionStruct, ParameterHandles,
        },
        networking::local::LocalNetworkingProducer,
        tests::helper::tests::{
            get_dummy_parameters, get_dummy_parameters_for_parties, get_large_session,
        },
    };
    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::{collections::HashSet, sync::Arc};

    #[test]
    fn too_large_threshold() {
        let parties = 3;
        let params = get_dummy_parameters_for_parties(parties, parties as u8, Role(1));
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
        let mut params = get_dummy_parameters_for_parties(parties, 1, Role(1));
        // remove my role
        params.role_assignments.remove(&Role(1));
        assert!(SessionParameters::new(
            params.threshold(),
            params.session_id(),
            params.own_identity(),
            params.role_assignments().clone(),
        )
        .is_err());
    }

    #[test]
    fn add_dispute_sunshine() {
        let parties: usize = 4;
        static DISPUTE_ROLE: Role = Role(2);
        async fn task(mut session: LargeSession) -> LargeSession {
            session
                .add_dispute_and_bcast(&Vec::from([DISPUTE_ROLE]))
                .await
                .unwrap();
            session
        }

        let results = execute_protocol(parties, 1, &mut task);

        assert_eq!(results.len(), parties);
        // check they agree on the disputed party
        for cur_session in results {
            if cur_session.my_role().unwrap() != DISPUTE_ROLE {
                for cur_role_id in 1..=parties as u64 {
                    let cur_dispute_set =
                        cur_session.disputed_roles.get(&Role(cur_role_id)).unwrap();
                    // Check that the view of each honest party is consistant with all parties in dispute with the same party
                    if cur_role_id != DISPUTE_ROLE.0 {
                        // Check there is only one dispute
                        assert_eq!(1, cur_dispute_set.len());
                        // Check the identity of the dispute
                        assert!(cur_dispute_set.contains(&DISPUTE_ROLE));
                    } else {
                        // And that the party in dispute is disagreeing with everyone else (except themself)
                        assert_eq!(parties - 1, cur_dispute_set.len());
                    }
                }
            }
        }
    }

    /// Tests what happens when a party drops out of broadcast
    /// NOTE non-responding parties which act as senders in a broadcast ARE considered corrupt
    /// TODO this is probably NOT the logic we actually want, in which case this test needs updating
    /// In large session, adding a party to corrupt will always make it in dispute with everyone

    #[test]
    fn party_not_responding() {
        let parties = 4;
        static NON_RESPONSE_ROLE: Role = Role(2);
        async fn task(mut session: LargeSession) -> LargeSession {
            if session.parameters.my_role().unwrap() != NON_RESPONSE_ROLE {
                session.add_dispute_and_bcast(&Vec::new()).await.unwrap();
            }
            session
        }

        let results = execute_protocol(parties, 1, &mut task);

        // Check that the party that did not respond does _not_ get marked as a dispute
        for cur_session in results {
            if cur_session.my_role().unwrap() != NON_RESPONSE_ROLE {
                for cur_role_id in 1..=parties as u64 {
                    let cur_dispute_set =
                        cur_session.disputed_roles.get(&Role(cur_role_id)).unwrap();
                    // Check there is the exepected number of disputes
                    if cur_role_id as usize != NON_RESPONSE_ROLE.party_id() {
                        assert_eq!(1, cur_dispute_set.len());
                    } else {
                        assert_eq!(parties - 1, cur_dispute_set.len());
                    }
                }
                // And there is one corruption
                assert_eq!(1, cur_session.corrupt_roles.len());
            }
        }
    }

    /// Tests what happens when the calling party is the one being added to the set of disputes when calling `add_dispute`
    #[test]
    fn test_i_am_dispute() {
        let mut session = get_large_session();
        let my_role = session.my_role().unwrap();
        assert_eq!(0, session.corrupt_roles.len());
        assert_eq!(0, session.my_disputes().unwrap().len());

        let set_of_self = vec![my_role];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let res = session.add_dispute_and_bcast(&set_of_self).await;
            assert!(res.is_ok());
            assert_eq!(0, session.corrupt_roles.len());
            // I cannot be in dispute with myself
            assert_eq!(0, session.my_disputes().unwrap().len());
        });
    }

    /// Tests what happens when there a party gets added to the dispute set using `add_dispute`
    #[test]
    fn test_dispute() {
        let parameters = get_dummy_parameters();
        let id = parameters.own_identity.clone();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        let mut session = LargeSessionStruct {
            parameters,
            network: Arc::new(net_producer.user_net(id)),
            rng: ChaCha20Rng::seed_from_u64(42),
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(43),
        };
        let set_of_other = vec![Role(42)];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let res = session.add_dispute_and_bcast(&set_of_other).await;
            assert!(res.is_ok());
            assert_eq!(0, session.corrupt_roles.len());
            // Check that only one party is in dispute
            assert_eq!(1, session.my_disputes().unwrap().len());
            // Check that party 42 is in dispute
            assert!(session
                .disputed_roles
                .get(&session.parameters.my_role().unwrap())
                .unwrap()
                .contains(&Role(42)));
        });
    }

    /// Tests what happens when more than `threshold` parties gets added to the dispute set using `add_dispute`.
    #[test]
    fn too_many_disputes() {
        let parties = 6;
        static DISPUTE_ROLES: [Role; 2] = [Role(2), Role(3)];
        async fn task(mut session: LargeSession) -> LargeSession {
            session
                .add_dispute_and_bcast(&Vec::from(DISPUTE_ROLES))
                .await
                .unwrap();
            session
        }

        let results = execute_protocol(parties, 1, &mut task);

        assert_eq!(results.len(), parties);
        // check that honest parties agree on the corrupt party
        for cur_session in results {
            for cur_role_id in 1..=parties as u64 {
                let cur_dispute_set = cur_session.disputed_roles.get(&Role(cur_role_id)).unwrap();
                // Check that the view of each honest party is consistant with all parties in dispute with the same party
                if !DISPUTE_ROLES.contains(&Role(cur_role_id)) {
                    // Check there are 2 disputes
                    assert_eq!(2, cur_dispute_set.len());
                    // Check that these are also considered corrupted (since everyone agrees they are in dispute)
                    assert!(cur_session.corrupt_roles.contains(&DISPUTE_ROLES[0]));
                    assert!(cur_session.corrupt_roles.contains(&DISPUTE_ROLES[1]));
                } else {
                    // And that the party in dispute is disagreeing with everyone else (except themself)
                    assert_eq!(parties - 1, cur_dispute_set.len());
                }
            }
        }
    }

    /// Tests what happens when the calling party is on the list of corrupt parties and `add_dispute` is executed.
    /// The expected result is that things go ok and that the calling party will stay on the list of corruptions.
    #[test]
    fn test_i_am_corrupt() {
        let set_of_self = HashSet::from([Role(1)]);
        let mut session = get_large_session();
        session.corrupt_roles = set_of_self.clone();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let res = session
                .add_dispute_and_bcast(&set_of_self.into_iter().collect_vec())
                .await;
            assert!(res.is_ok());
            assert!(session.corrupt_roles.contains(&Role(1)));
        });
    }
}
