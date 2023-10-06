use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

use crate::value::BroadcastValue;

use super::{broadcast::broadcast_with_corruption, distributed::DistributedSession, party::Role};

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

#[derive(Clone)]
pub struct Dispute {
    pub session: DistributedSession,
    pub my_role: Role,
    pub corrupt_roles: HashSet<Role>,
    pub disputed_roles: DisputeSet,
}

impl Dispute {
    /// Make a new [Dispute] object without any corruptions or disputes
    pub fn new(session: &DistributedSession) -> anyhow::Result<Self> {
        Ok(Dispute {
            session: session.clone(),
            my_role: session.get_role_from(&session.own_identity)?,
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(session.get_amount_of_parties()),
        })
    }

    pub async fn add_dispute(&mut self, disputed_parties: &Vec<Role>) -> anyhow::Result<()> {
        if self.corrupt_roles.contains(&self.my_role) {
            return Ok(());
        }
        let mut payload = DisputePayload {
            msg: DisputeMsg::OK,
            disputes: vec![],
        };
        if !disputed_parties.is_empty() {
            payload = DisputePayload {
                msg: DisputeMsg::CORRUPTION,
                disputes: disputed_parties.clone(),
            };
            for cur_role in disputed_parties {
                self.disputed_roles.add(&self.my_role, cur_role)?;
            }
        }
        let bcast_data = broadcast_with_corruption(
            &self.session,
            &mut self.corrupt_roles,
            BroadcastValue::AddDispute(payload),
        )
        .await?;
        for (cur_role, cur_payload) in bcast_data.into_iter() {
            if cur_role != self.my_role {
                let payload = match cur_payload {
                    BroadcastValue::AddDispute(payload) => payload,
                    _ => return Err(anyhow!("Unexpected data received from broadcast")),
                };
                if payload.msg != DisputeMsg::OK {
                    for dispute_role in payload.disputes {
                        self.disputed_roles.add(&cur_role, &dispute_role)?;
                        // Check whether each party in the dispute set has more than [threshold] disputes and if so add them to the corrupt set
                        if self.disputed_roles.get(&dispute_role)?.len()
                            > self.session.threshold as usize
                        {
                            let _ = self.corrupt_roles.insert(dispute_role);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
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
            .ok_or_else(|| anyhow!("Role does not exist"))?;
        let _ = a_disputes.insert(role_b.clone());
        // Insert the second pair of disputes
        let b_disputes: &mut BTreeSet<Role> = disputed_roles
            .get_mut((role_b.0 - 1) as usize)
            .ok_or_else(|| anyhow!("Role does not exist"))?;
        let _ = b_disputes.insert(role_a.clone());
        Ok(())
    }

    pub fn get(&self, role: &Role) -> anyhow::Result<&BTreeSet<Role>> {
        if let Some(cur) = self.disputed_roles.get((role.0 - 1) as usize) {
            Ok(cur)
        } else {
            Err(anyhow!("Role does not exist"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    use crate::{
        computation::SessionId,
        execution::{
            dispute::{Dispute, DisputeSet},
            distributed::{DistributedSession, DistributedTestRuntime},
            party::{Identity, Role},
        },
        networking::local::LocalNetworkingProducer,
    };

    /// Return a session to be used with a single party, with role 1
    fn get_dummy_session() -> DistributedSession {
        let mut role_assignment = HashMap::new();
        let id = Identity("localhost:5000".to_string());
        role_assignment.insert(Role(1), id.clone());
        let net_producer = LocalNetworkingProducer::from_ids(&[id.clone()]);
        DistributedSession::new(
            SessionId(1),
            role_assignment,
            Arc::new(net_producer.user_net(id.clone())),
            1,
            None,
            id.clone(),
        )
    }

    #[traced_test]
    #[test]
    fn sunshine() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];
        let parties = identities.len();

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let dispute_role = Role(2);

        let mut set = JoinSet::new();
        for party_id in 0..parties {
            let session = runtime.session_for_player(session_id, party_id);
            let dispute_set = vec![dispute_role.clone()];
            set.spawn(async move {
                let mut dispute = Dispute::new(&session).unwrap();
                dispute.add_dispute(&dispute_set).await.unwrap();
                dispute
            });
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        assert_eq!(results.len(), parties);
        // check they agree on the disputed party
        for cur in results {
            for cur_role_id in 1..=parties as u64 {
                let cur_dispute_set = cur.disputed_roles.get(&Role(cur_role_id)).unwrap();
                // Check that the view of each honest party is consistant with all parties in dispute with the same party
                if cur_role_id != dispute_role.0 {
                    // Check there is only one dispute
                    assert_eq!(1, cur_dispute_set.len());
                    // Check the identity of the dispute
                    assert!(cur_dispute_set.contains(&dispute_role));
                } else {
                    // And that the party in dispute is disagreeing with everyone else (except themself)
                    assert_eq!(parties - 1, cur_dispute_set.len());
                }
            }
        }
    }

    /// Tests what happens when a party drops out of broadcast
    /// NOTE non-responding parties which act as senders in a broadcast ARE considered corrupt
    /// TODO this is probably NOT the logic we actually want, in which case this test needs updating
    #[traced_test]
    #[test]
    fn party_not_responding() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];
        let parties = identities.len();

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let non_response_role = Role(2);

        let mut set = JoinSet::new();
        for party_id in 0..parties {
            // Don't spawn a thread for the non-responsive party
            if party_id + 1 != non_response_role.0 as usize {
                let session = runtime.session_for_player(session_id, party_id);

                set.spawn(async move {
                    let mut dispute = Dispute::new(&session).unwrap();
                    dispute.add_dispute(&Vec::new()).await.unwrap();
                    dispute
                });
            }
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        // Check that the party that did not respond does _not_ get marked as a dispute
        for cur in results {
            for cur_role_id in 1..=parties as u64 {
                let cur_dispute_set = cur.disputed_roles.get(&Role(cur_role_id)).unwrap();
                // Check there is no disputes
                assert_eq!(0, cur_dispute_set.len());
            }
            // And there is one corruption
            assert_eq!(1, cur.corrupt_roles.len());
        }
    }

    #[traced_test]
    #[test]
    fn test_i_am_dispute() {
        let my_role = Role(1);
        let mut dispute = Dispute::new(&get_dummy_session()).unwrap();
        assert_eq!(0, dispute.corrupt_roles.len());
        assert_eq!(0, dispute.disputed_roles.get(&my_role).unwrap().len());

        let set_of_self = vec![my_role.clone()];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let res = dispute.add_dispute(&set_of_self).await;
            assert!(res.is_ok());
            assert_eq!(0, dispute.corrupt_roles.len());
            // I cannot be in dispute with myself
            assert_eq!(0, dispute.disputed_roles.get(&my_role).unwrap().len());
        });
    }

    #[traced_test]
    #[test]
    fn test_other_dispute() {
        let mut dispute = Dispute {
            session: get_dummy_session(),
            my_role: Role(1),
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(43),
        };
        let set_of_other = vec![Role(42)];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let res = dispute.add_dispute(&set_of_other).await;
            assert!(res.is_ok());
            assert_eq!(0, dispute.corrupt_roles.len());
            // Check that only one party is in dispute
            assert_eq!(
                1,
                dispute.disputed_roles.get(&dispute.my_role).unwrap().len()
            );
            // Check that party 42 is in dispute
            assert!(dispute
                .disputed_roles
                .get(&dispute.my_role)
                .unwrap()
                .contains(&Role(42)));
        });
    }

    #[traced_test]
    #[test]
    fn too_many_disputes() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
            Identity("localhost:5005".to_string()),
        ];
        let parties = identities.len();

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let dispute_roles = vec![Role(2), Role(3)];

        let mut set = JoinSet::new();
        for party_id in 0..parties {
            let session = runtime.session_for_player(session_id, party_id);
            let cur_dispute_roles = dispute_roles.clone();
            set.spawn(async move {
                let mut dispute = Dispute::new(&session).unwrap();
                dispute.add_dispute(&cur_dispute_roles).await.unwrap();
                dispute
            });
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        assert_eq!(results.len(), parties);
        // check that honest parties agree on the corrupt party
        for cur in results {
            for cur_role_id in 1..=parties as u64 {
                let cur_dispute_set = cur.disputed_roles.get(&Role(cur_role_id)).unwrap();
                // Check that the view of each honest party is consistant with all parties in dispute with the same party
                if !dispute_roles.contains(&Role(cur_role_id)) {
                    // Check there are 2 disputes
                    assert_eq!(2, cur_dispute_set.len());
                    // Check that these are also considered corrupted (since everyone agrees they are in dispute)
                    assert!(cur.corrupt_roles.contains(&dispute_roles[0]));
                    assert!(cur.corrupt_roles.contains(&dispute_roles[1]));
                } else {
                    // And that the party in dispute is disagreeing with everyone else (except themself)
                    assert_eq!(parties - 1, cur_dispute_set.len());
                }
            }
        }
    }

    #[traced_test]
    #[test]
    fn test_i_am_corrupt() {
        let set_of_self = HashSet::from([Role(1)]);
        let mut dispute = Dispute {
            my_role: Role(1),
            corrupt_roles: set_of_self.clone(),
            disputed_roles: DisputeSet::new(1),
            session: get_dummy_session(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let res = dispute
                .add_dispute(&set_of_self.into_iter().collect())
                .await;
            assert!(res.is_ok());
            assert!(dispute.corrupt_roles.contains(&Role(1)));
        });
    }
}
