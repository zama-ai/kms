use std::{collections::HashMap, sync::Arc};

use itertools::Itertools;
use tokio::{
    task::JoinSet,
    time::{error::Elapsed, timeout},
};

use crate::{networking::constants::NETWORK_TIMEOUT, value::NetworkValue};

use super::{dispute::Dispute, distributed::DistributedSession, party::Role};

/// Helper function to check that senders and receivers make sense, returns [false] if they don't and adds a log.
/// Returns true if everything is fine.
/// By not making sense, we mean that the party is either the same as the currently executing party or that the
/// currently executing party is in conflict with the sendder/receiver, or the sender/receiver is corrupt
fn check_roles(communicating_with: &Role, dispute: &Dispute) -> anyhow::Result<bool> {
    // Ensure we don't send to ourself
    if communicating_with == &dispute.my_role {
        tracing::info!("You are trying to communicate with yourself.");
        return Ok(false);
    }
    // Ensure we don't send to corrupt parties, but log it
    if dispute.corrupt_roles.contains(communicating_with) {
        tracing::warn!(
            "You are communicating with a corrupt party: {:?}",
            communicating_with
        );
        return Ok(false);
    }
    // Ensure we don't send to disputed parties
    // Observe that if a party is corrupt it will also be in dispute, hence we only write the log that they are corrupt
    if dispute
        .disputed_roles
        .get(&dispute.my_role)?
        .contains(communicating_with)
    {
        tracing::info!(
            "You are communicating with a disputed party: {:?}",
            communicating_with
        );
        return Ok(false);
    }
    Ok(true)
}

/// Send specific values to specific parties.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
pub async fn send_to_parties(
    values_to_send: &HashMap<Role, NetworkValue>,
    dispute: &Dispute,
) -> anyhow::Result<()> {
    let mut send_job = JoinSet::new();
    internal_send_to_parties(&mut send_job, values_to_send, dispute)?;
    while (send_job.join_next().await).is_some() {}
    Ok(())
}

/// Add a job of sending specific values to specific parties.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
fn internal_send_to_parties(
    jobs: &mut JoinSet<Result<(), Elapsed>>,
    values_to_send: &HashMap<Role, NetworkValue>,
    dispute: &Dispute,
) -> anyhow::Result<()> {
    for (cur_receiver, cur_value) in values_to_send.iter() {
        // We check that it makes sense to send to the party
        if check_roles(cur_receiver, dispute)? {
            let networking = Arc::clone(&dispute.session.networking);
            let session_id = dispute.session.session_id;
            let receiver_identity = dispute.session.get_identity_from(cur_receiver)?;
            let value_to_send = cur_value.clone();
            jobs.spawn(timeout(*NETWORK_TIMEOUT, async move {
                let _ = networking
                    .send(value_to_send, &receiver_identity, &session_id)
                    .await;
            }));
        }
    }
    Ok(())
}

/// Send specific values to specific parties.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
pub async fn send_distinct_to_parties(
    session: &DistributedSession,
    sender: &Role,
    values_to_send: HashMap<&Role, NetworkValue>,
) -> anyhow::Result<()> {
    let mut send_jobs = JoinSet::new();
    for (other_role, other_identity) in session.role_assignments.iter() {
        let networking = Arc::clone(&session.networking);
        let session_id = session.session_id;
        let other_id = other_identity.clone();
        let msg = values_to_send[other_role].clone();
        if sender != other_role {
            send_jobs.spawn(async move {
                let _ = networking.send(msg, &other_id, &session_id).await;
            });
        }
    }
    while (send_jobs.join_next().await).is_some() {}
    Ok(())
}

/// Receive specific values to specific parties.
/// The list of parties to receive from is given in `senders`.
/// Returns [`NetworkValue::Bot`] in case of failure to receive but without adding parties to the corruption or dispute sets.
pub async fn receive_from_parties(
    senders: &Vec<Role>,
    dispute: &Dispute,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    let mut receive_job = JoinSet::new();
    internal_receive_from_parties(&mut receive_job, senders, dispute)?;
    let mut res = HashMap::with_capacity(senders.len());
    while let Some(received_data) = receive_job.join_next().await {
        let (sender_role, sender_data) = received_data?;
        // We can assume no value from [sender_role] is already in [res] since we only launched one task for each party
        let _ = res.insert(sender_role.clone(), sender_data);
    }
    Ok(res)
}

/// Add a job of receiving values from specific parties.
/// Each of the senders are contained in [senders].
/// If we don't receive anything, the value [NetworkValue::Bot] is returned
fn internal_receive_from_parties(
    jobs: &mut JoinSet<(Role, NetworkValue)>,
    senders: &Vec<Role>,
    dispute: &Dispute,
) -> anyhow::Result<()> {
    for cur_receiver in senders {
        // Check that we can actually expect a reasonable reply from the party
        if check_roles(cur_receiver, dispute)? {
            let networking = Arc::clone(&dispute.session.networking);
            let session_id = dispute.session.session_id;
            let receiver_identity = dispute.session.get_identity_from(cur_receiver)?;
            let role_to_receive_from = cur_receiver.clone();
            jobs.spawn(async move {
                match timeout(
                    *NETWORK_TIMEOUT,
                    networking.receive(&receiver_identity, &session_id),
                )
                .await
                {
                    Ok(Ok(val)) => (role_to_receive_from, val),
                    // We got an unexpected type of value from the network.
                    _ => (role_to_receive_from, NetworkValue::Bot),
                }
            });
        }
    }
    Ok(())
}
/// Method for parties to exchange values p2p while handling any potential disputes.
/// That is, each party wants to send and receive a value privately between each other party.
/// If an exchange is successful then the value sent to a given role will be included in the result,
/// but if an exchange is not successful then the `default_value` will be used instead.
/// In case of a malicious response the malicious party will get added to the `dispute`.
/// In case of _either_ a missing or malicious response the set and the `default_value` will be returned.
pub async fn exchange_values(
    values_to_send: &HashMap<Role, NetworkValue>,
    default_value: NetworkValue,
    dispute: &mut Dispute,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    send_to_parties(values_to_send, dispute).await?;
    let roles = values_to_send.keys().cloned().collect_vec();
    let received_values = receive_from_parties(&roles, dispute).await?;
    let mut res = HashMap::with_capacity(received_values.len());
    let mut disputed_parties = Vec::new();
    for (sender_role, sender_data) in received_values {
        // If we know the party had been malicious (by sending wrong types of information) then we add them to the dispute set
        match sender_data {
            NetworkValue::Bot => {
                tracing::info!(
                    "Party {:?} did not send any information as expected",
                    sender_role
                );
                disputed_parties.push(sender_role.clone());
                let _ = res.insert(sender_role.clone(), default_value.clone());
            }
            val => {
                // We can assume no value from `sender_role` is already in `res since we only launched one task for each party so we can insert without checking the result
                let _ = res.insert(sender_role.clone(), val);
            }
        }
    }
    // Insert default values for the corrupt and dispute parties
    for sender_role in dispute.disputed_roles.get(&dispute.my_role)? {
        res.insert(sender_role.clone(), default_value.clone());
    }
    // In case a value for myself was part of the values to send, then add it
    let self_value = values_to_send.get(&dispute.my_role);
    if let Some(value) = self_value {
        res.insert(dispute.my_role.clone(), value.clone());
    }
    dispute.add_dispute(&disputed_parties).await?;
    Ok(res)
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
            distributed::{DistributedSession, DistributedTestRuntime, SetupMode},
            p2p::{check_roles, exchange_values},
            party::{Identity, Role},
        },
        networking::local::LocalNetworkingProducer,
        value::{NetworkValue, Value},
    };

    // TODO move to common test files, will be done in issue 131
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
    fn test_check() {
        let set_of_disputes = DisputeSet::new(10);
        let mut dispute = Dispute {
            my_role: Role(1),
            corrupt_roles: HashSet::new(),
            disputed_roles: set_of_disputes,
            session: get_dummy_session(),
        };
        // No disputes
        assert!(check_roles(&Role(2), &dispute).unwrap());
        // Sending to myself
        assert!(!check_roles(&dispute.my_role, &dispute).unwrap());
        dispute
            .disputed_roles
            .add(&dispute.my_role, &Role(2))
            .unwrap();
        // Sending to dispute
        assert!(!check_roles(&Role(2), &dispute).unwrap());
    }

    #[traced_test]
    #[test]
    fn test_check_to_corrupt() {
        let dispute = Dispute {
            my_role: Role(1),
            corrupt_roles: vec![Role(2)].into_iter().collect(),
            disputed_roles: DisputeSet::new(10),
            session: get_dummy_session(),
        };
        // Not sending to myself
        assert!(check_roles(&Role(3), &dispute).unwrap());
        // Sending to corrupt
        assert!(!check_roles(&Role(2), &dispute).unwrap());
    }

    #[traced_test]
    #[test]
    fn optimistic_exchange_values() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];
        let threshold = 1;

        let test_runtime =
            DistributedTestRuntime::new(identities.clone(), threshold, None, SetupMode::NoPrss);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_no, _id) in identities.iter().cloned().enumerate() {
            // Make messages of the sending party's role number
            let msgs = (1..=identities.len())
                .map(|i| {
                    (
                        Role(i as u64),
                        NetworkValue::RingValue(Value::U64((party_no + 1) as u64)),
                    )
                })
                .collect();
            let num_parties = identities.len();
            let own_role = Role::from(party_no as u64 + 1);
            let session = test_runtime.session_for_player(session_id, party_no);

            set.spawn(async move {
                let mut dispute = Dispute {
                    session,
                    my_role: own_role.clone(),
                    corrupt_roles: HashSet::new(),
                    disputed_roles: DisputeSet::new(num_parties),
                };
                (
                    own_role.clone(),
                    exchange_values(&msgs, NetworkValue::RingValue(Value::U64(0)), &mut dispute)
                        .await,
                )
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

        assert_eq!(results.len(), identities.len());
        // Recover the values for each of the parties and validate that they reconstruct to the right message
        for (_cur_role, cur_data) in results {
            for (sender_role, sender_val) in cur_data.unwrap() {
                assert_eq!(
                    sender_val,
                    NetworkValue::RingValue(Value::U64(sender_role.0))
                );
            }
        }
    }

    #[traced_test]
    #[test]
    fn pessimistic_share_multiple_parties() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
        ];
        let threshold = 3;
        let mut dispute_set = DisputeSet::new(identities.len());
        let dispute_party = Role(5);
        // Party 1 is in dispute
        for i in 1..=identities.len() as u64 {
            dispute_set.add(&Role(i), &dispute_party).unwrap();
        }

        let test_runtime =
            DistributedTestRuntime::new(identities.clone(), threshold, None, SetupMode::NoPrss);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let mut set = JoinSet::new();
        for (party_no, _id) in identities.iter().cloned().enumerate() {
            // Make messages of the sending party's role number
            let msgs = (1..=identities.len())
                .map(|i| {
                    (
                        Role(i as u64),
                        NetworkValue::RingValue(Value::U64((party_no + 1) as u64)),
                    )
                })
                .collect();
            let own_role = Role::from(party_no as u64 + 1);
            let session = test_runtime.session_for_player(session_id, party_no);
            let internal_dispute_roles = dispute_set.clone();
            set.spawn(async move {
                let mut dispute = Dispute {
                    session,
                    my_role: own_role.clone(),
                    corrupt_roles: HashSet::new(),
                    disputed_roles: internal_dispute_roles,
                };
                (
                    own_role.clone(),
                    exchange_values(&msgs, NetworkValue::Bot, &mut dispute).await,
                )
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

        // Recover the shares shared by for each of the parties and validate that they reconstruct to the shared msg
        for (cur_role, cur_data) in results {
            if cur_role != dispute_party {
                // If `cur_role` is an honest party then check what we received
                assert!(cur_data.is_ok());
                for (sender_role, sender_val) in cur_data.unwrap() {
                    // Check the shares for all the honest parties with the dispute party (i.e. party 5) is Bot
                    if sender_role == dispute_party {
                        assert_eq!(NetworkValue::Bot, sender_val);
                    } else {
                        assert_eq!(
                            sender_val,
                            NetworkValue::RingValue(Value::U64(sender_role.0))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn party_does_not_reply() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
        ];
        let parties = identities.len();
        let threshold = 3;
        let non_sending_party = Role(1);

        let test_runtime =
            DistributedTestRuntime::new(identities.clone(), threshold, None, SetupMode::NoPrss);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let mut set = JoinSet::new();
        for (party_no, _id) in identities.iter().cloned().enumerate() {
            // Only `non_sending_party` is not executing
            if party_no + 1 != non_sending_party.0 as usize {
                // Make messages of the sending party's role number
                let msgs = (1..=parties)
                    .map(|i| {
                        (
                            Role(i as u64),
                            NetworkValue::RingValue(Value::U64((party_no + 1) as u64)),
                        )
                    })
                    .collect();
                let own_role = Role::from(party_no as u64 + 1);
                let session = test_runtime.session_for_player(session_id, party_no);
                set.spawn(async move {
                    let mut dispute = Dispute {
                        session,
                        my_role: own_role.clone(),
                        corrupt_roles: HashSet::new(),
                        disputed_roles: DisputeSet::new(parties),
                    };
                    let exchanged_values =
                        exchange_values(&msgs, NetworkValue::Bot, &mut dispute).await;
                    (dispute.clone(), exchanged_values)
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

        for (cur_dispute, cur_data) in results {
            if cur_dispute.my_role != non_sending_party {
                // If the current role is an honest party then check what we received
                assert!(cur_data.is_ok());
                // Check that the non-sending party is in the dispute set
                assert_eq!(
                    1,
                    cur_dispute
                        .disputed_roles
                        .get(&cur_dispute.my_role)
                        .unwrap()
                        .len()
                );
                assert!(cur_dispute
                    .disputed_roles
                    .get(&cur_dispute.my_role)
                    .unwrap()
                    .contains(&non_sending_party));
                // And has also been added to the set of corrupt parties (since none of the parties received anything)
                assert_eq!(1, cur_dispute.corrupt_roles.len());
                assert!(cur_dispute.corrupt_roles.contains(&non_sending_party));
                for (sender_role, sender_val) in cur_data.unwrap() {
                    // Check the shares for all the honest parties with the `non_sending_party` (i.e. party 1) is Bot
                    if sender_role == non_sending_party {
                        assert_eq!(NetworkValue::Bot, sender_val);
                    } else {
                        assert_eq!(
                            sender_val,
                            NetworkValue::RingValue(Value::U64(sender_role.0))
                        );
                    }
                }
            }
        }
    }
}
