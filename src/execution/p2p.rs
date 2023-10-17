use std::{collections::HashMap, sync::Arc};

use itertools::Itertools;
use rand::RngCore;
use tokio::{
    task::JoinSet,
    time::{error::Elapsed, timeout},
};

use crate::{networking::constants::NETWORK_TIMEOUT, value::NetworkValue};

use super::{
    party::Role,
    session::{
        BaseSession, BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
        ToBaseSession,
    },
};

/// Send specific values to specific parties, while validating that the parties are sensible within the session.
/// I.e. not the sending party or in dispute or corrupt.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
pub async fn send_to_parties<R: RngCore, B: BaseSessionHandles<R>>(
    values_to_send: &HashMap<Role, NetworkValue>,
    session: &B,
) -> anyhow::Result<()> {
    let mut send_job = JoinSet::new();
    internal_send_to_parties(&mut send_job, values_to_send, session)?;
    while (send_job.join_next().await).is_some() {}
    Ok(())
}

/// Add a job of sending specific values to specific parties.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
fn internal_send_to_parties<R: RngCore, B: BaseSessionHandles<R>>(
    jobs: &mut JoinSet<Result<(), Elapsed>>,
    values_to_send: &HashMap<Role, NetworkValue>,
    session: &B,
) -> anyhow::Result<()> {
    for (cur_receiver, cur_value) in values_to_send.iter() {
        // Ensure we don't send to ourself
        if cur_receiver == &session.my_role()? {
            tracing::info!("You are trying to communicate with yourself.");
            continue;
        }
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let receiver_identity = session.identity_from(cur_receiver)?;
        let value_to_send = cur_value.clone();
        jobs.spawn(timeout(*NETWORK_TIMEOUT, async move {
            let _ = networking
                .send(value_to_send, &receiver_identity, &session_id)
                .await;
        }));
    }
    Ok(())
}

/// Send specific values to specific parties.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
pub async fn send_distinct_to_parties<R: RngCore, B: BaseSessionHandles<R>>(
    session: &B,
    sender: &Role,
    values_to_send: HashMap<&Role, NetworkValue>,
) -> anyhow::Result<()> {
    let mut send_jobs = JoinSet::new();
    for (other_role, other_identity) in session.role_assignments().iter() {
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
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
    session: &BaseSession,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    let mut receive_job = JoinSet::new();
    internal_receive_from_parties(&mut receive_job, senders, session)?;
    let mut res = HashMap::with_capacity(senders.len());
    while let Some(received_data) = receive_job.join_next().await {
        let (sender_role, sender_data) = received_data?;
        // We can assume no value from [sender_role] is already in [res] since we only launched one task for each party
        let _ = res.insert(sender_role, sender_data);
    }
    Ok(res)
}

/// Add a job of receiving values from specific parties.
/// Each of the senders are contained in [senders].
/// If we don't receive anything, the value [NetworkValue::Bot] is returned
fn internal_receive_from_parties(
    jobs: &mut JoinSet<(Role, NetworkValue)>,
    senders: &Vec<Role>,
    session: &BaseSession,
) -> anyhow::Result<()> {
    for cur_receiver in senders {
        // Ensure we don't receive from ourself
        if cur_receiver == &session.my_role()? {
            tracing::info!("You are trying to communicate with yourself.");
            continue;
        }
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let receiver_identity = session.identity_from(cur_receiver)?;
        let role_to_receive_from = *cur_receiver;
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
    session: &mut LargeSession,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    send_to_parties(values_to_send, &session.to_base_session()).await?;
    let roles = values_to_send.keys().cloned().collect_vec();
    let received_values = receive_from_parties(&roles, &session.to_base_session()).await?;
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
                disputed_parties.push(sender_role);
                let _ = res.insert(sender_role, default_value.clone());
            }
            val => {
                // We can assume no value from `sender_role` is already in `res since we only launched one task for each party so we can insert without checking the result
                let _ = res.insert(sender_role, val);
            }
        }
    }
    // Insert default values for the corrupt and dispute parties
    for sender_role in session.my_disputes()? {
        res.insert(*sender_role, default_value.clone());
    }
    // In case a value for myself was part of the values to send, then add it
    let self_value = values_to_send.get(&session.my_role()?);
    if let Some(value) = self_value {
        res.insert(session.my_role()?, value.clone());
    }
    session.add_dispute(&disputed_parties).await?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::{
        execution::session::{LargeSession, ParameterHandles},
        tests::helper::tests::execute_protocol,
    };
    use crate::{
        execution::{p2p::exchange_values, party::Role},
        value::{NetworkValue, Value},
    };
    use std::collections::HashMap;

    #[test]
    fn optimistic_exchange_values() {
        let parties = 4;
        async fn task(mut session: LargeSession) -> anyhow::Result<HashMap<Role, NetworkValue>> {
            // Make messages of the sending party's role number
            let msgs = (1..=session.amount_of_parties())
                .map(|i| {
                    (
                        Role(i as u64),
                        NetworkValue::RingValue(Value::U64(session.my_role().unwrap().0)),
                    )
                })
                .collect();
            exchange_values(&msgs, NetworkValue::Bot, &mut session).await
        }
        let results = execute_protocol(parties, 1, &mut task);

        assert_eq!(results.len(), parties);
        // Recover the values for each of the parties and validate that they reconstruct to the right message
        for cur_data in results {
            for (sender_role, sender_val) in cur_data.unwrap() {
                assert_eq!(
                    sender_val,
                    NetworkValue::RingValue(Value::U64(sender_role.0))
                );
            }
        }
    }

    #[test]
    fn pessimistic_share_multiple_parties() {
        let parties = 5;
        static DISPUTE_PARTY: Role = Role(5);
        async fn task(
            mut session: LargeSession,
        ) -> (Role, anyhow::Result<HashMap<Role, NetworkValue>>) {
            for i in 1..=session.amount_of_parties() as u64 {
                session
                    .disputed_roles
                    .add(&Role(i), &DISPUTE_PARTY)
                    .unwrap();
            }
            // Make messages of the sending party's role number
            let msgs = (1..=session.amount_of_parties())
                .map(|i| {
                    (
                        Role(i as u64),
                        NetworkValue::RingValue(Value::U64(session.my_role().unwrap().0)),
                    )
                })
                .collect();
            let exchanged_values = exchange_values(&msgs, NetworkValue::Bot, &mut session).await;
            (session.my_role().unwrap(), exchanged_values)
        }

        let results = execute_protocol(parties, 1, &mut task);

        // Recover the shares shared by for each of the parties and validate that they reconstruct to the shared msg
        for (cur_role, cur_data) in results {
            if cur_role != DISPUTE_PARTY {
                // If `cur_role` is an honest party then check what we received
                assert!(cur_data.is_ok());
                for (sender_role, sender_val) in cur_data.unwrap() {
                    // Check the shares for all the honest parties with the dispute party (i.e. party 5) is Bot
                    if sender_role == DISPUTE_PARTY {
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
        let parties = 5;
        static NON_SENDING_PARTY: Role = Role(1);
        async fn task(
            mut session: LargeSession,
        ) -> (LargeSession, anyhow::Result<HashMap<Role, NetworkValue>>) {
            // Only `non_sending_party` is not executing
            if session.my_role().unwrap() != NON_SENDING_PARTY {
                // Make messages of the sending party's role number
                let msgs = (1..=session.amount_of_parties())
                    .map(|i| {
                        (
                            Role(i as u64),
                            NetworkValue::RingValue(Value::U64(session.my_role().unwrap().0)),
                        )
                    })
                    .collect();

                let exchanged_values =
                    exchange_values(&msgs, NetworkValue::Bot, &mut session).await;
                (session, exchanged_values)
            } else {
                (session, Ok(HashMap::new()))
            }
        }

        let results = execute_protocol(parties, 1, &mut task);

        for (cur_session, cur_data) in results {
            if cur_session.my_role().unwrap() != NON_SENDING_PARTY {
                // If the current role is an honest party then check what we received
                assert!(cur_data.is_ok());
                // Check that the non-sending party is in the dispute set
                assert_eq!(
                    1,
                    cur_session
                        .disputed_roles
                        .get(&cur_session.my_role().unwrap())
                        .unwrap()
                        .len()
                );
                assert!(cur_session
                    .disputed_roles
                    .get(&cur_session.my_role().unwrap())
                    .unwrap()
                    .contains(&NON_SENDING_PARTY));
                // And has also been added to the set of corrupt parties (since none of the parties received anything)
                assert_eq!(1, cur_session.corrupt_roles.len());
                assert!(cur_session.corrupt_roles.contains(&NON_SENDING_PARTY));
                for (sender_role, sender_val) in cur_data.unwrap() {
                    // Check the shares for all the honest parties with the `non_sending_party` (i.e. party 1) is Bot
                    if sender_role == NON_SENDING_PARTY {
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
