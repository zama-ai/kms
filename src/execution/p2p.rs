#![allow(deprecated)] //NOTE: TO BE REMOVED AT SOME POINT
use std::{collections::HashMap, sync::Arc};

use itertools::Itertools;
use rand::RngCore;
use tokio::{task::JoinSet, time::timeout_at};

use crate::value::NetworkValue;

use super::{
    party::Role,
    session::{
        BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles, ToBaseSession,
    },
};

/// Helper function to check that senders and receivers make sense, returns [false] if they don't and adds a log.
/// Returns true if everything is fine.
/// By not making sense, we mean that the party is either the same as the currently executing party or that the
/// currently executing party is in conflict with the sendder/receiver, or the sender/receiver is corrupt
fn check_roles<R: RngCore, L: LargeSessionHandles<R>>(
    communicating_with: &Role,
    session: &L,
) -> anyhow::Result<bool> {
    // Ensure we don't send to ourself
    if communicating_with == &session.my_role()? {
        tracing::info!("You are trying to communicate with yourself.");
        return Ok(false);
    }
    // Ensure we don't send to corrupt parties, but log it
    if session.corrupt_roles().contains(communicating_with) {
        tracing::warn!(
            "You are communicating with a corrupt party: {:?}",
            communicating_with
        );
        return Ok(false);
    }
    // Ensure we don't send to disputed parties
    // Observe that if a party is corrupt it will also be in dispute, hence we only write the log that they are corrupt
    if session
        .disputed_roles()
        .get(&session.my_role()?)?
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

fn check_talking_to_myself<R: RngCore, B: BaseSessionHandles<R>>(
    r: &Role,
    session: &B,
) -> anyhow::Result<bool> {
    Ok(r != &session.my_role()?)
}
/// Send specific values to specific parties.
/// I.e. not the sending party or in dispute or corrupt.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
pub async fn send_to_honest_parties<R: RngCore, B: BaseSessionHandles<R>>(
    values_to_send: &HashMap<Role, NetworkValue>,
    session: &B,
) -> anyhow::Result<()> {
    let mut send_job = JoinSet::new();
    internal_send_to_parties(
        &mut send_job,
        values_to_send,
        session,
        &check_talking_to_myself,
    )?;
    while (send_job.join_next().await).is_some() {}
    Ok(())
}

/// Send specific values to specific parties, while validating that the parties are sensible within the session.
/// I.e. not the sending party or in dispute or corrupt.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
pub async fn send_to_parties_w_dispute<R: RngCore, L: LargeSessionHandles<R>>(
    values_to_send: &HashMap<Role, NetworkValue>,
    session: &L,
) -> anyhow::Result<()> {
    let mut send_job = JoinSet::new();
    internal_send_to_parties(&mut send_job, values_to_send, session, &check_roles)?;
    while (send_job.join_next().await).is_some() {}
    Ok(())
}

/// Add a job of sending specific values to specific parties.
/// Each party is supposed to receive a specfic value, mapped to their role in `values_to_send`.
fn internal_send_to_parties<R: RngCore, B: BaseSessionHandles<R>>(
    jobs: &mut JoinSet<()>,
    values_to_send: &HashMap<Role, NetworkValue>,
    session: &B,
    check_fn: &dyn Fn(&Role, &B) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    for (cur_receiver, cur_value) in values_to_send.iter() {
        // Ensure we don't send to ourself
        if check_fn(cur_receiver, session)? {
            let networking = Arc::clone(session.network());
            let session_id = session.session_id();
            let receiver_identity = session.identity_from(cur_receiver)?;
            let value_to_send = cur_value.clone();
            jobs.spawn(async move {
                let _ = networking
                    .send(value_to_send, &receiver_identity, &session_id)
                    .await;
            });
        } else {
            tracing::info!("You are trying to communicate with a party that doesnt pass check");
            continue;
        }
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
pub async fn receive_from_parties<R: RngCore, S: BaseSessionHandles<R>>(
    senders: &Vec<Role>,
    session: &S,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    let mut receive_job = JoinSet::new();
    internal_receive_from_parties(&mut receive_job, senders, session, &check_talking_to_myself)?;
    let mut res = HashMap::with_capacity(senders.len());
    while let Some(received_data) = receive_job.join_next().await {
        let (sender_role, sender_data) = received_data?;
        // We can assume no value from [sender_role] is already in [res] since we only launched one task for each party
        let _ = res.insert(sender_role, sender_data);
    }
    Ok(res)
}
/// Receive specific values to specific parties.
/// The list of parties to receive from is given in `senders`.
/// Returns [`NetworkValue::Bot`] in case of failure to receive but without adding parties to the corruption or dispute sets.
/// Do not expect anything from disputed or corrupted parties
pub async fn receive_from_parties_w_dispute<R: RngCore, L: LargeSessionHandles<R>>(
    senders: &Vec<Role>,
    session: &L,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    let mut receive_job = JoinSet::new();
    internal_receive_from_parties(&mut receive_job, senders, session, &check_roles)?;
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
fn internal_receive_from_parties<R: RngCore, B: BaseSessionHandles<R>>(
    jobs: &mut JoinSet<(Role, NetworkValue)>,
    senders: &Vec<Role>,
    session: &B,
    check_fn: &dyn Fn(&Role, &B) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    for cur_receiver in senders {
        // Ensure we don't receive from ourself
        if check_fn(cur_receiver, session)? {
            let networking = Arc::clone(session.network());
            let session_id = session.session_id();
            let receiver_identity = session.identity_from(cur_receiver)?;
            let role_to_receive_from = *cur_receiver;
            let deadline = session.network().get_timeout_current_round()?;
            jobs.spawn(async move {
                match timeout_at(
                    deadline,
                    networking.receive(&receiver_identity, &session_id),
                )
                .await
                {
                    Ok(Ok(val)) => (role_to_receive_from, val),
                    // We got an unexpected type of value from the network.
                    _ => (role_to_receive_from, NetworkValue::Bot),
                }
            });
        } else {
            tracing::info!(
                "You are trying to communicate with a party that doesnt pass the check."
            );
            continue;
        }
    }
    Ok(())
}
//NOTE: Is this function used anywhere ? (except in the share_w_dispute version which we do not use?)
/// Method for parties to exchange values p2p while handling any potential disputes.
/// That is, each party wants to send and receive a value privately between each other party.
/// If an exchange is successful then the value sent to a given role will be included in the result,
/// but if an exchange is not successful then the `default_value` will be used instead.
/// In case of a malicious response the malicious party will get added to the `dispute`.
/// In case of _either_ a missing or malicious response the set and the `default_value` will be returned.
#[deprecated(note = "Only used by deprecated function [share_dispute::share_w_dispute]")]
pub async fn exchange_values(
    values_to_send: &HashMap<Role, NetworkValue>,
    default_value: NetworkValue,
    session: &mut LargeSession,
) -> anyhow::Result<HashMap<Role, NetworkValue>> {
    session.network().increase_round_counter().await?;
    send_to_honest_parties(values_to_send, &session.to_base_session()).await?;
    let roles = values_to_send.keys().cloned().collect_vec();
    let received_values = receive_from_parties(&roles, session).await?;
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
    session.add_dispute_and_bcast(&disputed_parties).await?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::execution::session::{LargeSession, ParameterHandles};
    use crate::{
        execution::{p2p::exchange_values, party::Role},
        tests::helper::tests_and_benches::execute_protocol_large,
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
                        Role::indexed_by_one(i),
                        NetworkValue::RingValue(Value::U64(
                            session.my_role().unwrap().one_based() as u64
                        )),
                    )
                })
                .collect();
            exchange_values(&msgs, NetworkValue::Bot, &mut session).await
        }
        let results = execute_protocol_large(parties, 1, &mut task);

        assert_eq!(results.len(), parties);
        // Recover the values for each of the parties and validate that they reconstruct to the right message
        for cur_data in results {
            for (sender_role, sender_val) in cur_data.unwrap() {
                assert_eq!(
                    sender_val,
                    NetworkValue::RingValue(Value::U64(sender_role.one_based() as u64))
                );
            }
        }
    }

    #[test]
    fn pessimistic_share_multiple_parties() {
        let parties = 5;
        let dispute_party: Role = Role::indexed_by_one(5);
        let mut task = |mut session: LargeSession| async move {
            for i in 1..=session.amount_of_parties() {
                session
                    .disputed_roles
                    .add(&Role::indexed_by_one(i), &dispute_party)
                    .unwrap();
            }
            // Make messages of the sending party's role number
            let msgs = (1..=session.amount_of_parties())
                .map(|i| {
                    (
                        Role::indexed_by_one(i),
                        NetworkValue::RingValue(Value::U64(
                            session.my_role().unwrap().one_based() as u64
                        )),
                    )
                })
                .collect();
            let exchanged_values = exchange_values(&msgs, NetworkValue::Bot, &mut session).await;
            (session.my_role().unwrap(), exchanged_values)
        };

        let results = execute_protocol_large(parties, 1, &mut task);

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
                            NetworkValue::RingValue(Value::U64(sender_role.one_based() as u64))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn party_does_not_reply() {
        let parties = 5;
        let non_sending_party: Role = Role::indexed_by_one(1);
        let mut task = |mut session: LargeSession| async move {
            // Only `non_sending_party` is not executing
            if session.my_role().unwrap() != non_sending_party {
                // Make messages of the sending party's role number
                let msgs = (1..=session.amount_of_parties())
                    .map(|i| {
                        (
                            Role::indexed_by_one(i),
                            NetworkValue::RingValue(Value::U64(
                                session.my_role().unwrap().one_based() as u64,
                            )),
                        )
                    })
                    .collect();

                let exchanged_values =
                    exchange_values(&msgs, NetworkValue::Bot, &mut session).await;
                (session, exchanged_values)
            } else {
                (session, Ok(HashMap::new()))
            }
        };

        let results = execute_protocol_large(parties, 1, &mut task);

        for (cur_session, cur_data) in results {
            if cur_session.my_role().unwrap() != non_sending_party {
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
                    .contains(&non_sending_party));
                // And has also been added to the set of corrupt parties (since none of the parties received anything)
                assert_eq!(1, cur_session.corrupt_roles.len());
                assert!(cur_session.corrupt_roles.contains(&non_sending_party));
                for (sender_role, sender_val) in cur_data.unwrap() {
                    // Check the shares for all the honest parties with the `non_sending_party` (i.e. party 1) is Bot
                    if sender_role == non_sending_party {
                        assert_eq!(NetworkValue::Bot, sender_val);
                    } else {
                        assert_eq!(
                            sender_val,
                            NetworkValue::RingValue(Value::U64(sender_role.one_based() as u64))
                        );
                    }
                }
            }
        }
    }
}
