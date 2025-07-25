use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::{
    task::JoinSet,
    time::{error::Elapsed, timeout_at},
};
use tracing::Instrument;

use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::runtime::{
        party::{Identity, Role},
        session::{BaseSessionHandles, LargeSessionHandles},
    },
    networking::value::NetworkValue,
};

/// Helper function to check that senders and receivers make sense, returns [false] if they don't and adds a log.
/// Returns true if everything is fine.
/// By not making sense, we mean that the party is either the same as the currently executing party or that the
/// currently executing party is in conflict with the sender/receiver, or the sender/receiver is corrupt
fn check_roles<L: LargeSessionHandles>(
    communicating_with: &Role,
    session: &L,
) -> anyhow::Result<bool> {
    // Ensure we don't send to ourself
    if communicating_with == &session.my_role() {
        tracing::info!("You are trying to communicate with yourself.");
        return Ok(false);
    }
    // Ensure we don't send to corrupt parties
    if session.corrupt_roles().contains(communicating_with) {
        tracing::warn!(
            "You are communicating with a corrupt party: {:?}",
            communicating_with
        );
        return Ok(false);
    }
    // Ensure we don't send to disputed parties
    // Observe that if a party is corrupt it will also be in dispute, hence we have already returned above and only write the log that they are corrupt
    if session
        .disputed_roles()
        .get(&session.my_role())
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

fn check_talking_to_myself<B: BaseSessionHandles>(r: &Role, session: &B) -> anyhow::Result<bool> {
    Ok(r != &session.my_role())
}

/// Send specific values to all parties.
/// Each party is supposed to receive a specific value, mapped to their role in `values_to_send`.
/// Automatically increases the round counter when called
/// Note: This also sends to corrupt parties
pub async fn send_to_parties<Z: Ring, B: BaseSessionHandles>(
    values_to_send: &HashMap<Role, NetworkValue<Z>>,
    session: &B,
) -> anyhow::Result<()> {
    session.network().increase_round_counter()?;
    // pass the always-true fn as check-fn, since we're checking for equal sender and receiver inside internal_send_to_parties
    internal_send_to_parties(values_to_send, session, &|_a: &Role, _b: &B| Ok(true)).await?;
    Ok(())
}

/// Send specific values to specific parties, while validating that the parties are sensible within the session.
/// I.e. not the sending party or in dispute or corrupt.
/// Each party is supposed to receive a specific value, mapped to their role in `values_to_send`.
/// Automatically increases the round counter when called
pub async fn send_to_honest_parties<Z: Ring, L: LargeSessionHandles>(
    values_to_send: &HashMap<Role, NetworkValue<Z>>,
    session: &L,
) -> anyhow::Result<()> {
    session.network().increase_round_counter()?;
    internal_send_to_parties(values_to_send, session, &check_roles).await?;
    Ok(())
}

/// Add a job of sending specific values to specific parties.
/// Each party is supposed to receive a specific value, mapped to their role in `values_to_send`.
async fn internal_send_to_parties<Z: Ring, B: BaseSessionHandles>(
    values_to_send: &HashMap<Role, NetworkValue<Z>>,
    session: &B,
    check_fn: &(dyn Fn(&Role, &B) -> anyhow::Result<bool> + Sync),
) -> anyhow::Result<()> {
    let my_role = session.my_role();
    for (cur_receiver, cur_value) in values_to_send.iter() {
        // do not send to myself
        if cur_receiver != &my_role {
            // Ensure the party we want to send to passes the check we specified
            if check_fn(cur_receiver, session)? {
                let networking = Arc::clone(session.network());
                let receiver_identity = session.identity_from(cur_receiver)?;
                let value_to_send = cur_value.clone();
                networking
                    .send(value_to_send.to_network(), &receiver_identity)
                    .await?;
            } else {
                tracing::warn!(
                    "I am {:?} trying to send to receiver {:?}, who doesn't pass check",
                    my_role,
                    cur_receiver
                );
                continue;
            }
        }
    }
    Ok(())
}

/// Send specific values to specific parties.
/// Each party is supposed to receive a specific value, mapped to their role in `values_to_send`.
pub async fn send_distinct_to_parties<Z: Ring, B: BaseSessionHandles>(
    session: &B,
    sender: &Role,
    values_to_send: HashMap<&Role, NetworkValue<Z>>,
) -> anyhow::Result<()> {
    for (other_role, other_identity) in session.role_assignments().iter() {
        let networking = Arc::clone(session.network());
        let other_id = other_identity.clone();
        let msg = values_to_send[other_role].clone();
        if sender != other_role {
            networking.send(msg.to_network(), &other_id).await?;
        }
    }
    Ok(())
}

/// Receive specific values to specific parties.
/// The list of parties to receive from is given in `senders`.
/// Returns [`NetworkValue::Bot`] in case of failure to receive but without adding parties to the corruption or dispute sets.
pub async fn receive_from_parties<Z: Ring, S: BaseSessionHandles>(
    senders: &Vec<Role>,
    session: &S,
) -> anyhow::Result<HashMap<Role, NetworkValue<Z>>> {
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
pub async fn receive_from_parties_w_dispute<Z: Ring, L: LargeSessionHandles>(
    senders: &Vec<Role>,
    session: &L,
) -> anyhow::Result<HashMap<Role, NetworkValue<Z>>> {
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
fn internal_receive_from_parties<Z: Ring, B: BaseSessionHandles>(
    jobs: &mut JoinSet<(Role, NetworkValue<Z>)>,
    senders: &Vec<Role>,
    session: &B,
    check_fn: &dyn Fn(&Role, &B) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    for cur_sender in senders {
        // Ensure we want to receive from that sender (e.g. not from ourself or a malicious party)
        if check_fn(cur_sender, session)? {
            let networking = Arc::clone(session.network());
            let sender_identity = session.identity_from(cur_sender)?;
            let role_to_receive_from = *cur_sender;
            let deadline = session.network().get_timeout_current_round()?;

            jobs.spawn(async move {
                let received = timeout_at(deadline, networking.receive(&sender_identity))
                    .await
                    .unwrap_or_else(|e| {
                        Err(anyhow_error_and_log(format!(
                            "Timed out with deadline {deadline:?} from {role_to_receive_from:?} : {e:?}"
                        )))
                    });
                match NetworkValue::<Z>::from_network(received) {
                    Ok(val) => (role_to_receive_from, val),
                    // We got an unexpected type of value from the network.
                    _ => (role_to_receive_from, NetworkValue::Bot),
                }
            });
        } else {
            tracing::info!(
                "I am {:?} trying to receive from sender {:?}, who doesn't pass check",
                session.my_role(),
                cur_sender
            );
            continue;
        }
    }
    Ok(())
}

/// Send to all parties and automatically increase round counter
pub async fn send_to_all<T, Z: Ring, B: BaseSessionHandles>(
    session: &B,
    sender: &Role,
    msg: T,
) -> anyhow::Result<()>
where
    T: AsRef<NetworkValue<Z>>,
{
    let serialized_message = msg.as_ref().to_network();

    session.network().increase_round_counter()?;
    for (other_role, other_identity) in session.role_assignments().iter() {
        let networking = Arc::clone(session.network());
        let serialized_message = serialized_message.clone();
        let other_id = other_identity.clone();
        if sender != other_role {
            networking.send(serialized_message, &other_id).await?;
        }
    }
    Ok(())
}

/// Spawns receive tasks and matches the incoming messages according to the match_network_value_fn.
///
/// The function makes sure that it process the correct type of message, i.e.
/// On the receiving end, a party processes a message of a single variant of the [NetworkValue] enum
/// and errors out if message is of a different form. This is helpful so that we can peel the message
/// from the inside enum.
///
/// **NOTE: We do not try to receive any value from the non_answering_parties set.**
pub fn generic_receive_from_all_senders<V, Z: Ring, B: BaseSessionHandles>(
    jobs: &mut JoinSet<Result<(Role, anyhow::Result<V>), Elapsed>>,
    session: &B,
    receiver: &Role,
    sender_list: &[Role],
    non_answering_parties: Option<&HashSet<Role>>,
    match_network_value_fn: fn(network_value: NetworkValue<Z>, id: &Identity) -> anyhow::Result<V>,
) -> anyhow::Result<()>
where
    V: std::marker::Send + 'static,
{
    let binding = HashSet::new();
    let non_answering_parties = non_answering_parties.unwrap_or(&binding);
    for sender in sender_list {
        let sender = *sender;
        if !non_answering_parties.contains(&sender) && receiver != &sender {
            //If role and IDs can't be tied, propagate error
            let sender_id = session
                .role_assignments()
                .get(&sender)
                .ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "Can't find sender's id {sender} in session {}",
                        session.session_id()
                    ))
                })?
                .clone();

            let networking = Arc::clone(session.network());
            let identity = session.own_identity();
            let my_role = session.my_role();
            let timeout = session.network().get_timeout_current_round()?;
            let task = async move {
                let stripped_message = timeout_at(timeout, networking.receive(&sender_id)).await;
                match stripped_message {
                    Ok(stripped_message) => {
                        let stripped_message =
                            match NetworkValue::<Z>::from_network(stripped_message) {
                                Ok(x) => match_network_value_fn(x, &identity),
                                Err(e) => Err(e),
                            };
                        Ok((sender, stripped_message))
                    }
                    Err(e) => {
                        tracing::warn!("Sender {sender} timed out when sending to {my_role}");
                        Err(e)
                    }
                }
            }
            .instrument(tracing::Span::current());
            jobs.spawn(task);
        }
    }
    Ok(())
}

/// Wrapper around [generic_receive_from_all_senders] where the sender list is all the parties.
pub fn generic_receive_from_all<V, Z: Ring, B: BaseSessionHandles>(
    jobs: &mut JoinSet<Result<(Role, anyhow::Result<V>), Elapsed>>,
    session: &B,
    receiver: &Role,
    non_answering_parties: Option<&HashSet<Role>>,
    match_network_value_fn: fn(network_value: NetworkValue<Z>, id: &Identity) -> anyhow::Result<V>,
) -> anyhow::Result<()>
where
    V: std::marker::Send + 'static,
{
    let sender_list: Vec<Role> = session.role_assignments().keys().cloned().collect();
    generic_receive_from_all_senders(
        jobs,
        session,
        receiver,
        &sender_list,
        non_answering_parties,
        match_network_value_fn,
    )
}
