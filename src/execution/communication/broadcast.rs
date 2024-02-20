use crate::algebra::structure_traits::Ring;
use crate::algebra::structure_traits::Zero;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::Identity;
use crate::execution::runtime::party::Role;
use crate::execution::runtime::session::BaseSessionHandles;
use crate::networking::value::BroadcastValue;
use crate::networking::value::NetworkValue;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;
use tokio::time::timeout_at;

type RoleValueMap<Z> = HashMap<Role, BroadcastValue<Z>>;

/// Send to all parties and automatically increase round counter
pub async fn send_to_all<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: &B,
    sender: &Role,
    msg: NetworkValue<Z>,
) -> anyhow::Result<()> {
    session.network().increase_round_counter().await?;
    let mut jobs = JoinSet::new();
    for (other_role, other_identity) in session.role_assignments().iter() {
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let msg = msg.clone();
        let other_id = other_identity.clone();
        if sender != other_role {
            jobs.spawn(async move {
                let _ = networking
                    .send(msg.to_network(), &other_id, &session_id)
                    .await;
            });
        }
    }
    while (jobs.join_next().await).is_some() {}
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
pub fn generic_receive_from_all_senders<V, Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
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
            let session_id = session.session_id();
            let identity = session.own_identity();
            let task = async move {
                let stripped_message = networking.receive(&sender_id, &session_id).await;
                let stripped_message = NetworkValue::<Z>::from_network(stripped_message)
                    .map_or_else(|e| Err(e), |x| match_network_value_fn(x, &identity));
                (sender, stripped_message)
            };
            jobs.spawn(timeout_at(
                session.network().get_timeout_current_round()?,
                task,
            ));
        }
    }
    Ok(())
}

/// Wrapper around [generic_receive_from_all_senders] where the sender list is all the parties.
pub fn generic_receive_from_all<V, Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
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

async fn receive_from_all_senders<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    round1_data: &mut RoleValueMap<Z>,
    session: &B,
    receiver: &Role,
    sender_list: &[Role],
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<()> {
    let mut jobs = JoinSet::<Result<(Role, anyhow::Result<BroadcastValue<Z>>), Elapsed>>::new();
    // The error we propagate here is if sender IDs and roles cannot be tied together.
    generic_receive_from_all_senders(
        &mut jobs,
        session,
        receiver,
        sender_list,
        Some(non_answering_parties),
        |msg, id| match msg {
            NetworkValue::Send(v) => Ok(v),
            NetworkValue::EchoBatch(_) => Err(anyhow_error_and_log(format!(
                "I have received an Echo batch instead of a Send message on party: {:?}",
                id
            ))),
            _ => Err(anyhow_error_and_log(format!(
                "I am {:?} have received sth different from Send message \n Received {:?}",
                id, msg
            ))),
        },
    )?;

    // Place the received (Send) messages in the hashmap
    let mut answering_parties = HashSet::<Role>::new();
    while let Some(v) = jobs.join_next().await {
        //Propagate only JoinErrors
        let joined_result = v?;
        match joined_result {
            Err(_e) => {}
            Ok((party_id, data)) => {
                answering_parties.insert(party_id);
                if let Err(e) = data {
                    tracing::warn!(
                        "(Bcast Round 1) I am {receiver}, received wrong type from {party_id} {:?}",
                        e
                    );
                } else {
                    round1_data.insert(party_id, data?);
                }
            }
        }
    }
    for party_id in sender_list {
        if !answering_parties.contains(party_id) && party_id != receiver {
            non_answering_parties.insert(*party_id);
            tracing::warn!("(Bcast Round1) I am {receiver}, haven't heard from {party_id}");
        }
    }
    Ok(())
}

type JobType<Z> = (Role, anyhow::Result<RoleValueMap<Z>>);
async fn receive_from_all_echo_batch<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: &B,
    receiver: &Role,
    non_answering_parties: &mut HashSet<Role>,
    echoed_data: &mut HashMap<(Role, BroadcastValue<Z>), u32>,
) -> anyhow::Result<HashMap<(Role, BroadcastValue<Z>), u32>> {
    let mut jobs = JoinSet::<Result<JobType<Z>, Elapsed>>::new();
    generic_receive_from_all(
        &mut jobs,
        session,
        receiver,
        Some(non_answering_parties),
        |msg, id| match msg {
            NetworkValue::EchoBatch(v) => Ok(v),
            NetworkValue::Empty => Ok(RoleValueMap::new()),
            _ => Err(anyhow_error_and_log(format!(
                "I have received sth different from an Echo Batch message on party: {:?}",
                id,
            ))),
        },
    )?;

    let registered_votes = process_echos(
        receiver,
        &mut jobs,
        echoed_data,
        session.num_parties(),
        session.threshold() as usize,
        non_answering_parties,
    )
    .await?;
    Ok(registered_votes)
}

fn receive_from_all_votes<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    jobs: &mut JoinSet<Result<JobType<Z>, Elapsed>>,
    session: &B,
    receiver: &Role,
    non_answering_parties: &HashSet<Role>,
) -> anyhow::Result<()> {
    generic_receive_from_all(
        jobs,
        session,
        receiver,
        Some(non_answering_parties),
        |msg, id| match msg {
            NetworkValue::VoteBatch(v) => Ok(v),
            NetworkValue::Empty => Ok(RoleValueMap::new()),
            _ => Err(anyhow_error_and_log(format!(
                "I have received sth different from an Vote Batch message on party: {:?}",
                id
            ))),
        },
    )
}

async fn internal_process_echos_or_votes<Z: Ring>(
    receiver: &Role,
    rcv_tasks: &mut JoinSet<Result<JobType<Z>, Elapsed>>,
    map_data: &mut HashMap<(Role, BroadcastValue<Z>), u32>,
    num_parties: usize,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<()> {
    // Receiving Echo messages one by one
    let mut answering_parties = HashSet::<Role>::new();
    while let Some(v) = rcv_tasks.join_next().await {
        let task_out = v?;
        // if no timeout error then we count it towards casting a vote
        if let Ok((from_party, data)) = task_out {
            answering_parties.insert(from_party);
            if let Ok(rcv_echo) = data {
                debug_assert!(rcv_echo.len() <= num_parties);
                // iterate through the echo batched message and check the frequency of each message
                rcv_echo.iter().for_each(|(role, m)| {
                    let entry = map_data.entry((*role, m.clone())).or_insert(0);
                    *entry += 1;
                });
            } else {
                tracing::warn!(
                    "(Process echos) I am {receiver}, received wrong type from {}: {:?}",
                    from_party.clone(),
                    data
                );
            }
        }
    }
    //Log timeouts
    for party_id in 1..=num_parties {
        if !answering_parties.contains(&Role::indexed_by_one(party_id))
            && party_id != receiver.one_based()
        {
            non_answering_parties.insert(Role::indexed_by_one(party_id));
            tracing::warn!("(Process echos) I am {receiver} haven't heard from {party_id}");
        }
    }
    Ok(())
}

/// Process Echo messages one by one, starting with the own echoed_data
/// If enough echoes >=(N-T) then party can cast a vote
async fn process_echos<Z: Ring>(
    receiver: &Role,
    echo_recv_tasks: &mut JoinSet<Result<JobType<Z>, Elapsed>>,
    echoed_data: &mut HashMap<(Role, BroadcastValue<Z>), u32>,
    num_parties: usize,
    threshold: usize,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<HashMap<(Role, BroadcastValue<Z>), u32>> {
    let mut registered_votes = HashMap::new();

    internal_process_echos_or_votes(
        receiver,
        echo_recv_tasks,
        echoed_data,
        num_parties,
        non_answering_parties,
    )
    .await?;

    //Any entry with at least N-t times is good for a vote
    for ((role, m), num_entries) in echoed_data.iter() {
        if num_entries >= &((num_parties - threshold) as u32) {
            registered_votes.insert((*role, m.clone()), 1);
        }
    }
    Ok(registered_votes)
}

/// Sender casts a vote only for messages m in registered_votes for which #m >= threshold
async fn cast_threshold_vote<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: &B,
    sender: &Role,
    registered_votes: &HashMap<(Role, BroadcastValue<Z>), u32>,
    threshold: u32,
) -> anyhow::Result<()> {
    let vote_data: RoleValueMap<Z> = registered_votes
        .iter()
        .filter_map(|(k, f)| {
            if *f >= threshold {
                Some((k.0, k.1.clone()))
            } else {
                None
            }
        })
        .collect();
    //Send empty msg to avoid waiting on timeouts on rcver side
    if vote_data.is_empty() {
        tracing::debug!("I am {sender}, sending an empty message");
        send_to_all(session, sender, NetworkValue::<Z>::Empty).await?;
    } else {
        send_to_all(session, sender, NetworkValue::VoteBatch(vote_data)).await?;
    }
    Ok(())
}

/// Sender gathers votes from all the other parties.
/// If enough votes >=(T+R) and sender hasn't voted then vote
/// If enough votes >=(N-T) then stop the computation
async fn gather_votes<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: &B,
    sender: &Role,
    registered_votes: &mut HashMap<(Role, BroadcastValue<Z>), u32>,
    casted: &mut HashMap<Role, bool>,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<()> {
    let num_parties = session.num_parties();
    let threshold = session.threshold() as usize;

    // wait for other parties' incoming vote
    for round in 1..=threshold + 1 {
        let mut vote_recv_tasks = JoinSet::new();

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_from_all_votes(&mut vote_recv_tasks, session, sender, non_answering_parties)?;
        internal_process_echos_or_votes(
            sender,
            &mut vote_recv_tasks,
            registered_votes,
            num_parties,
            non_answering_parties,
        )
        .await?;

        //We don't need to try to vote if it's the last round
        if round == threshold + 1 {
            return Ok(());
        }

        //Here propagate error if my own casted hashmap does not contain the expected party's id
        let mut round_registered_votes = HashMap::<(Role, BroadcastValue<Z>), u32>::new();
        for ((role, m), num_votes) in registered_votes.iter_mut() {
            if *num_votes as usize >= (threshold + round)
                && !*(casted.get(role).ok_or_else(|| {
                    anyhow_error_and_log("Cant retrieve whether I casted a vote".to_string())
                })?)
            {
                round_registered_votes.insert((*role, m.clone()), *num_votes);
                //Remember I casted a vote
                let casted_vote_role = casted.get_mut(role).ok_or_else(|| {
                    anyhow_error_and_log("Can't retrieve whether I casted a vote".to_string())
                })?;
                *casted_vote_role = true;
                //Also add a vote in my own data struct
                *num_votes += 1;
            }
        }
        cast_threshold_vote(
            session,
            sender,
            &round_registered_votes,
            (threshold + round) as u32,
        )
        .await?;
    }
    Ok(())
}

/// The parties in the set \[Pi] want to **reliably** broadcast a value Vi to all the other parties
///
/// Here sender_list = \[Pi] and  vi = Vi
/// Function returns a map bcast_data: Role => Value such that
/// all parties have the broadcasted values inside the map: bcast_data\[Pj] = Vj for all j in \[n].
/// This function does *not* handle corrupt parties.
pub async fn reliable_broadcast<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: &B,
    sender_list: &[Role],
    vi: Option<BroadcastValue<Z>>,
) -> anyhow::Result<RoleValueMap<Z>> {
    let num_parties = session.num_parties();
    if sender_list.is_empty() {
        return Err(anyhow_error_and_log(
            "We expect at least one party as sender in reliable broadcast".to_string(),
        ));
    }

    let threshold = session.threshold();
    let min_honest_nodes = num_parties as u32 - threshold as u32;

    let my_role = session.my_role()?;
    let is_sender = sender_list.contains(&my_role);
    let mut bcast_data: RoleValueMap<Z> = sender_list
        .iter()
        .map(|role| (*role, BroadcastValue::Bot))
        .collect();

    let mut non_answering_parties = HashSet::<Role>::new();

    // Communication round 1
    // Sender parties send the message they intend to broadcast to others
    // The send calls are followed by receive to get the incoming messages from the others
    let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
    match (vi, is_sender) {
        (Some(vi), true) => {
            bcast_data.insert(my_role, vi);
            round1_data.insert(my_role, bcast_data[&my_role].clone());
            let msg = NetworkValue::Send(round1_data[&my_role].clone());
            send_to_all(session, &my_role, msg).await?;
        }
        (None, false) => {
            session.network().increase_round_counter().await?; // We're not sending, but we must increase the round counter to stay in sync
        }
        (_, _) => {
            return Err(anyhow_error_and_log(
                "A sender must have a value in reliable broadcast".to_string(),
            ));
        }
    }

    // The error we propagate here is if sender IDs and roles cannot be tied together.
    receive_from_all_senders(
        &mut round1_data,
        session,
        &my_role,
        sender_list,
        &mut non_answering_parties,
    )
    .await?;

    // Communication round 2
    // Parties send Echo to the other parties
    // Parties receive Echo from others and process them, if there are enough Echo messages then they can cast a vote
    let msg = round1_data;
    send_to_all(session, &my_role, NetworkValue::EchoBatch(msg.clone())).await?;
    // adding own echo to the map
    let mut echos: HashMap<(Role, BroadcastValue<Z>), u32> =
        msg.iter().map(|(k, v)| ((*k, v.clone()), 1)).collect();
    // retrieve echos from all parties
    let mut registered_votes =
        receive_from_all_echo_batch(session, &my_role, &mut non_answering_parties, &mut echos)
            .await?;

    // Communication round 3
    // Parties try to cast the vote if received enough Echo messages (i.e. can_vote is true)
    //Here propagate error if my own casted hashmap does not contain the expected party's id
    let mut casted_vote: HashMap<Role, bool> =
        sender_list.iter().map(|role| (*role, false)).collect();

    cast_threshold_vote(session, &my_role, &registered_votes, 1).await?;

    for ((role, _), _) in registered_votes.iter() {
        let casted_vote_role = casted_vote.get_mut(role).ok_or_else(|| {
            anyhow_error_and_log(format!("Can't retrieve whether I ({role}) casted a vote"))
        })?;
        if *casted_vote_role {
            return Err(anyhow_error_and_log(
                "Trying to cast two votes for the same sender!".to_string(),
            ));
        }
        *casted_vote_role = true;
    }

    // receive votes from the other parties, if we have at least T for a message m associated to a party Pi
    // then we know for sure that Pi has broadcasted message m
    gather_votes(
        session,
        &my_role,
        &mut registered_votes,
        &mut casted_vote,
        &mut non_answering_parties,
    )
    .await?;
    for ((role, value), hits) in registered_votes.iter() {
        if *hits >= min_honest_nodes {
            bcast_data.insert(*role, value.clone());
        }
    }
    Ok(bcast_data)
}

/// **All** parties Pi want to **reliably** broadcast a value Vi to all the other parties
///
/// Function returns a map bcast_data: Role => Value such that
/// all players have the broadcasted values inside the map: bcast_data\[Pj] = Vj for all j in [n].
/// This function does not handle corrupt parties.
pub async fn broadcast_from_all<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: &B,
    vi: Option<BroadcastValue<Z>>,
) -> anyhow::Result<RoleValueMap<Z>> {
    let sender_list = session.role_assignments().clone().into_keys().collect_vec();
    reliable_broadcast(session, &sender_list, vi).await
}

/// Execute a [broadcast_from_all] in the presence of corrupt parties.
///
/// Parties in `corrupt_roles` are ignored during the execution and if any new corruptions are detected then they are added to `corrupt_roles`
/// WARNING: It is CRUCIAL that the corrupt roles are ignored, as otherwise they could cause a DoS attack with the current logic of the functions using this method.
pub async fn broadcast_from_all_w_corruption<
    Z: Ring,
    R: Rng + CryptoRng,
    Ses: BaseSessionHandles<R>,
>(
    session: &mut Ses,
    vi: BroadcastValue<Z>,
) -> anyhow::Result<RoleValueMap<Z>> {
    let bcast_type = BroadcastType::All(vi);
    broadcast_w_corruption_helper(session, bcast_type).await
}

/// Execute a [broadcast] from a (sub-)set of parties in the presence of corrupt parties.
///
/// Parties in `corrupt_roles` are ignored during the execution and if any new corruptions are detected then they are added to `corrupt_roles`
/// WARNING: It is CRUCIAL that the corrupt roles are ignored, as otherwise they could cause a DoS attack with the current logic of the functions using this method.
pub async fn broadcast_w_corruption<Z: Ring, R: Rng + CryptoRng, Ses: BaseSessionHandles<R>>(
    session: &mut Ses,
    sender_list: &[Role],
    vi: Option<BroadcastValue<Z>>,
) -> anyhow::Result<RoleValueMap<Z>> {
    let bcast_type = BroadcastType::Standard(sender_list, vi);
    broadcast_w_corruption_helper(session, bcast_type).await
}

enum BroadcastType<'a, Z: Zero + Eq> {
    All(BroadcastValue<Z>),
    Standard(&'a [Role], Option<BroadcastValue<Z>>),
}

/// Executes a reliable broadcast either from all parties or from a single party,
/// depending on the `bcast_type`, handling corrupt parties
async fn broadcast_w_corruption_helper<Z: Ring, R: Rng + CryptoRng, Ses: BaseSessionHandles<R>>(
    session: &mut Ses,
    bcast_type: BroadcastType<'_, Z>,
) -> anyhow::Result<RoleValueMap<Z>> {
    let sender_list = match &bcast_type {
        BroadcastType::All(_) => session.role_assignments().keys().cloned().collect_vec(),
        BroadcastType::Standard(roles, _) => roles.to_vec(),
    };

    // Remove corrupt parties from the current session
    let old_role_assignments = session.role_assignments().clone();
    let mut new_role_assignments = session.role_assignments().clone();
    session.corrupt_roles().iter().for_each(|r| {
        new_role_assignments.remove(r);
    });

    session.set_role_assignments(new_role_assignments);
    let mut broadcast_res = match bcast_type {
        BroadcastType::All(vi) => broadcast_from_all(session, Some(vi)).await?,
        BroadcastType::Standard(roles, vi) => reliable_broadcast(session, roles, vi).await?,
    };
    session.set_role_assignments(old_role_assignments);

    // Add bot for the parties which were already corrupt before the bcast
    for role in session.corrupt_roles() {
        broadcast_res.insert(*role, BroadcastValue::Bot);
    }

    // Note that the sender list is computed at the start
    // which differs depending on the broadcast type
    for role in sender_list {
        // Small optimization: the corrupt senders can be skipped
        if session.corrupt_roles().contains(&role) {
            continue;
        }

        // Each party that was supposed to broadcast but where the parties did not consistently agree on the result
        // is added to the set of corrupt parties
        if let BroadcastValue::Bot = broadcast_res.get(&role).ok_or_else(|| {
            anyhow_error_and_log(format!("Cannot find {role} in broadcast's result."))
        })? {
            session.add_corrupt(role)?;
        }
    }
    Ok(broadcast_res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::residue_poly::ResiduePoly128;
    use crate::computation::SessionId;
    use crate::execution::runtime::session::ParameterHandles;
    use crate::execution::runtime::test_runtime::{
        generate_fixed_identities, DistributedTestRuntime,
    };
    use crate::execution::sharing::shamir::ShamirRing;
    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;
    use std::num::Wrapping;

    fn legitimate_broadcast<Z: ShamirRing>(
        sender_parties: &[Role],
    ) -> (Vec<Identity>, Vec<BroadcastValue<Z>>, Vec<RoleValueMap<Z>>) {
        let identities = generate_fixed_identities(4);

        let input_values = vec![
            BroadcastValue::from(Z::ONE),
            BroadcastValue::from(Z::ONE + Z::ONE),
            BroadcastValue::from(Z::ONE + Z::ONE + Z::ONE),
            BroadcastValue::from(Z::ONE + Z::ONE + Z::ONE + Z::ONE),
        ];

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::<Z>::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        if identities.len() == sender_parties.len() {
            for (party_no, my_data) in input_values.iter().cloned().enumerate() {
                let num = party_no as u8;
                let session = runtime
                    .small_session_for_party(
                        session_id,
                        party_no,
                        Some(AesRng::seed_from_u64(num.into())),
                    )
                    .unwrap();
                set.spawn(
                    async move { broadcast_from_all(&session, Some(my_data)).await.unwrap() },
                );
            }
        } else {
            for (party_no, my_data) in input_values.iter().cloned().enumerate() {
                let session = runtime
                    .small_session_for_party(session_id, party_no, Some(AesRng::seed_from_u64(0)))
                    .unwrap();
                let sender_list = sender_parties.to_vec();
                if sender_parties.contains(&Role::indexed_by_zero(party_no)) {
                    set.spawn(async move {
                        reliable_broadcast(&session, &sender_list, Some(my_data))
                            .await
                            .unwrap()
                    });
                } else {
                    set.spawn(async move {
                        reliable_broadcast(&session, &sender_list, None)
                            .await
                            .unwrap()
                    });
                }
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

        (identities, input_values, results)
    }

    #[test]
    fn test_broadcast_all() {
        let sender_parties: Vec<Role> = (0..4).map(Role::indexed_by_zero).collect();
        let (identities, input_values, results) =
            legitimate_broadcast::<ResiduePoly128>(&sender_parties);

        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), identities.len());

        // check that each party has received the same output
        for i in 1..identities.len() {
            assert_eq!(results[0], results[i]);
        }

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_by_zero(0)], input_values[0]);
        assert_eq!(results[0][&Role::indexed_by_zero(1)], input_values[1]);
        assert_eq!(results[0][&Role::indexed_by_zero(2)], input_values[2]);
        assert_eq!(results[0][&Role::indexed_by_zero(3)], input_values[3]);
    }

    #[test]
    fn test_broadcast_p3() {
        let sender_parties = vec![Role::indexed_by_zero(3)];
        let (identities, input_values, results) =
            legitimate_broadcast::<ResiduePoly128>(&sender_parties);

        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), identities.len());

        // check that each party has received the same output
        for i in 1..identities.len() {
            assert_eq!(results[0], results[i]);
        }

        assert!(!results[0].contains_key(&Role::indexed_by_zero(0)));
        assert!(!results[0].contains_key(&Role::indexed_by_zero(1)));
        assert!(!results[0].contains_key(&Role::indexed_by_zero(2)));
        assert!(results[0].contains_key(&Role::indexed_by_zero(3)));

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_by_zero(3)], input_values[3]);
    }
    #[test]
    fn test_broadcast_p0_p2() {
        let sender_parties = vec![Role::indexed_by_one(1), Role::indexed_by_one(3)];
        let (identities, input_values, results) =
            legitimate_broadcast::<ResiduePoly128>(&sender_parties);
        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), identities.len());

        // check that each party has received the same output
        for i in 1..identities.len() {
            assert_eq!(results[0], results[i]);
        }

        // contains party P1
        assert!(results[0].contains_key(&Role::indexed_by_one(1)));
        assert!(!results[0].contains_key(&Role::indexed_by_one(2)));
        assert!(results[0].contains_key(&Role::indexed_by_one(3)));
        assert!(!results[0].contains_key(&Role::indexed_by_one(4)));

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_by_zero(0)], input_values[0]);
        assert_eq!(results[0][&Role::indexed_by_zero(2)], input_values[2]);
    }

    #[test]
    fn test_broadcast_dropout() {
        let identities = generate_fixed_identities(4);

        let input_values = vec![
            BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(1))),
            BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(2))),
            BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(3))),
            BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(4))),
        ];

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_no, my_data) in input_values.iter().cloned().enumerate() {
            let session = runtime
                .small_session_for_party(session_id, party_no, Some(AesRng::seed_from_u64(0)))
                .unwrap();
            if party_no != 0 {
                set.spawn(
                    async move { broadcast_from_all(&session, Some(my_data)).await.unwrap() },
                );
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

        // check that we have exactly n-1 bcast outputs, for each party
        assert_eq!(results.len(), 3);

        // check that each party has received the same output
        for i in 1..results.len() {
            assert_eq!(results[0], results[i]);
        }

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_by_zero(1)], input_values[1]);
        assert_eq!(results[0][&Role::indexed_by_zero(2)], input_values[2]);
        assert_eq!(results[0][&Role::indexed_by_zero(3)], input_values[3]);
    }

    /// Test that the broadcast with disputes ensures that corrupt parties get excluded from the broadcast execution
    #[test]
    fn test_broadcast_w_corruption() {
        let num_parties = 4;
        let msg = BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(42)));
        let identities = generate_fixed_identities(num_parties);
        let parties = identities.len();

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let corrupt_role = Role::indexed_by_one(4);

        let mut set = JoinSet::new();
        for (party_id, _) in runtime.identities.iter().enumerate() {
            if corrupt_role != Role::indexed_by_zero(party_id) {
                let mut session = runtime
                    .large_session_for_party(session_id, party_id)
                    .unwrap();
                let cur_msg = msg.clone();

                set.spawn(async move {
                    let res = broadcast_from_all_w_corruption(&mut session, cur_msg).await;
                    // Check no new corruptions are added to the honest parties view
                    if party_id != corrupt_role.zero_based() {
                        assert_eq!(1, session.corrupt_roles().len());
                    }
                    (party_id, res)
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

        for (cur_role_id, cur_res) in results {
            // Check that we received response from all and corrupt role is Bot
            if cur_role_id != corrupt_role.zero_based() {
                let unwrapped = cur_res.unwrap();
                assert_eq!(parties, unwrapped.len());
                for cur_role_id in 1..=parties {
                    // And that all parties agreed on the messages sent
                    if cur_role_id != corrupt_role.one_based() {
                        assert_eq!(
                            &msg,
                            unwrapped.get(&Role::indexed_by_one(cur_role_id)).unwrap()
                        );
                    } else {
                        assert_eq!(
                            &BroadcastValue::Bot,
                            unwrapped.get(&Role::indexed_by_one(cur_role_id)).unwrap()
                        );
                    }
                }
            }
        }
    }

    //In this strategy, the cheater broadcast something different to all the parties,
    //and then votes for something whenever it has the opportunity
    //this behavior is expected to NOT come to any output for this sender
    async fn cheater_broadcast_strategy_1<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
        session: &B,
        sender_list: &[Role],
        vec_vi: Option<Vec<BroadcastValue<Z>>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        let num_parties = session.num_parties();
        if sender_list.is_empty() {
            return Err(anyhow_error_and_log(
                "We expect at least one party as sender in reliable broadcast".to_string(),
            ));
        }
        let num_senders = sender_list.len();

        let threshold = session.threshold();
        let min_honest_nodes = num_parties as u32 - threshold as u32;

        let my_role = session.role_from(&session.own_identity())?;
        let is_sender = sender_list.contains(&my_role);
        let mut bcast_data = HashMap::with_capacity(num_senders);

        let mut non_answering_parties = HashSet::new();

        // Communication round 1
        // As a cheater I send a different message to all the parties
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter().await?;
        match (vec_vi.clone(), is_sender) {
            (Some(vec_vi), true) => {
                bcast_data.insert(my_role, vec_vi[1].clone());
                round1_data.insert(my_role, bcast_data[&my_role].clone());
                let mut jobs = JoinSet::new();
                for (other_role, other_identity) in session.role_assignments().iter() {
                    let networking = Arc::clone(session.network());
                    let session_id = session.session_id();
                    let msg = NetworkValue::Send(vec_vi[other_role.zero_based()].clone());
                    tracing::debug!(
                        "As malicious sender {my_role}, sending {:?} to {other_role}",
                        vec_vi[other_role.zero_based()]
                    );
                    let other_id = other_identity.clone();
                    if &my_role != other_role {
                        jobs.spawn(async move {
                            let _ = networking
                                .send(msg.to_network(), &other_id, &session_id)
                                .await;
                        });
                    }
                }
                while (jobs.join_next().await).is_some() {}
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ))
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_from_all_senders(
            &mut round1_data,
            session,
            &my_role,
            sender_list,
            &mut non_answering_parties,
        )
        .await?;

        // Communication round 2
        // Parties send Echo to the other parties
        // Parties receive Echo from others and process them, if there are enough Echo messages then they can cast a vote
        let msg = round1_data;
        send_to_all(session, &my_role, NetworkValue::EchoBatch(msg.clone())).await?;
        // adding own echo to the map
        let mut echos: HashMap<(Role, BroadcastValue<Z>), u32> =
            msg.iter().map(|(k, v)| ((*k, v.clone()), 1)).collect();
        // retrieve echos from all parties
        let mut registered_votes =
            receive_from_all_echo_batch(session, &my_role, &mut non_answering_parties, &mut echos)
                .await?;

        // Communication round 3
        // Parties try to cast the vote if received enough Echo messages (i.e. can_vote is true)
        // As cheater, voting for something even though I should not
        registered_votes.insert((Role::indexed_by_one(2), vec_vi.unwrap()[1].clone()), 1);
        let mut casted_vote: HashMap<Role, bool> = session
            .role_assignments()
            .keys()
            .map(|role| (*role, false))
            .collect();
        if !registered_votes.is_empty() {
            cast_threshold_vote(session, &my_role, &registered_votes, 1).await?;
            for ((role, _), _) in registered_votes.iter() {
                let casted_vote_role = casted_vote.get_mut(role).ok_or_else(|| {
                    anyhow_error_and_log("Can't retrieve whether I casted a vote".to_string())
                })?;
                if *casted_vote_role {
                    return Err(anyhow_error_and_log(
                        "Trying to cast two votes for the same sender!".to_string(),
                    ));
                }
                *casted_vote_role = true;
            }
        }

        // receive votes from the other parties, if we have at least T for a message m associated to a party Pi
        // then we know for sure that Pi has broadcasted message m
        gather_votes(
            session,
            &my_role,
            &mut registered_votes,
            &mut casted_vote,
            &mut non_answering_parties,
        )
        .await?;
        for ((role, value), hits) in registered_votes.iter() {
            if *hits >= min_honest_nodes {
                bcast_data.insert(*role, value.clone());
            }
        }
        Ok(bcast_data)
    }

    //Test bcast with one actively malicious party
    #[test]
    fn broadcast_w_malicious_1() {
        let msg = BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(42)));
        let corrupt_msg = (0..5)
            .map(|i| BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(43 + i))))
            .collect_vec();
        let identities = generate_fixed_identities(5);
        let parties = identities.len();

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut malicious_set = JoinSet::new();
        for party_id in 0..parties {
            let mut session = runtime
                .small_session_for_party(session_id, party_id, None)
                .unwrap();
            let cur_msg = msg.clone();
            if party_id == 0 {
                let cms = corrupt_msg.clone();
                malicious_set.spawn(async move {
                    let res = cheater_broadcast_strategy_1(
                        &session,
                        &session.role_assignments().clone().into_keys().collect_vec(),
                        Some(cms),
                    )
                    .await;
                    (party_id, res)
                });
            } else {
                set.spawn(async move {
                    let res = broadcast_from_all_w_corruption(&mut session, cur_msg).await;
                    // Check cheater is added to corrupt roles
                    assert_eq!(1, session.corrupt_roles().len());
                    (party_id, res)
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

        for (_cur_role_id, cur_res) in results {
            // Check that we received response from all the cheater P0 which should be mapped to Bot
            let unwrapped = cur_res.unwrap();
            assert_eq!(parties, unwrapped.len());
            for cur_role_id in 1..=parties {
                // And that all parties agreed on the messages sent
                if cur_role_id != 1 {
                    assert_eq!(
                        &msg,
                        unwrapped.get(&Role::indexed_by_one(cur_role_id)).unwrap()
                    );
                } else {
                    assert_eq!(
                        &BroadcastValue::Bot,
                        unwrapped.get(&Role::indexed_by_one(cur_role_id)).unwrap()
                    );
                }
            }
        }
    }

    //Assume 4 parties, P1 is the corrupt (hardcode roles in the strategy)
    //In this strategy, the cheater sends m0 to P2 and m1 to P3 and P4,
    //it then echoes m to P3 an P4 but echoes m0 to P2 and does not vote for anything
    //we thus expect that P2,P3,P4 will end up agreeing on m1 at the end of round5
    #[cfg(feature = "slow_tests")]
    async fn cheater_broadcast_strategy_2<Z: Ring, R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
        session: &B,
        sender_list: &[Role],
        vec_vi: Option<Vec<BroadcastValue<Z>>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        if sender_list.is_empty() {
            return Err(anyhow_error_and_log(
                "We expect at least one party as sender in reliable broadcast".to_string(),
            ));
        }
        let num_senders = sender_list.len();

        let my_role = session.role_from(&session.own_identity())?;
        let is_sender = sender_list.contains(&my_role);
        let mut bcast_data = HashMap::with_capacity(num_senders);

        let mut non_answering_parties = HashSet::new();

        // Communication round 1
        // As a cheater I send a different message to all the parties
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter().await?;
        match (vec_vi.clone(), is_sender) {
            (Some(vec_vi), true) => {
                bcast_data.insert(my_role, vec_vi[1].clone());
                round1_data.insert(my_role, bcast_data[&my_role].clone());
                let mut jobs = JoinSet::new();
                for (other_role, other_identity) in session.role_assignments().iter() {
                    let networking = Arc::clone(session.network());
                    let session_id = session.session_id();
                    let other_id = other_identity.clone();
                    if &my_role != other_role && other_role.one_based() > 2 {
                        let msg = NetworkValue::Send(vec_vi[1].clone());
                        jobs.spawn(async move {
                            let _ = networking
                                .send(msg.to_network(), &other_id, &session_id)
                                .await;
                        });
                    } else if other_role.one_based() == 2 {
                        let msg = NetworkValue::Send(vec_vi[0].clone());
                        jobs.spawn(async move {
                            let _ = networking
                                .send(msg.to_network(), &other_id, &session_id)
                                .await;
                        });
                    }
                }
                while (jobs.join_next().await).is_some() {}
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ))
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_from_all_senders(
            &mut round1_data,
            session,
            &my_role,
            sender_list,
            &mut non_answering_parties,
        )
        .await?;

        // Communication round 2
        // Parties send Echo to the other parties
        // Parties receive Echo from others and process them, if there are enough Echo messages then they can cast a vote
        session.network().increase_round_counter().await?;
        let mut msg_to_p2 = round1_data.clone();
        msg_to_p2.insert(my_role, vec_vi.clone().unwrap()[0].clone());
        let msg_to_others = round1_data;
        let mut jobs = JoinSet::new();
        for (other_role, other_identity) in session.role_assignments().iter() {
            let networking = Arc::clone(session.network());
            let session_id = session.session_id();
            let other_id = other_identity.clone();
            if &my_role != other_role && other_role.one_based() > 2 {
                let msg = NetworkValue::EchoBatch(msg_to_others.clone());
                jobs.spawn(async move {
                    let _ = networking
                        .send(msg.to_network(), &other_id, &session_id)
                        .await;
                });
            } else if other_role.one_based() == 2 {
                let msg = NetworkValue::EchoBatch(msg_to_p2.clone());
                jobs.spawn(async move {
                    let _ = networking
                        .send(msg.to_network(), &other_id, &session_id)
                        .await;
                });
            }
        }
        while (jobs.join_next().await).is_some() {}
        let msg = msg_to_others;
        // adding own echo to the map
        let mut echos: HashMap<(Role, BroadcastValue<Z>), u32> =
            msg.iter().map(|(k, v)| ((*k, v.clone()), 1)).collect();
        // retrieve echos from all parties
        let _ =
            receive_from_all_echo_batch(session, &my_role, &mut non_answering_parties, &mut echos)
                .await?;

        //Stop voting now

        Ok(bcast_data)
    }

    //Test bcast with one actively malicious party
    #[test]
    #[cfg(feature = "slow_tests")]
    fn broadcast_w_malicious_2() {
        let msg = BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(42)));
        let corrupt_msg = (0..5)
            .map(|i| BroadcastValue::from(ResiduePoly128::from_scalar(Wrapping(43 + i))))
            .collect_vec();
        let identities = generate_fixed_identities(4);
        let parties = identities.len();

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut malicious_set = JoinSet::new();
        for party_id in 0..parties {
            let mut session = runtime
                .small_session_for_party(session_id, party_id, None)
                .unwrap();
            let cur_msg = msg.clone();
            if party_id == 0 {
                let cms = corrupt_msg.clone();
                malicious_set.spawn(async move {
                    let res = cheater_broadcast_strategy_2(
                        &session,
                        &session.role_assignments().clone().into_keys().collect_vec(),
                        Some(cms),
                    )
                    .await;
                    (party_id, res)
                });
            } else {
                set.spawn(async move {
                    let res = broadcast_from_all_w_corruption(&mut session, cur_msg).await;
                    // Check cheater is not added to corrupt roles
                    assert_eq!(0, session.corrupt_roles().len());
                    (party_id, res)
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

        for (_cur_role_id, cur_res) in results {
            // Check that we received response from all except the cheater P0 which should be absent from result
            let unwrapped = cur_res.unwrap();
            assert_eq!(parties, unwrapped.len());
            for cur_role_id in 1..=parties {
                // And that all parties agreed on the messages sent
                if cur_role_id != 1 {
                    assert_eq!(
                        &msg,
                        unwrapped.get(&Role::indexed_by_one(cur_role_id)).unwrap()
                    );
                } else {
                    assert_eq!(
                        &corrupt_msg[1],
                        unwrapped.get(&Role::indexed_by_one(cur_role_id)).unwrap()
                    );
                }
            }
        }
    }
}
