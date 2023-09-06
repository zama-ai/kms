use crate::execution::distributed::DistributedSession;
use crate::execution::party::Role;
use crate::networking::constants::BCAST_TIMEOUT;
use crate::value::{NetworkValue, Value};
use anyhow::anyhow;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use super::party::Identity;

type RoleValueMap = HashMap<Role, Value>;

pub async fn send_to_all(session: &DistributedSession, sender: &Role, msg: NetworkValue) {
    let mut jobs = JoinSet::new();
    for (other_role, other_identity) in session.role_assignments.iter() {
        let networking = Arc::clone(&session.networking);
        let session_id = session.session_id;
        let msg = msg.clone();
        let other_id = other_identity.clone();
        if sender != other_role {
            jobs.spawn(async move {
                let _ = networking.send(msg, &other_id, &session_id).await;
            });
        }
    }
    while (jobs.join_next().await).is_some() {}
}

/// Spawns receive tasks and matches the incomming messages according to the match_network_value_fn
/// The function makes sure that it process the correct type of message, i.e.
/// On the receiving end, a party processes a message of a single type from the {Send, Echo, Vote} options
/// and errors out if message is of a different form. This is helpful so that we can peel the message
/// from the inside enum.
fn generic_receive_from_all<V>(
    jobs: &mut JoinSet<Result<(Role, anyhow::Result<V>), Elapsed>>,
    session: &DistributedSession,
    receiver: &Role,
    match_network_value_fn: fn(network_value: NetworkValue, id: &Identity) -> anyhow::Result<V>,
) where
    V: std::marker::Send + 'static,
{
    for (sender, sender_id) in session.role_assignments.clone() {
        if receiver != &sender {
            let networking = Arc::clone(&session.networking);
            let session_id = session.session_id;
            let identity = session.own_identity.clone();
            let task = async move {
                let stripped_message = networking
                    .receive(&sender_id, &session_id)
                    .await
                    .map_or_else(|e| Err(e), |x| match_network_value_fn(x, &identity));
                (sender, stripped_message)
            };
            jobs.spawn(timeout(*BCAST_TIMEOUT, task));
        }
    }
}

async fn receive_from_all_send(
    round1_data: &mut HashMap<Role, Value>,
    session: &DistributedSession,
    receiver: &Role,
) -> anyhow::Result<()> {
    let mut jobs = JoinSet::<Result<(Role, anyhow::Result<Value>), Elapsed>>::new();
    generic_receive_from_all::<Value>(&mut jobs, session, receiver, |msg, id| match msg {
        NetworkValue::Send(v) => Ok(v),
        NetworkValue::EchoBatch(_) => Err(anyhow!(
            "I have received an Echo batch instead of a Send message on party: {:?}",
            id
        )),
        _ => Err(anyhow!(
            "I have received sth different from Send message on party: {:?}",
            id
        )),
    });

    // Place the received (Send) messages in the hashmap
    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        match joined_result {
            Err(e) => {
                tracing::error!("Error {:?}", e);
            }
            Ok((party_id, data)) => {
                if let Err(e) = data {
                    tracing::error!("Error {:?}", e);
                } else {
                    round1_data.insert(party_id.clone(), data?);
                }
            }
        }
    }
    Ok(())
}

async fn receive_from_all_echo_batch(
    session: &DistributedSession,
    receiver: &Role,
    echoed_data: &mut HashMap<(Role, Value), u32>,
) -> anyhow::Result<HashMap<(Role, Value), u32>> {
    let mut jobs = JoinSet::<Result<(Role, anyhow::Result<RoleValueMap>), Elapsed>>::new();
    generic_receive_from_all::<RoleValueMap>(&mut jobs, session, receiver, |msg, id| match msg {
        NetworkValue::EchoBatch(v) => Ok(v),
        _ => Err(anyhow!(
            "I have received sth different from an Echo Batch message on party: {:?}",
            id
        )),
    });

    let registered_votes = process_echos(
        &mut jobs,
        echoed_data,
        session.role_assignments.len() as u32,
        session.threshold as u32,
    )
    .await?;
    Ok(registered_votes)
}

fn receive_from_all_votes(
    jobs: &mut JoinSet<Result<(Role, anyhow::Result<RoleValueMap>), Elapsed>>,
    session: &DistributedSession,
    receiver: &Role,
) {
    generic_receive_from_all::<RoleValueMap>(jobs, session, receiver, |msg, id| match msg {
        NetworkValue::VoteBatch(v) => Ok(v),
        _ => Err(anyhow!(
            "I have received sth different from an Vote Batch message on player: {:?}",
            id
        )),
    });
}

/// Process Echo messages one by one, starting with the own echoed_data
/// If enough echoes >=(N-T) then player can cast a vote
async fn process_echos(
    echo_recv_tasks: &mut JoinSet<Result<(Role, anyhow::Result<RoleValueMap>), Elapsed>>,
    echoed_data: &mut HashMap<(Role, Value), u32>,
    num_parties: u32,
    threshold: u32,
) -> anyhow::Result<HashMap<(Role, Value), u32>> {
    let mut registered_votes = HashMap::new();
    let mut common_batches = 0;

    // Receiving Echo messages one by one
    while let Some(v) = echo_recv_tasks.join_next().await {
        let task_out = v?.map_err(|_e| anyhow!("time out error in processing echos"));
        // if no timeout error then we count it towards casting a vote
        task_out.and_then(|(_from_party, data)| {
            data.map(|rcv_echo| {
                debug_assert!(rcv_echo.len() <= num_parties as usize);
                // iterate through the echo batched message and check the frequency of each message
                let min_entry = rcv_echo.iter().fold(u32::MAX, |acc, (role, m)| {
                    let entry = echoed_data.entry((role.clone(), m.clone())).or_insert(0);
                    *entry += 1;
                    u32::min(*entry, acc)
                });
                // if the entry with the least number of occurrences has appeared at least N-T times
                // then we good to cast a vote using data from echo
                common_batches = u32::max(common_batches, min_entry);
                if common_batches >= (num_parties - threshold) {
                    for (role, m) in rcv_echo {
                        registered_votes.insert((role, m), 1);
                    }
                }
            })
        })?;
        if !registered_votes.is_empty() {
            echo_recv_tasks.shutdown().await;
        }
    }
    Ok(registered_votes)
}

/// Sender casts a vote only for messages m in registered_votes for which #m >= threshold
async fn cast_threshold_vote(
    session: &DistributedSession,
    sender: &Role,
    registered_votes: &HashMap<(Role, Value), u32>,
    threshold: u32,
) -> anyhow::Result<()> {
    let vote_data: HashMap<Role, Value> = registered_votes
        .iter()
        .filter_map(|(k, f)| {
            if *f >= threshold {
                Some((k.0.clone(), k.1.clone()))
            } else {
                None
            }
        })
        .collect();
    if vote_data.is_empty() {
        Err(anyhow!(
            "registered votes didn't have any message which had at least threshold occurrences"
        ))
    } else {
        send_to_all(session, sender, NetworkValue::VoteBatch(vote_data)).await;
        Ok(())
    }
}

/// Sender gathers votes from all the other parties.
/// If enough votes >=(T+R) and sender hasn't voted then vote
/// If enough votes >=(N-T) then stop the computation
async fn gather_votes(
    session: &DistributedSession,
    sender: &Role,
    registered_votes: &mut HashMap<(Role, Value), u32>,
    casted: &mut bool,
) -> anyhow::Result<()> {
    let num_parties = session.role_assignments.len();
    let threshold = session.threshold as usize;
    let mut max_common_votes = 0;

    // wait for other parties' incoming vote
    for round in 1..=threshold {
        let mut vote_recv_tasks = JoinSet::new();
        receive_from_all_votes(&mut vote_recv_tasks, session, sender);

        while let Some(v) = vote_recv_tasks.join_next().await {
            let task_out = v?.map_err(|_e| anyhow!("timed out error"));
            task_out.and_then(|(_from_party, data)| {
                data.map(|inner_map| {
                    debug_assert!(inner_map.len() <= num_parties);
                    // iterate through the vote batch message and check the frequency of each message
                    let min_entry = inner_map.iter().fold(usize::MAX, |acc, (role, m)| {
                        let entry = registered_votes
                            .entry((role.clone(), m.clone()))
                            .or_insert(0);
                        *entry += 1;
                        usize::min(*entry as usize, acc)
                    });
                    max_common_votes = usize::max(min_entry, max_common_votes);
                })
            })?;
            // When processing incoming vote, we check whether we received at least T + r votes
            // If so, then we're safe to cast a vote to everyone else
            if max_common_votes >= threshold + round && !(*casted) {
                // cast_vote
                let _ = cast_threshold_vote(
                    session,
                    sender,
                    registered_votes,
                    (threshold + round) as u32,
                )
                .await;
                *casted = true;
            }
            // If we have received at least N-T votes then we can safely return the broadcast output
            if max_common_votes >= num_parties - threshold {
                vote_recv_tasks.shutdown().await;
                return Ok(());
            }
        }
        // increase network round as we either finished broadcast or need to go the next voting round
        session.networking.increase_round_counter().await?;
    }
    Ok(())
}

/// All parties Pi want to reliable broadcast a value Vi to all the other parties
/// Here Pi = sender and  vi = Vi
/// Function returns a map bcast_data: Role => Value such that
/// all players have the broadcasted values inside the map: bcast_data[Pj] = Vj for all j in [n]
pub async fn reliable_broadcast(
    session: &DistributedSession,
    sender: &Role,
    vi: Value,
) -> anyhow::Result<HashMap<Role, Value>> {
    let num_parties = session.role_assignments.len();
    let threshold = session.threshold;
    let min_honest_nodes = num_parties as u32 - threshold as u32;

    let mut bcast_data = HashMap::with_capacity(num_parties);
    bcast_data.insert(sender.clone(), vi);

    // Communication round 1
    // Parties send the message they intend to broadcast to others
    // The send calls are followed by receive to get the incoming messages from the others
    session.networking.increase_round_counter().await?;

    let mut round1_data = HashMap::<Role, Value>::new();
    round1_data.insert(sender.clone(), bcast_data[sender].clone());
    let msg = NetworkValue::Send(round1_data[sender].clone());
    send_to_all(session, sender, msg).await;
    receive_from_all_send(&mut round1_data, session, sender).await?;

    // Communication round 2
    // Parties send Echo to the other parties
    // Parties receive Echo from others and process them, if there are enough Echo messages then they can cast a vote
    session.networking.increase_round_counter().await?;
    let msg = round1_data;
    send_to_all(session, sender, NetworkValue::EchoBatch(msg.clone())).await;
    // adding own echo to the map
    let mut echos: HashMap<(Role, Value), u32> = msg
        .iter()
        .map(|(k, v)| ((k.clone(), v.clone()), 1))
        .collect();
    // retrieve echos from all parties
    let mut registered_votes = receive_from_all_echo_batch(session, sender, &mut echos).await?;

    // Communication round 3
    // Parties try to cast the vote if received enough Echo messages (i.e. can_vote is true)
    session.networking.increase_round_counter().await?;
    let mut casted_vote = false;
    if !registered_votes.is_empty() {
        cast_threshold_vote(session, sender, &registered_votes, 1).await?;
        casted_vote = true;
    }

    // receive votes from the other parties, if we have at least T for a message m associated to a party Pi
    // then we know for sure that Pi has broadcasted message m
    gather_votes(session, sender, &mut registered_votes, &mut casted_vote).await?;
    for ((role, value), hits) in registered_votes.iter() {
        if *hits >= min_honest_nodes {
            bcast_data.insert(role.clone(), value.clone());
        }
    }
    Ok(bcast_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computation::SessionId;
    use crate::execution::distributed::DistributedTestRuntime;
    use crate::execution::party::Identity;
    use std::num::Wrapping;
    use tracing_test::traced_test;

    #[test]
    fn test_broadcast() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];

        let input_values = vec![
            Value::Ring128(Wrapping(1)),
            Value::Ring128(Wrapping(2)),
            Value::Ring128(Wrapping(3)),
            Value::Ring128(Wrapping(4)),
        ];

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold, None, None);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_no, my_data) in input_values.iter().cloned().enumerate() {
            let own_role = Role::from(party_no as u64 + 1);
            let session = runtime.session_for_player(session_id, party_no);
            set.spawn(async move {
                reliable_broadcast(&session, &own_role, my_data)
                    .await
                    .unwrap()
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

        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), identities.len());

        // check that each party has received the same output
        for i in 1..identities.len() {
            assert_eq!(results[0], results[i]);
        }

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role(1)], input_values[0]);
        assert_eq!(results[0][&Role(2)], input_values[1]);
        assert_eq!(results[0][&Role(3)], input_values[2]);
        assert_eq!(results[0][&Role(4)], input_values[3]);
    }

    #[traced_test]
    #[test]
    fn test_broadcast_dropout() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];

        let input_values = vec![
            Value::Ring128(Wrapping(1)),
            Value::Ring128(Wrapping(2)),
            Value::Ring128(Wrapping(3)),
            Value::Ring128(Wrapping(4)),
        ];

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities, threshold, None, None);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_no, my_data) in input_values.iter().cloned().enumerate() {
            let own_role = Role::from(party_no as u64 + 1);
            let session = runtime.session_for_player(session_id, party_no);
            if party_no != 0 {
                set.spawn(async move {
                    reliable_broadcast(&session, &own_role, my_data)
                        .await
                        .unwrap()
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

        // check that we have exactly n-1 bcast outputs, for each party
        assert_eq!(results.len(), 3);

        // check that each party has received the same output
        for i in 1..results.len() {
            assert_eq!(results[0], results[i]);
        }

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role(2)], input_values[1]);
        assert_eq!(results[0][&Role(3)], input_values[2]);
        assert_eq!(results[0][&Role(4)], input_values[3]);
    }
}
