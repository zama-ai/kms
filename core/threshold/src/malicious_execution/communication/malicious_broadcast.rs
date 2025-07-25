use std::collections::{HashMap, HashSet};

use aes_prng::AesRng;
use tonic::async_trait;

use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::{
            broadcast::{
                cast_threshold_vote, gather_votes, receive_contribution_from_all_senders,
                receive_echos_from_all_batched, Broadcast, RoleValueMap,
            },
            p2p::send_to_all,
        },
        runtime::{party::Role, session::BaseSessionHandles},
    },
    networking::value::{BcastHash, BroadcastValue, NetworkValue},
    ProtocolDescription,
};

/// Malicious implementation of the [`Broadcast`] protocol
/// that simply does nothing.
#[derive(Clone, Default)]
pub struct MaliciousBroadcastDrop {}

impl ProtocolDescription for MaliciousBroadcastDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-MaliciousBroadcastDrop")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastDrop {
    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        _session: &B,
        _sender_list: &[Role],
        _my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        Ok(RoleValueMap::new())
    }
}

/// Malicious implementation of the [`Broadcast`] protocol
/// where the party, when acting as the sender, sends a different (random) message to all the parties
/// and then acts honestly
#[derive(Clone, Default)]
pub struct MaliciousBroadcastSender {}

impl ProtocolDescription for MaliciousBroadcastSender {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-MaliciousBroadcastSender")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastSender {
    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &B,
        sender_list: &[Role],
        my_message: Option<BroadcastValue<Z>>,
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

        let my_role = session.my_role();
        let is_sender = sender_list.contains(&my_role);
        let mut bcast_data = HashMap::with_capacity(num_senders);

        let mut non_answering_parties = HashSet::new();

        // Communication round 1
        // As a cheater I send a different message to all the parties
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter()?;
        let mut rng = AesRng::from_random_seed();
        match (my_message.clone(), is_sender) {
            (Some(message), true) => {
                bcast_data.insert(my_role, message.clone());
                round1_data.insert(my_role, bcast_data[&my_role].clone());
                for (other_role, other_identity) in session.role_assignments().iter() {
                    let malicious_msg =
                        NetworkValue::Send(BroadcastValue::from(Z::sample(&mut rng)));

                    let other_id = other_identity.clone();
                    if &my_role != other_role {
                        session
                            .network()
                            .send(malicious_msg.to_network(), &other_id)
                            .await?;
                    }
                }
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ))
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_contribution_from_all_senders(
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
        let mut echos_count: HashMap<(Role, BroadcastValue<Z>), u32> =
            msg.iter().map(|(k, v)| ((*k, v.clone()), 1)).collect();
        // retrieve echos from all parties
        let mut registered_votes = receive_echos_from_all_batched(
            session,
            &my_role,
            &mut non_answering_parties,
            &mut echos_count,
        )
        .await?;

        let mut map_hash_to_value: HashMap<(Role, BcastHash), BroadcastValue<Z>> = echos_count
            .into_iter()
            .map(|((role, value), _)| {
                let hash = value.to_bcast_hash().map_err(|e| {
                    anyhow::anyhow!("Failed to compute broadcast hash for role {}: {}", role, e)
                })?;
                Ok(((role, hash), value))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        // Communication round 3
        // Parties try to cast the vote if received enough Echo messages (i.e. can_vote is true)
        let mut casted_vote: HashMap<Role, bool> =
            sender_list.iter().map(|role| (*role, false)).collect();

        cast_threshold_vote::<Z, B>(session, &my_role, &registered_votes, 1).await?;

        //Keep track of which instances of bcast we already voted for so we don't vote twice
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
        gather_votes::<Z, B>(
            session,
            &my_role,
            &mut registered_votes,
            &mut casted_vote,
            &mut non_answering_parties,
        )
        .await?;
        for ((role, value), hits) in registered_votes.into_iter() {
            if hits >= min_honest_nodes {
                //Retrieve the actual data from the hash
                let value = map_hash_to_value.remove(&(role, value)).ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "Can't retrieve the value from the hash in broadcast. Role {role}.",
                    ))
                })?;

                bcast_data.insert(role, value);
            }
        }
        Ok(bcast_data)
    }
}

/// Malicious implementation of the [`Broadcast`] protocol where the
/// party (P_i), when acting as the sender, sends the correct message to the party with index i+1
/// and the same random message to all the other parties, and does the same during the echo phase but
/// does not vote for anything.
///
/// The party outputs what it sees during round 1
#[derive(Default, Clone)]
pub struct MaliciousBroadcastSenderEcho {}

impl ProtocolDescription for MaliciousBroadcastSenderEcho {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-MaliciousBroadcastSenderEcho")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastSenderEcho {
    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &B,
        sender_list: &[Role],
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        if sender_list.is_empty() {
            return Err(anyhow_error_and_log(
                "We expect at least one party as sender in reliable broadcast".to_string(),
            ));
        }
        let num_senders = sender_list.len();

        let my_role = session.my_role();
        let num_parties = session.num_parties();
        // Lie to the "next" party
        let role_to_lie_to = Role::indexed_from_zero(my_role.one_based() % num_parties);

        let is_sender = sender_list.contains(&my_role);
        let mut bcast_data = HashMap::with_capacity(num_senders);

        let mut non_answering_parties = HashSet::new();

        // Communication round 1
        // As a cheater I send a different message to role_to_lie_to
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter()?;
        let mut rng = AesRng::from_random_seed();
        let random_message = BroadcastValue::from(Z::sample(&mut rng));
        match (my_message.clone(), is_sender) {
            (Some(message), true) => {
                bcast_data.insert(my_role, message.clone());
                round1_data.insert(my_role, bcast_data[&my_role].clone());
                for (other_role, other_identity) in session.role_assignments().iter() {
                    let other_id = other_identity.clone();
                    if &my_role != other_role && other_role != &role_to_lie_to {
                        let msg = NetworkValue::Send(message.clone());
                        session.network().send(msg.to_network(), &other_id).await?;
                    } else if other_role == &role_to_lie_to {
                        let msg = NetworkValue::Send(random_message.clone());
                        session.network().send(msg.to_network(), &other_id).await?;
                    }
                }
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ))
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_contribution_from_all_senders(
            &mut round1_data,
            session,
            &my_role,
            sender_list,
            &mut non_answering_parties,
        )
        .await?;

        // Communication round 2
        // Parties send Echo to the other parties, lying in the same way as for the original send
        session.network().increase_round_counter()?;
        let mut msg_to_victim = round1_data.clone();
        msg_to_victim.insert(my_role, random_message.clone());
        let msg_to_others = round1_data.clone();
        for (other_role, other_identity) in session.role_assignments().iter() {
            let other_id = other_identity.clone();
            if &my_role != other_role && other_role != &role_to_lie_to {
                let msg = NetworkValue::EchoBatch(msg_to_others.clone());
                session.network().send(msg.to_network(), &other_id).await?;
            } else if other_role == &role_to_lie_to {
                let msg = NetworkValue::EchoBatch(msg_to_victim.clone());
                session.network().send(msg.to_network(), &other_id).await?;
            }
        }
        let msg = msg_to_others;
        // adding own echo to the map
        let mut echos: HashMap<(Role, BroadcastValue<Z>), u32> =
            msg.iter().map(|(k, v)| ((*k, v.clone()), 1)).collect();
        // retrieve echos from all parties
        let _ = receive_echos_from_all_batched(
            session,
            &my_role,
            &mut non_answering_parties,
            &mut echos,
        )
        .await?;

        //Stop voting now
        Ok(round1_data)
    }
}
