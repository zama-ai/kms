use std::collections::{HashMap, HashSet};

use aes_prng::AesRng;
use std::sync::Arc;
use tonic::async_trait;

use crate::{
    communication::{
        broadcast::{
            Broadcast, RoleValueMap, SyncReliableBroadcast, cast_new_votes, gather_votes,
            receive_contribution_from_all_senders, receive_echos_from_all_batched,
        },
        p2p::send_to_all,
    },
    large_execution::{local_single_share::MapsSharesChallenges, vss::ValueOrPoly},
    network_value::{BroadcastValue, NetworkValue},
    runtime::sessions::base_session::BaseSessionHandles,
};
use algebra::{poly::Poly, structure_traits::Ring};
use error_utils::anyhow_error_and_log;
use threshold_types::protocol::ProtocolDescription;
use threshold_types::role::Role;

/// Malicious implementation of the [`Broadcast`] protocol
/// that simply does nothing.
#[derive(Clone, Default)]
pub struct MaliciousBroadcastDrop {}

impl ProtocolDescription for MaliciousBroadcastDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousBroadcastDrop")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastDrop {
    fn num_rounds(num_parties: usize, threshold: usize) -> usize {
        SyncReliableBroadcast::num_rounds(num_parties, threshold)
    }

    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        _session: &mut B,
        _senders: &HashSet<Role>,
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
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousBroadcastSender")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastSender {
    fn num_rounds(num_parties: usize, threshold: usize) -> usize {
        SyncReliableBroadcast::num_rounds(num_parties, threshold)
    }

    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &mut B,
        senders: &HashSet<Role>,
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        let num_parties = session.num_parties();
        if senders.is_empty() {
            return Err(anyhow_error_and_log(
                "We expect at least one party as sender in reliable broadcast".to_string(),
            ));
        }
        let num_senders = senders.len();

        let threshold = session.threshold();
        let min_honest_nodes = num_parties - threshold as usize;

        let my_role = session.my_role();
        let is_sender = senders.contains(&my_role);
        let mut bcast_data = HashMap::with_capacity(num_senders);

        let mut non_answering_parties = HashSet::new();

        // Communication round 1
        // As a cheater I send a different message to all the parties
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter().await;
        let mut rng = AesRng::from_random_seed();
        match (my_message.clone(), is_sender) {
            (Some(message), true) => {
                bcast_data.insert(my_role, message.clone());
                round1_data.insert(my_role, bcast_data[&my_role].clone());
                for other_role in session.roles().iter() {
                    let malicious_msg =
                        NetworkValue::Send(BroadcastValue::from(Z::sample(&mut rng)));
                    if my_role != *other_role {
                        session
                            .network()
                            .send(Arc::new(malicious_msg.to_network()), other_role)
                            .await?;
                    }
                }
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ));
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_contribution_from_all_senders(
            &mut round1_data,
            session,
            senders,
            &mut non_answering_parties,
        )
        .await?;

        // Communication round 2
        // Parties send Echo to the other parties
        // Parties receive Echo from others and process them, if there are enough Echo messages then they can cast a vote
        let msg = round1_data;
        send_to_all(session, NetworkValue::EchoBatch(msg.clone())).await?;
        // adding own echo to the map
        let echos_count: HashMap<(Role, BroadcastValue<Z>), HashSet<Role>> = msg
            .iter()
            .map(|(k, v)| ((*k, v.clone()), HashSet::from([session.my_role()])))
            .collect();
        // retrieve echos from all parties
        let (mut registered_votes, mut map_hash_to_value) =
            receive_echos_from_all_batched(session, &mut non_answering_parties, echos_count)
                .await?;

        // Communication round 3
        // Parties try to cast the vote if received enough Echo messages (i.e. can_vote is true)
        let mut casted_vote: HashMap<Role, bool> =
            senders.iter().map(|role| (*role, false)).collect();

        cast_new_votes::<Z, B>(session, &mut registered_votes, &mut casted_vote, 1).await?;

        // receive votes from the other parties, if we have at least T for a message m associated to a party Pi
        // then we know for sure that Pi has broadcasted message m
        gather_votes::<Z, B>(
            session,
            &mut registered_votes,
            &mut casted_vote,
            &mut non_answering_parties,
        )
        .await?;
        for ((role, value), hits) in registered_votes.into_iter() {
            if hits.len() >= min_honest_nodes {
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
/// party (P_i), when acting as the sender, sends a message to the party with index i+1
/// and the same correct message to all the other parties, and does the same during the echo phase but
/// does not vote for anything.
///
/// The party outputs what it sees during round 1
#[derive(Default, Clone)]
pub struct MaliciousBroadcastSenderEcho {}

impl ProtocolDescription for MaliciousBroadcastSenderEcho {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousBroadcastSenderEcho")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastSenderEcho {
    fn num_rounds(num_parties: usize, threshold: usize) -> usize {
        SyncReliableBroadcast::num_rounds(num_parties, threshold)
    }

    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &mut B,
        senders: &HashSet<Role>,
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        if senders.is_empty() {
            return Err(anyhow_error_and_log(
                "We expect at least one party as sender in reliable broadcast".to_string(),
            ));
        }
        let num_senders = senders.len();

        let my_role = session.my_role();
        let num_parties = session.num_parties();
        // Lie to the "next" party
        let role_to_lie_to = Role::indexed_from_zero(my_role.one_based() % num_parties);

        let is_sender = senders.contains(&my_role);
        let mut bcast_data = HashMap::with_capacity(num_senders);

        let mut non_answering_parties = HashSet::new();

        // Communication round 1
        // As a cheater I send a different message to role_to_lie_to
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_data = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter().await;
        let mut rng = AesRng::from_random_seed();
        let random_message = BroadcastValue::from(Z::sample(&mut rng));
        match (my_message.clone(), is_sender) {
            (Some(message), true) => {
                bcast_data.insert(my_role, message.clone());
                round1_data.insert(my_role, bcast_data[&my_role].clone());
                for other_role in session.roles().iter() {
                    if my_role != *other_role && *other_role != role_to_lie_to {
                        let msg = NetworkValue::Send(message.clone());
                        session
                            .network()
                            .send(Arc::new(msg.to_network()), other_role)
                            .await?;
                    } else if *other_role == role_to_lie_to {
                        let msg = NetworkValue::Send(random_message.clone());
                        session
                            .network()
                            .send(Arc::new(msg.to_network()), other_role)
                            .await?;
                    }
                }
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ));
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_contribution_from_all_senders(
            &mut round1_data,
            session,
            senders,
            &mut non_answering_parties,
        )
        .await?;

        // Communication round 2
        // Parties send Echo to the other parties, lying in the same way as for the original send
        session.network().increase_round_counter().await;
        let mut msg_to_victim = round1_data.clone();
        msg_to_victim.insert(my_role, random_message.clone());
        let msg_to_others = round1_data.clone();
        for other_role in session.roles().iter() {
            if my_role != *other_role && *other_role != role_to_lie_to {
                let msg = NetworkValue::EchoBatch(msg_to_others.clone());
                session
                    .network()
                    .send(Arc::new(msg.to_network()), other_role)
                    .await?;
            } else if *other_role == role_to_lie_to {
                let msg = NetworkValue::EchoBatch(msg_to_victim.clone());
                session
                    .network()
                    .send(Arc::new(msg.to_network()), other_role)
                    .await?;
            }
        }
        let msg = msg_to_others;
        // adding own echo to the map
        let echos: HashMap<(Role, BroadcastValue<Z>), HashSet<Role>> = msg
            .iter()
            .map(|(k, v)| ((*k, v.clone()), HashSet::from([my_role])))
            .collect();
        // retrieve echos from all parties
        let _ = receive_echos_from_all_batched(session, &mut non_answering_parties, echos).await?;

        //Stop voting now
        Ok(round1_data)
    }
}

/// Malicious implementation of the [`Broadcast`] protocol where the
/// party (P_i), when acting as the sender, honestly broadcasts a random message (of the same variant) instead of its prescribed input
#[derive(Default, Clone)]
pub struct MaliciousBroadcastRandomizer {}

impl ProtocolDescription for MaliciousBroadcastRandomizer {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousBroadcastRandomizer")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastRandomizer {
    fn num_rounds(num_parties: usize, threshold: usize) -> usize {
        SyncReliableBroadcast::num_rounds(num_parties, threshold)
    }

    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &mut B,
        senders: &HashSet<Role>,
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        let rng = session.rng();
        let my_message = my_message.map(|value| match value {
            BroadcastValue::Bot => BroadcastValue::Bot,
            BroadcastValue::RingVector(items) => {
                BroadcastValue::RingVector(items.into_iter().map(|_| Z::sample(rng)).collect())
            }
            BroadcastValue::RingValue(_) => BroadcastValue::RingValue(Z::sample(rng)),
            BroadcastValue::PRSSVotes(items) => BroadcastValue::PRSSVotes(
                items
                    .into_iter()
                    .map(|v| (v.0, v.1.iter().map(|_| Z::sample(rng)).collect()))
                    .collect(),
            ),
            BroadcastValue::Round2VSS(items) => BroadcastValue::Round2VSS(
                items
                    .into_iter()
                    .map(|v| {
                        v.into_iter()
                            .map(|v| {
                                v.into_iter()
                                    .map(|_| (Z::sample(rng), Z::sample(rng)))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect(),
            ),
            BroadcastValue::Round3VSS(btree_map) => BroadcastValue::Round3VSS(
                btree_map
                    .into_iter()
                    .map(|(role, vec_of_vec)| {
                        (
                            role,
                            vec_of_vec.into_iter().map(|_| Z::sample(rng)).collect(),
                        )
                    })
                    .collect(),
            ),
            BroadcastValue::Round4VSS(btree_map) => BroadcastValue::Round4VSS(
                btree_map
                    .into_iter()
                    .map(|(role, val_or_poly)| {
                        (
                            role,
                            match val_or_poly {
                                ValueOrPoly::Value(items) => ValueOrPoly::Value(
                                    items.into_iter().map(|_| Z::sample(rng)).collect(),
                                ),
                                ValueOrPoly::Poly(items) => ValueOrPoly::Poly(
                                    items
                                        .into_iter()
                                        .map(|poly| {
                                            Poly::from_coefs(
                                                poly.coefs()
                                                    .iter()
                                                    .map(|_| Z::sample(rng))
                                                    .collect(),
                                            )
                                        })
                                        .collect(),
                                ),
                            },
                        )
                    })
                    .collect(),
            ),
            BroadcastValue::LocalSingleShare(batch) => BroadcastValue::LocalSingleShare(
                batch
                    .into_iter()
                    .map(|maps_shares_challenges| {
                        let MapsSharesChallenges {
                            checks_for_all,
                            checks_for_mine,
                        } = maps_shares_challenges;
                        let new_checks_for_all = checks_for_all
                            .into_keys()
                            .map(|role| (role, Z::sample(rng)))
                            .collect();
                        let new_checks_for_mine = checks_for_mine
                            .into_keys()
                            .map(|role| (role, Z::sample(rng)))
                            .collect();
                        MapsSharesChallenges {
                            checks_for_all: new_checks_for_all,
                            checks_for_mine: new_checks_for_mine,
                        }
                    })
                    .collect(),
            ),
            BroadcastValue::LocalDoubleShare(batch) => BroadcastValue::LocalDoubleShare(
                batch
                    .into_iter()
                    .map(|(map_1, map_2, map_3, map_4)| {
                        (
                            map_1
                                .into_keys()
                                .map(|role| (role, Z::sample(rng)))
                                .collect(),
                            map_2
                                .into_keys()
                                .map(|role| (role, Z::sample(rng)))
                                .collect(),
                            map_3
                                .into_keys()
                                .map(|role| (role, Z::sample(rng)))
                                .collect(),
                            map_4
                                .into_keys()
                                .map(|role| (role, Z::sample(rng)))
                                .collect(),
                        )
                    })
                    .collect(),
            ),
            BroadcastValue::PartialProof(_partial_proof) => {
                todo!("Non trivial to randomize")
            }
            BroadcastValue::MapRingVector(btree_map) => BroadcastValue::MapRingVector(
                btree_map
                    .into_iter()
                    .map(|(role, vec)| (role, vec.into_iter().map(|_| Z::sample(rng)).collect()))
                    .collect(),
            ),
        });
        SyncReliableBroadcast::default()
            .execute(session, senders, my_message)
            .await
    }
}

/// Malicious implementation of the [`Broadcast`] protocol that tries to exploit a
/// missing *per-voter* deduplication in the vote-counting logic.
///
/// Each colluding party equivocates on its own sender slot in round 1 (sending a
/// different random value to every party, like [`MaliciousBroadcastSender`]) so
/// that no honest value for that slot ever reaches the `n - t` echo threshold — a
/// correct protocol therefore outputs `Bot` for it and flags the sender as
/// corrupt. The coalition then *injects* a fixed `phantom` value into each
/// `target` slot: it echoes the phantom (so honest parties learn its pre-image,
/// but with only `t` echoes it is never *registered*), and, crucially, it
/// re-broadcasts a vote for `(target, hash(phantom))` in *every* one of the
/// `threshold + 1` voting rounds.
///
/// If votes were tallied by `(sender, value)` with no record of *who* voted,
/// every re-sent copy is counted: `t` colluding parties contribute up to
/// `t * (t + 1)` votes for the phantom — enough to cross the `n - t` delivery
/// threshold (for `t >= 2`, e.g. `n = 7, t = 2`). Honest parties then deliver the
/// phantom for a slot that no honest party legitimately voted for, so the
/// equivocating senders would evade `Bot`/corruption detection and agreement is
/// violated. This would make the protocol's correctness assertion fail.
#[derive(Clone)]
pub struct MaliciousBroadcastDoubleVote {
    /// Sender slots to inject the phantom value into. In the coalition setting
    /// these are the malicious parties' own (equivocated) slots.
    pub targets: HashSet<Role>,
}

impl ProtocolDescription for MaliciousBroadcastDoubleVote {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousBroadcastDoubleVote")
    }
}

#[async_trait]
impl Broadcast for MaliciousBroadcastDoubleVote {
    fn num_rounds(num_parties: usize, threshold: usize) -> usize {
        SyncReliableBroadcast::num_rounds(num_parties, threshold)
    }

    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &mut B,
        senders: &HashSet<Role>,
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        if senders.is_empty() {
            return Err(anyhow_error_and_log(
                "We expect at least one party as sender in reliable broadcast".to_string(),
            ));
        }
        let threshold = session.threshold() as usize;
        let my_role = session.my_role();
        let is_sender = senders.contains(&my_role);
        let mut non_answering_parties = HashSet::new();

        // The value the coalition injects into every target slot: a fixed, non-Bot
        // constant whose pre-image we make available through our Echo messages.
        let phantom = BroadcastValue::from(Z::ONE);
        assert_ne!(
            my_message,
            Some(phantom.clone()),
            "The phantom must be distinct from the input for this strategy to be malicious"
        );
        let phantom_hash = phantom.to_bcast_hash()?;

        // ---- Round 1 (Send): equivocate — send a different random value to each
        // party, so no single value for our own slot reaches n - t echoes. We stay
        // "answering", so honest parties keep counting our echoes and votes. ----
        let mut round1_contributions = HashMap::<Role, BroadcastValue<Z>>::new();
        session.network().increase_round_counter().await;
        let mut rng = AesRng::from_random_seed();
        match (my_message, is_sender) {
            (Some(message), true) => {
                round1_contributions.insert(my_role, message);
                for other_role in session.roles().iter() {
                    if my_role != *other_role {
                        let malicious_msg =
                            NetworkValue::Send(BroadcastValue::from(Z::sample(&mut rng)));
                        session
                            .network()
                            .send(Arc::new(malicious_msg.to_network()), other_role)
                            .await?;
                    }
                }
            }
            (None, false) => (),
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ));
            }
        }
        receive_contribution_from_all_senders(
            &mut round1_contributions,
            session,
            senders,
            &mut non_answering_parties,
        )
        .await?;

        // ---- Round 2 (Echo): announce the phantom for every target slot so honest
        // parties store its pre-image. Only the malicious coalition echoes it (< n - t), so it
        // is never *registered* from echoes — it is forced through via votes. ----
        let mut echo_batch = round1_contributions;
        for target in self.targets.iter() {
            echo_batch.insert(*target, phantom.clone());
        }
        let to_send = NetworkValue::EchoBatch(echo_batch);
        send_to_all(session, &to_send).await?;
        let _ = receive_echos_from_all_batched::<Z, B>(
            session,
            &mut non_answering_parties,
            HashMap::new(),
        )
        .await?;

        // ---- Vote phase: THE EXPLOIT. ----
        // Honest parties emit exactly `threshold + 1` vote messages (one initial
        // cast + `threshold` amplification casts). We match that count exactly to
        // stay in round-sync, but we re-send the same votes for every target slot
        // every time. With no per-voter dedup, each
        // copy is counted, inflating the tally past `n - t`.
        let mut inflated_vote = HashMap::new();
        for target in self.targets.iter() {
            inflated_vote.insert(*target, phantom_hash);
        }
        for _ in 0..=threshold {
            let msg: NetworkValue<Z> = NetworkValue::VoteBatch(inflated_vote.clone());
            send_to_all(session, &msg).await?;
        }

        // The attacker does not care about its own output.
        Ok(RoleValueMap::new())
    }
}
