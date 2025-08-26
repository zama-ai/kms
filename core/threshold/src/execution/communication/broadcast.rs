use super::p2p::{generic_receive_from_all, generic_receive_from_all_senders, send_to_all};
use crate::algebra::structure_traits::Ring;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::Role;
use crate::execution::runtime::session::BaseSessionHandles;
use crate::execution::runtime::session::DeSerializationRunTime;
use crate::networking::value::BcastHash;
use crate::networking::value::BroadcastValue;
use crate::networking::value::NetworkValue;
use crate::thread_handles::spawn_compute_bound;
use crate::ProtocolDescription;
use std::collections::{HashMap, HashSet};
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;
use tonic::async_trait;
use tracing::instrument;

pub(crate) type RoleValueMap<Z> = HashMap<Role, BroadcastValue<Z>>;
type SendEchoJobType<Z> = (Role, anyhow::Result<RoleValueMap<Z>>);
type VoteJobType = (Role, anyhow::Result<HashMap<Role, BcastHash>>);
type GenericEchoVoteJob<T> = JoinSet<Result<(Role, anyhow::Result<HashMap<Role, T>>), Elapsed>>;

#[async_trait]
pub trait Broadcast: ProtocolDescription + Send + Sync + Clone {
    /// Execution of the _regular_ protocol, must be defined for all structs implementing this trait.
    ///
    /// Takes an `sender_list`, an explicit list of all the senders
    /// and `my_message` the message to broadcat if the current party is a sender.
    ///
    /// __NOTE__: This function will try to interact with parties that are already considered malicious
    /// and does __NOT__ mutate the corrupt set even it finds a malicious sender.
    /// Use [`Broadcast::broadcast_w_corrupt_set_update`] to ignore known corrupt parties and update
    /// the malicious set with malicious senders.
    async fn execute<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &mut B,
        senders: &HashSet<Role>,
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>>;

    /// Blanket implementation that relies on [`Self::execute`].
    /// **All** parties Pi want to **reliably** broadcast a message to all the other parties
    ///
    /// Function returns a map bcast_data: Role => Value such that
    /// all players have the broadcasted values inside the map: bcast_data\[Pj] = message_j for all j in [n].
    /// This function does not handle corrupt parties.
    ///
    /// __NOTE__: This function will try to interact with parties that are already considered malicious
    /// and does __NOT__ mutate the corrupt set even it finds a malicious sender.
    /// Use [`Broadcast::broadcast_from_all_w_corrupt_set_update`] to ignore known corrupt parties and update
    /// the malicious set with malicious senders.
    async fn broadcast_from_all<Z: Ring, B: BaseSessionHandles>(
        &self,
        session: &mut B,
        my_message: BroadcastValue<Z>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        self.execute(session, session.roles(), Some(my_message))
            .await
    }

    /// Blanket implementation that relies on Self implementation of [`Broadcast::execute`].
    /// Executes a [`Broadcast::broadcast_from_all`] with parties in `corrupt_roles`
    /// ignored during the execution and any new corruption detected is added to `corrupt_roles` of the session.
    /// The current party sends `my_message`.
    ///
    /// This corresponds to the "modified" version of the protocol in the NIST document.
    ///
    /// WARNING: It is CRUCIAL that the corrupt roles are ignored, as otherwise they could cause a DoS attack with the current logic of the functions using this method.
    async fn broadcast_from_all_w_corrupt_set_update<Z: Ring, Ses: BaseSessionHandles>(
        &self,
        session: &mut Ses,
        my_message: BroadcastValue<Z>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        self.broadcast_w_corrupt_set_update(session, session.roles().clone(), Some(my_message))
            .await
    }

    /// Blanket implementation that relies on Self implementation of [`Broadcast::execute`].
    /// Executes a broadcast with all parties in `senders` acting as senders
    /// and parties in `corrupt_roles`
    /// ignored during the execution and any new corruption detected is added to `corrupt_roles` of the session.
    /// If the current party is in `senders`, it broadcasts `my_message`.
    ///
    /// This corresponds to the "modified" version of the protocol in the NIST document.
    ///
    /// WARNING: It is CRUCIAL that the corrupt roles are ignored, as otherwise they could cause a DoS attack with the current logic of the functions using this method.
    #[instrument(name= "Syn-Bcast-Corrupt",skip(self,session,senders,my_message),fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
    async fn broadcast_w_corrupt_set_update<Z: Ring, Ses: BaseSessionHandles>(
        &self,
        session: &mut Ses,
        senders: HashSet<Role>,
        my_message: Option<BroadcastValue<Z>>,
    ) -> anyhow::Result<RoleValueMap<Z>> {
        // Remove corrupt parties from the current session and from the sender list
        let known_corrupt = session.corrupt_roles();

        let old_roles = session.roles().clone();
        let mut new_roles = session.roles().clone();
        known_corrupt.iter().for_each(|r| {
            tracing::warn!("I'm {:?}, removing corrupt player {r}", session.my_role());
            new_roles.remove(r);
        });

        let senders_without_corrupt = senders
            .into_iter()
            .filter(|role| !known_corrupt.contains(role))
            .collect::<HashSet<_>>();

        *session.roles_mut() = new_roles;

        let mut broadcast_res = self
            .execute(session, &senders_without_corrupt, my_message)
            .await?;

        *session.roles_mut() = old_roles;

        // Add bot for the parties which were already corrupt before the bcast
        for role in session.corrupt_roles() {
            broadcast_res.insert(*role, BroadcastValue::Bot);
        }

        // Note that the sender list is computed at the start
        // which differs depending on the broadcast type
        for role in senders_without_corrupt {
            // Small optimization: the corrupt senders can be skipped
            // But we already removed the known corrupt parties, so can't happen.
            if session.corrupt_roles().contains(&role) {
                continue;
            }

            // Each party that was supposed to broadcast but where the parties did not consistently agree on the result
            // is added to the set of corrupt parties
            if let BroadcastValue::Bot = broadcast_res.get(&role).ok_or_else(|| {
                anyhow_error_and_log(format!("Cannot find {role} in broadcast's result."))
            })? {
                session.add_corrupt(role);
            }
        }
        Ok(broadcast_res)
    }
}

#[derive(Default, Clone)]
/// Implements the synchronous broadcast protocol defined in the NIST document
pub struct SyncReliableBroadcast {}

impl ProtocolDescription for SyncReliableBroadcast {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-SyncReliableBroadcast")
    }
}

/// Receives the contribution from all the senders in parallel
///
/// Inputs are:
/// - a mutable map (Role, Value) to store the contributions
/// - current network session
/// - role of current party
/// - the list of expected senders
/// - a mutable set of non answering parties
pub(crate) async fn receive_contribution_from_all_senders<Z: Ring, B: BaseSessionHandles>(
    round1_data: &mut RoleValueMap<Z>,
    session: &B,
    receiver: &Role,
    senders: &HashSet<Role>,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<()> {
    let mut jobs = JoinSet::<Result<(Role, anyhow::Result<BroadcastValue<Z>>), Elapsed>>::new();
    // The error we propagate here is if sender IDs and roles cannot be tied together.
    generic_receive_from_all_senders(
        &mut jobs,
        session,
        receiver,
        senders,
        Some(non_answering_parties),
        |msg, id| match msg {
            NetworkValue::Send(v) => Ok(v),
            NetworkValue::EchoBatch(_) => Err(anyhow_error_and_log(format!(
                "I have received an Echo batch instead of a Send message on party: {id:?}"
            ))),
            _ => Err(anyhow_error_and_log(format!(
                "I am {id:?} have received sth different from Send message \n Received {msg:?}"
            ))),
        },
    )
    .await;

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
    for party_id in senders {
        if !answering_parties.contains(party_id) && party_id != receiver {
            non_answering_parties.insert(*party_id);
            tracing::warn!("(Bcast Round1) I am {receiver}, haven't heard from {party_id}");
        }
    }
    Ok(())
}

/// Receives the echo round from all parties, for all the parallel bcast
///
/// Inputs are:
/// - current network session
/// - role of current party
/// - a mutable set of non answering parties
/// - a mutable set to count the number of echos
///
/// Output is:
///  - a Map from (Role, Hash(contribution)) to (contribution, 1) with an entry __IFF__ there was enough echo for this particular contribution
pub(crate) async fn receive_echos_from_all_batched<Z: Ring, B: BaseSessionHandles>(
    session: &B,
    receiver: &Role,
    non_answering_parties: &mut HashSet<Role>,
    echoed_data: HashMap<(Role, BroadcastValue<Z>), u32>,
) -> anyhow::Result<(
    HashMap<(Role, BcastHash), u32>,
    HashMap<(Role, BcastHash), BroadcastValue<Z>>,
)> {
    //Receiving from every parties as everyone can send an echo
    let mut jobs = JoinSet::<Result<SendEchoJobType<Z>, Elapsed>>::new();
    generic_receive_from_all(
        &mut jobs,
        session,
        receiver,
        Some(non_answering_parties),
        |msg, id| match msg {
            NetworkValue::EchoBatch(v) => Ok(v),
            NetworkValue::Empty => Ok(RoleValueMap::new()),
            _ => Err(anyhow_error_and_log(format!(
                "I have received sth different from an Echo Batch message on party: {id:?}",
            ))),
        },
    )
    .await;

    //Process all the messages we just received, looking for values we can vote for
    process_echos(
        receiver,
        &mut jobs,
        echoed_data,
        session.num_parties(),
        session.threshold() as usize,
        non_answering_parties,
    )
    .await
}

/// Receives the votes from all parties, for all the parallel bcast
///
/// Inputs are:
/// - a mutable set of jobs used to retrieve the answers by the caller
/// - current network session
/// - role of current party
/// - a set of non answering parties that we wont try to receive from
///
async fn receive_from_all_votes<Z: Ring, B: BaseSessionHandles>(
    jobs: &mut JoinSet<Result<VoteJobType, Elapsed>>,
    session: &B,
    receiver: &Role,
    non_answering_parties: &HashSet<Role>,
) {
    generic_receive_from_all(
        jobs,
        session,
        receiver,
        Some(non_answering_parties),
        |msg: NetworkValue<Z>, id| match msg {
            NetworkValue::VoteBatch(v) => Ok(v),
            NetworkValue::Empty => Ok(HashMap::new()),
            _ => Err(anyhow_error_and_log(format!(
                "I have received sth different from an Vote Batch message on party: {id:?}"
            ))),
        },
    )
    .await
}

///Update the vote counts for each (sender, value) by processing the echos or votes from all the other parties
async fn internal_process_echos_or_votes<T>(
    receiver: &Role,
    rcv_tasks: &mut GenericEchoVoteJob<T>,
    map_data: &mut HashMap<(Role, T), u32>,
    num_parties: usize,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<()>
where
    T: std::fmt::Debug + Eq + std::hash::Hash + Clone + 'static,
{
    // Receiving Echo or Vote messages one by one
    let mut answering_parties = HashSet::<Role>::new();
    while let Some(v) = rcv_tasks.join_next().await {
        let task_out = v?;
        // if no timeout error then we count it towards casting a vote
        if let Ok((from_party, data)) = task_out {
            answering_parties.insert(from_party);
            //Each message we receive is a Map from Sender Roles to claimed contributions
            if let Ok(rcv_vote_or_echo) = data {
                debug_assert!(rcv_vote_or_echo.len() <= num_parties);
                // iterate through the echo batched message and check the frequency of each message
                rcv_vote_or_echo.into_iter().for_each(|(role, m)| {
                    let entry = map_data.entry((role, m)).or_insert(0);
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
        if !answering_parties.contains(&Role::indexed_from_one(party_id))
            && party_id != receiver.one_based()
        {
            non_answering_parties.insert(Role::indexed_from_one(party_id));
            tracing::warn!("(Process echos) I am {receiver} haven't heard from {party_id}");
        }
    }
    Ok(())
}

/// Process Echo messages one by one, starting with the own echoed_data
/// If enough echoes >=(N-T) then party can cast a vote
async fn process_echos<Z: Ring>(
    receiver: &Role,
    echo_recv_tasks: &mut JoinSet<Result<SendEchoJobType<Z>, Elapsed>>,
    mut echoed_data: HashMap<(Role, BroadcastValue<Z>), u32>,
    num_parties: usize,
    threshold: usize,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<(
    HashMap<(Role, BcastHash), u32>,
    HashMap<(Role, BcastHash), BroadcastValue<Z>>,
)> {
    internal_process_echos_or_votes(
        receiver,
        echo_recv_tasks,
        &mut echoed_data,
        num_parties,
        non_answering_parties,
    )
    .await?;

    let (registered_vote, map_hash_to_value) = spawn_compute_bound(move || {
        let mut registered_votes = HashMap::new();
        let mut map_hash_to_value = HashMap::new();
        //Any entry with at least N-t times is good for a vote
        for ((role, m), num_entries) in echoed_data.into_iter() {
            let hash = m.to_bcast_hash().map_err(|e| {
                anyhow::anyhow!("Failed to compute broadcast hash for role {}: {}", role, e)
            })?;
            map_hash_to_value.insert((role, hash), m);
            if num_entries >= ((num_parties - threshold) as u32) {
                registered_votes.insert((role, hash), 1);
            }
        }
        Ok::<_, anyhow::Error>((registered_votes, map_hash_to_value))
    })
    .await??;
    Ok((registered_vote, map_hash_to_value))
}

/// Sender casts a vote only for messages m in registered_votes for which numbers of votes >= threshold
///
/// __NOTE__:  We vote using the Hash of the broadcast value
pub(crate) async fn cast_threshold_vote<Z: Ring, B: BaseSessionHandles>(
    session: &B,
    sender: &Role,
    registered_votes: &HashMap<(Role, BcastHash), u32>,
    threshold: u32,
) -> anyhow::Result<()> {
    let vote_data: HashMap<Role, BcastHash> = registered_votes
        .iter()
        .filter_map(|(k, f)| {
            if *f >= threshold {
                Some((k.0, k.1))
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
        send_to_all(session, sender, NetworkValue::<Z>::VoteBatch(vote_data)).await?;
    }
    Ok(())
}

/// For threshold rounds, look at the votes we have received, and cast a vote if needed
///
/// If enough votes >=(T+R) and sender hasn't voted then vote
pub(crate) async fn gather_votes<Z: Ring, B: BaseSessionHandles>(
    session: &B,
    sender: &Role,
    registered_votes: &mut HashMap<(Role, BcastHash), u32>,
    casted: &mut HashMap<Role, bool>,
    non_answering_parties: &mut HashSet<Role>,
) -> anyhow::Result<()> {
    let num_parties = session.num_parties();
    let threshold = session.threshold() as usize;

    // wait for other parties' incoming vote
    for round in 1..=threshold + 1 {
        let mut vote_recv_tasks = JoinSet::new();

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_from_all_votes::<Z, B>(
            &mut vote_recv_tasks,
            session,
            sender,
            non_answering_parties,
        )
        .await;
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
        let mut round_registered_votes = HashMap::new();
        for ((role, m), num_votes) in registered_votes.iter_mut() {
            if *num_votes as usize >= (threshold + round)
                && !*(casted.get(role).ok_or_else(|| {
                    anyhow_error_and_log("Cant retrieve whether I casted a vote".to_string())
                })?)
            {
                round_registered_votes.insert((*role, *m), *num_votes);
                //Remember I casted a vote
                let casted_vote_role = casted.get_mut(role).ok_or_else(|| {
                    anyhow_error_and_log("Can't retrieve whether I casted a vote".to_string())
                })?;
                *casted_vote_role = true;
                //Also add a vote in my own data struct
                *num_votes += 1;
            }
        }
        cast_threshold_vote::<Z, B>(
            session,
            sender,
            &round_registered_votes,
            (threshold + round) as u32,
        )
        .await?;
    }
    Ok(())
}

#[async_trait]
impl Broadcast for SyncReliableBroadcast {
    #[instrument(name= "Syn-Bcast",skip(self,session,senders,my_message),fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
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

        let threshold = session.threshold() as usize;
        if num_parties <= threshold {
            return Err(anyhow_error_and_log(format!(
                "The number of parties {num_parties} is less or equal to the threshold {threshold}"
            )));
        }
        let min_honest_nodes = num_parties as u32 - threshold as u32;

        let my_role = session.my_role();
        let is_sender = senders.contains(&my_role);
        let mut bcast_data: RoleValueMap<Z> = senders
            .iter()
            .map(|role| (*role, BroadcastValue::Bot))
            .collect();

        let mut non_answering_parties = HashSet::<Role>::new();

        // Communication round 1
        // Sender parties send the message they intend to broadcast to others
        // The send calls are followed by receive to get the incoming messages from the others
        let mut round1_contributions = HashMap::<Role, BroadcastValue<Z>>::new();
        match (my_message, is_sender) {
            (Some(my_message), true) => {
                bcast_data.insert(my_role, my_message.clone());
                let msg = NetworkValue::Send(my_message);
                send_to_all(session, &my_role, &msg).await?;
                let msg = match msg {
                    NetworkValue::Send(v) => v,
                    _ => panic!("Bug here, we just wrapped send into Send"),
                };
                round1_contributions.insert(my_role, msg);
            }
            (None, false) => {
                session.network().increase_round_counter().await; // We're not sending, but we must increase the round counter to stay in sync
            }
            (_, _) => {
                return Err(anyhow_error_and_log(
                    "A sender must have a value in reliable broadcast".to_string(),
                ));
            }
        }

        // The error we propagate here is if sender IDs and roles cannot be tied together.
        receive_contribution_from_all_senders(
            &mut round1_contributions,
            session,
            &my_role,
            senders,
            &mut non_answering_parties,
        )
        .await?;

        // Communication round 2
        // Parties send Echo to the other parties
        let to_send = NetworkValue::EchoBatch(round1_contributions);
        send_to_all(session, &my_role, &to_send).await?;
        let round1_contributions = match to_send {
            NetworkValue::EchoBatch(v) => v,
            _ => panic!("Bug here, we just wrapped send into EchoBatch"),
        };

        // Parties receive Echo from others and process them,
        // if there are enough Echo messages then they will cast a vote in subsequent rounds
        // adding own echo to the map
        let echos_count: HashMap<(Role, BroadcastValue<Z>), u32> = round1_contributions
            .into_iter()
            .map(|(k, v)| ((k, v), 1))
            .collect();
        // receive echos from all parties,
        // updates the echos_count and outputs the values I should vote for
        let (mut registered_votes, mut map_hash_to_value) = receive_echos_from_all_batched(
            session,
            &my_role,
            &mut non_answering_parties,
            echos_count,
        )
        .await?;

        // Communication round 3 onward
        // We are only exchanging hashes at this point, so we use the tokio runtime for deserialization
        let old_deser_runtime = session.get_deserialization_runtime();
        session.set_deserialization_runtime(DeSerializationRunTime::Tokio);
        // Parties try to cast the vote if received enough Echo messages (i.e. can_vote is true)
        // Here propagate error if my own casted hashmap does not contain the expected party's id
        let mut casted_vote: HashMap<Role, bool> =
            senders.iter().map(|role| (*role, false)).collect();

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
        for ((role, hash), hits) in registered_votes.into_iter() {
            if hits >= min_honest_nodes {
                //Retrieve the actual data from the hash
                let value = map_hash_to_value.remove(&(role, hash)).ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "Can't retrieve the value from the hash in broadcast. Role {role}.",
                    ))
                })?;

                bcast_data.insert(role, value);
            }
        }
        // Set back the old runtime
        session.set_deserialization_runtime(old_deser_runtime);
        Ok(bcast_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z128;
    use crate::algebra::structure_traits::{ErrorCorrect, Invert};
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::runtime::test_runtime::{generate_fixed_roles, DistributedTestRuntime};
    use crate::execution::small_execution::prf::PRSSConversions;
    #[cfg(feature = "slow_tests")]
    use crate::malicious_execution::communication::malicious_broadcast::MaliciousBroadcastSenderEcho;
    use crate::malicious_execution::communication::malicious_broadcast::{
        MaliciousBroadcastDrop, MaliciousBroadcastSender,
    };
    use crate::networking::NetworkMode;
    use crate::session_id::SessionId;
    use crate::tests::helper::tests::{execute_protocol_small_w_malicious, TestingParameters};
    use itertools::Itertools;

    fn legitimate_broadcast<Z: Ring, const EXTENSION_DEGREE: usize>(
        senders: &HashSet<Role>,
    ) -> (HashSet<Role>, Vec<BroadcastValue<Z>>, Vec<RoleValueMap<Z>>) {
        let num_parties = 4;
        let roles = generate_fixed_roles(num_parties);
        let session_id = SessionId::from(1);

        let input_values = vec![
            BroadcastValue::from(Z::ONE),
            BroadcastValue::from(Z::ONE + Z::ONE),
            BroadcastValue::from(Z::ONE + Z::ONE + Z::ONE),
            BroadcastValue::from(Z::ONE + Z::ONE + Z::ONE + Z::ONE),
        ];

        // code for session setup
        let threshold = 1;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        //Broadcast assumes Sync network
        let test_runtime = DistributedTestRuntime::<Z, EXTENSION_DEGREE>::new(
            roles.clone(),
            threshold,
            NetworkMode::Sync,
            None,
        );

        for (party, my_data) in roles.iter().sorted().zip(input_values.iter().cloned()) {
            let mut session = test_runtime.base_session_for_party(session_id, *party, None);
            if roles.len() == senders.len() {
                set.spawn(async move {
                    SyncReliableBroadcast::default()
                        .broadcast_from_all(&mut session, my_data)
                        .await
                        .unwrap()
                });
            }
        } else {
            for (party_no, my_data) in input_values.iter().cloned().enumerate() {
                let mut session = test_runtime.base_session_for_party(session_id, party_no, None);
                let sender_list = sender_parties.to_vec();
                if sender_parties.contains(&Role::indexed_from_zero(party_no)) {
                    set.spawn(async move {
                        SyncReliableBroadcast::default()
                            .execute(&mut session, &sender_list, Some(my_data))
                            .await
                            .unwrap()
                    });
                } else {
                    None
                };
                set.spawn(async move {
                    SyncReliableBroadcast::default()
                        .execute(&mut session, &senders, msg)
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

        (roles, input_values, results)
    }

    #[test]
    fn test_broadcast_all() {
        let senders = generate_fixed_roles(4);
        let (roles, input_values, results) = legitimate_broadcast::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(&senders);

        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), roles.len());

        // check that each party has received the same output
        for i in 1..roles.len() {
            assert_eq!(results[0], results[i]);
        }

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_from_zero(0)], input_values[0]);
        assert_eq!(results[0][&Role::indexed_from_zero(1)], input_values[1]);
        assert_eq!(results[0][&Role::indexed_from_zero(2)], input_values[2]);
        assert_eq!(results[0][&Role::indexed_from_zero(3)], input_values[3]);
    }

    #[test]
    fn test_broadcast_p3() {
        let senders = HashSet::from([Role::indexed_from_zero(3)]);
        let (roles, input_values, results) = legitimate_broadcast::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(&senders);

        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), roles.len());

        // check that each party has received the same output
        for i in 1..roles.len() {
            assert_eq!(results[0], results[i]);
        }

        assert!(!results[0].contains_key(&Role::indexed_from_zero(0)));
        assert!(!results[0].contains_key(&Role::indexed_from_zero(1)));
        assert!(!results[0].contains_key(&Role::indexed_from_zero(2)));
        assert!(results[0].contains_key(&Role::indexed_from_zero(3)));

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_from_zero(3)], input_values[3]);
    }
    #[test]
    fn test_broadcast_p0_p2() {
        let senders = HashSet::from([Role::indexed_from_one(1), Role::indexed_from_one(3)]);
        let (roles, input_values, results) = legitimate_broadcast::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(&senders);
        // check that we have exactly n bcast outputs, for each party
        assert_eq!(results.len(), roles.len());

        // check that each party has received the same output
        for i in 1..roles.len() {
            assert_eq!(results[0], results[i]);
        }

        // contains party P1
        assert!(results[0].contains_key(&Role::indexed_from_one(1)));
        assert!(!results[0].contains_key(&Role::indexed_from_one(2)));
        assert!(results[0].contains_key(&Role::indexed_from_one(3)));
        assert!(!results[0].contains_key(&Role::indexed_from_one(4)));

        // check output from first party, as they are all equal
        assert_eq!(results[0][&Role::indexed_from_zero(0)], input_values[0]);
        assert_eq!(results[0][&Role::indexed_from_zero(2)], input_values[2]);
    }

    /// Generic function to test malicious broadcast strategies.
    /// Executes [`Broadcast::broadcast_from_all_w_corrupt_set_update`]
    /// as that is the more genreal version of broadcast
    async fn test_broadcast_from_all_w_corrupt_set_update_strategies<
        Z: ErrorCorrect + Invert + PRSSConversions,
        const EXTENSION_DEGREE: usize,
        B: Broadcast + 'static,
    >(
        params: TestingParameters,
        malicious_broadcast: B,
    ) {
        let mut task_honest = |mut session: SmallSession<Z>| async move {
            let real_broadcast = SyncReliableBroadcast::default();
            let my_data = BroadcastValue::from(Z::sample(session.rng()));
            (
                my_data.clone(),
                real_broadcast
                    .broadcast_from_all_w_corrupt_set_update(&mut session, my_data)
                    .await
                    .unwrap(),
                session.corrupt_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: SmallSession<Z>, malicious_broadcast: B| async move {
            let my_data = BroadcastValue::from(Z::sample(session.rng()));
            (
                my_data.clone(),
                malicious_broadcast
                    .broadcast_from_all_w_corrupt_set_update(&mut session, my_data)
                    .await,
                session.corrupt_roles().clone(),
            )
        };

        let (results_honest, results_malicious) =
            execute_protocol_small_w_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.malicious_roles,
                malicious_broadcast,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            )
            .await;

        //Assert malicious parties we shouldve been caught indeed are
        if params.should_be_detected {
            for (_, (_, _, corrupt_set)) in results_honest.iter() {
                for role in params.malicious_roles.iter() {
                    assert!(corrupt_set.contains(role));
                }
            }
        }

        //Check that result is correct
        let mut collected_results: RoleValueMap<Z> = results_honest
            .iter()
            .map(|(role, (data, _, _))| (*role, data.clone()))
            .collect();
        if !params.should_be_detected {
            results_malicious.iter().for_each(|(role, data)| {
                if let Ok((data, _, _)) = data {
                    collected_results.insert(*role, data.clone());
                }
            })
        } else {
            params.malicious_roles.iter().for_each(|role| {
                let _ = collected_results.insert(*role, BroadcastValue::Bot);
            });
        }

        for (role, (_, protocol_result, _)) in results_honest.iter() {
            assert_eq!(
                collected_results, *protocol_result,
                "Party {role} doesnt agree with the collected results. Output {protocol_result:?} expected {collected_results:?}"
            );
        }

        if !params.should_be_detected {
            results_malicious.iter().for_each(|(role, result)| {
                if let Ok((_,result,_)) = result {

                let result = result.as_ref().unwrap();
                assert_eq!(*result, collected_results, "Malicious but undetected party {role} doesnt agree with the collected results. Output {result:?} expected {collected_results:?}");
                }
            });
        }
    }

    #[tokio::test]
    async fn test_honest_broadcast() {
        let malicious_strategy = SyncReliableBroadcast::default();
        let params = TestingParameters::init(4, 1, &[], &[], &[], false, Some(1 + 3));

        test_broadcast_from_all_w_corrupt_set_update_strategies::<ResiduePolyF4Z128, 4, _>(
            params,
            malicious_strategy,
        )
        .await;
    }

    #[tokio::test]
    async fn test_dropout_broadcast() {
        let malicious_strategy = MaliciousBroadcastDrop::default();
        let params = TestingParameters::init(4, 1, &[0], &[], &[], true, Some(1 + 3));

        test_broadcast_from_all_w_corrupt_set_update_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
        >(params, malicious_strategy)
        .await;
    }

    #[tokio::test]
    async fn test_malicious_sender_broadcast() {
        let malicious_strategy = MaliciousBroadcastSender::default();
        let params = TestingParameters::init(4, 1, &[0], &[], &[], true, Some(1 + 3));

        test_broadcast_from_all_w_corrupt_set_update_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
        >(params, malicious_strategy)
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn test_malicious_sender_echo_broadcast() {
        let malicious_strategy = MaliciousBroadcastSenderEcho::default();
        let params = TestingParameters::init(4, 1, &[0], &[], &[], false, Some(1 + 3));

        test_broadcast_from_all_w_corrupt_set_update_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
        >(params, malicious_strategy)
        .await;
    }
}
