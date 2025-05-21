use super::{
    prf::{xor_u8_arr_in_place, PrfKey},
    prss::create_sets,
};
use crate::{
    algebra::{base_ring::Z64, structure_traits::ErrorCorrect},
    commitment::{commit, verify, Commitment, Opening, KEY_BYTE_LEN},
    error::error_handler::{anyhow_error_and_log, log_error_wrapper},
    execution::{
        communication::p2p::{receive_from_parties, send_to_parties},
        runtime::{party::Role, session::BaseSessionHandles},
        sharing::open::{RobustOpen, SecureRobustOpen},
    },
    hashing::{hash_element, hash_element_w_size, DomainSep},
    networking::value::{AgreeRandomValue, NetworkValue},
};
use anyhow::Context;
use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use tracing::instrument;

/// Domain separator for `agree_random_robust`.
pub(crate) const DSEP_AR: DomainSep = *b"AGREERND";

/// Trait to capture the AgreeRandom protocols
/// with no secret input
#[async_trait]
pub trait AgreeRandom: Clone + Send + Sync {
    /// Perform a batched version of Agree Random on all subsets of size n-t
    ///
    /// This follows the AgreeRandom and AgreeRandom-w-Abort protocols in the NIST document.
    async fn execute<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>>;
}

/// Trait to capture the AgreeRandom protocol
/// with a secret input
#[async_trait]
pub trait AgreeRandomFromShare: Clone + Send + Sync {
    /// Perform a batched version of Agree Random on all subsets of size n-t
    /// where parties agree on the hash of the reconstructed value.
    ///
    /// This follows the AgreeRandom-Robust protocol of the NIST document.
    async fn execute<Z: ErrorCorrect, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        shares: Vec<Z>,
        all_party_sets: &[Vec<usize>],
    ) -> anyhow::Result<Vec<PrfKey>>;
}

#[derive(Clone, Default)]
/// Defines the passively secure protocol [`AgreeRandom`] described in the NIST document
pub struct PassiveSecureAgreeRandom {}

#[derive(Clone, Default)]
/// Defines the secure with abort [`AgreeRandom`] protocol described in the NIST document
pub struct AbortSecureAgreeRandom {}

#[derive(Clone)]
/// Defines the robust [`AgreeRandomFromShare`] protocol described in the NIST document
/// Relies on a [`RobustOpen`] protocol
pub struct RobustRealAgreeRandom<RO: RobustOpen> {
    robust_open: RO,
}

impl<RO: RobustOpen> RobustRealAgreeRandom<RO> {
    pub fn new(robust_open: RO) -> Self {
        Self { robust_open }
    }
}

impl<RO: RobustOpen + Default> Default for RobustRealAgreeRandom<RO> {
    fn default() -> Self {
        Self {
            robust_open: RO::default(),
        }
    }
}

/// Alias for [`RobustRealAgreeRandom`] with a secure implementation of
/// [`RobustOpen`]
pub type RobustSecureAgreeRandom = RobustRealAgreeRandom<SecureRobustOpen>;

#[derive(Clone, Default)]
/// Defines a dummy (insecure) version of the [`AgreeRandom`] protocol
pub struct DummyAgreeRandom {}

#[derive(Clone, Default)]
/// Defines a dummy (insecure) version of the [`AgreeRandomFromShare`] protocol
pub struct DummyAgreeRandomFromShare {}

#[async_trait]
impl<RO: RobustOpen> AgreeRandomFromShare for RobustRealAgreeRandom<RO> {
    ///Perform Agree Random Robust among all sets of size n - t with hardcoded output length of [`KEY_BYTE_LEN`] bytes.
    ///
    /// n and t are dictated by the [`BaseSessionHandles`] parameters num_parties and threshold.
    /// The parties in party_set[set_id] agree on shares[set_id]
    /// Returns the list of agreed randomness only for the subsets I am part of
    #[instrument(name="AgreeRandom-Robust",skip(self,session,shares,all_party_sets),fields(sid = ?session.session_id(),own_identity = ?session.own_identity(),batch_size = ?shares.len()))]
    async fn execute<Z: ErrorCorrect, Rnd: Rng + CryptoRng, L: BaseSessionHandles<Rnd>>(
        &self,
        session: &mut L,
        shares: Vec<Z>,
        all_party_sets: &[Vec<usize>],
    ) -> anyhow::Result<Vec<PrfKey>> {
        //We need at least as many shares as there are sets, could be that we have more than necessary
        //due to how the protocol works
        assert!(shares.len() >= all_party_sets.len());

        //map party role to the message I need to send to it
        let mut msg_to_send = HashMap::new();
        for (set_idx, set) in all_party_sets.iter().enumerate() {
            //set indexes parties starting at 1
            for p in set {
                msg_to_send
                    .entry(Role::indexed_by_one(*p))
                    .and_modify(|vec: &mut Vec<Z>| vec.push(shares[set_idx]))
                    .or_insert(vec![shares[set_idx]]);
            }
        }

        //I participate in opening to others on all values, even if I am not part of the subset
        //I only expect to receive values for subsets I am part of
        let r_vec = self
            .robust_open
            .multi_robust_open_list_to(session, msg_to_send, session.threshold() as usize)
            .await?
            .with_context(|| log_error_wrapper("No valid result from open"))?;

        let s_vec = r_vec
            .iter()
            .map(|cur_r| {
                let hash = hash_element(&DSEP_AR, &cur_r.to_byte_vec());
                let mut digest = [0_u8; KEY_BYTE_LEN];
                digest.copy_from_slice(&hash[..KEY_BYTE_LEN]);
                PrfKey(digest)
            })
            .collect_vec();
        Ok(s_vec)
    }
}

#[async_trait]
impl AgreeRandom for PassiveSecureAgreeRandom {
    ///Perform Agree Random among all sets of size n - t with hardcoded output length of [`KEY_BYTE_LEN`] bytes.
    ///
    /// n and t are dictated by the [`BaseSessionHandles`] parameters num_parties and threshold.
    /// Returns the list of agreed randomness in a vec indexed by set_id
    #[instrument(name = "AgreeRandom", skip(self,session),fields(sid = ?session.session_id(),own_identity = ?session.own_identity()))]
    async fn execute<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        let num_parties = session.num_parties();
        let party_id = session.my_role()?.one_based();
        let session_id = session.session_id().into();
        let round_id = session.network().get_current_round()?;

        //Compute all the subsets of size n-t I am part of
        let mut party_sets = compute_party_sets(
            session.my_role()?,
            session.num_parties(),
            session.threshold() as usize,
        );

        let mut s = [0u8; KEY_BYTE_LEN];

        //Format for both is vec[party_id][set_id]
        let mut keys_opens: Vec<Vec<(PrfKey, Opening)>> = vec![Vec::new(); num_parties];
        let mut coms: Vec<Vec<Commitment>> = vec![Vec::new(); num_parties];

        // compute randomness s and commit to it, hold on to all values in vectors
        for set in &party_sets {
            session.rng().fill_bytes(&mut s);
            let (c, o) = commit(
                &s,
                party_id as u64,
                session_id,
                round_id as u64,
                &mut session.rng(),
            );
            for p in set {
                keys_opens[p - 1].push((PrfKey(s), o));
                coms[p - 1].push(c);
            }
        }

        //Format is vec[sender_id][set_id]
        let (mut rcv_coms, mut rcv_keys_opens) =
            agree_random_communication::<R, S>(session, &coms, &keys_opens).await?;

        let r_a_keys = verify_and_xor_keys(
            party_id,
            session_id,
            round_id as u64,
            &mut party_sets,
            &mut keys_opens,
            &mut rcv_keys_opens,
            &mut rcv_coms,
        )?;

        Ok(r_a_keys)
    }
}

#[async_trait]
impl AgreeRandom for AbortSecureAgreeRandom {
    ///Perform Agree Random with Abort among all sets of size n - t with hardcoded output length of [`KEY_BYTE_LEN`] bytes.
    ///
    /// n and t are dictated by the [`BaseSessionHandles`] parameters num_parties and threshold.
    /// Returns the list of agreed randomness in a vec indexed by set_id
    #[instrument(name="AgreeRandom-w-Abort",skip(self,session),fields(sid = ?session.session_id(),own_identity = ?session.own_identity()))]
    async fn execute<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        let num_parties = session.num_parties();
        let party_id = session.my_role()?.one_based();

        //Compute all the subsets of size n-t I am part of
        let mut party_sets = compute_party_sets(
            session.my_role()?,
            num_parties,
            session.threshold() as usize,
        );

        // run plain AgreeRandom to determine random keys as a first step
        let ars = PassiveSecureAgreeRandom::default()
            .execute::<R, S>(session)
            .await?;

        debug_assert_eq!(ars.len(), party_sets.len());

        //Format is vec[party_id][set_id]
        let mut keys: Vec<Vec<PrfKey>> = vec![Vec::new(); num_parties];

        // put all agreed randomness in vector for sending, grouped by party
        for (set_id, set) in party_sets.iter().enumerate() {
            for p in set {
                keys[p - 1].push(ars[set_id].clone());
            }
        }

        // send keys to all other parties. Each party gets the values for _all_ sets that they are member of at once to avoid multiple comm rounds
        // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
        // protocol are agnostic to the underlying ring. So we pick Z64 as default.
        let mut key_to_send: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
        for p in 1..=num_parties {
            if p != party_id {
                key_to_send.insert(
                    Role::indexed_by_one(p),
                    NetworkValue::AgreeRandom(AgreeRandomValue::KeyValue(keys[p - 1].clone())),
                );
            }
        }

        // communication (send all keys, then receive all keys)
        send_to_parties(&key_to_send, session).await?;
        let receive_from_roles = key_to_send.keys().cloned().collect_vec();
        // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
        // protocol are agnostic to the underlying ring. So we pick Z64 as default.
        let received_keys = receive_from_parties::<Z64, R, S>(&receive_from_roles, session).await?;

        let mut rcv_keys = check_and_unpack_keys(&received_keys, num_parties)?;

        //Make sure the keys I sent correspond to the keys I received, i.e. we all agree on the key within a set
        let r_a_keys = verify_keys_equal(party_id, &mut party_sets, &mut keys, &mut rcv_keys)?;

        Ok(r_a_keys)
    }
}

#[async_trait]
impl AgreeRandom for DummyAgreeRandom {
    async fn execute<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        let party_sets = compute_party_sets(
            session.my_role()?,
            session.num_parties(),
            session.threshold() as usize,
        );

        // byte array for holding the randomness
        let mut r_a = [0u8; KEY_BYTE_LEN];

        let r_a_keys = party_sets
            .iter()
            .map(|set| {
                // hash party IDs contained in this set as dummy value for r_a
                // Observe that since each element is of constant and equal size, it is safe to just concatenate before hashing
                // Also observe that we map each element to 64 bits to ensure consistency across 32, 64 and 128 bit systems, which have variable size of `usize`
                let flat_vec = set
                    .iter()
                    .flat_map(|p| (*p as u64).to_le_bytes())
                    .collect::<Vec<_>>();
                let hash = hash_element_w_size(&DSEP_AR, &flat_vec, KEY_BYTE_LEN);
                r_a.copy_from_slice(&hash[..KEY_BYTE_LEN]);
                PrfKey(r_a)
            })
            .collect();

        Ok(r_a_keys)
    }
}

#[async_trait]
impl AgreeRandomFromShare for DummyAgreeRandomFromShare {
    // Just runs dummy agree random, ignoring shares and all_party_sets
    async fn execute<Z: ErrorCorrect, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        _shares: Vec<Z>,
        _all_party_sets: &[Vec<usize>],
    ) -> anyhow::Result<Vec<PrfKey>> {
        DummyAgreeRandom::default().execute(session).await
    }
}

fn check_rcv_len(rcv_len: usize, expect_len: usize, tstr: &str) -> anyhow::Result<()> {
    // check that we have all expected responses
    if rcv_len != expect_len {
        return Err(anyhow_error_and_log(format!(
            "have received {} {tstr}, but expected {}",
            rcv_len, expect_len
        )));
    }
    Ok(())
}

/// Generic function to check the types of received values and unpack into a vector.
fn check_and_unpack<T>(
    // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
    // protocol are agnostic to the underlying ring. So we pick Z64 as default.
    received_values: &HashMap<Role, NetworkValue<Z64>>,
    num_parties: usize,
    variant_match: fn(&AgreeRandomValue) -> Option<&Vec<T>>,
    type_str: &str,
) -> anyhow::Result<Vec<Vec<T>>>
where
    T: Clone,
{
    check_rcv_len(received_values.len(), num_parties - 1, type_str)?;

    let mut rcv_values: Vec<Vec<T>> = vec![Vec::new(); num_parties];
    for (sender_role, sender_data) in received_values {
        if let NetworkValue::AgreeRandom(ar_value) = sender_data {
            if let Some(value) = variant_match(ar_value) {
                rcv_values[sender_role.zero_based()] = value.to_vec();
            } else {
                return Err(anyhow_error_and_log(format!(
                    "Have not received a {} from role {}!",
                    type_str, sender_role
                )));
            }
        } else {
            return Err(anyhow_error_and_log(format!(
                "Have not received an AgreeRandomValue from role {}!",
                sender_role
            )));
        }
    }

    Ok(rcv_values)
}

/// Helper function to extract CommitmentValue from AgreeRandomValue.
fn match_com_val(value: &AgreeRandomValue) -> Option<&Vec<Commitment>> {
    match value {
        AgreeRandomValue::CommitmentValue(cv) => Some(cv),
        _ => None,
    }
}

/// Helper function to extract KeyOpenValue from AgreeRandomValue.
fn match_key_open_val(value: &AgreeRandomValue) -> Option<&Vec<(PrfKey, Opening)>> {
    match value {
        AgreeRandomValue::KeyOpenValue(kov) => Some(kov),
        _ => None,
    }
}

/// Helper function to extract KeyValue from AgreeRandomValue.
fn match_key_val(value: &AgreeRandomValue) -> Option<&Vec<PrfKey>> {
    match value {
        AgreeRandomValue::KeyValue(kv) => Some(kv),
        _ => None,
    }
}

/// Check the types of the received CommitmentValues and unpack into [`Vec<Commitment>']
/// Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
/// protocol are agnostic to the underlying ring. So we pick Z64 as default.
fn check_and_unpack_coms(
    rcv_coms: &HashMap<Role, NetworkValue<Z64>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<Commitment>>> {
    check_and_unpack(rcv_coms, num_parties, match_com_val, "CommitmentValue")
}

/// Check the types of the received KeyOpenValues and unpack into [`Vec<(PrfKey, Opening)>`]
/// Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
/// protocol are agnostic to the underlying ring. So we pick Z64 as default.
fn check_and_unpack_keys_openings(
    rcv_ko: &HashMap<Role, NetworkValue<Z64>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<(PrfKey, Opening)>>> {
    check_and_unpack(rcv_ko, num_parties, match_key_open_val, "KeyOpenValue")
}

/// Check the types of the received KeyValues and unpack into [`Vec<PrfKey>`]
/// Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
/// protocol are agnostic to the underlying ring. So we pick Z64 as default.
fn check_and_unpack_keys(
    rcv_k: &HashMap<Role, NetworkValue<Z64>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<PrfKey>>> {
    check_and_unpack(rcv_k, num_parties, match_key_val, "KeyValue")
}

/// Verifies that the received keys are identical
fn verify_keys_equal(
    self_id: usize,
    party_sets: &mut Vec<Vec<usize>>,
    keys: &mut [Vec<PrfKey>],
    rcv_keys: &mut [Vec<PrfKey>],
) -> anyhow::Result<Vec<PrfKey>> {
    // reverse the list of sets so we can pop the received values afterwards
    party_sets.reverse();

    let mut r_a_keys: Vec<PrfKey> = Vec::new();

    for set in party_sets {
        //Retrieve my key for this set as ground truth
        let my_key = keys[self_id - 1]
            .pop()
            .with_context(|| log_error_wrapper("could not find my own key!"))?;

        // for each party in the set, check against my key
        for p in set {
            // check values received from the other parties
            if *p != self_id {
                let k = rcv_keys[*p - 1].pop().with_context(|| {
                    log_error_wrapper(format!("could not find key value for party {p}!"))
                })?;

                if k != my_key {
                    return Err(anyhow_error_and_log(log_error_wrapper(format!(
                        "received a key from party {p} that does not match my own!"
                    ))));
                }
            }
        }

        //If all checks passed, we can use this key for this set
        r_a_keys.push(my_key);
    }

    // reverse the list of results so it matches the expected order of sets outside this function
    r_a_keys.reverse();

    Ok(r_a_keys)
}

/// Verifies the commitments on the received keys are valid and if so, xors the keys to compute agreed randomness
fn verify_and_xor_keys(
    self_id: usize,
    session_id: u128,
    round_id: u64,
    party_sets: &mut Vec<Vec<usize>>,
    keys_opens: &mut [Vec<(PrfKey, Opening)>],
    rcv_keys_opens: &mut [Vec<(PrfKey, Opening)>],
    rcv_coms: &mut [Vec<Commitment>],
) -> anyhow::Result<Vec<PrfKey>> {
    // reverse the list of sets so we can pop the received values afterwards
    party_sets.reverse();

    let mut r_a_keys: Vec<PrfKey> = Vec::new();
    let mut s: [u8; KEY_BYTE_LEN];

    for set in party_sets {
        s = [0_u8; KEY_BYTE_LEN];

        // for each party in the set, xor the received randomness s
        for p in set {
            //Consider my own key for this set
            if *p == self_id {
                // XOR my own value
                xor_u8_arr_in_place(
                    &mut s,
                    &keys_opens[*p - 1]
                        .pop()
                        .with_context(|| log_error_wrapper("could not find my own key!"))?
                        .0
                         .0,
                );
            //Consider others' keys for this set
            } else {
                let ko = rcv_keys_opens[*p - 1].pop().with_context(|| {
                    log_error_wrapper(format!("could not find KeyOpenValue for party {p}!"))
                })?;
                let com = rcv_coms[*p - 1].pop().with_context(|| {
                    log_error_wrapper(format!("could not find CommitmentValue for party {p}!"))
                })?;

                // check that randomnes was properly committed to in the first round
                match verify(&ko.0 .0, *p as u64, session_id, round_id, &com, &ko.1) {
                    Ok(_) => {}
                    Err(_) => {
                        return Err(anyhow_error_and_log(format!(
                            "Commitment verification has failed for party {p}!"
                        )));
                    }
                }

                // XOR verified external value
                xor_u8_arr_in_place(&mut s, &ko.0 .0);
            }
        }

        r_a_keys.push(PrfKey(s));
    }

    // reverse the list of results so it matches the expected order of sets outside this function
    r_a_keys.reverse();

    Ok(r_a_keys)
}

/// Does the communication for RealAgreeRandom and returns the unpacked commitments and keys/openings
async fn agree_random_communication<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    coms: &[Vec<Commitment>],
    keys_opens: &[Vec<(PrfKey, Opening)>],
) -> anyhow::Result<(Vec<Vec<Commitment>>, Vec<Vec<(PrfKey, Opening)>>)> {
    let num_parties = session.num_parties();
    let party_id = session.my_role()?.one_based();

    // Send commitments to all other parties. Each party gets the commitment for _all_ sets that they are member of at once to avoid multiple comm rounds
    // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
    // protocol are agnostic to the underlying ring. So we pick Z64 as default.
    let mut coms_to_send: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
    for p in 1..=num_parties {
        if p != party_id {
            coms_to_send.insert(
                Role::indexed_by_one(p),
                NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(coms[p - 1].clone())),
            );
        }
    }
    send_to_parties(&coms_to_send, session).await?;

    // receive commitments from other parties
    // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
    // protocol are agnostic to the underlying ring. So we pick Z64 as default.
    let receive_from_roles = coms_to_send.keys().cloned().collect_vec();
    let received_coms = receive_from_parties::<Z64, R, S>(&receive_from_roles, session).await?;

    let rcv_coms = check_and_unpack_coms(&received_coms, num_parties)?;

    // 2nd round: openings and randomness
    // send keys and openings to all other parties. Each party gets the values for _all_ sets that they are member of at once to avoid multiple comm rounds
    // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
    // protocol are agnostic to the underlying ring. So we pick Z64 as default.
    let mut key_open_to_send: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
    for p in 1..=num_parties {
        if p != party_id {
            key_open_to_send.insert(
                Role::indexed_by_one(p),
                NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(
                    keys_opens[p - 1].clone(),
                )),
            );
        }
    }
    send_to_parties(&key_open_to_send, session).await?;

    // receive keys and openings from other parties
    // Note: we have to use a type because NetworkValue is generic, but values sent in the agree random
    // protocol are agnostic to the underlying ring. So we pick Z64 as default.
    let received_keys = receive_from_parties::<Z64, R, S>(&receive_from_roles, session).await?;

    let rcv_keys_opens = check_and_unpack_keys_openings(&received_keys, num_parties)?;

    Ok((rcv_coms, rcv_keys_opens))
}

/// Helper function returns all the subsets of party IDs of size n-t of which the given party is a member
fn compute_party_sets(my_role: Role, parties: usize, threshold: usize) -> Vec<Vec<usize>> {
    let party_id = my_role.one_based();
    create_sets(parties, threshold)
        .into_iter()
        .filter(|aset| aset.contains(&party_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        check_and_unpack_coms, check_rcv_len, verify_and_xor_keys, AbortSecureAgreeRandom,
        AgreeRandom, AgreeRandomFromShare, DummyAgreeRandom, PassiveSecureAgreeRandom,
        RobustRealAgreeRandom, RobustSecureAgreeRandom,
    };
    use crate::{
        algebra::{
            base_ring::Z64,
            galois_rings::degree_4::ResiduePolyF4Z128,
            structure_traits::{ErrorCorrect, Invert, Ring},
        },
        commitment::{
            commitment_inner_hash, Commitment, Opening, COMMITMENT_BYTE_LEN, KEY_BYTE_LEN,
        },
        execution::{
            runtime::{
                party::Role,
                session::{ParameterHandles, SmallSession},
            },
            sharing::open::test::deterministically_compute_my_shares,
            small_execution::{
                agree_random::{
                    check_and_unpack_keys, check_and_unpack_keys_openings, compute_party_sets,
                    verify_keys_equal,
                },
                prf::{xor_u8_arr_in_place, PrfKey},
                prss::create_sets,
            },
        },
        malicious_execution::{
            open::malicious_open::MaliciousRobustOpenLie,
            small_execution::malicious_agree_random::MaliciousAgreeRandomDrop,
        },
        networking::{
            value::{AgreeRandomValue, NetworkValue},
            NetworkMode,
        },
        tests::helper::{
            testing::get_networkless_base_session_for_parties,
            tests::{execute_protocol_small_w_malicious, TestingParameters},
        },
    };
    use itertools::Itertools;
    use std::collections::{HashMap, VecDeque};
    use tokio::task::JoinError;

    #[test]
    fn test_u8_xor() {
        let mut a = [0u8; KEY_BYTE_LEN];
        let mut b = [42u8; KEY_BYTE_LEN];
        let mut c = [255u8; KEY_BYTE_LEN];

        let zero = [0u8; KEY_BYTE_LEN];
        let ff = [255u8; KEY_BYTE_LEN];
        let fortytwo = [42u8; KEY_BYTE_LEN];

        let tmp1: [u8; KEY_BYTE_LEN] = (0_u8..KEY_BYTE_LEN as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let tmp2: [u8; KEY_BYTE_LEN] = (0_u8..KEY_BYTE_LEN as u8)
            .map(|i| 42_u8 ^ i)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        xor_u8_arr_in_place(&mut a, &zero);
        assert_eq!(a, zero);
        xor_u8_arr_in_place(&mut c, &zero);
        assert_eq!(c, ff);
        xor_u8_arr_in_place(&mut c, &ff);
        assert_eq!(c, zero);

        xor_u8_arr_in_place(&mut a, &b);
        assert_eq!(a, fortytwo);

        xor_u8_arr_in_place(&mut b, &tmp1);
        assert_eq!(b, tmp2);
    }

    #[test]
    fn test_dummy_agree_random() {
        let num_parties = 7;
        let threshold = 2;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut allkeys: Vec<VecDeque<PrfKey>> = Vec::new();

        for p in 1..=num_parties {
            let mut sess = get_networkless_base_session_for_parties(
                num_parties,
                threshold,
                Role::indexed_by_one(p),
            );

            let _guard = rt.enter();
            let keys = rt
                .block_on(async { DummyAgreeRandom::default().execute::<_, _>(&mut sess).await })
                .unwrap();

            let vd = VecDeque::from(keys);
            allkeys.push(vd);

            // in this case we do not communicate, rounds should be zero
            assert_eq!(sess.network.get_current_round().unwrap(), 0);
        }

        let all_party_sets: Vec<Vec<usize>> = create_sets(num_parties, threshold as usize)
            .into_iter()
            .collect();

        for set in all_party_sets {
            let partykeys: Vec<PrfKey> = set
                .iter()
                .map(|sp| allkeys[*sp - 1].pop_front().unwrap())
                .collect();

            // check that all keys for this set are equal
            assert!(itertools::all(&partykeys, |k| k == &partykeys[0]));
        }
    }

    #[test]
    fn test_agree_random_passive() {
        let testing_parameters = TestingParameters::init(7, 2, &[], &[], &[], false, Some(2));
        test_agree_random_strategies::<PassiveSecureAgreeRandom, _>(
            testing_parameters,
            PassiveSecureAgreeRandom::default(),
        );
    }

    #[test]
    fn test_agree_random_with_abort() {
        let testing_parameters = TestingParameters::init(7, 2, &[], &[], &[], false, Some(3));
        test_agree_random_strategies::<AbortSecureAgreeRandom, _>(
            testing_parameters,
            AbortSecureAgreeRandom::default(),
        );
    }

    #[test]
    fn test_dropout_real_agree_random_with_abort() {
        let testing_parameters = TestingParameters::init(7, 2, &[0], &[], &[], true, None);
        test_agree_random_strategies::<AbortSecureAgreeRandom, _>(
            testing_parameters,
            MaliciousAgreeRandomDrop::default(),
        );
    }

    #[test]
    fn test_agree_random_robust() {
        let testing_parameters = TestingParameters::init(7, 2, &[], &[], &[], false, Some(1));
        test_agree_random_from_share_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
        >(testing_parameters, RobustSecureAgreeRandom::default());
    }

    #[test]
    fn test_lie_robust_open_agree_random_robust() {
        let testing_parameters = TestingParameters::init(7, 2, &[0, 3], &[], &[], false, None);
        test_agree_random_from_share_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
        >(
            testing_parameters,
            RobustRealAgreeRandom::new(MaliciousRobustOpenLie::default()),
        );
    }

    #[test]
    fn test_dropout_agree_random_robust() {
        let testing_parameters = TestingParameters::init(7, 2, &[1, 4], &[], &[], false, None);
        test_agree_random_from_share_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
        >(testing_parameters, MaliciousAgreeRandomDrop::default());
    }

    /// Generic function to test the different strategies for agree random.
    /// We use [`TestingParameters::should_be_detected`] field to
    /// tell the test whether the honest parties are expected to abort
    /// due to some malicious bahviour
    fn test_agree_random_strategies<
        AHonest: AgreeRandom + Default + 'static,
        AMalicious: AgreeRandom + 'static,
    >(
        params: TestingParameters,
        malicious_agree_random: AMalicious,
    ) {
        //We hardcode ResiduePolyF4Z128 as AgreeRandom doesn't care about the underlying ring
        let mut task_honest = |mut session: SmallSession<ResiduePolyF4Z128>| async move {
            let secure_agree_random_w_abort = AHonest::default();

            (
                session.my_role().unwrap(),
                secure_agree_random_w_abort.execute(&mut session).await,
            )
        };

        //We use ResiduePolyF4Z128 as AgreeRandom doesn't care about the underlying ring
        let mut task_malicious =
            |mut session: SmallSession<ResiduePolyF4Z128>, malicious_agree_random: AMalicious| async move {
                (
                    session.my_role().unwrap(),
                    malicious_agree_random.execute(&mut session).await,
                )
            };

        let (results_honest, results_malicious) = execute_protocol_small_w_malicious::<
            _,
            _,
            _,
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            &params,
            &params.malicious_roles,
            malicious_agree_random,
            NetworkMode::Sync,
            None,
            &mut task_honest,
            &mut task_malicious,
        );

        // Since the protocol is secure with abort, we make sure that in case of a
        // malicious party it does abort
        if params.should_be_detected {
            for (_, result) in results_honest.iter() {
                assert!(result.is_err());
            }
        } else {
            validate_result(
                results_honest,
                results_malicious,
                params.num_parties,
                params.threshold,
                None,
            )
        }

        // Else, we can extract and test the results
    }

    /// Generic function to test the different strategies for agree random from share.
    /// Ignores [`TestinParameters::should_be_detected`] because the protocol
    /// does not mutate the corrupt set
    fn test_agree_random_from_share_strategies<
        Z: ErrorCorrect + Invert,
        const EXTENSION_DEGREE: usize,
        A: AgreeRandomFromShare + 'static,
    >(
        params: TestingParameters,
        malicious_agree_random: A,
    ) {
        let mut task_honest = |mut session: SmallSession<Z>| async move {
            let secure_agree_random_w_abort = RobustSecureAgreeRandom::default();

            let num_parties = session.num_parties();
            let threshold = session.threshold() as usize;
            let my_role = session.my_role().unwrap();

            let all_party_sets: Vec<Vec<usize>> =
                create_sets(num_parties, threshold).into_iter().collect();

            //The protocol's input is a valid secret sharing amongst all the parties
            let (_secret, shares) = deterministically_compute_my_shares::<Z>(
                all_party_sets.len(),
                my_role,
                num_parties,
                threshold,
                43,
            );

            (
                my_role,
                secure_agree_random_w_abort
                    .execute(&mut session, shares, &all_party_sets)
                    .await,
            )
        };

        let mut task_malicious = |mut session: SmallSession<Z>, malicious_agree_random: A| async move {
            let num_parties = session.num_parties();
            let threshold = session.threshold() as usize;
            let my_role = session.my_role().unwrap();

            let all_party_sets: Vec<Vec<usize>> =
                create_sets(num_parties, threshold).into_iter().collect();

            //The protocol's input is a valid secret sharing amongst all the parties
            let (_secret, shares) = deterministically_compute_my_shares::<Z>(
                all_party_sets.len(),
                my_role,
                num_parties,
                threshold,
                43,
            );
            (
                session.my_role().unwrap(),
                malicious_agree_random
                    .execute(&mut session, shares, &all_party_sets)
                    .await,
            )
        };

        let (results_honest, _results_malicious) =
            execute_protocol_small_w_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.malicious_roles,
                malicious_agree_random,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            );

        // Since the protocol is robust, we make sure in all cases
        // honest parties have a valid result
        validate_result(
            results_honest,
            Vec::new(),
            params.num_parties,
            params.threshold,
            Some(params.malicious_roles),
        )
    }

    #[allow(clippy::type_complexity)]
    /// Validates the result of agree random,
    /// except for the roles in `ignore_roles`
    fn validate_result(
        honest_results: Vec<(Role, anyhow::Result<Vec<PrfKey>>)>,
        malicious_results: Vec<Result<(Role, anyhow::Result<Vec<PrfKey>>), JoinError>>,
        num_parties: usize,
        threshold: usize,
        ignore_roles: Option<Vec<Role>>,
    ) {
        let mut concatenated_results = honest_results
            .into_iter()
            .map(|(role, result)| (role, VecDeque::from(result.unwrap())))
            .collect_vec();
        concatenated_results.extend(
            malicious_results
                .into_iter()
                .map(|result_malicious| {
                    let (role, result) = result_malicious.unwrap();
                    (role, VecDeque::from(result.unwrap()))
                })
                .collect_vec(),
        );

        // unpack results into hashmap
        let mut key_hm: HashMap<usize, VecDeque<PrfKey>> = HashMap::new();
        for (role, data) in concatenated_results {
            key_hm.insert(role.zero_based(), data);
        }

        let all_party_sets: Vec<Vec<usize>> =
            create_sets(num_parties, threshold).into_iter().collect();

        let ignore_roles = ignore_roles.unwrap_or_default();
        let mut allkeys: Vec<VecDeque<PrfKey>> = (0..num_parties)
            .map(|p| {
                if !ignore_roles.contains(&Role::indexed_by_zero(p)) {
                    key_hm[&p].clone()
                } else {
                    VecDeque::new()
                }
            })
            .collect();

        for set in all_party_sets {
            let partykeys: Vec<PrfKey> = set
                .iter()
                .filter_map(|sp| {
                    if !ignore_roles.contains(&Role::indexed_by_one(*sp)) {
                        Some(allkeys[*sp - 1].pop_front().unwrap())
                    } else {
                        None
                    }
                })
                .collect();

            // All the sets have at least n-2t honest parties in it
            assert!(partykeys.len() >= num_parties - 2 * threshold);

            // check that all keys for this set are equal
            assert!(itertools::all(&partykeys, |k| k == &partykeys[0]));
        }
    }

    #[test]
    fn test_check_rcv_len() {
        check_rcv_len(2, 2, "foos").unwrap();
        check_rcv_len(0, 0, "zeros").unwrap();
        check_rcv_len(0, 0, "").unwrap();
        let err = check_rcv_len(23, 42, "things").unwrap_err().to_string();
        assert!(err.contains("have received 23 things, but expected 42"));
        let err = check_rcv_len(42, 23, "bars").unwrap_err().to_string();
        assert!(err.contains("have received 42 bars, but expected 23"));
    }

    #[test]
    fn test_check_and_unpack_coms() {
        // test normal behavior
        let num_parties = 3;
        let mut rc: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
        let c1 = Commitment([12_u8; COMMITMENT_BYTE_LEN]);
        let c2 = Commitment([42_u8; COMMITMENT_BYTE_LEN]);

        rc.insert(
            Role::indexed_by_one(3),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c1])),
        );

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("have received 1 CommitmentValue, but expected 2"));

        rc.insert(
            Role::indexed_by_one(1),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c2])),
        );
        let r = check_and_unpack_coms(&rc, num_parties).unwrap();

        let expect = vec![vec![c2], Vec::<Commitment>::new(), vec![c1]];
        assert_eq!(r, expect);

        // Test Error when receiving wrong number of values
        rc.insert(
            Role::indexed_by_one(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c2])),
        );

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("have received 3 CommitmentValue, but expected 2"));
    }

    #[test]
    fn test_check_and_unpack_coms_type() {
        let num_parties = 2;
        let mut rc: HashMap<Role, NetworkValue<Z64>> = HashMap::new();

        // Test Error when receiving a wrong AR value
        let ko = (
            PrfKey([42_u8; KEY_BYTE_LEN]),
            Opening([42_u8; KEY_BYTE_LEN]),
        );

        rc.insert(
            Role::indexed_by_one(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko])),
        );

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("Have not received a CommitmentValue from role 2!"));

        // Test Error when receiving Bot
        rc.insert(Role::indexed_by_one(2), NetworkValue::Bot);

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("Have not received an AgreeRandomValue from role 2!"));
    }

    #[test]
    fn test_check_and_unpack_keys_openings() {
        // test normal behavior
        let num_parties = 3;
        let mut rc: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
        let ko1 = (PrfKey([1_u8; KEY_BYTE_LEN]), Opening([2_u8; KEY_BYTE_LEN]));
        let ko2 = (
            PrfKey([42_u8; KEY_BYTE_LEN]),
            Opening([42_u8; KEY_BYTE_LEN]),
        );

        rc.insert(
            Role::indexed_by_one(3),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko1.clone()])),
        );
        rc.insert(
            Role::indexed_by_one(1),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko2.clone()])),
        );
        let r = check_and_unpack_keys_openings(&rc, num_parties).unwrap();

        let expect = vec![
            vec![ko2.clone()],
            Vec::<(PrfKey, Opening)>::new(),
            vec![ko1],
        ];
        assert_eq!(r, expect);

        // Test Error when receiving wrong number of values
        rc.insert(
            Role::indexed_by_one(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko2.clone()])),
        );

        let r = check_and_unpack_keys_openings(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("have received 3 KeyOpenValue, but expected 2"));
    }

    #[test]
    fn test_check_and_unpack_keys_openings_type() {
        let num_parties = 2;
        let mut rc: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
        // Test Error when receiving a wrong AR value
        let c = Commitment([12_u8; COMMITMENT_BYTE_LEN]);

        rc.insert(
            Role::indexed_by_one(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c])),
        );

        let r = check_and_unpack_keys_openings(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("Have not received a KeyOpenValue from role 2!"));

        // Test Error when receiving Bot
        rc = HashMap::new();
        rc.insert(Role::indexed_by_one(1), NetworkValue::Bot);

        let r = check_and_unpack_keys_openings(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("Have not received an AgreeRandomValue from role 1!"));
    }

    #[test]
    fn test_check_and_unpack_keys() {
        // test normal behavior
        let num_parties = 3;
        let mut rc: HashMap<Role, NetworkValue<Z64>> = HashMap::new();
        let key1 = PrfKey([1_u8; KEY_BYTE_LEN]);
        let key2 = PrfKey([42_u8; KEY_BYTE_LEN]);

        rc.insert(
            Role::indexed_by_one(3),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyValue(vec![key1.clone()])),
        );
        rc.insert(
            Role::indexed_by_one(1),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyValue(vec![key2.clone()])),
        );
        let r = check_and_unpack_keys(&rc, num_parties).unwrap();

        let expect = vec![vec![key2.clone()], Vec::<PrfKey>::new(), vec![key1]];
        assert_eq!(r, expect);

        // Test Error when receiving wrong number of values
        rc.insert(
            Role::indexed_by_one(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyValue(vec![key2])),
        );

        let r = check_and_unpack_keys(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("have received 3 KeyValue, but expected 2"));
    }

    #[test]
    fn test_check_and_unpack_keys_type() {
        // Test Error when receiving a wrong AR value
        let num_parties = 2;
        let mut rc: HashMap<Role, NetworkValue<Z64>> = HashMap::new();

        rc.insert(
            Role::indexed_by_one(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![(
                PrfKey([1_u8; KEY_BYTE_LEN]),
                Opening([2_u8; KEY_BYTE_LEN]),
            )])),
        );

        let r = check_and_unpack_keys(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("Have not received a KeyValue from role 2!"));

        // Test Error when receiving Bot
        rc = HashMap::new();
        rc.insert(Role::indexed_by_one(1), NetworkValue::Bot);

        let r = check_and_unpack_keys(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert!(r.contains("Have not received an AgreeRandomValue from role 1!"));
    }

    #[test]
    fn test_verify_and_xor_keys() {
        let party_id = 2;
        let session_id = 12u128;
        let round_id = 66u64;
        let party_sets = vec![vec![1_usize, 2]];

        // received key and opening
        let key1 = PrfKey([42_u8; KEY_BYTE_LEN]);
        let opening1 = Opening([69_u8; KEY_BYTE_LEN]);
        let ko1 = (key1.clone(), opening1);
        let rcv_keys_opens = vec![vec![ko1.clone()], Vec::<(PrfKey, Opening)>::new()];

        let commitment1 = commitment_inner_hash(
            &key1.0,
            party_sets[0][0] as u64,
            session_id,
            round_id,
            &opening1,
        );
        let mut rcv_coms = vec![vec![commitment1], Vec::<Commitment>::new()];

        // my own key and opening
        let ko2 = (PrfKey([1_u8; KEY_BYTE_LEN]), Opening([23_u8; KEY_BYTE_LEN]));
        let keys_opens = vec![Vec::<(PrfKey, Opening)>::new(), vec![ko2]];

        // test correctly working verification and key generation
        let res = verify_and_xor_keys(
            party_id,
            session_id,
            round_id,
            &mut party_sets.clone(),
            &mut keys_opens.clone(),
            &mut rcv_keys_opens.clone(),
            &mut rcv_coms.clone(),
        )
        .unwrap();

        // test that resulting key is the xor of the input keys 42 ^ 1 = 43
        assert_eq!(res, vec![PrfKey([43_u8; KEY_BYTE_LEN])]);

        // test failing commitment verification with wrong commitment
        {
            rcv_coms = vec![
                vec![Commitment([0_u8; COMMITMENT_BYTE_LEN])],
                Vec::<Commitment>::new(),
            ];

            let r = verify_and_xor_keys(
                party_id,
                session_id,
                round_id,
                &mut party_sets.clone(),
                &mut keys_opens.clone(),
                &mut rcv_keys_opens.clone(),
                &mut rcv_coms.clone(),
            )
            .unwrap_err()
            .to_string();

            assert!(r.contains("Commitment verification has failed for party 1!"));
        }
        // test wrong session ID
        {
            let r = verify_and_xor_keys(
                party_id,
                session_id + 1,
                round_id,
                &mut party_sets.clone(),
                &mut keys_opens.clone(),
                &mut rcv_keys_opens.clone(),
                &mut rcv_coms.clone(),
            )
            .unwrap_err()
            .to_string();

            assert!(r.contains("Commitment verification has failed for party 1!"));
        }
        // test wrong round ID
        {
            let r = verify_and_xor_keys(
                party_id,
                session_id,
                round_id + 1,
                &mut party_sets.clone(),
                &mut keys_opens.clone(),
                &mut rcv_keys_opens.clone(),
                &mut rcv_coms.clone(),
            )
            .unwrap_err()
            .to_string();

            assert!(r.contains("Commitment verification has failed for party 1!"));
        }
    }

    #[test]
    fn test_verify_keys_equal_2p() {
        let party_id = 2;
        let party_sets = vec![vec![1_usize, 2]];

        // received keys/openings
        let key1 = PrfKey([42_u8; KEY_BYTE_LEN]);
        let rcv_keys = vec![vec![key1.clone()], Vec::<PrfKey>::new()];
        let my_keys = vec![Vec::<PrfKey>::new(), vec![key1]];

        // test correctly working verification and key generation
        let res = verify_keys_equal(
            party_id,
            &mut party_sets.clone(),
            &mut my_keys.clone(),
            &mut rcv_keys.clone(),
        )
        .unwrap();

        // test that resulting key is the same same as the input key = 42
        assert_eq!(res, vec![PrfKey([42_u8; KEY_BYTE_LEN])]);

        // set my own key to sth else, so that the received key does not match my own
        let key2 = PrfKey([1_u8; KEY_BYTE_LEN]);
        let keys_fail = vec![Vec::<PrfKey>::new(), vec![key2]];

        let r = verify_keys_equal(
            party_id,
            &mut party_sets.clone(),
            &mut keys_fail.clone(),
            &mut rcv_keys.clone(),
        )
        .unwrap_err()
        .to_string();

        assert!(r.contains("received a key from party 1 that does not match my own!"))
    }

    #[test]
    fn test_verify_keys_equal_3p() {
        let party_id = 1;
        let party_sets = compute_party_sets(Role::indexed_by_one(1), 3, 1);

        // received keys/openings
        let set_keys = vec![PrfKey([12_u8; KEY_BYTE_LEN]), PrfKey([13_u8; KEY_BYTE_LEN])];
        let rcv_keys = vec![
            Vec::<PrfKey>::new(),
            vec![set_keys[0].clone()],
            vec![set_keys[1].clone()],
        ];
        let my_keys = vec![set_keys.clone(), Vec::<PrfKey>::new(), Vec::<PrfKey>::new()];

        // test correctly working verification and key generation
        let res = verify_keys_equal(
            party_id,
            &mut party_sets.clone(),
            &mut my_keys.clone(),
            &mut rcv_keys.clone(),
        )
        .unwrap();

        // test that resulting key is the same same as the input key = 42
        assert_eq!(res, set_keys);

        // set received key of p2 to sth else, so that the it does not match my own
        let key2 = PrfKey([234_u8; KEY_BYTE_LEN]);
        let keys_fail = vec![Vec::<PrfKey>::new(), vec![key2], vec![set_keys[1].clone()]];

        let r = verify_keys_equal(
            party_id,
            &mut party_sets.clone(),
            &mut my_keys.clone(),
            &mut keys_fail.clone(),
        )
        .unwrap_err()
        .to_string();
        assert!(r.contains("received a key from party 2 that does not match my own!"))
    }
}
