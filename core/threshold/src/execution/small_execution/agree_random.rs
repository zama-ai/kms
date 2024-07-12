use super::{
    prf::{xor_u8_arr_in_place, PrfKey},
    prss::{create_sets, DSEP_AR},
};
use crate::{
    algebra::structure_traits::Ring,
    commitment::{commit, verify, Commitment, Opening, KEY_BYTE_LEN},
    error::error_handler::{anyhow_error_and_log, log_error_wrapper},
    execution::{
        communication::p2p::{receive_from_parties, send_to_honest_parties},
        runtime::{party::Role, session::BaseSessionHandles},
    },
    networking::value::{AgreeRandomValue, NetworkValue},
};
use anyhow::Context;
use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use sha3::{
    digest::ExtendableOutput,
    digest::{Update, XofReader},
    Shake256,
};
use std::collections::HashMap;
use tracing::instrument;

#[async_trait]
pub trait AgreeRandom {
    /// agree on a random value, as seen from a single party's view (determined by the session)
    async fn agree_random<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>>;
}

pub struct RealAgreeRandom {}

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
fn check_and_unpack<Z: Ring, T>(
    received_values: &HashMap<Role, NetworkValue<Z>>,
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

/// check the types of the received CommitmentValues and unpack into Vector<Commitment>
fn check_and_unpack_coms<Z: Ring>(
    rcv_coms: &HashMap<Role, NetworkValue<Z>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<Commitment>>> {
    check_and_unpack(rcv_coms, num_parties, match_com_val, "CommitmentValue")
}

/// check the types of the received KeyOpenValues and unpack into Vector<(PrfKey, Opening)>
fn check_and_unpack_keys_openings<Z: Ring>(
    rcv_ko: &HashMap<Role, NetworkValue<Z>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<(PrfKey, Opening)>>> {
    check_and_unpack(rcv_ko, num_parties, match_key_open_val, "KeyOpenValue")
}

/// check the types of the received KeyValues and unpack into Vector<PrfKey>
fn check_and_unpack_keys<Z: Ring>(
    rcv_k: &HashMap<Role, NetworkValue<Z>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<PrfKey>>> {
    check_and_unpack(rcv_k, num_parties, match_key_val, "KeyValue")
}

/// verifies that the received keys are identical
fn verify_keys_equal(
    party_id: usize,
    party_sets: &mut Vec<Vec<usize>>,
    keys: &mut [Vec<PrfKey>],
    rcv_keys: &mut [Vec<PrfKey>],
) -> anyhow::Result<Vec<PrfKey>> {
    // reverse the list of sets so we can pop the received values afterwards
    party_sets.reverse();

    let mut r_a_keys: Vec<PrfKey> = Vec::new();

    for set in party_sets {
        let mykey = &keys[party_id - 1]
            .pop()
            .with_context(|| log_error_wrapper("could not find my own key!"))?;

        // for each party in the set, xor the received randomness s
        for p in set {
            // check values received from the other parties
            if *p != party_id {
                let k = rcv_keys[*p - 1].pop().with_context(|| {
                    log_error_wrapper(format!("could not find key value for party {p}!"))
                })?;

                if &k != mykey {
                    return Err(anyhow_error_and_log(log_error_wrapper(format!(
                        "received a key from party {p} that does not match my own!"
                    ))));
                }
            }
        }

        r_a_keys.push(mykey.clone());
    }

    // reverse the list of results so it matches the expected order of sets outside this function
    r_a_keys.reverse();

    Ok(r_a_keys)
}

/// verifies the commitments on the received keys are valid and if so, xors the keys to compute agreed randomness
fn verify_and_xor_keys(
    party_id: usize,
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
            if *p == party_id {
                // XOR my own value
                xor_u8_arr_in_place(
                    &mut s,
                    &keys_opens[*p - 1]
                        .pop()
                        .with_context(|| log_error_wrapper("could not find my own key!"))?
                        .0
                         .0,
                );
            } else {
                let ko = rcv_keys_opens[*p - 1].pop().with_context(|| {
                    log_error_wrapper(format!("could not find KeyOpenValue for party {p}!"))
                })?;
                let com = rcv_coms[*p - 1].pop().with_context(|| {
                    log_error_wrapper(format!("could not find CommitmentValue for party {p}!"))
                })?;

                // check that randomnes was properly committed to in the first round
                if !verify(&ko.0 .0, &com, &ko.1) {
                    return Err(anyhow_error_and_log(format!(
                        "Commitment verification has failed for party {p}!"
                    )));
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

/// does the communication for RealAgreeRandom and returns the unpacked commitments and keys/openings
async fn agree_random_communication<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    coms: &[Vec<Commitment>],
    keys_opens: &[Vec<(PrfKey, Opening)>],
) -> anyhow::Result<(Vec<Vec<Commitment>>, Vec<Vec<(PrfKey, Opening)>>)> {
    let num_parties = session.num_parties();
    let party_id = session.my_role()?.one_based();

    // send commitments to all other parties. Each party gets the commitment for _all_ sets that they are member of at once to avoid multiple comm rounds
    let mut coms_to_send: HashMap<Role, NetworkValue<Z>> = HashMap::new();
    for p in 1..=num_parties {
        if p != party_id {
            coms_to_send.insert(
                Role::indexed_by_one(p),
                NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(coms[p - 1].clone())),
            );
        }
    }
    send_to_honest_parties(&coms_to_send, session).await?;

    // receive commitments from other parties
    let receive_from_roles = coms_to_send.keys().cloned().collect_vec();
    let received_coms = receive_from_parties::<Z, R, S>(&receive_from_roles, session).await?;

    let rcv_coms = check_and_unpack_coms(&received_coms, num_parties)?;

    // 2nd round: openings and randomness
    // send keys and openings to all other parties. Each party gets the values for _all_ sets that they are member of at once to avoid multiple comm rounds
    let mut key_open_to_send: HashMap<Role, NetworkValue<Z>> = HashMap::new();
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
    send_to_honest_parties(&key_open_to_send, session).await?;

    // receive keys and openings from other parties
    let received_keys = receive_from_parties::<Z, R, S>(&receive_from_roles, session).await?;

    let rcv_keys_opens = check_and_unpack_keys_openings(&received_keys, num_parties)?;

    Ok((rcv_coms, rcv_keys_opens))
}

#[async_trait]
impl AgreeRandom for RealAgreeRandom {
    #[instrument(name = "AgreeRandom", skip(session),fields(session_id = ?session.session_id(),own_identity = ?session.own_identity()))]
    async fn agree_random<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        let num_parties = session.num_parties();
        let party_id = session.my_role()?.one_based();

        let mut party_sets = compute_party_sets(
            session.my_role()?,
            session.num_parties(),
            session.threshold() as usize,
        );

        let mut s = [0u8; KEY_BYTE_LEN];

        let mut keys_opens: Vec<Vec<(PrfKey, Opening)>> = vec![Vec::new(); num_parties];
        let mut coms: Vec<Vec<Commitment>> = vec![Vec::new(); num_parties];

        // compute randomness s and commit to it, hold on to all values in vectors
        for set in &party_sets {
            session.rng().fill_bytes(&mut s);
            let (c, o) = commit(&s, &mut session.rng());
            for p in set {
                keys_opens[p - 1].push((PrfKey(s), o));
                coms[p - 1].push(c);
            }
        }

        let (mut rcv_coms, mut rcv_keys_opens) =
            agree_random_communication::<Z, R, S>(session, &coms, &keys_opens).await?;

        let r_a_keys = verify_and_xor_keys(
            party_id,
            &mut party_sets,
            &mut keys_opens,
            &mut rcv_keys_opens,
            &mut rcv_coms,
        )?;

        Ok(r_a_keys)
    }
}

pub struct RealAgreeRandomWithAbort {}

#[async_trait]
impl AgreeRandom for RealAgreeRandomWithAbort {
    #[instrument(name="AgreeRandom-w-Abort",skip(session),fields(session_id = ?session.session_id(),own_identity = ?session.own_identity()))]
    async fn agree_random<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        let num_parties = session.num_parties();
        let party_id = session.my_role()?.one_based();

        let mut party_sets = compute_party_sets(
            session.my_role()?,
            num_parties,
            session.threshold() as usize,
        );

        // run plain AgreeRandom to determine random keys as a first step
        let ars = RealAgreeRandom::agree_random::<Z, R, S>(session).await?;

        debug_assert_eq!(ars.len(), party_sets.len());

        let mut keys: Vec<Vec<PrfKey>> = vec![Vec::new(); num_parties];

        // put all agreed randomness in vector for sending, grouped by party
        for (idx, set) in party_sets.iter().enumerate() {
            for p in set {
                keys[p - 1].push(ars[idx].clone());
            }
        }

        // send keys to all other parties. Each party gets the values for _all_ sets that they are member of at once to avoid multiple comm rounds
        let mut key_to_send: HashMap<Role, NetworkValue<Z>> = HashMap::new();
        for p in 1..=num_parties {
            if p != party_id {
                key_to_send.insert(
                    Role::indexed_by_one(p),
                    NetworkValue::AgreeRandom(AgreeRandomValue::KeyValue(keys[p - 1].clone())),
                );
            }
        }

        // communication (send all keys, then receive all keys)
        send_to_honest_parties(&key_to_send, session).await?;
        let receive_from_roles = key_to_send.keys().cloned().collect_vec();
        let received_keys = receive_from_parties::<Z, R, S>(&receive_from_roles, session).await?;

        let mut rcv_keys = check_and_unpack_keys(&received_keys, num_parties)?;

        let r_a_keys = verify_keys_equal(party_id, &mut party_sets, &mut keys, &mut rcv_keys)?;

        Ok(r_a_keys)
    }
}

pub struct DummyAgreeRandom {}

#[async_trait]
impl AgreeRandom for DummyAgreeRandom {
    async fn agree_random<Z, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
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
                let mut hasher = Shake256::default();
                hasher.update(DSEP_AR);
                for &p in set {
                    hasher.update(&p.to_le_bytes());
                }
                let mut or = hasher.finalize_xof();
                or.read(&mut r_a);
                PrfKey(r_a)
            })
            .collect();

        Ok(r_a_keys)
    }
}

/// helper function returns the all the subsets of party IDs of size n-t of which the given party is a member
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
        check_and_unpack_coms, check_rcv_len, verify_and_xor_keys, AgreeRandom, DummyAgreeRandom,
        RealAgreeRandom, RealAgreeRandomWithAbort,
    };
    use crate::{
        algebra::residue_poly::ResiduePoly128,
        commitment::{Commitment, Opening, COMMITMENT_BYTE_LEN, DSEP_COMM, KEY_BYTE_LEN},
        execution::{
            runtime::{
                party::Role,
                session::{ParameterHandles, SmallSession},
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            small_execution::{
                agree_random::{
                    check_and_unpack_keys, check_and_unpack_keys_openings, compute_party_sets,
                    verify_keys_equal,
                },
                prf::{xor_u8_arr_in_place, PrfKey},
                prss::create_sets,
            },
        },
        networking::value::{AgreeRandomValue, NetworkValue},
        session_id::SessionId,
        tests::helper::{
            tests::get_networkless_base_session_for_parties,
            tests_and_benches::execute_protocol_small,
        },
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use sha3::{Digest, Sha3_256};
    use std::collections::{HashMap, VecDeque};
    use tokio::task::JoinSet;

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
                .block_on(async {
                    DummyAgreeRandom::agree_random::<ResiduePoly128, _, _>(&mut sess).await
                })
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
    fn test_real_agree_random() {
        generic_real_agree_random_test::<RealAgreeRandom>(2);
    }

    #[test]
    fn test_real_agree_random_with_abort() {
        generic_real_agree_random_test::<RealAgreeRandomWithAbort>(3);
    }

    fn generic_real_agree_random_test<A: AgreeRandom + 'static>(expected_rounds: usize) {
        let num_parties = 7;
        let threshold = 2;

        async fn task<A: AgreeRandom>(
            mut session: SmallSession<ResiduePoly128>,
        ) -> (Role, VecDeque<PrfKey>) {
            let keys = A::agree_random::<ResiduePoly128, _, _>(&mut session).await;
            let vd = VecDeque::from(keys.unwrap());
            (session.my_role().unwrap(), vd)
        }

        let res = execute_protocol_small(
            num_parties,
            threshold,
            Some(expected_rounds),
            &mut task::<A>,
        );

        // unpack results into hashmap
        let mut key_hm: HashMap<usize, VecDeque<PrfKey>> = HashMap::new();
        for (role, data) in res {
            key_hm.insert(role.zero_based(), data);
        }

        let all_party_sets: Vec<Vec<usize>> = create_sets(num_parties, threshold as usize)
            .into_iter()
            .collect();

        let mut allkeys: Vec<VecDeque<PrfKey>> =
            (0..num_parties).map(|p| key_hm[&p].clone()).collect();

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
    #[should_panic(expected = "Have not received an AgreeRandomValue from role 1!")]
    fn test_real_agree_random_no_reply() {
        let num_parties = 7;
        let threshold = 2;

        let identities = generate_fixed_identities(num_parties);

        assert_eq!(identities.len(), num_parties);

        let runtime = DistributedTestRuntime::new(identities, threshold as u8);

        // create sessions for each prss party, except party 0, which does not respond in this case
        let sessions: Vec<SmallSession<ResiduePoly128>> = (1..num_parties)
            .map(|p| {
                let num = p as u8;
                runtime.small_session_for_party(
                    SessionId(u128::MAX),
                    p,
                    Some(AesRng::seed_from_u64(num.into())),
                )
            })
            .collect();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut jobs = JoinSet::new();

        for sess in sessions.iter() {
            let mut ss = sess.clone();

            jobs.spawn(async move {
                RealAgreeRandom::agree_random::<ResiduePoly128, _, _>(&mut ss).await
            });
        }

        rt.block_on(async {
            for _ in &sessions {
                while let Some(v) = jobs.join_next().await {
                    let _ = v.unwrap().unwrap();
                }
            }
        });
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
        let mut rc: HashMap<Role, NetworkValue<ResiduePoly128>> = HashMap::new();
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
        let mut rc: HashMap<Role, NetworkValue<ResiduePoly128>> = HashMap::new();

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
        let mut rc: HashMap<Role, NetworkValue<ResiduePoly128>> = HashMap::new();
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
        let mut rc: HashMap<Role, NetworkValue<ResiduePoly128>> = HashMap::new();
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
        let mut rc: HashMap<Role, NetworkValue<ResiduePoly128>> = HashMap::new();
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
        let mut rc: HashMap<Role, NetworkValue<ResiduePoly128>> = HashMap::new();

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
        let party_sets = vec![vec![1_usize, 2]];

        // received key and opening
        let key1 = PrfKey([42_u8; KEY_BYTE_LEN]);
        let opening1 = Opening([69_u8; KEY_BYTE_LEN]);
        let ko1 = (key1.clone(), opening1);
        let rcv_keys_opens = vec![vec![ko1.clone()], Vec::<(PrfKey, Opening)>::new()];

        // compute commitment for received key
        let mut hasher = Sha3_256::new();
        hasher.update(DSEP_COMM);
        hasher.update(opening1.0);
        hasher.update(key1.0);
        let or = hasher.finalize();

        let com_buf: [u8; COMMITMENT_BYTE_LEN] = or.as_slice().try_into().expect("wrong length");
        let commitment1 = Commitment(com_buf);
        let mut rcv_coms = vec![vec![commitment1], Vec::<Commitment>::new()];

        // my own key and opening
        let ko2 = (PrfKey([1_u8; KEY_BYTE_LEN]), Opening([23_u8; KEY_BYTE_LEN]));
        let keys_opens = vec![Vec::<(PrfKey, Opening)>::new(), vec![ko2]];

        // test correctly working verification and key generation
        let res = verify_and_xor_keys(
            party_id,
            &mut party_sets.clone(),
            &mut keys_opens.clone(),
            &mut rcv_keys_opens.clone(),
            &mut rcv_coms.clone(),
        )
        .unwrap();

        // test that resulting key is the xor of the input keys 42 ^ 1 = 43
        assert_eq!(res, vec![PrfKey([43_u8; KEY_BYTE_LEN])]);

        // test failing commitment verification
        rcv_coms = vec![
            vec![Commitment([0_u8; COMMITMENT_BYTE_LEN])],
            Vec::<Commitment>::new(),
        ];

        let r = verify_and_xor_keys(
            party_id,
            &mut party_sets.clone(),
            &mut keys_opens.clone(),
            &mut rcv_keys_opens.clone(),
            &mut rcv_coms.clone(),
        )
        .unwrap_err()
        .to_string();

        assert!(r.contains("Commitment verification has failed for party 1!"));
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
