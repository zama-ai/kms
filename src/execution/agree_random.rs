use super::{
    p2p::{receive_from_parties, send_to_parties},
    party::Role,
    session::{BaseSession, BaseSessionHandles, ParameterHandles},
    small_execution::prss::{create_sets, PrfKey},
};
use crate::{
    commitment::{commit, KEY_BYTE_LEN},
    value::NetworkValue,
};
use crate::{
    commitment::{verify, Commitment, Opening},
    value::AgreeRandomValue,
};
use anyhow::anyhow;
use async_trait::async_trait;
use blake3::Hasher;
use itertools::Itertools;
use rand::RngCore;
use std::collections::HashMap;

#[async_trait]
pub trait AgreeRandom {
    /// agree on a random value, as seen from a single party's view (determined by the session)
    async fn agree_random(session: &mut BaseSession) -> anyhow::Result<Vec<PrfKey>>;
}

pub struct RealAgreeRandom {}

fn check_rcv_len(rcv_len: usize, expect_len: usize, tstr: &str) -> anyhow::Result<()> {
    // check that we have all expected responses
    if rcv_len != expect_len {
        tracing::error!(
            "have received {} {tstr}, but expected {}",
            rcv_len,
            expect_len
        );
        return Err(anyhow!(
            "have received {} {tstr}, but expected {}",
            rcv_len,
            expect_len
        ));
    }
    Ok(())
}

fn check_and_unpack_coms(
    received_coms: &HashMap<Role, NetworkValue>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<Commitment>>> {
    check_rcv_len(received_coms.len(), num_parties - 1, "commitments")?;

    // unpack received commitments and check message types
    let mut rcv_coms: Vec<Vec<Commitment>> = vec![Vec::new(); num_parties]; //even though we only receive n-1 values, we currently need a vec with size n for indexing and mutating below.
    for (sender_role, sender_data) in received_coms {
        match sender_data {
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(cv)) => {
                rcv_coms[(sender_role.0 - 1) as usize] = cv.to_vec();
            }
            _ => {
                tracing::error!("Have not received a CommitmentValue from role {sender_role}!");
                return Err(anyhow!(
                    "Have not received a CommitmentValue from role {sender_role}!"
                ));
            }
        }
    }

    Ok(rcv_coms)
}

fn check_and_unpack_keys(
    received_keys: &HashMap<Role, NetworkValue>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<(PrfKey, Opening)>>> {
    check_rcv_len(received_keys.len(), num_parties - 1, "keys/openings")?;

    // unpack received keys and openings and check message types
    let mut rcv_keys_opens: Vec<Vec<(PrfKey, Opening)>> = vec![Vec::new(); num_parties]; //even though we only receive n-1 values, we currently need a vec with size n for indexing and mutating below.
    for (sender_role, sender_data) in received_keys {
        match sender_data {
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(kov)) => {
                rcv_keys_opens[(sender_role.0 - 1) as usize] = kov.to_vec();
            }
            _ => {
                return {
                    tracing::error!(
                        "Have not received a KeyOpenValue value from role {sender_role}!"
                    );
                    Err(anyhow!(
                        "Have not received a KeyOpenValue value from role {sender_role}!"
                    ))
                }
            }
        }
    }

    Ok(rcv_keys_opens)
}

fn compute_and_verify(
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
                        .expect("could not find my own key!")
                        .0
                         .0,
                );
            } else {
                let ko = rcv_keys_opens[*p - 1]
                    .pop()
                    .expect("could not find key/opening value for party {p}!");
                let com = rcv_coms[*p - 1]
                    .pop()
                    .expect("could not find commitment for party {p}!");

                // check that randomnes was properly committed to in the first round
                if !verify(&ko.0 .0, &com, &ko.1) {
                    tracing::error!("Commitment verification has failed for party {p}!");
                    return Err(anyhow!("Commitment verification has failed for party {p}!"));
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

#[async_trait]
impl AgreeRandom for RealAgreeRandom {
    async fn agree_random(session: &mut BaseSession) -> anyhow::Result<Vec<PrfKey>> {
        let num_parties = session.amount_of_parties();
        let party_id = session.my_role()?.0 as usize;

        // compute dummy randomness for all the subsets in which this party_id is a member
        let mut party_sets: Vec<Vec<usize>> =
            create_sets(num_parties, session.threshold() as usize)
                .into_iter()
                .filter(|aset: &Vec<usize>| aset.contains(&party_id))
                .collect();

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

        // send commitments to all other parties. Each party gets the commitment for _all_ sets that they are member of at once to avoid multiple comm rounds
        let mut coms_to_send: HashMap<Role, NetworkValue> = HashMap::new();
        for p in 1..=num_parties {
            if p != party_id {
                coms_to_send.insert(
                    Role(p as u64),
                    NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(
                        coms[p - 1].clone(),
                    )),
                );
            }
        }
        send_to_parties(&coms_to_send, session).await?;

        // receive commitments from other parties
        let receive_from_roles = coms_to_send.keys().cloned().collect_vec();
        let received_coms = receive_from_parties(&receive_from_roles, session).await?;

        let mut rcv_coms = check_and_unpack_coms(&received_coms, num_parties)?;

        // 2nd round: openings and randomness
        session.network().increase_round_counter().await?;

        // send keys and openings to all other parties. Each party gets the values for _all_ sets that they are member of at once to avoid multiple comm rounds
        let mut key_open_to_send: HashMap<Role, NetworkValue> = HashMap::new();
        for p in 1..=num_parties {
            if p != party_id {
                key_open_to_send.insert(
                    Role(p as u64),
                    NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(
                        keys_opens[p - 1].clone(),
                    )),
                );
            }
        }
        send_to_parties(&key_open_to_send, session).await?;

        // receive keys and opensings from other parties
        let received_keys = receive_from_parties(&receive_from_roles, session).await?;

        let mut rcv_keys_opens = check_and_unpack_keys(&received_keys, num_parties)?;

        let r_a_keys = compute_and_verify(
            party_id,
            &mut party_sets,
            &mut keys_opens,
            &mut rcv_keys_opens,
            &mut rcv_coms,
        )?;

        Ok(r_a_keys)
    }
}

pub struct DummyAgreeRandom {}

#[async_trait]
impl AgreeRandom for DummyAgreeRandom {
    async fn agree_random(session: &mut BaseSession) -> anyhow::Result<Vec<PrfKey>> {
        let num_parties = session.amount_of_parties();
        let party_id = session.my_role()?.0 as usize;

        // compute dummy randomness for all the subsets in which this party_id is a member
        let party_sets: Vec<Vec<usize>> = create_sets(num_parties, session.threshold() as usize)
            .into_iter()
            .filter(|aset| aset.contains(&party_id))
            .collect();

        // byte array for holding the randomness
        let mut r_a = [0u8; KEY_BYTE_LEN];

        let r_a_keys = party_sets
            .iter()
            .map(|set| {
                // hash party IDs contained in this set as dummy value for r_a
                let mut bytes: Vec<u8> = Vec::new();
                for &p in set {
                    bytes.extend_from_slice(&p.to_le_bytes());
                }

                let mut hasher = Hasher::new();
                hasher.update(&bytes);
                let mut or = hasher.finalize_xof();
                or.fill(&mut r_a);
                PrfKey(r_a)
            })
            .collect();

        Ok(r_a_keys)
    }
}

// compute bit-wise xor of two byte arrays in place
fn xor_u8_arr_in_place(arr1: &mut [u8; KEY_BYTE_LEN], arr2: &[u8; KEY_BYTE_LEN]) {
    for i in 0..KEY_BYTE_LEN {
        arr1[i] ^= arr2[i];
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_and_unpack_coms, check_rcv_len, compute_and_verify, xor_u8_arr_in_place, AgreeRandom,
        DummyAgreeRandom, RealAgreeRandom,
    };
    use crate::{
        commitment::{Commitment, Opening, COMMITMENT_BYTE_LEN, KEY_BYTE_LEN},
        computation::SessionId,
        execution::{
            agree_random::check_and_unpack_keys,
            distributed::DistributedTestRuntime,
            party::Role,
            session::{SmallSession, ToBaseSession},
            small_execution::prss::{create_sets, PrfKey},
        },
        tests::helper::tests::get_small_session_for_parties,
        value::{AgreeRandomValue, NetworkValue},
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rstest::rstest;
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
            let sess = get_small_session_for_parties(num_parties, threshold, Role(p as u64));

            let _guard = rt.enter();
            let keys = rt
                .block_on(async {
                    DummyAgreeRandom::agree_random(&mut sess.to_base_session()).await
                })
                .unwrap();

            let vd = VecDeque::from(keys);
            allkeys.push(vd);
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

    #[rstest]
    #[case(ChaCha20Rng::from_seed([42_u8; 32]))]
    #[case(ChaCha20Rng::from_entropy())]
    fn test_real_agree_random(#[case] rng: ChaCha20Rng) {
        let num_parties = 7;
        let threshold = 2;
        let identities = crate::tests::helper::tests::generate_identities(num_parties);
        assert_eq!(identities.len(), num_parties);

        let runtime = DistributedTestRuntime::new(identities, threshold as u8);

        // create sessions for each prss party
        let sessions: Vec<SmallSession> = (0..num_parties)
            .map(|p| {
                runtime
                    .small_session_for_player(SessionId(u128::MAX), p, Some(rng.clone()))
                    .unwrap()
            })
            .collect();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut jobs = JoinSet::new();

        for (role_idx, sess) in sessions.iter().enumerate() {
            let ss = sess.clone();

            jobs.spawn(async move {
                let keys = RealAgreeRandom::agree_random(&mut ss.to_base_session()).await;
                let vd = VecDeque::from(keys.unwrap());
                (role_idx, vd)
            });
        }

        let mut key_hm: HashMap<usize, VecDeque<PrfKey>> = HashMap::new();

        rt.block_on(async {
            for _ in &sessions {
                while let Some(v) = jobs.join_next().await {
                    let vv = v.unwrap();
                    let data = vv.1;
                    let role = vv.0;
                    key_hm.insert(role, data);
                }
            }
        });

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
    #[should_panic(expected = "Have not received a CommitmentValue from role 1!")]
    fn test_real_agree_random_no_reply() {
        let num_parties = 7;
        let threshold = 2;

        let identities = crate::tests::helper::tests::generate_identities(num_parties);

        assert_eq!(identities.len(), num_parties);

        let runtime = DistributedTestRuntime::new(identities, threshold as u8);

        // create sessions for each prss party, except party 0, which does not respond in this case
        let sessions: Vec<SmallSession> = (1..num_parties)
            .map(|p| {
                let num = p as u8;
                runtime
                    .small_session_for_player(
                        SessionId(u128::MAX),
                        p,
                        Some(ChaCha20Rng::from_seed([num; 32])),
                    )
                    .unwrap()
            })
            .collect();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut jobs = JoinSet::new();

        for sess in sessions.iter() {
            let ss = sess.clone();

            jobs.spawn(
                async move { RealAgreeRandom::agree_random(&mut ss.to_base_session()).await },
            );
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
        assert_eq!(err, "have received 23 things, but expected 42".to_string());
    }

    #[test]
    fn test_check_and_unpack_coms() {
        // test normal behavior
        let mut num_parties = 3;
        let mut rc: HashMap<Role, NetworkValue> = HashMap::new();
        let c1 = Commitment([12_u8; COMMITMENT_BYTE_LEN]);
        let c2 = Commitment([42_u8; COMMITMENT_BYTE_LEN]);

        rc.insert(
            Role(3),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c1])),
        );
        rc.insert(
            Role(1),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c2])),
        );
        let r = check_and_unpack_coms(&rc, num_parties).unwrap();

        let expect = vec![vec![c2], Vec::<Commitment>::new(), vec![c1]];
        assert_eq!(r, expect);

        // Test Error when receiving wrong number of values
        rc.insert(
            Role(4),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c2])),
        );

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert_eq!(r, "have received 3 commitments, but expected 2");

        // Test Error when receiving a wrong AR value
        let ko = (
            PrfKey([42_u8; KEY_BYTE_LEN]),
            Opening([42_u8; KEY_BYTE_LEN]),
        );
        num_parties = 2;
        rc = HashMap::new();
        rc.insert(
            Role(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko])),
        );

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert_eq!(r, "Have not received a CommitmentValue from role 2!");

        // Test Error when receiving Bot
        rc = HashMap::new();
        rc.insert(Role(1), NetworkValue::Bot);

        let r = check_and_unpack_coms(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert_eq!(r, "Have not received a CommitmentValue from role 1!");
    }

    #[test]
    fn test_check_and_unpack_keys() {
        // test normal behavior
        let mut num_parties = 3;
        let mut rc: HashMap<Role, NetworkValue> = HashMap::new();
        let ko1 = (PrfKey([1_u8; KEY_BYTE_LEN]), Opening([2_u8; KEY_BYTE_LEN]));
        let ko2 = (
            PrfKey([42_u8; KEY_BYTE_LEN]),
            Opening([42_u8; KEY_BYTE_LEN]),
        );

        rc.insert(
            Role(3),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko1.clone()])),
        );
        rc.insert(
            Role(1),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko2.clone()])),
        );
        let r = check_and_unpack_keys(&rc, num_parties).unwrap();

        let expect = vec![
            vec![ko2.clone()],
            Vec::<(PrfKey, Opening)>::new(),
            vec![ko1],
        ];
        assert_eq!(r, expect);

        // Test Error when receiving wrong number of values
        rc.insert(
            Role(4),
            NetworkValue::AgreeRandom(AgreeRandomValue::KeyOpenValue(vec![ko2])),
        );

        let r = check_and_unpack_keys(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert_eq!(r, "have received 3 keys/openings, but expected 2");

        // Test Error when receiving a wrong AR value
        let c = Commitment([12_u8; COMMITMENT_BYTE_LEN]);
        num_parties = 2;
        rc = HashMap::new();
        rc.insert(
            Role(2),
            NetworkValue::AgreeRandom(AgreeRandomValue::CommitmentValue(vec![c])),
        );

        let r = check_and_unpack_keys(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert_eq!(r, "Have not received a KeyOpenValue value from role 2!");

        // Test Error when receiving Bot
        rc = HashMap::new();
        rc.insert(Role(1), NetworkValue::Bot);

        let r = check_and_unpack_keys(&rc, num_parties)
            .unwrap_err()
            .to_string();
        assert_eq!(r, "Have not received a KeyOpenValue value from role 1!");
    }

    #[test]
    fn test_compute_and_verify() {
        let party_id = 2;
        let party_sets = vec![vec![1_usize, 2]];

        let key1 = PrfKey([42_u8; KEY_BYTE_LEN]);
        let opening1 = Opening([69_u8; KEY_BYTE_LEN]);

        let ko1 = (key1.clone(), opening1);
        let ko2 = (PrfKey([1_u8; KEY_BYTE_LEN]), Opening([23_u8; KEY_BYTE_LEN]));

        let keys_opens = vec![Vec::<(PrfKey, Opening)>::new(), vec![ko2]];

        let rcv_keys_opens = vec![vec![ko1.clone()], Vec::<(PrfKey, Opening)>::new()];

        let mut com_buf = [0u8; COMMITMENT_BYTE_LEN];
        let mut hasher = blake3::Hasher::new();
        hasher.update(&opening1.0);
        hasher.update(&key1.0);
        let mut or = hasher.finalize_xof();
        or.fill(&mut com_buf);
        let commitment1 = Commitment(com_buf);

        let mut rcv_coms = vec![vec![commitment1], Vec::<Commitment>::new()];

        // test correctly working verification and key generation
        let res = compute_and_verify(
            party_id,
            &mut party_sets.clone(),
            &mut keys_opens.clone(),
            &mut rcv_keys_opens.clone(),
            &mut rcv_coms.clone(),
        )
        .unwrap();

        // test that resulting key is the xor of the input keys 42 ^ 1 = 43
        assert_eq!(res, vec![PrfKey([43_u8; KEY_BYTE_LEN])]);

        // test failing verification
        rcv_coms = vec![
            vec![Commitment([0_u8; COMMITMENT_BYTE_LEN])],
            Vec::<Commitment>::new(),
        ];

        let r = compute_and_verify(
            party_id,
            &mut party_sets.clone(),
            &mut keys_opens.clone(),
            &mut rcv_keys_opens.clone(),
            &mut rcv_coms.clone(),
        )
        .unwrap_err()
        .to_string();

        assert_eq!(r, "Commitment verification has failed for party 1!");
    }
}
