use crate::{
    computation::SessionId,
    execution::constants::LOG_BD1_NOM,
    poly::{Poly, Ring},
    residue_poly::ResiduePoly,
    One, Zero, Z128,
};
use anyhow::anyhow;
use blake3::Hasher;
use byteorder::{BigEndian, ReadBytesExt};
use itertools::Itertools;
use rand::RngCore;
use std::num::Wrapping;

use super::constants::PRSS_SIZE_MAX;

fn create_sets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (1..=n).combinations(n - t).collect()
}

/// structure for holding values for each subset of n-t parties
#[derive(Debug, Clone)]
struct PrssSet {
    parties: Vec<usize>,
    random_agreed_key: PrfKey,
}

/// PRSS object that holds info in a certain epoch
#[derive(Debug, Clone)]
pub struct PRSSSetup {
    /// the logarithm of n choose t (num_parties choose threshold)
    log_n_choose_t: u32,
    /// all possible subsets of n-t parties (A) and their shared PRG
    sets: Vec<PrssSet>,
    /// points on the f_A polynomials for the sets of parties in A
    f_a_points: Vec<Vec<ResiduePoly<Z128>>>,
}

/// PRSS state for use within a given session.
#[derive(Debug, Clone)]
pub struct PRSSState {
    /// session id, which is fixed
    session_id: u128,
    /// counter that increases on every call to .next()
    counter: u128,
    /// PRSSSetup
    prss_setup: PRSSSetup,
}

/// key for blake3
#[derive(Debug, Clone)]
struct PrfKey([u8; 16]);

/// Function Psi that generates bounded randomness
fn psi(psi_prf_key: &PrfKey, sid: u128, ctr: u128, log_n_choose_t: u32) -> anyhow::Result<Z128> {
    let keyvec = [psi_prf_key.0, sid.to_le_bytes()].concat();
    let key = <&[u8; 32]>::try_from(keyvec.as_slice())?;

    let mut prf = Hasher::new_keyed(key);
    prf.update(&ctr.to_le_bytes());
    let mut psi_out = prf.finalize_xof();
    let mut res = [0_u128; 1];
    psi_out.read_u128_into::<BigEndian>(&mut res)?;

    let u = res[0] >> (Z128::EL_BIT_LENGTH as u32 - LOG_BD1_NOM + log_n_choose_t);

    Ok(Wrapping(u))
}

/// computes the points on the polys f_A for all parties in the sets A
/// f_A is one at 0, and zero at the party indices not in set A
fn compute_f_a_points(
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<Vec<ResiduePoly<Z128>>>> {
    if num_integer::binomial(num_parties, threshold) > PRSS_SIZE_MAX {
        return Err(anyhow!("PRSS set size is too large!"));
    }

    // compute lifted and inverted gamma values once
    let mut inv_coefs = (1..=num_parties)
        .map(ResiduePoly::<Z128>::lift_and_invert)
        .collect::<Result<Vec<_>, _>>()?;
    inv_coefs.insert(0, ResiduePoly::<Z128>::ZERO);

    // embed party IDs once
    let parties: Vec<_> = (0..=num_parties)
        .map(ResiduePoly::<Z128>::embed)
        .collect::<Result<Vec<_>, _>>()?;

    // compute additive inverse of embedded party IDs
    let neg_parties: Vec<_> = (0..=num_parties)
        .map(|p| Poly::from_coefs(vec![ResiduePoly::<Z128>::ZERO - parties[p]]))
        .collect::<Vec<_>>();

    // the combinations of party IDs *not* in the sets A
    let mut combinations = (1..=num_parties)
        .combinations(threshold)
        .collect::<Vec<_>>();
    // reverse the list of party IDs, so the order matches with the combinations of parties *in* the sets A in create_sets()
    combinations.reverse();

    // polynomial x
    let x: Poly<ResiduePoly<std::num::Wrapping<u128>>> =
        Poly::from_coefs(vec![ResiduePoly::<Z128>::ZERO, ResiduePoly::<Z128>::ONE]);

    let mut sets = Vec::new();

    for c in &combinations {
        // compute poly for this combination of parties
        // poly will be of degree T, zero at the points p in c, and one at 0
        let mut poly = Poly::from_coefs(vec![ResiduePoly::<Z128>::ONE]);
        for p in c {
            poly = poly
                * (x.clone() + neg_parties[*p].clone())
                * Poly::from_coefs(vec![inv_coefs[*p]]);
        }

        // check that poly is 1 at position 0
        debug_assert_eq!(ResiduePoly::<Z128>::ONE, poly.eval(&parties[0]));

        // evaluate the poly at the party indices gamma
        let set: Vec<_> = (1..=num_parties).map(|p| poly.eval(&parties[p])).collect();

        sets.push(set);
    }
    Ok(sets)
}

impl PRSSState {
    /// PRSS Next for a single party
    pub fn next(&mut self, party_id: usize) -> anyhow::Result<ResiduePoly<Z128>> {
        // party IDs start from 1
        debug_assert!(party_id > 0);

        let mut res = ResiduePoly::<Z128>::ZERO;

        for (idx, set) in self.prss_setup.sets.iter_mut().enumerate() {
            if set.parties.contains(&party_id) {
                let psi = psi(
                    &set.random_agreed_key,
                    self.session_id,
                    self.counter,
                    self.prss_setup.log_n_choose_t,
                )?;
                let f_a = self.prss_setup.f_a_points[idx][party_id - 1];
                res += f_a * psi;
            }
        }

        self.counter += 1;

        Ok(res)
    }
}

impl PRSSSetup {
    /// PRSS Init that is called once at the beginning of an epoch
    pub fn epoch_init<R: RngCore>(
        num_parties: usize,
        threshold: usize,
        rng: &mut R,
    ) -> anyhow::Result<Self> {
        let log_n_choose_t = num_integer::binomial(num_parties, threshold)
            .next_power_of_two()
            .ilog2();

        let sets = create_sets(num_parties, threshold)
            .into_iter()
            .map(|aset| {
                let mut r_a = [0u8; 16];
                rng.fill_bytes(&mut r_a);
                PrssSet {
                    parties: aset,
                    random_agreed_key: PrfKey(r_a),
                }
            })
            .collect();

        let points = compute_f_a_points(num_parties, threshold)?;

        Ok(PRSSSetup {
            log_n_choose_t,
            sets,
            f_a_points: points,
        })
    }

    pub fn new_session(&self, sid: SessionId) -> PRSSState {
        PRSSState {
            session_id: sid.0,
            counter: 0_u128,
            prss_setup: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{Circuit, Operation, Operator},
        execution::{
            distributed::{DecryptionMode, DistributedTestRuntime},
            party::Identity,
            prep::to_large_ciphertext,
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet},
        shamir::ShamirGSharings,
        tests::test_data_setup::tests::TEST_KEY_PATH,
        value::Value,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;

    #[test]
    fn test_create_sets() {
        let c = create_sets(4, 1);
        assert_eq!(
            c,
            vec![vec![1, 2, 3], vec![1, 2, 4], vec![1, 3, 4], vec![2, 3, 4],]
        )
    }

    #[rstest]
    #[case([23_u8; 16])]
    #[case(AesRng::generate_random_seed())]
    fn test_prss_no_network(#[case] seed: [u8; 16]) {
        let num_parties = 10;
        let threshold = 3;
        let n_choose_t: usize = num_integer::binomial(num_parties, threshold);
        let log_n_choose_t = n_choose_t.next_power_of_two().ilog2();

        let sid = SessionId::from(23);

        let mut rng = AesRng::from_seed(seed);
        let prss_setup = PRSSSetup::epoch_init(num_parties, threshold, &mut rng).unwrap();

        let shares = (1..=num_parties)
            .map(|p| {
                let mut state = prss_setup.new_session(sid);

                assert_eq!(state.counter, 0);
                assert_eq!(state.session_id, sid.0);

                let nextval = state.next(p).unwrap();

                // prss state counter must have increased after call to next
                assert_eq!(state.counter, 1);
                // prss state session ID must have stayed the same
                assert_eq!(state.session_id, sid.0);

                (p, nextval)
            })
            .collect();

        let e_shares = ShamirGSharings { shares };

        let recon = e_shares.reconstruct(threshold).unwrap();

        tracing::debug!("reconstructed prss value: {}", recon.0);
        tracing::debug!("bitsize of reconstructed value: {}", recon.0.ilog2());
        tracing::debug!("maximum allowed bitsize: {}", LOG_BD1_NOM);

        // check that reconstructed PRSS random output E has limited bit length
        // must be at most (2^pow-1) * Bd bits (which is the nominator of Bd1)
        assert!(recon.0.ilog2() < LOG_BD1_NOM);

        // check that E is the sum of all r_A values
        let mut rng = AesRng::from_seed(seed);
        let mut plain_e = Z128::ZERO;
        for _ in 0..num_integer::binomial(num_parties, threshold) {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            let k: [u8; 32] = [key, sid.0.to_le_bytes()].concat().try_into().unwrap();

            let mut prf = Hasher::new_keyed(&k);
            prf.update(&0_u128.to_le_bytes());
            let mut psi_out = prf.finalize_xof();
            let mut res = [0_u128; 1];
            psi_out.read_u128_into::<BigEndian>(&mut res).unwrap();

            let u = res[0] >> (Z128::EL_BIT_LENGTH as u32 - LOG_BD1_NOM + log_n_choose_t);

            plain_e += u;
        }

        assert_eq!(plain_e, recon);
    }

    #[test]
    fn test_prss_distributed_local() {
        let threshold = 3;
        let num_parties = 10;
        let mut rng = AesRng::seed_from_u64(423);
        let msg: u8 = 21;
        let keys: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::PrssPrep,
                    operands: vec![String::from("s0")], // Preprocess random value and store in register s0
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("3"),     // Ignored
                        String::from("false"), // Ignored
                        String::from("c0"),    // Register we store in
                        String::from("s0"),    // Register we read
                    ],
                },
                Operation {
                    operator: Operator::ShrCI, // Right shift
                    operands: vec![String::from("c1"), String::from("c0"), String::from("123")], // Stores the result in c1, reads from c0, and shifts it 123=127-2*2
                },
                Operation {
                    operator: Operator::PrintRegPlain, // Output the value
                    operands: vec![
                        String::from("c1"), // From index c1
                        keys.pk
                            .threshold_lwe_parameters
                            .input_cipher_parameters
                            .usable_message_modulus_log
                            .0
                            .to_string(), // Bits in message
                    ],
                },
            ],
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
            Identity("localhost:5005".to_string()),
            Identity("localhost:5006".to_string()),
            Identity("localhost:5007".to_string()),
            Identity("localhost:5008".to_string()),
            Identity("localhost:5009".to_string()),
        ];

        let prss_setup = Some(PRSSSetup::epoch_init(num_parties, threshold, &mut rng).unwrap());

        // generate keys
        let key_shares = keygen_all_party_shares(&keys, &mut rng, num_parties, threshold).unwrap();
        let ct = keys.pk.encrypt(&mut rng, msg);
        let large_ct = to_large_ciphertext(&keys.ck, &ct);

        let runtime =
            DistributedTestRuntime::new(identities, threshold as u8, prss_setup, Some(key_shares));

        // test PRSS with circuit evaluation
        let results_circ = runtime
            .evaluate_circuit(&circuit, Some(large_ct.clone()))
            .unwrap();
        let out_circ = &results_circ[&Identity("localhost:5000".to_string())];

        // test PRSS with decryption endpoint
        let results_dec = runtime
            .threshold_decrypt(large_ct, DecryptionMode::PRSSDecrypt)
            .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        assert_eq!(out_dec[0], Value::Ring128(std::num::Wrapping(msg as u128)));
        assert_eq!(out_circ[0], Value::Ring128(std::num::Wrapping(msg as u128)));
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(23)]
    fn test_prss_next_ctr(#[case] rounds: u128) {
        let num_parties = 4;
        let threshold = 1;

        let sid = SessionId::from(23425);

        let mut rng = AesRng::seed_from_u64(54321);
        let prss = PRSSSetup::epoch_init(num_parties, threshold, &mut rng).unwrap();

        let mut state = prss.new_session(sid);

        assert_eq!(state.counter, 0);
        assert_eq!(state.session_id, sid.0);

        for _ in 0..rounds {
            let _ = state.next(1);
        }

        // prss state counter must have increased to n after n rounds
        assert_eq!(state.counter, rounds);

        // prss state session ID must have stayed the same
        assert_eq!(state.session_id, sid.0);
    }

    #[rstest]
    #[case(4, 1)]
    #[case(10, 3)]
    /// check that points computed on f_A are well-formed
    fn test_prss_fa_poly(#[case] num_parties: usize, #[case] threshold: usize) {
        let mut rng = AesRng::seed_from_u64(5);
        let prss = PRSSSetup::epoch_init(num_parties, threshold, &mut rng).unwrap();

        let mut combinations = (1..=num_parties)
            .combinations(threshold)
            .collect::<Vec<_>>();
        combinations.reverse();

        for (idx, c) in combinations.iter().enumerate() {
            for p in 1..=num_parties {
                let point = prss.f_a_points[idx][p - 1];
                if c.contains(&p) {
                    assert_eq!(point, ResiduePoly::<Z128>::ZERO)
                } else {
                    assert_ne!(point, ResiduePoly::<Z128>::ZERO)
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "PRSS set size is too large!")]
    fn test_prss_too_large() {
        let mut rng = AesRng::seed_from_u64(1);
        let _prss = PRSSSetup::epoch_init(22, 7, &mut rng).unwrap();
    }

    #[test]
    // check that the combinations of party ID in A and not in A add up to all party IDs and that the indices match when reversing one list
    fn test_matching_combinations() {
        let num_parties = 10;
        let threshold = 3;

        // the combinations of party IDs *in* the sets A
        let sets = create_sets(num_parties, threshold);

        // the combinations of party IDs *not* in the sets A
        let mut combinations = (1..=num_parties)
            .combinations(threshold)
            .collect::<Vec<_>>();
        // reverse the list of party IDs, so the order matches with the combinations of parties *in* the sets A in create_sets()
        combinations.reverse();

        // the list of all party IDs 1..=N in order
        let all_parties = (1..=num_parties).collect_vec();

        for (idx, c) in combinations.iter().enumerate() {
            // merge both sets of party IDs
            let mut merge = [sets[idx].clone(), c.clone()].concat();

            // sort the list, so we can check for equality with all_parites
            merge.sort();

            assert_eq!(merge, all_parties);
        }
    }
}
