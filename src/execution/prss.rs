use crate::{
    computation::SessionId, execution::LOG_BD1_NOM, residue_poly::ResiduePoly, One, Ring, ZConsts,
    Zero, Z128,
};
use blake3::Hasher;
use byteorder::{BigEndian, ReadBytesExt};
use itertools::Itertools;
use rand::RngCore;
use std::num::Wrapping;

/// precomputed points on poly f_A for n=4 and t=1
const PRECOMP_POINTS_4_1: [[[Z128; 8]; 4]; 4] = [
    [
        [
            Z128::ZERO,
            Z128::ONE,
            Z128::ZERO,
            Wrapping(u128::MAX),
            Z128::ZERO,
            Z128::ZERO,
            Z128::ONE,
            Wrapping(u128::MAX),
        ],
        [
            Z128::TWO,
            Z128::ZERO,
            Z128::ONE,
            Z128::ONE,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ONE,
        ],
        [
            Z128::ONE,
            Z128::ONE,
            Z128::ONE,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ONE,
            Z128::ZERO,
        ],
        [
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
    ],
    [
        [
            Z128::ONE,
            Z128::ONE,
            Wrapping(u128::MAX),
            Z128::TWO,
            Wrapping(u128::MAX),
            Z128::ONE,
            Wrapping(u128::MAX),
            Z128::ONE,
        ],
        [
            Z128::ZERO,
            Wrapping(u128::MAX),
            Z128::ONE,
            Wrapping(u128::MAX - 1),
            Z128::ONE,
            Wrapping(u128::MAX),
            Z128::ONE,
            Wrapping(u128::MAX),
        ],
        [
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
        [
            Z128::TWO,
            Z128::ZERO,
            Wrapping(u128::MAX),
            Z128::TWO,
            Wrapping(u128::MAX),
            Z128::ONE,
            Wrapping(u128::MAX),
            Z128::ONE,
        ],
    ],
    [
        [
            Z128::TWO,
            Z128::ZERO,
            Z128::ONE,
            Z128::ONE,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ONE,
        ],
        [
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
        [
            Z128::ONE,
            Z128::ZERO,
            Z128::ONE,
            Z128::ONE,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ONE,
        ],
        [
            Z128::ONE,
            Wrapping(u128::MAX),
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
    ],
    [
        [
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
        [
            Z128::ONE,
            Wrapping(u128::MAX),
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
        [
            Z128::ZERO,
            Wrapping(u128::MAX),
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
        [
            Z128::ONE,
            Z128::ZERO,
            Wrapping(u128::MAX),
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
            Z128::ZERO,
        ],
    ],
];

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
    /// all possible subsets of n-t parties and their shared PRG
    sets: Vec<PrssSet>,
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
fn psi(
    psi_prf_key: &mut PrfKey,
    sid: u128,
    ctr: u128,
    log_n_choose_t: u32,
) -> anyhow::Result<Z128> {
    let keyvec = [psi_prf_key.0, sid.to_le_bytes()].concat();
    let key = <&[u8; 32]>::try_from(keyvec.as_slice())?;

    let mut prf = Hasher::new_keyed(key);
    prf.update(&ctr.to_le_bytes());
    let mut psi_out = prf.finalize_xof();
    let mut res = [0_u128; 1];
    psi_out.read_u128_into::<BigEndian>(&mut res)?;

    let u = res[0] >> (Z128::RING_SIZE as u32 - LOG_BD1_NOM + log_n_choose_t);

    Ok(Wrapping(u))
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
                    &mut set.random_agreed_key,
                    self.session_id,
                    self.counter,
                    self.prss_setup.log_n_choose_t,
                )?;
                let f_a = ResiduePoly::<Z128>::from_slice(PRECOMP_POINTS_4_1[idx][party_id - 1]);
                res = res + f_a * psi;
            }
        }

        self.counter += 1;

        Ok(res)
    }
}

impl PRSSSetup {
    /// PRSS Init that is called once at the beginning of an epoch
    pub fn epoch_init<R: RngCore>(num_parties: usize, threshold: usize, rng: &mut R) -> Self {
        // we are currently limited to 4 parties and threshold 1 for the PRSS due to pre-computed points for these params
        assert_eq!(num_parties, 4);
        assert_eq!(threshold, 1);
        let log_n_choose_t = num_integer::binomial(num_parties, threshold).ilog2();

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

        PRSSSetup {
            log_n_choose_t,
            sets,
        }
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
        execution::{distributed::DistributedTestRuntime, player::Identity},
        shamir::ShamirGSharings,
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
        let num_parties = 4;
        let threshold = 1;
        let log_n_choose_t = 2;

        // Session ID 0 used in encryption is the same as the first value of the AesRng, so we can compare the two in this test
        let sid = SessionId::from(23);

        let mut rng = AesRng::from_seed(seed);
        let prss_setup = PRSSSetup::epoch_init(num_parties, threshold, &mut rng);

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
        tracing::debug!("bitsize of reconstruced value: {}", recon.0.ilog2());
        tracing::debug!("maximum allowed bitsize: {}", LOG_BD1_NOM);

        // check that reconstruced PRSS random output E has limited bit length
        // must be at most (2^pow-1) * Bd bits (which is the nominator of Bd1)
        assert!(recon.0.ilog2() < LOG_BD1_NOM);

        // check that E is the sum of all r_A values
        let mut rng = AesRng::from_seed(seed);
        let mut plain_e = Z128::ZERO;
        for _ in 0..num_parties {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            let k: [u8; 32] = [key, sid.0.to_le_bytes()].concat().try_into().unwrap();

            let mut prf = Hasher::new_keyed(&k);
            prf.update(&0_u128.to_le_bytes());
            let mut psi_out = prf.finalize_xof();
            let mut res = [0_u128; 1];
            psi_out.read_u128_into::<BigEndian>(&mut res).unwrap();

            let u = res[0] >> (Z128::RING_SIZE as u32 - LOG_BD1_NOM + log_n_choose_t);

            plain_e += u;
        }

        assert_eq!(plain_e, recon);
    }

    #[test]
    fn test_prss_distributed_local() {
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::PrssPrep,
                    operands: vec![
                        String::from("s0"),
                        String::from("2"),
                        String::from("234"),
                        String::from("2500"),
                    ],
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("3"),
                        String::from("false"),
                        String::from("c0"),
                        String::from("s0"),
                    ],
                },
                Operation {
                    operator: Operator::ShrCI,
                    operands: vec![String::from("c1"), String::from("c0"), String::from("121")],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c1")],
                },
            ],
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];
        let threshold = 1;
        let num_parties = 4;
        let mut rng = AesRng::seed_from_u64(423);

        let prss_setup = Some(PRSSSetup::epoch_init(num_parties, threshold, &mut rng));

        let runtime = DistributedTestRuntime::new(identities, threshold as u8, prss_setup);
        let results = runtime.evaluate_circuit(&circuit).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(2)));
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(23)]
    fn test_prss_next_ctr(#[case] rounds: u128) {
        let num_parties = 4;
        let threshold = 1;

        // Session ID 0 used in encryption is the same as the first value of the AesRng, so we can compare the two in this test
        let sid = SessionId::from(23425);

        let mut rng = AesRng::seed_from_u64(54321);
        let prss = PRSSSetup::epoch_init(num_parties, threshold, &mut rng);

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
}
