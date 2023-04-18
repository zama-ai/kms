use crate::{
    execution::LOG_BD1_NOM, residue_poly::ResiduePoly, shamir::ShamirGSharings, One, Ring, Sample,
    ZConsts, Zero, Z128,
};
use aes_prng::AesRng;
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
use std::num::Wrapping;

// precomputed points on poly f_A for n=4 and t=1
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
    (1..n + 1).combinations(n - t).collect()
}

// structure for holding values for each subset of n-t parties
struct PrssSet {
    parties: Vec<usize>,
    psi_prg: Prg,
}

pub struct PRSS {
    num_parties: usize,
    log_n_choose_t: u32,
    sets: Vec<PrssSet>,
}

struct Prg(AesRng);

impl Prg {
    fn init(key: [u8; 16]) -> Self {
        Prg(AesRng::from_seed(key))
    }
}

// Psi
fn psi(psi_prg: &mut Prg, log_n_choose_t: u32) -> Z128 {
    let res = Z128::sample(&mut psi_prg.0);

    // result is bounded by Bd_1
    Wrapping(res.0 >> (Z128::RING_SIZE as u32 - LOG_BD1_NOM + log_n_choose_t))
}

impl PRSS {
    /// PRSS Init
    pub fn init<R: RngCore>(num_parties: usize, threshold: usize, rng: &mut R) -> Self {
        // we are currently limited to 4 parties and threshold 1 for the PRSS due to pre-computed points for these params
        assert_eq!(num_parties, 4);
        assert_eq!(threshold, 1);
        let log_n_choose_t = num_integer::binomial(num_parties, threshold).ilog2();

        let sets = create_sets(num_parties, threshold)
            .into_iter()
            .map(|aset| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                PrssSet {
                    parties: aset,
                    psi_prg: Prg::init(key),
                }
            })
            .collect();

        PRSS {
            num_parties,
            log_n_choose_t,
            sets,
        }
    }

    /// PRSS Next for all parties at once for local testing
    pub fn next_all(&mut self) -> ShamirGSharings<Z128> {
        let mut shares: Vec<_> = (1..self.num_parties + 1)
            .map(|p| (p, ResiduePoly::<Z128>::ZERO))
            .collect();

        for (idx, set) in self.sets.iter_mut().enumerate() {
            let psi = psi(&mut set.psi_prg, self.log_n_choose_t);
            for (p, share) in shares.iter_mut().enumerate().take(self.num_parties) {
                if set.parties.contains(&share.0) {
                    let f_a = ResiduePoly::<Z128>::from_slice(PRECOMP_POINTS_4_1[idx][p]);
                    share.1 = share.1 + f_a * psi;
                }
            }
        }
        ShamirGSharings { shares }
    }

    /// PRSS Next for a single party
    pub fn next(&mut self, party_id: usize) -> ResiduePoly<Z128> {
        // party IDs start from 1
        debug_assert!(party_id > 0);

        let mut res = ResiduePoly::<Z128>::ZERO;

        for (idx, set) in self.sets.iter_mut().enumerate() {
            if set.parties.contains(&party_id) {
                let psi = psi(&mut set.psi_prg, self.log_n_choose_t);
                let f_a = ResiduePoly::<Z128>::from_slice(PRECOMP_POINTS_4_1[idx][party_id - 1]);
                res = res + f_a * psi;
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

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
    fn test_prss(#[case] seed: [u8; 16]) {
        let num_parties = 4;
        let threshold = 1;
        let log_n_choose_t = 2;

        let mut rng = AesRng::from_seed(seed);
        let mut prss = PRSS::init(num_parties, threshold, &mut rng);
        let e_shares = prss.next_all();

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
            let mut seed = [0u8; 16];
            rng.fill_bytes(&mut seed);

            let mut aes_rng = AesRng::from_seed(seed);
            let r_a = Z128::sample(&mut aes_rng).0
                >> (Z128::RING_SIZE as u32 - LOG_BD1_NOM + log_n_choose_t);
            plain_e += r_a;
        }

        assert_eq!(plain_e, recon);
    }
}
