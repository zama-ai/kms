use rand::CryptoRng;
use rand::Rng;

use crate::experimental::algebra::cyclotomic::TernaryEntry;

/// This defines how Gaussians are generated for the BGV/BFV schemes. We use
/// the NewHope approximation of sum(b_i - b'_i) where b_i and b'_i {0, 1}
/// with the sum being over NewHopeB values of i.
/// This gives an approximation to a discrete Gaussian with standard deviation \sigma = \sqrt{NewHopeB/2}.
/// eg: if new_hope_bound = 1 then {-1, 0, 1} are selected with probabilities:
/// Pr[0] = 1/2; Pr[1] = Pr[-1] = 1/4
pub(crate) fn approximate_gaussian<R: Rng + CryptoRng>(
    rng: &mut R,
    new_hope_bound: usize,
) -> TernaryEntry {
    let bytes_amount = (2 * new_hope_bound + 7) / 8;
    let mut ss = vec![0_u8; bytes_amount];
    rng.fill(ss.as_mut_slice());

    let mut s = 0;
    let mut cnt = 0;

    for ss_j in ss.iter_mut() {
        let mut k = 0;
        while k < 4 && cnt < new_hope_bound {
            s += (*ss_j & 1) as i32;
            *ss_j >>= 1;

            s -= (*ss_j & 1) as i32;
            *ss_j >>= 1;

            cnt += 1;
            k += 1;
        }
    }
    assert!(s == -1 || s == 0 || s == 1);

    if s == -1 {
        TernaryEntry::NegativeOne
    } else if s == 0 {
        TernaryEntry::Zero
    } else {
        TernaryEntry::PositiveOne
    }
}
