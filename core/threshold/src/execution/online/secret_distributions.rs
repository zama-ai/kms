use super::preprocessing::BitPreprocessing;
use crate::{
    algebra::structure_traits::Ring,
    execution::{sharing::share::Share, tfhe_internals::parameters::TUniformBound},
};

pub trait SecretDistributions {
    fn t_uniform<Z, P>(
        n: usize,
        bound: TUniformBound,
        preproc: &mut P,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z> + Send + ?Sized;
}

/// Structures to execute the Secret Shared Distributions as described in Fig. 70 of NIST document.
pub struct RealSecretDistributions {}

impl SecretDistributions for RealSecretDistributions {
    /// Sample shares of a secret sampled from the TUniform(1, -2^bound, 2^bound)
    /// that is every value in (-2^bound, 2^bound) is selected with prob 1/2^{bound+1}
    /// and the endpoints are selected with prob 1/2^{bound+2}
    fn t_uniform<Z, P>(
        n: usize,
        bound: TUniformBound,
        preproc: &mut P,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z> + Send + ?Sized,
    {
        let bound = bound.0;
        let b = preproc.next_bit_vec(n * (bound + 2))?;

        let mut res = Vec::with_capacity(n);

        for i in 1..=n {
            let r = (i - 1) * (bound + 2);
            let mut ei = b[r + bound + 2 - 1] - Z::from_u128(1 << bound);
            for j in 1..=bound + 1 {
                ei += b[r + j - 1] * Z::from_u128(1 << (j - 1));
            }
            res.push(ei);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        algebra::residue_poly::{ResiduePoly128, ResiduePoly64},
        execution::{
            online::{preprocessing::dummy::DummyPreprocessing, triple::open_list},
            runtime::session::{LargeSession, ParameterHandles},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::{RealSecretDistributions, SecretDistributions, TUniformBound};

    // TODO these two test could be merged into a generic test and then just calles with Z64 and Z128 respectively.
    #[test]
    fn test_uniform_z128() {
        let parties = 5;
        let threshold = 1;
        let bound = TUniformBound(2_usize);
        let batch = 100_usize;

        let mut task = |session: LargeSession| async move {
            let mut large_preproc =
                DummyPreprocessing::<ResiduePoly128, _, _>::new(0, session.clone());

            let res_vec =
                RealSecretDistributions::t_uniform(batch, bound, &mut large_preproc).unwrap();

            let opened_res = open_list(&res_vec, &session).await.unwrap();

            (session.my_role().unwrap(), opened_res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init single sharing
        //         share dispute = 1 round
        //         pads =  1 round
        //         coinflip = vss + open = (1 + 3 + threshold) + 1
        //         verify = 1 reliable_broadcast = 3 + t rounds
        // init double sharing
        //         same as single sharing above (the single and double sharings are batched)
        //  triple batch - have been precomputed, just one open = 1 round
        //  random batch - have been precomputed = 0 rounds
        // t_uniform generates bits (mult + open) = 2 rounds
        // opening of the final output = 1 round
        //let rounds = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1 + 2 + 1;
        //This is now a unit test as we use DummyPreprocessing, so only 1 round (for openeing at the end)
        let results =
            execute_protocol_large::<ResiduePoly128, _, _>(parties, threshold, Some(1), &mut task);

        //Check all parties agree and fall within expected bounds
        let ref_res = results[0].1.clone();
        for (_, res) in results {
            assert_eq!(res, ref_res);
        }
        for r in ref_res {
            let r = r.to_scalar().unwrap();
            //Center r
            let centered_r = if r + r > r {
                r.0 as i128
            } else {
                let tmp = u128::MAX - r.0;
                -(tmp as i128 + 1)
            };
            let bound = 2_i128.pow(bound.0 as u32);
            assert!(centered_r <= bound && centered_r >= -bound);
        }
    }

    #[test]
    fn test_uniform_z64() {
        let parties = 5;
        let threshold = 1;
        let bound = TUniformBound(2_usize);
        let batch = 100_usize;

        let mut task = |session: LargeSession| async move {
            //let mut large_preproc = RealLargePreprocessing::<ResiduePoly64>::init(
            //    &mut session,
            //    batch_sizes,
            //    TrueSingleSharing::default(),
            //    TrueDoubleSharing::default(),
            //)
            //.await
            //.unwrap();

            let mut large_preproc =
                DummyPreprocessing::<ResiduePoly64, _, _>::new(0, session.clone());

            let res_vec =
                RealSecretDistributions::t_uniform(batch, bound, &mut large_preproc).unwrap();

            let opened_res = open_list(&res_vec, &session).await.unwrap();

            (session.my_role().unwrap(), opened_res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init single sharing
        //         share dispute = 1 round
        //         pads =  1 round
        //         coinflip = vss + open = (1 + 3 + threshold) + 1
        //         verify = 1 reliable_broadcast = 3 + t rounds
        // init double sharing
        //         same as single sharing above (the single and double sharings are batched)
        //  triple batch - have been precomputed, just one open = 1 round
        //  random batch - have been precomputed = 0 rounds
        // t_uniform generates bits (mult + open) = 2 rounds
        // opening of the final output = 1 round
        //let rounds = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1 + 2 + 1;
        //This is now a unit test as we use DummyPreprocessing, so only 1 round (for openeing at the end)
        let results =
            execute_protocol_large::<ResiduePoly64, _, _>(parties, threshold, Some(1), &mut task);

        //Check all parties agree and fall within expected bounds
        let ref_res = results[0].1.clone();
        for (_, res) in results {
            assert_eq!(res, ref_res);
        }
        for r in ref_res {
            let r = r.to_scalar().unwrap();
            //Center r
            let centered_r = if r + r > r {
                r.0 as i64
            } else {
                let tmp = u64::MAX - r.0;
                -(tmp as i64 + 1)
            };
            let bound = 2_i64.pow(bound.0 as u32);
            assert!(centered_r <= bound && centered_r >= -bound);
        }
    }
}
