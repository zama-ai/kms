use super::{
    gen_bits::{BitGenEven, Solve},
    preprocessing::Preprocessing,
};
use crate::execution::{
    runtime::session::BaseSessionHandles,
    sharing::{shamir::ShamirRing, share::Share},
};
use async_trait::async_trait;
use rand_core::CryptoRngCore;

#[async_trait]
pub trait SecretDistributions {
    async fn t_uniform<Z, Rnd, P, S, BitGen>(
        n: usize,
        bound: usize,
        preproc: &mut P,
        session: &mut S,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: ShamirRing + Solve,
        Rnd: CryptoRngCore + Send + Sync,
        S: BaseSessionHandles<Rnd>,
        P: Preprocessing<Z> + Send,
        BitGen: BitGenEven;
}

/// Structures to execute the Secret Shared Distributions as described in Fig. 67 of NIST document.
pub struct RealSecretDistributions {}

#[async_trait]
impl SecretDistributions for RealSecretDistributions {
    /// Sample shares of a secret sampled from the TUniform(1, -2^bound, 2^bound)
    /// that is every value in (-2^bound, 2^bound) is selected with prob 1/2^{bound+1}
    /// and the endpoints are selected with prob 1/2^{bound+2}
    async fn t_uniform<Z, Rnd, P, S, BitGen>(
        n: usize,
        bound: usize,
        preproc: &mut P,
        session: &mut S,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: ShamirRing + Solve,
        Rnd: CryptoRngCore + Send + Sync,
        S: BaseSessionHandles<Rnd>,
        P: Preprocessing<Z> + Send,
        BitGen: BitGenEven,
    {
        let b = BitGen::gen_bits_even(n * (bound + 2), preproc, session).await?;

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
            config::BatchParams,
            large_execution::offline::{
                RealLargePreprocessing, TrueDoubleSharing, TrueSingleSharing,
            },
            online::{gen_bits::RealBitGenEven, triple::open_list},
            runtime::session::{LargeSession, ParameterHandles},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    use super::{RealSecretDistributions, SecretDistributions};

    // TODO these two test could be merged into a generic test and then just calles with Z64 and Z128 respectively.
    #[test]
    fn test_uniform_z128() {
        let parties = 5;
        let threshold = 1;
        let bound = 2_usize;
        let batch = 100_usize;

        let mut task = |mut session: LargeSession| async move {
            let batch_sizes = BatchParams {
                triples: batch * (bound + 2),
                randoms: batch * (bound + 2),
            };
            let mut large_preproc = RealLargePreprocessing::<ResiduePoly128>::init(
                &mut session,
                batch_sizes,
                TrueSingleSharing::default(),
                TrueDoubleSharing::default(),
            )
            .await
            .unwrap();

            let res_vec = RealSecretDistributions::t_uniform::<_, _, _, _, RealBitGenEven>(
                batch,
                bound,
                &mut large_preproc,
                &mut session,
            )
            .await
            .unwrap();

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
        let rounds = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1 + 2 + 1;
        let results = execute_protocol_large::<ResiduePoly128, _, _>(
            parties,
            threshold,
            Some(rounds),
            &mut task,
        );

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
            let bound = 2_i128.pow(bound as u32);
            assert!(centered_r <= bound && centered_r >= -bound);
        }
    }

    #[test]
    fn test_uniform_z64() {
        let parties = 5;
        let threshold = 1;
        let bound = 2_usize;
        let batch = 100_usize;

        let mut task = |mut session: LargeSession| async move {
            let batch_sizes = BatchParams {
                triples: batch * (bound + 2),
                randoms: batch * (bound + 2),
            };
            let mut large_preproc = RealLargePreprocessing::<ResiduePoly64>::init(
                &mut session,
                batch_sizes,
                TrueSingleSharing::default(),
                TrueDoubleSharing::default(),
            )
            .await
            .unwrap();

            let res_vec = RealSecretDistributions::t_uniform::<_, _, _, _, RealBitGenEven>(
                batch,
                bound,
                &mut large_preproc,
                &mut session,
            )
            .await
            .unwrap();

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
        let rounds = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1 + 2 + 1;
        let results = execute_protocol_large::<ResiduePoly64, _, _>(
            parties,
            threshold,
            Some(rounds),
            &mut task,
        );

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
            let bound = 2_i64.pow(bound as u32);
            assert!(centered_r <= bound && centered_r >= -bound);
        }
    }
}
