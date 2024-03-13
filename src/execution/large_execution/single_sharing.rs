use super::local_single_share::LocalSingleShare;
use crate::{
    algebra::{
        bivariate::{compute_powers, MatrixMul},
        structure_traits::{Derive, ErrorCorrect, HenselLiftInverse, Ring, RingEmbed},
    },
    error::error_handler::anyhow_error_and_log,
    execution::runtime::{party::Role, session::LargeSessionHandles},
};
use async_trait::async_trait;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use rand::{CryptoRng, Rng};
use std::collections::HashMap;

#[async_trait]
pub trait SingleSharing<Z: Ring>: Send + Default + Clone {
    async fn init<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()>;
    async fn next<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<Z>;
}

//Might want to store the dispute set at the output of the lsl call
//as that'll influence how to reconstruct stuff later on
#[derive(Clone, Default)]
pub struct RealSingleSharing<Z, S: LocalSingleShare> {
    local_single_share: S,
    available_lsl: Vec<ArrayD<Z>>,
    available_shares: Vec<Z>,
    max_num_iterations: usize,
    vdm_matrix: ArrayD<Z>,
}

#[async_trait]
impl<Z: Ring + RingEmbed + HenselLiftInverse + Derive + ErrorCorrect, S: LocalSingleShare>
    SingleSharing<Z> for RealSingleSharing<Z, S>
{
    async fn init<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()> {
        if l == 0 {
            return Ok(());
        }

        let my_secrets = (0..l).map(|_| Z::sample(session.rng())).collect_vec();

        let shares = self
            .local_single_share
            .execute(session, &my_secrets)
            .await?;

        self.available_lsl = format_for_next(shares, l)?;
        self.max_num_iterations = l;

        //Init vdm matrix only once or when dim changes
        let shape = self.vdm_matrix.shape();
        let curr_height = session.num_parties();
        let curr_width = session.num_parties() - session.threshold() as usize;
        if self.vdm_matrix.is_empty() || curr_height != shape[0] || curr_width != shape[1] {
            self.vdm_matrix = init_vdm(
                session.num_parties(),
                session.num_parties() - session.threshold() as usize,
            )?;
        }
        Ok(())
    }
    async fn next<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<Z> {
        if self.available_shares.is_empty() {
            if self.available_lsl.is_empty() {
                self.init(session, self.max_num_iterations).await?;
            }
            self.available_shares = compute_next_batch(&mut self.available_lsl, &self.vdm_matrix)?;
        }
        Ok(self
            .available_shares
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Trying to pop an empty vector".to_string()))?)
    }
}

pub fn init_vdm<Z: Ring + RingEmbed>(height: usize, width: usize) -> anyhow::Result<ArrayD<Z>> {
    let invertible_points: Vec<Z> = (0..height)
        .map(|inv_idx| Z::embed_exceptional_set(inv_idx + 1))
        .try_collect()?;

    let powers_of_invertible_points: Vec<Z> = invertible_points
        .into_iter()
        .fold(Vec::<Z>::new(), |acc, point| {
            [acc, compute_powers(point, width - 1)].concat()
        });

    Ok(ArrayD::from_shape_vec(IxDyn(&[height, width]), powers_of_invertible_points)?.into_dyn())
}
//Have to be careful about ordering (e.g. cant just iterate over the set of key as its unordered)
//Format the map with keys role_i in Roles
//role_i -> [<x_1^{(i)}>_{self}, ... , <x_l^{(i)}>_{self}]
//to a map appropriate for the randomness extraction with keys j in [l]
// j -> [<x_j^{(1)}>_{self}, ..., <x_j^{(n)}>_{self}]
fn format_for_next<Z: Ring>(
    local_single_shares: HashMap<Role, Vec<Z>>,
    l: usize,
) -> anyhow::Result<Vec<ArrayD<Z>>> {
    let num_parties = local_single_shares.len();
    let mut res = Vec::with_capacity(l);
    for i in 0..l {
        let mut vec = Vec::with_capacity(num_parties);
        for j in 0..num_parties {
            vec.push(
                local_single_shares
                    .get(&Role::indexed_by_zero(j))
                    .ok_or_else(|| {
                        anyhow_error_and_log(format!("Can not find shares for Party {}", j + 1))
                    })?[i],
            );
        }
        res.push(ArrayD::from_shape_vec(IxDyn(&[num_parties]), vec)?.into_dyn());
    }
    Ok(res)
}

fn compute_next_batch<Z: Ring>(
    formated_lsl: &mut Vec<ArrayD<Z>>,
    vdm: &ArrayD<Z>,
) -> anyhow::Result<Vec<Z>> {
    let res = formated_lsl
        .pop()
        .ok_or_else(|| anyhow_error_and_log("Can not pop empty formated_lsl vector".to_string()))?
        .matmul(vdm)?;
    Ok(res.into_raw_vec())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{init_vdm, RealSingleSharing};
    use crate::execution::sharing::shamir::RevealOp;
    use crate::{
        algebra::{
            residue_poly::ResiduePoly,
            structure_traits::{Derive, ErrorCorrect, HenselLiftInverse, Ring, RingEmbed, Sample},
        },
        execution::{
            large_execution::{
                coinflip::RealCoinflip,
                local_single_share::{LocalSingleShare, RealLocalSingleShare},
                share_dispute::RealShareDispute,
                single_sharing::SingleSharing,
                vss::RealVss,
            },
            runtime::party::Role,
            runtime::session::{LargeSession, ParameterHandles},
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };
    use ndarray::Ix2;
    use rstest::rstest;
    use std::num::Wrapping;

    use crate::algebra::residue_poly::ResiduePoly128;
    use crate::algebra::residue_poly::ResiduePoly64;
    type TrueLocalSingleShare = RealLocalSingleShare<RealCoinflip<RealVss>, RealShareDispute>;

    pub(crate) fn create_real_single_sharing<Z: Ring, L: LocalSingleShare>(
        lsl_strategy: L,
    ) -> RealSingleSharing<Z, L> {
        RealSingleSharing {
            local_single_share: lsl_strategy,
            ..Default::default()
        }
    }

    //#[test]
    fn test_singlesharing<Z: Ring + RingEmbed + Derive + ErrorCorrect + HenselLiftInverse>(
        parties: usize,
        threshold: usize,
    ) {
        let mut task = |mut session: LargeSession| async move {
            let lsl_batch_size = 10_usize;
            let extracted_size = session.num_parties() - session.threshold() as usize;
            let num_output = lsl_batch_size * extracted_size + 1;
            let mut res = Vec::<Z>::new();
            let mut single_sharing = RealSingleSharing::<Z, TrueLocalSingleShare>::default();
            single_sharing
                .init(&mut session, lsl_batch_size)
                .await
                .unwrap();
            for _ in 0..num_output {
                res.push(single_sharing.next(&mut session).await.unwrap());
            }
            (session.my_role().unwrap(), res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init single sharing
        //      share dispute = 1 round
        //      pads =  1 round
        //      coinflip = vss + open = (1 + 3 + threshold) + 1
        //      verify = 1 reliable_broadcast = 3 + t rounds
        // next() calls for the batch
        //      We're doing one more sharing than pre-computed in the initial init (see num_output)
        //      Thus we have one more call to init, and therefore we double the rounds from above
        let rounds = (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) * 2;
        let result = execute_protocol_large::<Z, _, _>(parties, threshold, Some(rounds), &mut task);

        //Check we can reconstruct
        let lsl_batch_size = 10_usize;
        let extracted_size = parties - threshold;
        let num_output = lsl_batch_size * extracted_size + 1;
        assert_eq!(result[0].1.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec = Vec::new();
            for (role, res) in result.iter() {
                res_vec.push(Share::new(*role, res[value_idx]));
            }
            let shamir_sharing = ShamirSharings::create(res_vec);
            let res = shamir_sharing.reconstruct(threshold);
            assert!(res.is_ok());
        }
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    fn test_singlesharing_z128(#[case] num_parties: usize, #[case] threshold: usize) {
        test_singlesharing::<ResiduePoly128>(num_parties, threshold);
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    fn test_singlesharing_z64(#[case] num_parties: usize, #[case] threshold: usize) {
        test_singlesharing::<ResiduePoly64>(num_parties, threshold);
    }
    //P2 dropout, but gives random value for reconstruction.
    // expect to see it as corrupt but able to reconstruct
    #[test]
    fn test_singlesharing_dropout() {
        let parties = 4;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, Vec<ResiduePoly128>) {
            let lsl_batch_size = 10_usize;
            let extracted_size = session.num_parties() - session.threshold() as usize;
            let num_output = lsl_batch_size * extracted_size + 1;
            let mut res = Vec::<ResiduePoly128>::new();
            if session.my_role().unwrap().one_based() != 2 {
                let mut single_sharing =
                    RealSingleSharing::<ResiduePoly128, TrueLocalSingleShare>::default();
                single_sharing
                    .init(&mut session, lsl_batch_size)
                    .await
                    .unwrap();
                for _ in 0..num_output {
                    res.push(single_sharing.next(&mut session).await.unwrap());
                }
                assert!(session.corrupt_roles.contains(&Role::indexed_by_one(2)));
            } else {
                for _ in 0..num_output {
                    res.push(ResiduePoly128::sample(&mut session.rng));
                }
            }
            (session.my_role().unwrap(), res)
        }

        let result =
            execute_protocol_large::<ResiduePoly128, _, _>(parties, threshold, None, &mut task);

        //Check we can reconstruct
        let lsl_batch_size = 10_usize;
        let extracted_size = parties - threshold;
        let num_output = lsl_batch_size * extracted_size + 1;
        assert_eq!(result[0].1.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec = Vec::new();
            for (role, res) in result.iter() {
                res_vec.push(Share::new(*role, res[value_idx]));
            }
            let shamir_sharing = ShamirSharings::create(res_vec);
            //Expect max 1 error coming from dropout
            let res = shamir_sharing.err_reconstruct(threshold, 1);
            assert!(res.is_ok());
        }
    }

    #[test]
    fn test_vdm() {
        let vdm = init_vdm(4, 4).unwrap();
        let coefs = vec![
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^2
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^3
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X + 1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(2_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^2 + 2Y + 1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(3_u128),
                    Wrapping(3_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^3 + 3*Y^2 + 3*Y + 1
            ResiduePoly {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^2
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^4
            ResiduePoly {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                ],
            }, //X^6
        ];

        let vdm = vdm.into_dimensionality::<Ix2>().unwrap();
        for i in 0..4 {
            for j in 0..4 {
                assert_eq!(coefs[4 * i + j], vdm[(i, j)]);
            }
        }
    }
}
