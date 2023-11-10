use std::collections::HashMap;

use async_trait::async_trait;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use rand::RngCore;

use super::local_single_share::LocalSingleShare;
use crate::{
    algebra::bivariate::{compute_powers, MatrixMul},
    error::error_handler::anyhow_error_and_log,
    execution::{party::Role, session::LargeSessionHandles},
    residue_poly::ResiduePoly,
    Sample, Z128,
};

#[async_trait]
pub trait SingleSharing: Send + Default {
    async fn init<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()>;
    async fn next<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>>;
}

//Might want to store the dispute set at the output of the lsl call
//as that'll influence how to reconstruct stuff later on
#[derive(Clone, Default)]
pub struct RealSingleSharing<S: LocalSingleShare> {
    _marker_local_single_share: std::marker::PhantomData<S>,
    available_lsl: Vec<ArrayD<ResiduePoly<Z128>>>,
    available_shares: Vec<ResiduePoly<Z128>>,
    max_num_iterations: usize,
    vdm_matrix: ArrayD<ResiduePoly<Z128>>,
}

#[async_trait]
impl<S: LocalSingleShare> SingleSharing for RealSingleSharing<S> {
    async fn init<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()> {
        let my_secrets = (0..l)
            .map(|_| ResiduePoly::<Z128>::sample(session.rng()))
            .collect_vec();

        self.available_lsl = format_for_next(S::execute(session, &my_secrets).await?, l)?;
        self.max_num_iterations = l;
        self.vdm_matrix = init_vdm(
            session.amount_of_parties(),
            session.amount_of_parties() - session.threshold() as usize,
        )?;
        Ok(())
    }
    async fn next<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>> {
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

pub fn init_vdm(height: usize, width: usize) -> anyhow::Result<ArrayD<ResiduePoly<Z128>>> {
    let invertible_points: Vec<ResiduePoly<Z128>> = (0..height)
        .map(|inv_idx| ResiduePoly::<Z128>::embed(inv_idx + 1))
        .try_collect()?;

    let powers_of_invertible_points: Vec<ResiduePoly<Z128>> = invertible_points
        .into_iter()
        .fold(Vec::<ResiduePoly<Z128>>::new(), |acc, point| {
            [acc, compute_powers(point, width - 1)].concat()
        });

    Ok(ArrayD::from_shape_vec(IxDyn(&[height, width]), powers_of_invertible_points)?.into_dyn())
}
//Have to be careful about ordering (e.g. cant just iterate over the set of key as its unordered)
//Format the map with keys role_i in Roles
//role_i -> [<x_1^{(i)}>_{self}, ... , <x_l^{(i)}>_{self}]
//to a map appropriate for the randomness extraction with keys j in [l]
// j -> [<x_j^{(1)}>_{self}, ..., <x_j^{(n)}>_{self}]
fn format_for_next(
    local_single_shares: HashMap<Role, Vec<ResiduePoly<Z128>>>,
    l: usize,
) -> anyhow::Result<Vec<ArrayD<ResiduePoly<Z128>>>> {
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

fn compute_next_batch(
    formated_lsl: &mut Vec<ArrayD<ResiduePoly<Z128>>>,
    vdm: &ArrayD<ResiduePoly<Z128>>,
) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
    let res = formated_lsl
        .pop()
        .ok_or_else(|| anyhow_error_and_log("Can not pop empty formated_lsl vector".to_string()))?
        .matmul(vdm)?;
    Ok(res.into_raw_vec())
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use ndarray::Ix2;
    use tracing_test::traced_test;

    use crate::{
        execution::{
            coinflip::RealCoinflip,
            large_execution::share_dispute::RealShareDispute,
            party::Role,
            session::{LargeSession, ParameterHandles},
        },
        residue_poly::ResiduePoly,
        shamir::ShamirGSharings,
        sharing::{
            local_single_share::RealLocalSingleShare,
            single_sharing::{RealSingleSharing, SingleSharing},
            vss::RealVss,
        },
        tests::helper::tests::execute_protocol,
        Sample, Zero, Z128,
    };

    use super::init_vdm;

    type TrueLocalSingleShare = RealLocalSingleShare<RealCoinflip<RealVss>, RealShareDispute>;

    #[traced_test]
    #[test]
    fn test_singlesharing() {
        let parties = 4;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, [u8; 32], Vec<ResiduePoly<Z128>>) {
            let lsl_batch_size = 10_usize;
            let extracted_size = session.amount_of_parties() - session.threshold() as usize;
            let mut res = Vec::<ResiduePoly<Z128>>::new();
            let mut single_sharing = RealSingleSharing::<TrueLocalSingleShare>::default();
            single_sharing
                .init(&mut session, lsl_batch_size)
                .await
                .unwrap();
            for _ in 0..lsl_batch_size * extracted_size + 1 {
                res.push(single_sharing.next(&mut session).await.unwrap());
            }
            (session.my_role().unwrap(), session.rng.get_seed(), res)
        }

        let result = execute_protocol(parties, threshold, &mut task);

        //Check we can reconstruct
        let lsl_batch_size = 10_usize;
        let extracted_size = parties - threshold as usize;
        let num_output = lsl_batch_size * extracted_size + 1;
        assert_eq!(result[0].2.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec = vec![(0_usize, ResiduePoly::<Z128>::ZERO); parties];
            for (role, _, res) in result.iter() {
                res_vec[role.zero_based()] = (role.one_based(), res[value_idx]);
            }
            let shamir_sharing = ShamirGSharings { shares: res_vec };
            let res = shamir_sharing.reconstruct(threshold as usize);
            assert!(res.is_ok());
        }
    }

    //P2 dropout, but gives random value for reconstruction.
    // expect to see it as corrupt but able to reconstruct
    #[test]
    fn test_singlesharing_dropout() {
        let parties = 4;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, [u8; 32], Vec<ResiduePoly<Z128>>) {
            let lsl_batch_size = 10_usize;
            let extracted_size = session.amount_of_parties() - session.threshold() as usize;
            let mut res = Vec::<ResiduePoly<Z128>>::new();
            if session.my_role().unwrap().one_based() != 2 {
                let mut single_sharing = RealSingleSharing::<TrueLocalSingleShare>::default();
                single_sharing
                    .init(&mut session, lsl_batch_size)
                    .await
                    .unwrap();
                for _ in 0..lsl_batch_size * extracted_size + 1 {
                    res.push(single_sharing.next(&mut session).await.unwrap());
                }
                assert!(session.corrupt_roles.contains(&Role::indexed_by_one(2)));
            } else {
                for _ in 0..lsl_batch_size * extracted_size + 1 {
                    res.push(ResiduePoly::<Z128>::sample(&mut session.rng));
                }
            }
            (session.my_role().unwrap(), session.rng.get_seed(), res)
        }

        let result = execute_protocol(parties, threshold, &mut task);

        //Check we can reconstruct
        let lsl_batch_size = 10_usize;
        let extracted_size = parties - threshold as usize;
        let num_output = lsl_batch_size * extracted_size + 1;
        assert_eq!(result[0].2.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec = vec![(0_usize, ResiduePoly::<Z128>::ZERO); parties];
            for (role, _, res) in result.iter() {
                res_vec[role.zero_based()] = (role.one_based(), res[value_idx]);
            }
            let shamir_sharing = ShamirGSharings { shares: res_vec };
            //Expect max 1 error coming from dropout
            let res = shamir_sharing.err_reconstruct(threshold as usize, 1);
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
