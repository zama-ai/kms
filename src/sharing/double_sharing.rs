use std::collections::HashMap;

use async_trait::async_trait;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use rand::RngCore;

use crate::{
    algebra::bivariate::MatrixMul,
    error::error_handler::anyhow_error_and_log,
    execution::{party::Role, session::LargeSessionHandles},
    residue_poly::ResiduePoly,
    Sample, Z128,
};

use super::{
    local_double_share::{DoubleShares, LocalDoubleShare},
    single_sharing::init_vdm,
};

type DoubleArrayShares = (ArrayD<ResiduePoly<Z128>>, ArrayD<ResiduePoly<Z128>>);

pub struct DoubleShare {
    #[allow(dead_code)]
    pub(crate) degree_t: ResiduePoly<Z128>,
    #[allow(dead_code)]
    pub(crate) degree_2t: ResiduePoly<Z128>,
}

#[async_trait]
pub trait DoubleSharing: Send + Default {
    async fn init<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()>;

    async fn next<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<DoubleShare>;
}

//Might want to store the dispute set at the output of the lsl call
//as that'll influence how to reconstruct stuff later on
#[derive(Clone, Default)]
pub struct RealDoubleSharing<S: LocalDoubleShare> {
    _marker_local_single_share: std::marker::PhantomData<S>,
    available_ldl: Vec<DoubleArrayShares>,
    available_shares: Vec<(ResiduePoly<Z128>, ResiduePoly<Z128>)>,
    max_nb_iterations: usize,
    vdm_matrix: ArrayD<ResiduePoly<Z128>>,
}

#[async_trait]
impl<S: LocalDoubleShare> DoubleSharing for RealDoubleSharing<S> {
    async fn init<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()> {
        let my_secrets = (0..l)
            .map(|_| ResiduePoly::<Z128>::sample(session.rng()))
            .collect_vec();

        let ldl = S::execute(session, &my_secrets).await?;

        self.available_ldl = format_for_next(ldl, l)?;
        self.max_nb_iterations = l;
        self.vdm_matrix = init_vdm(
            session.amount_of_parties(),
            session.amount_of_parties() - session.threshold() as usize,
        )?;
        Ok(())
    }
    async fn next<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<DoubleShare> {
        if self.available_shares.is_empty() {
            if self.available_ldl.is_empty() {
                self.init(session, self.max_nb_iterations).await?;
            }
            self.available_shares = compute_next_batch(&mut self.available_ldl, &self.vdm_matrix)?;
        }
        let res = self
            .available_shares
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Trying to pop an empty vector".to_string()))?;
        Ok(DoubleShare {
            degree_t: res.0,
            degree_2t: res.1,
        })
    }
}

//Have to be careful about ordering (e.g. cant just iterate over the set of key as its unordered)
//Format the map with keys role_i in Roles
//role_i -> DoubleShare{
//          share_t: [<x_1^{(i)}>_{self}^t, ... , <x_l^{(i)}>_{self}^t],
//          share_2t: [<x_1^{(i)}>_{self}^{2t}, ... , <x_l^{(i)}>_{self}^{2t}]
//          }
//to a map appropriate for the randomness extraction with keys j in [l]
// j -> ([<x_j^{(1)}>_{self}^t, ..., <x_j^{(n)}>_{self}^t], [<x_j^{(1)}>_{self}^{2t}, ..., <x_j^{(n)}>_{self}^{2t}])
fn format_for_next(
    local_double_shares: HashMap<Role, DoubleShares>,
    l: usize,
) -> anyhow::Result<Vec<DoubleArrayShares>> {
    let num_parties = local_double_shares.len();
    let mut res = Vec::with_capacity(l);
    for i in 0..l {
        let mut vec_t = Vec::with_capacity(num_parties);
        let mut vec_2t = Vec::with_capacity(num_parties);
        for j in 0..num_parties {
            let double_share_j = local_double_shares
                .get(&Role::indexed_by_zero(j))
                .ok_or_else(|| {
                    anyhow_error_and_log(format!("Can not find shares for Party {}", j + 1))
                })?;
            vec_t.push(double_share_j.share_t[i]);
            vec_2t.push(double_share_j.share_2t[i]);
        }
        res.push((
            ArrayD::from_shape_vec(IxDyn(&[num_parties]), vec_t)?.into_dyn(),
            ArrayD::from_shape_vec(IxDyn(&[num_parties]), vec_2t)?.into_dyn(),
        ));
    }
    Ok(res)
}

fn compute_next_batch(
    formated_ldl: &mut Vec<DoubleArrayShares>,
    vdm: &ArrayD<ResiduePoly<Z128>>,
) -> anyhow::Result<Vec<(ResiduePoly<Z128>, ResiduePoly<Z128>)>> {
    let next_formated_ldl = formated_ldl.pop().ok_or_else(|| {
        anyhow_error_and_log("Can not acces pop empty formated_ldl vector".to_string())
    })?;
    let res_t = next_formated_ldl.0.matmul(vdm)?.into_raw_vec();
    let res_2t = next_formated_ldl.1.matmul(vdm)?.into_raw_vec();
    let res = res_t.into_iter().zip(res_2t).collect_vec();
    Ok(res)
}

#[cfg(test)]
mod tests {
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
            double_sharing::{DoubleShare, DoubleSharing, RealDoubleSharing},
            local_double_share::RealLocalDoubleShare,
            vss::RealVss,
        },
        tests::helper::tests::execute_protocol,
        Sample, Zero, Z128,
    };

    type TrueLocalDoubleShare = RealLocalDoubleShare<RealCoinflip<RealVss>, RealShareDispute>;

    #[test]
    fn test_doublesharing() {
        let parties = 4;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, [u8; 32], Vec<DoubleShare>) {
            let ldl_batch_size = 10_usize;
            let extracted_size = session.amount_of_parties() - session.threshold() as usize;
            let mut res = Vec::<DoubleShare>::new();
            let mut double_sharing = RealDoubleSharing::<TrueLocalDoubleShare>::default();
            double_sharing
                .init(&mut session, ldl_batch_size)
                .await
                .unwrap();
            for _ in 0..ldl_batch_size * extracted_size + 1 {
                res.push(double_sharing.next(&mut session).await.unwrap());
            }
            (session.my_role().unwrap(), session.rng.get_seed(), res)
        }

        let result = execute_protocol(parties, threshold, &mut task);

        //Check we can reconstruct both degree t and 2t, and they are equal
        let ldl_batch_size = 10_usize;
        let extracted_size = parties - threshold as usize;
        let nb_output = ldl_batch_size * extracted_size + 1;
        assert_eq!(result[0].2.len(), nb_output);
        for value_idx in 0..nb_output {
            let mut res_vec_t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); parties];
            let mut res_vec_2t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); parties];
            for (role, _, res) in result.iter() {
                res_vec_t[role.zero_based()] = (role.one_based(), res[value_idx].degree_t);
                res_vec_2t[role.zero_based()] = (role.one_based(), res[value_idx].degree_2t);
            }
            let shamir_sharing_t = ShamirGSharings { shares: res_vec_t };
            let shamir_sharing_2t = ShamirGSharings { shares: res_vec_2t };
            let res_t = shamir_sharing_t.reconstruct(threshold as usize);
            let res_2t = shamir_sharing_2t.reconstruct(2 * threshold as usize);
            assert!(res_t.is_ok());
            assert!(res_2t.is_ok());
            assert_eq!(res_t.unwrap(), res_2t.unwrap());
        }
    }

    #[test]
    fn test_doublesharing_dropout() {
        let parties = 4;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, [u8; 32], Vec<DoubleShare>) {
            let ldl_batch_size = 10_usize;
            let extracted_size = session.amount_of_parties() - session.threshold() as usize;
            let mut res = Vec::<DoubleShare>::new();
            if session.my_role().unwrap().zero_based() != 1 {
                let mut double_sharing = RealDoubleSharing::<TrueLocalDoubleShare>::default();
                double_sharing
                    .init(&mut session, ldl_batch_size)
                    .await
                    .unwrap();
                for _ in 0..ldl_batch_size * extracted_size + 1 {
                    res.push(double_sharing.next(&mut session).await.unwrap());
                }
                assert!(session.corrupt_roles.contains(&Role::indexed_by_zero(1)));
            } else {
                for _ in 0..ldl_batch_size * extracted_size + 1 {
                    res.push(DoubleShare {
                        degree_t: ResiduePoly::<Z128>::sample(&mut session.rng),
                        degree_2t: ResiduePoly::<Z128>::sample(&mut session.rng),
                    })
                }
            }
            (session.my_role().unwrap(), session.rng.get_seed(), res)
        }

        let result = execute_protocol(parties, threshold, &mut task);

        //Check we can reconstruct both degree t and 2t, and they are equal
        let ldl_batch_size = 10_usize;
        let extracted_size = parties - threshold as usize;
        let nb_output = ldl_batch_size * extracted_size + 1;
        assert_eq!(result[0].2.len(), nb_output);
        for value_idx in 0..nb_output {
            let mut res_vec_t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); parties];
            let mut res_vec_2t = vec![(0_usize, ResiduePoly::<Z128>::ZERO); parties];
            for (role, _, res) in result.iter() {
                res_vec_t[role.zero_based()] = (role.one_based(), res[value_idx].degree_t);
                res_vec_2t[role.zero_based()] = (role.one_based(), res[value_idx].degree_2t);
            }
            //Remove corrupt party's share
            res_vec_2t.remove(1);
            let shamir_sharing_t = ShamirGSharings { shares: res_vec_t };
            let shamir_sharing_2t = ShamirGSharings { shares: res_vec_2t };
            //Expect at most 1 error from the dropout party
            let res_t = shamir_sharing_t.err_reconstruct(threshold as usize, 1);
            //Here we needed to remove the corrupt party's share because of the pol. degree
            let res_2t = shamir_sharing_2t.reconstruct(2 * threshold as usize);
            assert!(res_t.is_ok());
            assert!(res_2t.is_ok());
            assert_eq!(res_t.unwrap(), res_2t.unwrap());
        }
    }
}
