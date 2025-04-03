use super::{
    local_double_share::{DoubleShares, LocalDoubleShare},
    single_sharing::init_vdm,
};
use crate::{
    algebra::{
        bivariate::MatrixMul,
        structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed},
    },
    error::error_handler::anyhow_error_and_log,
    execution::runtime::{party::Role, session::LargeSessionHandles},
};
use async_trait::async_trait;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use tracing::instrument;

type DoubleArrayShares<Z> = (ArrayD<Z>, ArrayD<Z>);

pub struct DoubleShare<Z> {
    pub(crate) degree_t: Z,
    pub(crate) degree_2t: Z,
}

#[async_trait]
pub trait DoubleSharing<Z: Ring>: Send + Sync + Default + Clone {
    async fn init<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()>;

    async fn next<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<DoubleShare<Z>>;
}

//Might want to store the dispute set at the output of the ldl call
//as that'll influence how to reconstruct stuff later on
#[derive(Clone, Default)]
pub struct RealDoubleSharing<Z, S: LocalDoubleShare> {
    local_double_share: S,
    available_ldl: Vec<DoubleArrayShares<Z>>,
    available_shares: Vec<(Z, Z)>,
    max_num_iterations: usize,
    vdm_matrix: ArrayD<Z>,
}

#[async_trait]
impl<Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert, S: LocalDoubleShare> DoubleSharing<Z>
    for RealDoubleSharing<Z, S>
{
    #[instrument(name="DoubleSharing.Init",skip(self,session),fields(sid = ?session.session_id(),own_identity=?session.own_identity(), batch_size = ?l))]
    async fn init<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()> {
        if l == 0 {
            return Ok(());
        }

        let my_secrets = (0..l).map(|_| Z::sample(session.rng())).collect_vec();

        let ldl = self
            .local_double_share
            .execute(session, &my_secrets)
            .await?;

        //Prepare data from the map output by LocalDoubleShare to 2 vectors ready to be multiplied with the VDM matrix
        self.available_ldl = format_for_next(ldl, l)?;
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

    //NOTE: This is instrumented by the caller function to use the same span for all calls
    async fn next<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<DoubleShare<Z>> {
        //If there's no share available we recompute a new batch
        if self.available_shares.is_empty() {
            //If there's no more randomness to extract we re init
            if self.available_ldl.is_empty() {
                self.init(session, self.max_num_iterations).await?;
            }
            //Extract randomness from the next available set of LocalDoubleShare
            self.available_shares = compute_next_batch(&mut self.available_ldl, &self.vdm_matrix)?;
        }
        let res = self
            .available_shares
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Trying to pop an empty vector"))?;
        Ok(DoubleShare {
            degree_t: res.0,
            degree_2t: res.1,
        })
    }
}

///Have to be careful about ordering (e.g. cant just iterate over the set of key as its unordered)
///
///Format the map with keys role_i in Roles
///
///role_i -> DoubleShare{
///          share_t: [<x_1^{(i)}>_{self}^t, ... , <x_l^{(i)}>_{self}^t],
///          share_2t: [<x_1^{(i)}>_{self}^{2t}, ... , <x_l^{(i)}>_{self}^{2t}]
///          }
///
///to a vector of tuples appropriate for the randomness extraction with keys j in [l]
///
/// j -> (
///       [<x_j^{(1)}>_{self}^t, ..., <x_j^{(n)}>_{self}^t],
///       [<x_j^{(1)}>_{self}^{2t}, ..., <x_j^{(n)}>_{self}^{2t}]
///      )
fn format_for_next<Z: Ring>(
    local_double_shares: HashMap<Role, DoubleShares<Z>>,
    l: usize,
) -> anyhow::Result<Vec<DoubleArrayShares<Z>>> {
    let num_parties = local_double_shares.len();
    let mut res = Vec::with_capacity(l);
    for i in 0..l {
        let mut vec_t = Vec::with_capacity(num_parties);
        let mut vec_2t = Vec::with_capacity(num_parties);
        for party_idx in 0..num_parties {
            let double_share_j = local_double_shares
                .get(&Role::indexed_by_zero(party_idx))
                .ok_or_else(|| {
                    anyhow_error_and_log(format!("Can not find shares for Party {}", party_idx + 1))
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

/// Extract randomness of degree t and 2t using the parties' contributions and the VDM matrix
fn compute_next_batch<Z: Ring>(
    formatted_ldl: &mut Vec<DoubleArrayShares<Z>>,
    vdm: &ArrayD<Z>,
) -> anyhow::Result<Vec<(Z, Z)>> {
    let next_formatted_ldl = formatted_ldl
        .pop()
        .ok_or_else(|| anyhow_error_and_log("Can not access pop empty formatted_ldl vector"))?;
    let res_t = next_formatted_ldl
        .0
        .matmul(vdm)?
        .into_raw_vec_and_offset()
        .0;
    let res_2t = next_formatted_ldl
        .1
        .matmul(vdm)?
        .into_raw_vec_and_offset()
        .0;
    let res = res_t.into_iter().zip(res_2t).collect_vec();
    Ok(res)
}

#[cfg(test)]
pub(crate) mod tests {
    use num_integer::div_ceil;
    use rstest::rstest;

    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z128;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z64;
    use crate::algebra::structure_traits::Derive;
    use crate::algebra::structure_traits::ErrorCorrect;
    use crate::algebra::structure_traits::Invert;
    use crate::algebra::structure_traits::RingEmbed;
    use crate::execution::large_execution::constants::DISPUTE_STAT_SEC;
    use crate::execution::runtime::session::BaseSessionHandles;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::networking::NetworkMode;
    use crate::{
        algebra::structure_traits::{Ring, Sample},
        execution::{
            large_execution::{
                coinflip::RealCoinflip,
                double_sharing::{DoubleShare, DoubleSharing, LocalDoubleShare, RealDoubleSharing},
                local_double_share::RealLocalDoubleShare,
                share_dispute::RealShareDispute,
                vss::RealVss,
            },
            runtime::{
                party::Role,
                session::{LargeSession, ParameterHandles},
            },
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };

    type TrueLocalDoubleShare = RealLocalDoubleShare<RealCoinflip<RealVss>, RealShareDispute>;

    pub(crate) fn create_real_double_sharing<Z: Ring, L: LocalDoubleShare>(
        ldl_strategy: L,
    ) -> RealDoubleSharing<Z, L> {
        RealDoubleSharing {
            local_double_share: ldl_strategy,
            ..Default::default()
        }
    }
    //#[test]
    fn test_doublesharing<
        Z: Ring + RingEmbed + ErrorCorrect + Derive + Invert,
        const EXTENSION_DEGREE: usize,
    >(
        parties: usize,
        threshold: usize,
    ) {
        let mut task = |mut session: LargeSession| async move {
            let ldl_batch_size = 10_usize;
            let extracted_size = session.num_parties() - session.threshold() as usize;
            let num_output = ldl_batch_size * extracted_size + 1;
            let mut res = Vec::new();
            let mut double_sharing = RealDoubleSharing::<Z, TrueLocalDoubleShare>::default();
            double_sharing
                .init(&mut session, ldl_batch_size)
                .await
                .unwrap();
            for _ in 0..num_output {
                res.push(double_sharing.next(&mut session).await.unwrap());
            }
            (session.my_role().unwrap(), res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init double sharing
        //      share dispute = 1 round
        //      pads =  1 round
        //      coinflip = vss + open = (1 + 3 + threshold) + 1
        //      verify = m reliable_broadcast = m*(3 + t) rounds
        // next() calls for the batch
        //      We're doing one more sharing than pre-computed in the initial init (see num_output)
        //      Thus we have one more call to init, and therefore we double the rounds from above
        let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
        let rounds = (1 + 1 + (1 + 3 + threshold) + 1 + m * (3 + threshold)) * 2;
        //DoubleSharing assumes Sync network
        let result = execute_protocol_large::<_, _, Z, EXTENSION_DEGREE>(
            parties,
            threshold,
            Some(rounds),
            NetworkMode::Sync,
            None,
            &mut task,
        );

        //Check we can reconstruct both degree t and 2t, and they are equal
        let ldl_batch_size = 10_usize;
        let extracted_size = parties - threshold;
        let num_output = ldl_batch_size * extracted_size + 1;
        assert_eq!(result[0].1.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec_t = Vec::new();
            let mut res_vec_2t = Vec::new();
            for (role, res) in result.iter() {
                res_vec_t.push(Share::new(*role, res[value_idx].degree_t));
                res_vec_2t.push(Share::new(*role, res[value_idx].degree_2t));
            }
            let shamir_sharing_t = ShamirSharings::create(res_vec_t);
            let shamir_sharing_2t = ShamirSharings::create(res_vec_2t);
            let res_t = shamir_sharing_t.reconstruct(threshold);
            let res_2t = shamir_sharing_2t.reconstruct(2 * threshold);
            assert!(res_t.is_ok());
            assert!(res_2t.is_ok());
            assert_eq!(res_t.unwrap(), res_2t.unwrap());
        }
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    fn test_doublesharing_z128(#[case] num_parties: usize, #[case] threshold: usize) {
        test_doublesharing::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>(
            num_parties,
            threshold,
        );
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    fn test_doublesharing_z64(#[case] num_parties: usize, #[case] threshold: usize) {
        test_doublesharing::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>(
            num_parties,
            threshold,
        );
    }

    #[test]
    fn test_doublesharing_dropout() {
        let parties = 5;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, Vec<DoubleShare<ResiduePolyF4Z128>>) {
            let ldl_batch_size = 10_usize;
            let extracted_size = session.num_parties() - session.threshold() as usize;
            let num_output = ldl_batch_size * extracted_size + 1;
            let mut res = Vec::new();
            if session.my_role().unwrap().zero_based() != 1 {
                let mut double_sharing =
                    RealDoubleSharing::<ResiduePolyF4Z128, TrueLocalDoubleShare>::default();
                double_sharing
                    .init(&mut session, ldl_batch_size)
                    .await
                    .unwrap();
                for _ in 0..num_output {
                    res.push(double_sharing.next(&mut session).await.unwrap());
                }
                assert!(session.corrupt_roles().contains(&Role::indexed_by_zero(1)));
            } else {
                for _ in 0..num_output {
                    res.push(DoubleShare {
                        degree_t: ResiduePolyF4Z128::sample(session.rng()),
                        degree_2t: ResiduePolyF4Z128::sample(session.rng()),
                    })
                }
            }
            (session.my_role().unwrap(), res)
        }

        //DoubleSharing assumes Sync network
        let result = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(parties, threshold, None, NetworkMode::Sync, None, &mut task);

        //Check we can reconstruct both degree t and 2t, and they are equal
        let ldl_batch_size = 10_usize;
        let extracted_size = parties - threshold;
        let num_output = ldl_batch_size * extracted_size + 1;
        assert_eq!(result[0].1.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec_t = Vec::new();
            let mut res_vec_2t = Vec::new();
            for (role, res) in result.iter() {
                res_vec_t.push(Share::new(*role, res[value_idx].degree_t));
                //Dont take into account corrupt party's share (due to pol. degree)
                if role.zero_based() != 1 {
                    res_vec_2t.push(Share::new(*role, res[value_idx].degree_2t));
                }
            }
            let shamir_sharing_t = ShamirSharings::create(res_vec_t);
            let shamir_sharing_2t = ShamirSharings::create(res_vec_2t);
            //Expect at most 1 error from the dropout party
            let res_t = shamir_sharing_t.err_reconstruct(threshold, 1);
            //Here we needed to remove the corrupt party's share because of the pol. degree
            let res_2t = shamir_sharing_2t.reconstruct(2 * threshold);
            assert!(res_t.is_ok());
            assert!(res_2t.is_ok());
            assert_eq!(res_t.unwrap(), res_2t.unwrap());
        }
    }
}
