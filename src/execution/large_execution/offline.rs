use itertools::Itertools;
use rand::RngCore;

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        distributed::robust_opens_to_all,
        online::{preprocessing::Preprocessing, share::Share, triple::Triple},
        session::LargeSessionHandles,
    },
    residue_poly::ResiduePoly,
    sharing::{double_sharing::DoubleSharing, single_sharing::SingleSharing},
    value::Value,
    Z128,
};

pub struct BatchParams {
    pub single_double_sharing_batch_size: usize,
    pub triple_batch_size: usize,
    pub random_batch_size: usize,
}

const SINGLE_DOUBLE_SHARING_BATCH_SIZE: usize = 100_usize;
const TRIPLE_BATCH_SIZE: usize = 100_usize;
const RANDOM_BATCH_SIZE: usize = 100_usize;

impl Default for BatchParams {
    fn default() -> Self {
        Self {
            single_double_sharing_batch_size: SINGLE_DOUBLE_SHARING_BATCH_SIZE,
            triple_batch_size: TRIPLE_BATCH_SIZE,
            random_batch_size: RANDOM_BATCH_SIZE,
        }
    }
}

pub struct LargePreprocessing<S: SingleSharing, D: DoubleSharing> {
    triple_batch_size: usize,
    random_batch_size: usize,
    single_sharing_handle: S,
    double_sharing_handle: D,
    available_triples: Vec<Triple<ResiduePoly<Z128>>>,
    available_randoms: Vec<Share<ResiduePoly<Z128>>>,
}

impl<S: SingleSharing, D: DoubleSharing> LargePreprocessing<S, D> {
    ///NOTE: if None is passed for the option, we use the constants, which should at some point
    /// be set to give an optimized offline phase for ddec.
    ///
    /// batch_sizes is an option which contains in order:
    /// - batch size for single and double sharing
    /// - batch size for triple generation
    /// - batch size for random generation
    pub async fn init<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        batch_sizes: Option<BatchParams>,
    ) -> anyhow::Result<Self> {
        let batch_sizes = batch_sizes.unwrap_or_default();
        //Init single sharing
        let mut shh = S::default();
        shh.init(session, batch_sizes.single_double_sharing_batch_size)
            .await?;

        //Init double sharing
        let mut dsh = D::default();
        dsh.init(session, batch_sizes.single_double_sharing_batch_size)
            .await?;

        let mut large_preproc = Self {
            triple_batch_size: batch_sizes.triple_batch_size,
            random_batch_size: batch_sizes.random_batch_size,
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            available_triples: Vec::new(),
            available_randoms: Vec::new(),
        };

        large_preproc.next_triple_batch(session).await?;
        large_preproc.next_random_batch(session).await?;

        Ok(large_preproc)
    }

    async fn next_triple_batch<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<()> {
        let mut vec_share_x = Vec::with_capacity(self.triple_batch_size);
        let mut vec_share_y = Vec::with_capacity(self.triple_batch_size);
        let mut vec_double_share_v = Vec::with_capacity(self.triple_batch_size);
        for _ in 0..self.triple_batch_size {
            vec_share_x.push(self.single_sharing_handle.next(session).await?);
            vec_share_y.push(self.single_sharing_handle.next(session).await?);
            vec_double_share_v.push(self.double_sharing_handle.next(session).await?);
        }

        let network_vec_share_d = vec_share_x
            .iter()
            .zip(vec_share_y.iter())
            .zip(vec_double_share_v.iter())
            .map(|((x, y), v)| {
                let res = x * y + v.degree_2t;
                Value::Poly128(res)
            })
            .collect_vec();

        session.network().increase_round_counter().await?;

        let recons_vec_share_d = robust_opens_to_all(
            session,
            &network_vec_share_d,
            2 * session.threshold() as usize,
        )
        .await?
        .ok_or_else(|| {
            anyhow_error_and_log("Reconstruction failed in offline triple generation".to_string())
        })?;

        let vec_shares_z: Vec<_> = recons_vec_share_d
            .into_iter()
            .zip(vec_double_share_v.iter())
            .map(|(d, v)| {
                if let Value::Poly128(d) = d {
                    Ok(d - v.degree_t)
                } else {
                    Err(anyhow_error_and_log(
                        "Reconstructed value of incorrect type in offline triple generation"
                            .to_string(),
                    ))
                }
            })
            .try_collect()?;

        let my_role = session.my_role()?;
        let res = vec_share_x
            .into_iter()
            .zip(vec_share_y.into_iter())
            .zip(vec_shares_z.into_iter())
            .map(|((x, y), z)| {
                Triple::new(
                    Share::new(my_role, x),
                    Share::new(my_role, y),
                    Share::new(my_role, z),
                )
            })
            .collect_vec();
        self.available_triples = res;
        Ok(())
    }

    async fn next_random_batch<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<()> {
        let my_role = session.my_role()?;
        let mut res = Vec::with_capacity(self.random_batch_size);
        for _ in 0..self.random_batch_size {
            res.push(Share::new(
                my_role,
                self.single_sharing_handle.next(session).await?,
            ));
        }
        self.available_randoms = res;
        Ok(())
    }
}

impl<Rnd, L, S, D> Preprocessing<Rnd, ResiduePoly<Z128>, L> for LargePreprocessing<S, D>
where
    Rnd: RngCore + Send + Sync + Clone,
    L: LargeSessionHandles<Rnd>,
    S: SingleSharing,
    D: DoubleSharing,
{
    fn next_triple(&mut self, _session: &mut L) -> anyhow::Result<Triple<ResiduePoly<Z128>>> {
        //if self.available_triples.is_empty() {
        //    self.next_triple_batch(session).await?;
        //}

        self.available_triples
            .pop()
            .ok_or_else(|| anyhow_error_and_log("available_triple is empty".to_string()))
    }
    fn next_triple_vec(
        &mut self,
        amount: usize,
        _session: &mut L,
    ) -> anyhow::Result<Vec<Triple<ResiduePoly<Z128>>>> {
        if self.available_triples.len() >= amount {
            let mut res = Vec::with_capacity(amount);
            for _ in 0..amount {
                res.push(self.available_triples.pop().ok_or_else(|| {
                    anyhow_error_and_log("available_triple is empty".to_string())
                })?);
            }
            Ok(res)
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough triples to pop {amount}"
            )))
        }
    }
    fn next_random(&mut self, _session: &mut L) -> anyhow::Result<Share<ResiduePoly<Z128>>> {
        //if self.available_randoms.is_empty() {
        //    self.next_random_batch(session).await?;
        //}

        self.available_randoms
            .pop()
            .ok_or_else(|| anyhow_error_and_log("available_triple is empty".to_string()))
    }

    fn next_random_vec(
        &mut self,
        amount: usize,
        _session: &mut L,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128>>>> {
        if self.available_randoms.len() >= amount {
            let mut res = Vec::with_capacity(amount);
            for _ in 0..amount {
                res.push(self.available_randoms.pop().ok_or_else(|| {
                    anyhow_error_and_log("available_random is empty".to_string())
                })?);
            }
            Ok(res)
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough randomness to pop {amount}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        execution::{
            coinflip::RealCoinflip,
            large_execution::{
                offline::{LargePreprocessing, TRIPLE_BATCH_SIZE},
                share_dispute::RealShareDispute,
            },
            online::{preprocessing::Preprocessing, triple::Triple},
            party::Role,
            session::{LargeSession, ParameterHandles},
        },
        residue_poly::ResiduePoly,
        shamir::ShamirGSharings,
        sharing::{
            double_sharing::RealDoubleSharing, local_double_share::RealLocalDoubleShare,
            local_single_share::RealLocalSingleShare, single_sharing::RealSingleSharing,
            vss::RealVss,
        },
        tests::helper::tests::execute_protocol,
        Z128,
    };

    type TrueSingleSharing =
        RealSingleSharing<RealLocalSingleShare<RealCoinflip<RealVss>, RealShareDispute>>;
    type TrueDoubleSharing =
        RealDoubleSharing<RealLocalDoubleShare<RealCoinflip<RealVss>, RealShareDispute>>;

    #[test_log::test]
    fn test_triple_generation() {
        let parties = 5;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, Vec<Triple<ResiduePoly<Z128>>>) {
            let mut large_preproc =
                LargePreprocessing::<TrueSingleSharing, TrueDoubleSharing>::init(
                    &mut session,
                    None,
                )
                .await
                .unwrap();
            let mut res = Vec::new();
            for _ in 0..TRIPLE_BATCH_SIZE {
                res.push(large_preproc.next_triple(&mut session).unwrap());
            }
            (session.my_role().unwrap(), res)
        }

        let result = execute_protocol(parties, threshold, &mut task);

        //Check we can reconstruct everything and we do have multiplication triples
        for idx in 0..TRIPLE_BATCH_SIZE {
            let mut res_vec_x = Vec::new();
            let mut res_vec_y = Vec::new();
            let mut res_vec_z = Vec::new();
            for (_, res) in result.iter() {
                let curr_triple = res.get(idx).unwrap();
                let (x, y, z) = curr_triple.take();
                res_vec_x.push((x.owner().one_based(), x.value()));
                res_vec_y.push((y.owner().one_based(), y.value()));
                res_vec_z.push((z.owner().one_based(), z.value()));
            }

            let shamir_x = ShamirGSharings { shares: res_vec_x };
            let shamir_y = ShamirGSharings { shares: res_vec_y };
            let shamir_z = ShamirGSharings { shares: res_vec_z };

            let x = shamir_x.reconstruct(threshold as usize);
            assert!(x.is_ok());
            let y = shamir_y.reconstruct(threshold as usize);
            assert!(y.is_ok());
            let z = shamir_z.reconstruct(threshold as usize);
            assert!(z.is_ok());

            let expected_z = x.unwrap() * y.unwrap();
            assert_eq!(z.unwrap(), expected_z);
        }
    }

    //Test with P2 that never participates
    //Expect everything to go fine (although slower)
    #[test_log::test]
    fn test_triple_generation_dropout() {
        let parties = 5;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, Vec<Triple<ResiduePoly<Z128>>>) {
            if session.my_role().unwrap().zero_based() != 1 {
                let mut large_preproc =
                    LargePreprocessing::<TrueSingleSharing, TrueDoubleSharing>::init(
                        &mut session,
                        None,
                    )
                    .await
                    .unwrap();
                let mut res = Vec::new();
                for _ in 0..TRIPLE_BATCH_SIZE {
                    res.push(large_preproc.next_triple(&mut session).unwrap());
                }
                //assert P2 is corrupt
                assert!(session.corrupt_roles.contains(&Role::indexed_by_zero(1)));

                (session.my_role().unwrap(), res)
            } else {
                (session.my_role().unwrap(), Vec::new())
            }
        }

        let result = execute_protocol(parties, threshold, &mut task);

        //Check we can reconstruct everything and we do have multiplication triples
        for idx in 0..TRIPLE_BATCH_SIZE {
            let mut res_vec_x = Vec::new();
            let mut res_vec_y = Vec::new();
            let mut res_vec_z = Vec::new();
            for (role, res) in result.iter() {
                if role.zero_based() != 1 {
                    let curr_triple = res.get(idx).unwrap();
                    let (x, y, z) = curr_triple.take();
                    res_vec_x.push((x.owner().one_based(), x.value()));
                    res_vec_y.push((y.owner().one_based(), y.value()));
                    res_vec_z.push((z.owner().one_based(), z.value()));
                }
            }

            let shamir_x = ShamirGSharings { shares: res_vec_x };
            let shamir_y = ShamirGSharings { shares: res_vec_y };
            let shamir_z = ShamirGSharings { shares: res_vec_z };

            let x = shamir_x.reconstruct(threshold as usize);
            assert!(x.is_ok());
            let y = shamir_y.reconstruct(threshold as usize);
            assert!(y.is_ok());
            let z = shamir_z.reconstruct(threshold as usize);
            assert!(z.is_ok());

            let expected_z = x.unwrap() * y.unwrap();
            assert_eq!(z.unwrap(), expected_z);
        }
    }
}
