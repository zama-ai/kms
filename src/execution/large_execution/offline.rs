use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{
            preprocessing::{
                BasePreprocessing, Preprocessing, RANDOM_BATCH_SIZE, TRIPLE_BATCH_SIZE,
            },
            triple::Triple,
        },
        runtime::session::LargeSessionHandles,
        sharing::{open::robust_opens_to_all, shamir::ShamirRing, share::Share},
    },
};
use itertools::Itertools;
use rand::RngCore;

#[derive(Clone, Copy)]
pub struct BatchParams {
    pub triple_batch_size: usize,
    pub random_batch_size: usize,
}

impl Default for BatchParams {
    fn default() -> Self {
        Self {
            triple_batch_size: TRIPLE_BATCH_SIZE,
            random_batch_size: RANDOM_BATCH_SIZE,
        }
    }
}

#[derive(Default, Clone)]
pub struct LargePreprocessing<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>> {
    triple_batch_size: usize,
    random_batch_size: usize,
    single_sharing_handle: S,
    double_sharing_handle: D,
    elements: BasePreprocessing<Z>,
}

impl<Z: ShamirRing, S: SingleSharing<Z>, D: DoubleSharing<Z>> LargePreprocessing<Z, S, D> {
    /// Initializes the preprocessing for a new epoch, by preprocessing a batch
    /// NOTE: if None is passed for the option, we use the constants, which should at some point
    /// be set to give an optimized offline phase for ddec.
    ///
    /// batch_sizes is an option which contains in order:
    /// - batch size for single and double sharing
    /// - batch size for triple generation
    /// - batch size for random generation
    pub async fn init<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        batch_sizes: Option<BatchParams>,
        mut shh: S,
        mut dsh: D,
    ) -> anyhow::Result<Self> {
        let batch_sizes = batch_sizes.unwrap_or_default();
        //Init single sharing
        shh.init(
            session,
            2 * batch_sizes.triple_batch_size + batch_sizes.random_batch_size,
        )
        .await?;

        //Init double sharing
        dsh.init(session, batch_sizes.triple_batch_size).await?;
        let base_preprocessing = BasePreprocessing {
            available_triples: Vec::new(),
            available_randoms: Vec::new(),
        };
        let mut large_preproc = Self {
            triple_batch_size: batch_sizes.triple_batch_size,
            random_batch_size: batch_sizes.random_batch_size,
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            elements: base_preprocessing,
        };

        large_preproc.next_triple_batch(session).await?;
        large_preproc.next_random_batch(session).await?;

        Ok(large_preproc)
    }

    /// Constructs a new batch of triples and appends this to the internal triple storage.
    /// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
    async fn next_triple_batch<R: RngCore, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<()> {
        if self.triple_batch_size == 0 {
            return Ok(());
        }

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
            .map(|((x, y), v)| *x * *y + v.degree_2t)
            .collect_vec();

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
            .map(|(d, v)| d - v.degree_t)
            .collect_vec();

        let my_role = session.my_role()?;
        let mut res = vec_share_x
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
        self.elements.available_triples.append(&mut res);
        Ok(())
    }

    /// Computes a new batch of random values and appends the new batch to the the existing stash of prepreocessing random values.
    /// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
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
        self.elements.available_randoms.append(&mut res);
        Ok(())
    }
}

impl<Z: Ring, S, D> Preprocessing<Z> for LargePreprocessing<Z, S, D>
where
    S: SingleSharing<Z>,
    D: DoubleSharing<Z>,
{
    fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
        self.elements.next_triple()
    }

    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        self.elements.next_triple_vec(amount)
    }

    fn next_random(&mut self) -> anyhow::Result<Share<Z>> {
        self.elements.next_random()
    }

    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.elements.next_random_vec(amount)
    }
}

use crate::execution::large_execution::share_dispute::RealShareDispute;

use super::{
    coinflip::RealCoinflip,
    double_sharing::{DoubleSharing, RealDoubleSharing},
    local_double_share::RealLocalDoubleShare,
    local_single_share::RealLocalSingleShare,
    single_sharing::{RealSingleSharing, SingleSharing},
    vss::RealVss,
};

pub type TrueSingleSharing<Z> =
    RealSingleSharing<Z, RealLocalSingleShare<RealCoinflip<RealVss>, RealShareDispute>>;
pub type TrueDoubleSharing<Z> =
    RealDoubleSharing<Z, RealLocalDoubleShare<RealCoinflip<RealVss>, RealShareDispute>>;
pub type RealLargePreprocessing<Z> =
    LargePreprocessing<Z, TrueSingleSharing<Z>, TrueDoubleSharing<Z>>;

#[cfg(test)]
mod tests {
    use super::{BatchParams, TrueDoubleSharing, TrueSingleSharing};
    use crate::{
        algebra::{
            residue_poly::{ResiduePoly128, ResiduePoly64},
            structure_traits::Ring,
        },
        execution::{
            large_execution::{
                coinflip::{
                    tests::{DroppingCoinflipAfterVss, MaliciousCoinflipRecons},
                    Coinflip, RealCoinflip,
                },
                double_sharing::{tests::create_real_double_sharing, DoubleSharing},
                local_double_share::{
                    tests::{MaliciousReceiverLocalDoubleShare, MaliciousSenderLocalDoubleShare},
                    LocalDoubleShare, RealLocalDoubleShare,
                },
                local_single_share::{
                    tests::{MaliciousReceiverLocalSingleShare, MaliciousSenderLocalSingleShare},
                    Derive, LocalSingleShare, RealLocalSingleShare,
                },
                offline::LargePreprocessing,
                share_dispute::{
                    tests::{
                        DroppingShareDispute, MaliciousShareDisputeRecons, WrongShareDisputeRecons,
                    },
                    RealShareDispute, ShareDispute,
                },
                single_sharing::{tests::create_real_single_sharing, SingleSharing},
                vss::{
                    tests::{
                        DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart,
                        MaliciousVssR1,
                    },
                    RealVss, Vss,
                },
            },
            online::{
                preprocessing::{Preprocessing, RANDOM_BATCH_SIZE, TRIPLE_BATCH_SIZE},
                triple::Triple,
            },
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{
                open::robust_opens_to_all,
                shamir::{ShamirRing, ShamirSharing},
                share::Share,
            },
        },
        tests::helper::{
            tests::{execute_protocol_w_disputes_and_malicious, TestingParameters},
            tests_and_benches::execute_protocol_large,
        },
    };
    use async_trait::async_trait;
    use itertools::Itertools;
    use rstest::rstest;

    fn test_offline_strategies<
        Z: Ring + Derive + ShamirRing,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
        P: GenericMaliciousPreprocessing<Z, S, D> + 'static,
    >(
        params: TestingParameters,
        malicious_offline: P,
    ) {
        let nb_batches = 3;
        let (_, malicious_due_to_dispute) = params.get_dispute_map();
        let batch_sizes = BatchParams::default();
        let mut task_honest = |mut session: LargeSession| async move {
            let mut res_triples = Vec::new();
            let mut res_random = Vec::new();

            for _ in 0..nb_batches {
                let mut real_preproc =
                    LargePreprocessing::<Z, TrueSingleSharing<Z>, TrueDoubleSharing<Z>>::init(
                        &mut session,
                        Some(batch_sizes),
                        TrueSingleSharing::default(),
                        TrueDoubleSharing::default(),
                    )
                    .await
                    .unwrap();

                res_triples.append(
                    &mut real_preproc
                        .next_triple_vec(batch_sizes.triple_batch_size)
                        .unwrap(),
                );
                res_random.append(
                    &mut real_preproc
                        .next_random_vec(batch_sizes.random_batch_size)
                        .unwrap(),
                );
            }

            (
                session.my_role().unwrap(),
                (res_triples, res_random),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, mut malicious_offline: P| async move {
            for _ in 0..nb_batches {
                let _ = malicious_offline.init(&mut session, None).await;
            }

            session.my_role().unwrap()
        };

        let (result_honest, _) = execute_protocol_w_disputes_and_malicious::<Z, _, _, _, _, _>(
            &params,
            &params.dispute_pairs,
            &[
                malicious_due_to_dispute.clone(),
                params.malicious_roles.to_vec(),
            ]
            .concat(),
            malicious_offline,
            &mut task_honest,
            &mut task_malicious,
        );

        //make sure the dispute and malicious set of all honest parties is in sync
        let ref_malicious_set = result_honest[0].2.clone();
        let ref_dispute_set = result_honest[0].3.clone();
        for (_, _, malicious_set, dispute_set) in result_honest.iter() {
            assert_eq!(malicious_set, &ref_malicious_set);
            assert_eq!(dispute_set, &ref_dispute_set);
        }

        //If it applies
        //Make sure malicious parties are detected as such
        if params.should_be_detected {
            for role in &[
                malicious_due_to_dispute.clone(),
                params.malicious_roles.to_vec(),
            ]
            .concat()
            {
                assert!(ref_malicious_set.contains(role));
            }
        } else {
            assert!(ref_malicious_set.is_empty());
        }

        //Check that everything reconstructs, and that triples are triples
        for triple_idx in 0..nb_batches * batch_sizes.random_batch_size {
            let mut vec_x = Vec::new();
            let mut vec_y = Vec::new();
            let mut vec_z = Vec::new();
            let mut vec_r = Vec::new();
            for (_, res, _, _) in result_honest.iter() {
                let (x, y, z) = res.0[triple_idx].take();
                let r = res.1[triple_idx];
                vec_x.push(x);
                vec_y.push(y);
                vec_z.push(z);
                vec_r.push(r);
            }
            let shamir_sharing_x = ShamirSharing::create(vec_x);
            let shamir_sharing_y = ShamirSharing::create(vec_y);
            let shamir_sharing_z = ShamirSharing::create(vec_z);
            let x = shamir_sharing_x.reconstruct(params.threshold);
            let y = shamir_sharing_y.reconstruct(params.threshold);
            let z = shamir_sharing_z.reconstruct(params.threshold);
            assert!(x.is_ok());
            assert!(y.is_ok());
            assert!(z.is_ok());
            assert_eq!(x.unwrap() * y.unwrap(), z.unwrap());

            let shamir_sharing_r = ShamirSharing::create(vec_r);
            let r = shamir_sharing_r.reconstruct(params.threshold);
            assert!(r.is_ok());
        }
    }

    #[async_trait]
    trait GenericMaliciousPreprocessing<
        Z: ShamirRing + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    >: Preprocessing<Z> + Clone + Send
    {
        async fn init(
            &mut self,
            session: &mut LargeSession,
            batch_sizes: Option<BatchParams>,
        ) -> anyhow::Result<()>;

        async fn next_triple_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()>;

        async fn next_random_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()>;
    }

    #[derive(Default, Clone)]
    ///Malicious strategy that introduces an error in the reconstruction of beaver
    /// NOTE: Expect to fill single_sharing and double_sharing at creation
    pub(crate) struct CheatingLargePreprocessing<
        Z: ShamirRing + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    > {
        triple_batch_size: usize,
        random_batch_size: usize,
        single_sharing_handle: S,
        double_sharing_handle: D,
        available_triples: Vec<Triple<Z>>,
        available_randoms: Vec<Share<Z>>,
    }

    #[derive(Default, Clone)]
    ///Acts as a wrapper around the acutal protocol, needed because of the trait design around preprocessing
    pub(crate) struct HonestLargePreprocessing<
        Z: ShamirRing + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    > {
        single_sharing_handle: S,
        double_sharing_handle: D,
        large_preproc: LargePreprocessing<Z, S, D>,
    }

    #[async_trait]
    impl<Z: ShamirRing + Derive, S: SingleSharing<Z>, D: DoubleSharing<Z>>
        GenericMaliciousPreprocessing<Z, S, D> for CheatingLargePreprocessing<Z, S, D>
    {
        async fn init(
            &mut self,
            session: &mut LargeSession,
            batch_sizes: Option<BatchParams>,
        ) -> anyhow::Result<()> {
            let batch_sizes = batch_sizes.unwrap_or_default();
            //Init single sharing
            self.single_sharing_handle
                .init(
                    session,
                    2 * batch_sizes.triple_batch_size + batch_sizes.random_batch_size,
                )
                .await?;

            //Init double sharing
            self.double_sharing_handle
                .init(session, batch_sizes.triple_batch_size)
                .await?;

            self.triple_batch_size = batch_sizes.triple_batch_size;
            self.random_batch_size = batch_sizes.random_batch_size;
            self.available_triples.clear();
            self.available_randoms.clear();

            self.next_triple_batch(session).await?;
            self.next_random_batch(session).await?;

            Ok(())
        }

        //Lie to other in reconstructing masked product
        async fn next_triple_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            let mut vec_share_x = Vec::with_capacity(self.triple_batch_size);
            let mut vec_share_y = Vec::with_capacity(self.triple_batch_size);
            let mut vec_double_share_v = Vec::with_capacity(self.triple_batch_size);
            for _ in 0..self.triple_batch_size {
                vec_share_x.push(self.single_sharing_handle.next(session).await?);
                vec_share_y.push(self.single_sharing_handle.next(session).await?);
                vec_double_share_v.push(self.double_sharing_handle.next(session).await?);
            }

            //Add random error to every d and remove one
            let mut network_vec_share_d = vec_share_x
                .iter()
                .zip(vec_share_y.iter())
                .zip(vec_double_share_v.iter())
                .map(|((x, y), v)| {
                    let res = *x * *y + v.degree_2t + Z::sample(session.rng());
                    res
                })
                .collect_vec();
            network_vec_share_d.pop();

            let recons_vec_share_d = robust_opens_to_all(
                session,
                &network_vec_share_d,
                2 * session.threshold() as usize,
            )
            .await?
            .unwrap();

            let vec_share_z: Vec<_> = recons_vec_share_d
                .into_iter()
                .zip(vec_double_share_v.iter())
                .map(|(d, v)| d - v.degree_t)
                .collect_vec();

            let my_role = session.my_role()?;
            let res = vec_share_x
                .into_iter()
                .zip(vec_share_y)
                .zip(vec_share_z)
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

        async fn next_random_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
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

    impl<Z, S, D> Preprocessing<Z> for CheatingLargePreprocessing<Z, S, D>
    where
        Z: ShamirRing + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    {
        fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
            Ok(self.available_triples.pop().unwrap())
        }
        fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
            if self.available_triples.len() >= amount {
                let mut res = Vec::with_capacity(amount);
                for _ in 0..amount {
                    res.push(self.available_triples.pop().unwrap());
                }
                Ok(res)
            } else {
                Ok(Vec::new())
            }
        }
        fn next_random(&mut self) -> anyhow::Result<Share<Z>> {
            Ok(self.available_randoms.pop().unwrap())
        }

        fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
            if self.available_randoms.len() >= amount {
                let mut res = Vec::with_capacity(amount);
                for _ in 0..amount {
                    res.push(self.available_randoms.pop().unwrap());
                }
                Ok(res)
            } else {
                Ok(Vec::new())
            }
        }
    }

    //Needed because LargePreprocessing doesnt implement a specific trait
    #[async_trait]
    impl<Z: ShamirRing + Derive, S: SingleSharing<Z>, D: DoubleSharing<Z>>
        GenericMaliciousPreprocessing<Z, S, D> for HonestLargePreprocessing<Z, S, D>
    {
        async fn init(
            &mut self,
            session: &mut LargeSession,
            batch_sizes: Option<BatchParams>,
        ) -> anyhow::Result<()> {
            self.large_preproc = LargePreprocessing::<Z, S, D>::init(
                session,
                batch_sizes,
                self.single_sharing_handle.clone(),
                self.double_sharing_handle.clone(),
            )
            .await
            .unwrap();
            Ok(())
        }

        async fn next_triple_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            self.large_preproc.next_triple_batch(session).await
        }

        async fn next_random_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            self.large_preproc.next_random_batch(session).await
        }
    }

    impl<Z, S, D> Preprocessing<Z> for HonestLargePreprocessing<Z, S, D>
    where
        Z: ShamirRing + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    {
        fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
            self.large_preproc.next_triple()
        }
        fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
            self.large_preproc.next_triple_vec(amount)
        }
        fn next_random(&mut self) -> anyhow::Result<Share<Z>> {
            self.large_preproc.next_random()
        }

        fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
            self.large_preproc.next_random_vec(amount)
        }
    }

    // Rounds (happy path)
    // init single sharing
    //         share dispute = 1 round
    //         pads =  1 round
    //         coinflip = vss + open = (1 + 3 + threshold) + 1
    //         verify = 1 reliable_broadcast = 3 + t rounds
    // init double sharing
    //         same as single sharing above (single and double sharings are batched)
    //  triple batch - have been precomputed, just one open = 1 round
    //  random batch - have been precomputed = 0 rounds
    // = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1
    // = 21 + 4 * threshold (per init call)
    // Note: 3 batches, so above rounds times 3
    #[rstest]
    #[case(TestingParameters::init_honest(5, 1, Some(3 * 25)))]
    #[case(TestingParameters::init_honest(9, 2, Some(3 * 29)))]
    fn test_large_offline_z128(#[case] params: TestingParameters) {
        let malicious_offline = HonestLargePreprocessing::<
            ResiduePoly128,
            TrueSingleSharing<ResiduePoly128>,
            TrueDoubleSharing<ResiduePoly128>,
        >::default();

        test_offline_strategies(params, malicious_offline);
    }

    // Rounds: same as for z128, see above
    #[rstest]
    #[case(TestingParameters::init_honest(5, 1, Some(3 * 25)))]
    #[case(TestingParameters::init_honest(9, 2, Some(3 * 29)))]
    fn test_large_offline_z64(#[case] params: TestingParameters) {
        let malicious_offline = HonestLargePreprocessing::<
            ResiduePoly64,
            TrueSingleSharing<ResiduePoly64>,
            TrueDoubleSharing<ResiduePoly64>,
        >::default();

        test_offline_strategies(params, malicious_offline);
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0,3],&[],true,None),
            )]
        params: TestingParameters,
        #[values(
                DroppingVssFromStart::default(),
                DroppingVssAfterR1::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)

            )]
        _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        ldl_strategy: LDL,
    ) {
        let shh = create_real_single_sharing::<ResiduePoly64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);

        let shh = create_real_single_sharing::<ResiduePoly128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_bis<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0,3],&[],true,None),
            )]
        params: TestingParameters,
        #[values(RealVss::default())] _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)
            )]
        _share_dispute_strategy: S,
        #[values(
                MaliciousSenderLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                MaliciousSenderLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let shh = create_real_single_sharing::<ResiduePoly64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);

        let shh = create_real_single_sharing::<ResiduePoly128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_not_caught<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0],&[],false,None),
            )]
        params: TestingParameters,
        #[values(
                RealVss::default(),
                DroppingVssAfterR2::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                MaliciousCoinflipRecons::init(_vss_strategy.clone()),
            )]
        _coinflip_strategy: C,
        #[values(RealShareDispute::default())] _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let shh = create_real_single_sharing::<ResiduePoly64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies(params.clone(), malicious_offline);

        let shh = create_real_single_sharing::<ResiduePoly128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies(params.clone(), malicious_offline);
    }

    // Test what happens when no more triples are present
    #[test]
    fn test_no_more_elements() {
        let parties = 5;
        let threshold = 1;

        async fn task(
            mut session: LargeSession,
        ) -> (
            LargeSession,
            Vec<Triple<ResiduePoly128>>,
            Vec<Share<ResiduePoly128>>,
        ) {
            let mut preproc = LargePreprocessing::<
                ResiduePoly128,
                TrueSingleSharing<ResiduePoly128>,
                TrueDoubleSharing<ResiduePoly128>,
            >::init(
                &mut session,
                None,
                TrueSingleSharing::default(),
                TrueDoubleSharing::default(),
            )
            .await
            .unwrap();
            let mut triple_res = preproc.next_triple_vec(TRIPLE_BATCH_SIZE - 1).unwrap();
            triple_res.push(preproc.next_triple().unwrap());
            let mut rand_res = preproc.next_random_vec(RANDOM_BATCH_SIZE - 1).unwrap();
            rand_res.push(preproc.next_random().unwrap());
            // We have now used the entire batch of values and should thus fail
            assert!(preproc.next_triple().is_err());
            let err = preproc.next_triple().unwrap_err().to_string();
            assert!(err.contains("available_triple is empty"));
            let err = preproc.next_random().unwrap_err().to_string();
            assert!(err.contains("available_random is empty"));
            (session, triple_res, rand_res)
        }

        let result =
            execute_protocol_large::<ResiduePoly128, _, _>(parties, threshold, None, &mut task);

        for (_session, res_trip, res_rand) in result.iter() {
            assert_eq!(res_trip.len(), TRIPLE_BATCH_SIZE);
            assert_eq!(res_rand.len(), RANDOM_BATCH_SIZE);
        }
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2,5,6],&[],true,None)
            )]
        params: TestingParameters,
        #[values(
                DroppingVssFromStart::default(),
                DroppingVssAfterR1::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)

            )]
        _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        ldl_strategy: LDL,
    ) {
        let shh = create_real_single_sharing::<ResiduePoly64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);

        let shh = create_real_single_sharing::<ResiduePoly128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_bis_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2,5,6],&[],true,None)
            )]
        params: TestingParameters,
        #[values(RealVss::default())] _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)
            )]
        _share_dispute_strategy: S,
        #[values(
                MaliciousSenderLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                MaliciousSenderLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let shh = create_real_single_sharing::<ResiduePoly64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);

        let shh = create_real_single_sharing::<ResiduePoly128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies(params.clone(), malicious_offline);
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_not_caught_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2],&[],false,None)
            )]
        params: TestingParameters,
        #[values(
                RealVss::default(),
                DroppingVssAfterR2::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                MaliciousCoinflipRecons::init(_vss_strategy.clone()),
            )]
        _coinflip_strategy: C,
        #[values(RealShareDispute::default())] _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let shh = create_real_single_sharing::<ResiduePoly64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies(params.clone(), malicious_offline);

        let shh = create_real_single_sharing::<ResiduePoly128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: shh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies(params.clone(), malicious_offline);
    }
}
