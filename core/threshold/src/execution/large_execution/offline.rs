use crate::execution::config::BatchParams;
use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
use crate::execution::small_execution::offline::Preprocessing;
use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::triple::Triple,
        runtime::session::LargeSessionHandles,
        sharing::{
            open::{RobustOpen, SecureRobustOpen},
            share::Share,
        },
    },
    ProtocolDescription,
};
use itertools::Itertools;
use tonic::async_trait;
use tracing::{info_span, instrument, Instrument};

use super::double_sharing::{DoubleSharing, SecureDoubleSharing};
use super::single_sharing::{SecureSingleSharing, SingleSharing};

#[derive(Clone)]
pub struct RealLargePreprocessing<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>, RO: RobustOpen>
{
    single_sharing: S,
    double_sharing: D,
    robust_open: RO,
    // Note: PhantomData is needed because
    // both SingleSharing and DoubleSharing
    // rely on it for their definition
    ring_marker: std::marker::PhantomData<Z>,
}

impl<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>, RO: RobustOpen> ProtocolDescription
    for RealLargePreprocessing<Z, S, D, RO>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RealLargePreprocessing:\n{}\n{}\n{}",
            indent,
            S::protocol_desc(depth + 1),
            D::protocol_desc(depth + 1),
            RO::protocol_desc(depth + 1)
        )
    }
}

impl<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>, RO: RobustOpen>
    RealLargePreprocessing<Z, S, D, RO>
{
    pub fn new(single_sharing: S, double_sharing: D, robust_open: RO) -> Self {
        Self {
            single_sharing,
            double_sharing,
            robust_open,
            ring_marker: std::marker::PhantomData,
        }
    }
}

impl<
        Z: Ring,
        S: SingleSharing<Z> + Default,
        D: DoubleSharing<Z> + Default,
        RO: RobustOpen + Default,
    > Default for RealLargePreprocessing<Z, S, D, RO>
{
    fn default() -> Self {
        Self::new(S::default(), D::default(), RO::default())
    }
}

/// Alias for [`RealLargePreprocessing`] with a secure implementation of
/// [`SingleSharing`], [`DoubleSharing`], and [`RobustOpen`]
pub type SecureLargePreprocessing<Z> =
    RealLargePreprocessing<Z, SecureSingleSharing<Z>, SecureDoubleSharing<Z>, SecureRobustOpen>;

#[async_trait]
impl<
        Z: ErrorCorrect,
        Ses: LargeSessionHandles,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
        RO: RobustOpen,
    > Preprocessing<Z, Ses> for RealLargePreprocessing<Z, S, D, RO>
{
    async fn execute(
        &mut self,
        large_session: &mut Ses,
        batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>> {
        let init_span = info_span!("MPC_Large.Init", sid=?large_session.session_id(), own_identity=?large_session.own_identity(), batch_size=?batch_sizes);
        // We always want the session to use in-memory storage, it's up to higher level process (e.g. orchestrator)
        // to maybe decide to store data somewhere else
        let mut base_preprocessing = InMemoryBasePreprocessing::<Z>::default();

        //Init single sharing, we need 2 calls per triple and 1 call per randomness
        self.single_sharing
            .init(large_session, 2 * batch_sizes.triples + batch_sizes.randoms)
            .instrument(init_span.clone())
            .await?;

        //Init double sharing, we need 1 call per triple
        self.double_sharing
            .init(large_session, batch_sizes.triples)
            .instrument(init_span)
            .await?;

        if batch_sizes.triples > 0 {
            //Preprocess a batch of triples
            base_preprocessing.append_triples(
                next_triple_batch(
                    batch_sizes.triples,
                    &mut self.single_sharing,
                    &mut self.double_sharing,
                    &self.robust_open,
                    large_session,
                )
                .await?,
            );
        }
        if batch_sizes.randoms > 0 {
            //Preprocess a batch of randomness
            base_preprocessing.append_randoms(
                next_random_batch(batch_sizes.randoms, &mut self.single_sharing, large_session)
                    .await?,
            );
        }

        Ok(base_preprocessing)
    }
}

/// Constructs a new batch of triples and appends this to the internal triple storage.
/// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
#[instrument(name="MPC_Large.GenTriples",skip_all, fields(sid = ?session.session_id(), own_identity = ?session.own_identity(), ?batch_size=amount))]
async fn next_triple_batch<
    Z: ErrorCorrect,
    L: LargeSessionHandles,
    S: SingleSharing<Z>,
    D: DoubleSharing<Z>,
    RO: RobustOpen,
>(
    amount: usize,
    single_sharing: &mut S,
    double_sharing: &mut D,
    robust_open: &RO,
    session: &mut L,
) -> anyhow::Result<Vec<Triple<Z>>> {
    if amount == 0 {
        return Ok(Vec::new());
    }

    //NOTE: We create the telemetry span for SingleSharing Next here, but in truth the bulk of the work has been done in init
    //Next will simply pop stuff
    let single_sharing_span = info_span!(
        "SingleSharing.Next",
        session_id = ?session.session_id(),
        own_identity = ?session.own_identity(),
        batch_size = 2 * amount
    );

    //NOTE: We create the telemetry span for DoubleSharing Next here, but in truth the bulk of the work has been done in init
    //Next will simply pop stuff
    let double_sharing_span = info_span!("DoubleSharing.Next",
        sid = ?session.session_id(),
            own_identity = ?session.own_identity(),
            batch_size = amount
    );

    let mut vec_share_x = Vec::with_capacity(amount);
    let mut vec_share_y = Vec::with_capacity(amount);
    let mut vec_double_share_v = Vec::with_capacity(amount);

    for _ in 0..amount {
        vec_share_x.push(
            single_sharing
                .next(session)
                .instrument(single_sharing_span.clone())
                .await?,
        );
        vec_share_y.push(
            single_sharing
                .next(session)
                .instrument(single_sharing_span.clone())
                .await?,
        );
        vec_double_share_v.push(
            double_sharing
                .next(session)
                .instrument(double_sharing_span.clone())
                .await?,
        );
    }

    //Compute <d>_i^{2t} = <x>_i * <y>_i + <v>^{2t}
    let network_vec_share_d = vec_share_x
        .iter()
        .zip(vec_share_y.iter())
        .zip(vec_double_share_v.iter())
        .map(|((x, y), v)| *x * *y + v.degree_2t)
        .collect_vec();

    //Perform RobustOpen on the degree 2t masked z component
    let recons_vec_share_d = robust_open
        .robust_open_list_to_all(
            session,
            network_vec_share_d,
            2 * session.threshold() as usize,
        )
        .await?
        .ok_or_else(|| {
            anyhow_error_and_log("Reconstruction failed in offline triple generation".to_string())
        })?;

    //Remove the mask from the opened value
    let vec_shares_z: Vec<_> = recons_vec_share_d
        .into_iter()
        .zip(vec_double_share_v.iter())
        .map(|(d, v)| d - v.degree_t)
        .collect_vec();

    let my_role = session.my_role();
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
    Ok(res)
}

/// Computes a new batch of random values and appends the new batch to the the existing stash of prepreocessing random values.
/// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
#[instrument(name="MPC_Large.GenRandom",skip_all, fields(sid = ?session.session_id(), own_identity = ?session.own_identity(), batch_size = ?amount))]
pub(crate) async fn next_random_batch<Z: Ring, S: SingleSharing<Z>, L: LargeSessionHandles>(
    amount: usize,
    single_sharing: &mut S,
    session: &mut L,
) -> anyhow::Result<Vec<Share<Z>>> {
    //NOTE: We create the telemetry span for SingleSharing Next here, but in truth the bulk of the work has been done in init
    //Next will simply pop stuff
    let single_sharing_span = info_span!(
        "SingleSharing.Next",
        sid = ?session.session_id(),
        own_identity = ?session.own_identity(),
        batch_size = amount
    );
    let my_role = session.my_role();
    let mut res = Vec::with_capacity(amount);
    for _ in 0..amount {
        res.push(Share::new(
            my_role,
            single_sharing
                .next(session)
                .instrument(single_sharing_span.clone())
                .await?,
        ));
    }
    Ok(res)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
mod tests {
    use super::SecureLargePreprocessing;
    use crate::algebra::structure_traits::{Derive, ErrorCorrect, Invert};
    use crate::execution::config::BatchParams;
    use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
    use crate::execution::sharing::shamir::RevealOp;
    use crate::malicious_execution::large_execution::{
        malicious_coinflip::{DroppingCoinflipAfterVss, MaliciousCoinflipRecons},
        malicious_local_double_share::{
            MaliciousReceiverLocalDoubleShare, MaliciousSenderLocalDoubleShare,
        },
        malicious_local_single_share::{
            MaliciousReceiverLocalSingleShare, MaliciousSenderLocalSingleShare,
        },
        malicious_share_dispute::{
            DroppingShareDispute, MaliciousShareDisputeRecons, WrongShareDisputeRecons,
        },
        malicious_vss::{
            DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart, MaliciousVssR1,
        },
    };
    use crate::networking::NetworkMode;
    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
            structure_traits::Ring,
        },
        execution::{
            communication::broadcast::{Broadcast, SyncReliableBroadcast},
            large_execution::{
                coinflip::{Coinflip, RealCoinflip},
                double_sharing::RealDoubleSharing,
                local_double_share::{LocalDoubleShare, RealLocalDoubleShare},
                local_single_share::{LocalSingleShare, RealLocalSingleShare},
                offline::RealLargePreprocessing,
                share_dispute::{RealShareDispute, ShareDispute},
                single_sharing::RealSingleSharing,
                vss::{RealVss, SecureVss, Vss},
            },
            online::triple::Triple,
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{
                open::{RobustOpen, SecureRobustOpen},
                shamir::ShamirSharings,
                share::Share,
            },
            small_execution::offline::Preprocessing,
        },
        tests::helper::{
            tests::{execute_protocol_large_w_disputes_and_malicious, TestingParameters},
            tests_and_benches::execute_protocol_large,
        },
    };
    use rstest::rstest;

    fn test_offline_strategies<
        Z: Derive + Invert + ErrorCorrect,
        const EXTENSION_DEGREE: usize,
        P: Preprocessing<Z, LargeSession> + Clone + 'static,
    >(
        params: TestingParameters,
        malicious_offline: P,
    ) {
        let num_batches = 3;
        let (_, malicious_due_to_dispute) = params.get_dispute_map();
        let batch_sizes = BatchParams {
            triples: 10,
            randoms: 10,
        };
        let mut task_honest = |mut session: LargeSession| async move {
            let mut res_triples = Vec::new();
            let mut res_randoms = Vec::new();
            for _ in 0..num_batches {
                let mut correlated_randomness = SecureLargePreprocessing::<Z>::default()
                    .execute(&mut session, batch_sizes)
                    .await
                    .unwrap();

                res_triples.extend(
                    correlated_randomness
                        .next_triple_vec(batch_sizes.triples)
                        .unwrap(),
                );
                res_randoms.extend(
                    correlated_randomness
                        .next_random_vec(batch_sizes.randoms)
                        .unwrap(),
                );
            }

            (
                session.my_role(),
                (res_triples, res_randoms),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, mut malicious_offline: P| async move {
            for _ in 0..num_batches {
                let _ = malicious_offline.execute(&mut session, batch_sizes).await;
            }

            session.my_role()
        };

        //Preprocessing assumes Sync network
        let (result_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.dispute_pairs,
                &[
                    malicious_due_to_dispute.clone(),
                    params.malicious_roles.to_vec(),
                ]
                .concat(),
                malicious_offline,
                NetworkMode::Sync,
                None,
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
        for triple_idx in 0..num_batches * batch_sizes.randoms {
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
            let shamir_sharing_x = ShamirSharings::create(vec_x);
            let shamir_sharing_y = ShamirSharings::create(vec_y);
            let shamir_sharing_z = ShamirSharings::create(vec_z);
            let x = shamir_sharing_x.reconstruct(params.threshold);
            let y = shamir_sharing_y.reconstruct(params.threshold);
            let z = shamir_sharing_z.reconstruct(params.threshold);
            assert!(x.is_ok());
            assert!(y.is_ok());
            assert!(z.is_ok());
            assert_eq!(x.unwrap() * y.unwrap(), z.unwrap());

            let shamir_sharing_r = ShamirSharings::create(vec_r);
            let r = shamir_sharing_r.reconstruct(params.threshold);
            assert!(r.is_ok());
        }
    }

    // Rounds (happy path)
    // init single sharing
    //         share dispute = 1 round
    //         pads =  1 round
    //         coinflip = vss + open = (1 + 3 + threshold) + 1
    //         verify = m reliable_broadcast = m*(3 + t) rounds
    // init double sharing
    //         same as single sharing above (single and double sharings are batched)
    //  triple batch - have been precomputed, just one open = 1 round
    //  random batch - have been precomputed = 0 rounds
    // = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + m*(3 + threshold)) + 1
    // Note: 3 batches, so above rounds times 3
    // m = 20 for extension degree 4
    #[rstest]
    #[case(TestingParameters::init_honest(5, 1, Some(3 * 177)))]
    #[case(TestingParameters::init_honest(9, 2, Some(3 * 219)))]
    fn test_large_offline_z128(#[case] params: TestingParameters) {
        let honest_offline = SecureLargePreprocessing::default();

        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params,
            honest_offline,
        );
    }

    // Rounds: same as for z128, see above
    #[rstest]
    #[case(TestingParameters::init_honest(5, 1, Some(3 * 177)))]
    #[case(TestingParameters::init_honest(9, 2, Some(3 * 219)))]
    fn test_large_offline_z64(#[case] params: TestingParameters) {
        let honest_offline = SecureLargePreprocessing::default();

        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params,
            honest_offline,
        );
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + Default + 'static,
        LDL: LocalDoubleShare + Default + 'static,
        BCast: Broadcast + Default + 'static,
        RO: RobustOpen + Default + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0,3],&[],true,None),
            )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] _broadcast_strategy: BCast,
        #[values(
                DroppingVssFromStart::default(),
                DroppingVssAfterR1::default(),
                MaliciousVssR1::new(&_broadcast_strategy,&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::new(_vss_strategy.clone(),robust_open_strategy.clone()),
                DroppingCoinflipAfterVss::new(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::new(&params.roles_to_lie_to)

            )]
        _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone()
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone()
                )
            )]
        ldl_strategy: LDL,
    ) {
        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );

        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );

        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_bis<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0,3],&[],true,None),
            )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] _broadcast_strategy: BCast,
        #[values(SecureVss::default())] _vss_strategy: V,
        #[values(
                RealCoinflip::new(_vss_strategy.clone(),robust_open_strategy.clone()),
                DroppingCoinflipAfterVss::new(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::new(&params.roles_to_lie_to)
            )]
        _share_dispute_strategy: S,
        #[values(
                MaliciousSenderLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                MaliciousSenderLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );

        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_not_caught<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0],&[],false,None),
            )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] _broadcast_strategy: BCast,
        #[values(
                RealVss::new(&_broadcast_strategy),
                DroppingVssAfterR2::new(&_broadcast_strategy),
                MaliciousVssR1::new(&_broadcast_strategy,&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::new(_vss_strategy.clone(),robust_open_strategy.clone()),
                MaliciousCoinflipRecons::new(_vss_strategy.clone(),robust_open_strategy.clone()),
            )]
        _coinflip_strategy: C,
        #[values(RealShareDispute::default())] _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                ),
                MaliciousReceiverLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                ),
                MaliciousReceiverLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );

        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );
    }

    // Test what happens when no more triples are present
    #[test]
    fn test_no_more_elements() {
        let parties = 5;
        let threshold = 1;

        const TRIPLE_BATCH_SIZE: usize = 10_usize;
        const RANDOM_BATCH_SIZE: usize = 10_usize;

        async fn task(
            mut session: LargeSession,
        ) -> (
            LargeSession,
            Vec<Triple<ResiduePolyF4Z128>>,
            Vec<Share<ResiduePolyF4Z128>>,
        ) {
            let mut preproc = SecureLargePreprocessing::<ResiduePolyF4Z128>::default()
                .execute(
                    &mut session,
                    BatchParams {
                        triples: TRIPLE_BATCH_SIZE,
                        randoms: RANDOM_BATCH_SIZE,
                    },
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
            assert!(err.contains("Not enough triples to pop 1"));
            let err = preproc.next_random().unwrap_err().to_string();
            assert!(err.contains("Not enough randomness to pop 1"));
            (session, triple_res, rand_res)
        }

        //Preprocessing assumes Sync network
        let result = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(parties, threshold, None, NetworkMode::Sync, None, &mut task);

        for (_session, res_trip, res_rand) in result.iter() {
            assert_eq!(res_trip.len(), TRIPLE_BATCH_SIZE);
            assert_eq!(res_rand.len(), RANDOM_BATCH_SIZE);
        }
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2,5,6],&[],true,None)
            )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] _broadcast_strategy: BCast,
        #[values(
                DroppingVssFromStart::default(),
                DroppingVssAfterR1::default(),
                MaliciousVssR1::new(&_broadcast_strategy,&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::new(_vss_strategy.clone(),robust_open_strategy.clone()),
                DroppingCoinflipAfterVss::new(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::new(&params.roles_to_lie_to)

            )]
        _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                )
            )]
        ldl_strategy: LDL,
    ) {
        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );

        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_bis_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2,5,6],&[],true,None)
            )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] _broadcast_strategy: BCast,
        #[values(RealVss::new(&_broadcast_strategy))] _vss_strategy: V,
        #[values(
                RealCoinflip::new(_vss_strategy.clone(),robust_open_strategy.clone()),
                DroppingCoinflipAfterVss::new(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::new(&params.roles_to_lie_to)
            )]
        _share_dispute_strategy: S,
        #[values(
                MaliciousSenderLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                MaliciousSenderLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );

        let malicious_offline = RealLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_not_caught_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
        BCast: Broadcast + 'static,
        RO: RobustOpen + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2],&[],false,None)
            )]
        params: TestingParameters,
        #[values(SecureRobustOpen::default())] robust_open_strategy: RO,
        #[values(SyncReliableBroadcast::default())] _broadcast_strategy: BCast,
        #[values(
                RealVss::new(&_broadcast_strategy),
                DroppingVssAfterR2::new(&_broadcast_strategy),
                MaliciousVssR1::new(&_broadcast_strategy,&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::new(_vss_strategy.clone(),robust_open_strategy.clone()),
                MaliciousCoinflipRecons::new(_vss_strategy.clone(),robust_open_strategy.clone()),
            )]
        _coinflip_strategy: C,
        #[values(RealShareDispute::default())] _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                ),
                MaliciousReceiverLocalSingleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                ),
                MaliciousReceiverLocalDoubleShare::new(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    _broadcast_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        use crate::malicious_execution::large_execution::malicious_offline::CheatingLargePreprocessing;

        let malicious_offline = CheatingLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );

        let malicious_offline = CheatingLargePreprocessing::new(
            RealSingleSharing::new(lsl_strategy.clone()),
            RealDoubleSharing::new(ldl_strategy.clone()),
            robust_open_strategy.clone(),
        );
        test_offline_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_offline,
        );
    }
}
